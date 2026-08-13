package server

import (
	"context"
	"strings"
	"testing"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	clientdto "winkyou/pkg/coordinator/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestSharedAuthUnaryInterceptor(t *testing.T) {
	tests := []struct {
		name       string
		authKey    string
		ctx        context.Context
		wantCode   codes.Code
		wantCalled bool
	}{
		{name: "disabled", ctx: context.Background(), wantCode: codes.OK, wantCalled: true},
		{name: "missing", authKey: "secret", ctx: context.Background(), wantCode: codes.Unauthenticated},
		{name: "wrong", authKey: "secret", ctx: incomingAuthContext("wrong"), wantCode: codes.Unauthenticated},
		{name: "duplicate", authKey: "secret", ctx: incomingAuthContext("secret", "secret"), wantCode: codes.Unauthenticated},
		{name: "valid", authKey: "secret", ctx: incomingAuthContext("secret"), wantCode: codes.OK, wantCalled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			_, err := SharedAuthUnaryInterceptor(tt.authKey)(
				tt.ctx,
				nil,
				&grpc.UnaryServerInfo{FullMethod: "/test.Service/Unary"},
				func(ctx context.Context, _ any) (any, error) {
					called = true
					if tt.authKey != "" {
						if err := requireSharedAuthContext(ctx, tt.authKey); err != nil {
							t.Fatalf("authenticated context marker error = %v", err)
						}
					}
					return nil, nil
				},
			)
			if got := status.Code(err); got != tt.wantCode {
				t.Fatalf("status code = %s, want %s (err=%v)", got, tt.wantCode, err)
			}
			if called != tt.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tt.wantCalled)
			}
		})
	}
}

func TestSharedAuthStreamInterceptorRejectsBeforeHandler(t *testing.T) {
	stream := &authTestServerStream{ctx: context.Background()}
	called := false
	err := SharedAuthStreamInterceptor("secret")(
		nil,
		stream,
		&grpc.StreamServerInfo{FullMethod: "/test.Service/Signal", IsClientStream: true, IsServerStream: true},
		func(_ any, stream grpc.ServerStream) error {
			called = true
			if err := requireSharedAuthContext(stream.Context(), "secret"); err != nil {
				t.Fatalf("authenticated stream context marker error = %v", err)
			}
			return nil
		},
	)
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("status code = %s, want %s (err=%v)", got, codes.Unauthenticated, err)
	}
	if called {
		t.Fatal("stream handler ran without authentication")
	}
}

func TestGRPCServiceFailsClosedWithoutAuthInterceptors(t *testing.T) {
	domain, err := New(&Config{
		ListenAddress: "127.0.0.1:0",
		NetworkCIDR:   "10.99.0.0/24",
		AuthKey:       "secret",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = domain.Close() }()

	service := NewGRPCService(domain)
	if _, err := service.Register(context.Background(), &coordinatorv1.RegisterRequest{
		PublicKey: "body-key-must-not-authenticate",
		AuthKey:   "secret",
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Register() without interceptor code = %s, want %s (err=%v)", status.Code(err), codes.Unauthenticated, err)
	}
	if _, err := service.ListPeers(context.Background(), &coordinatorv1.ListPeersRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("ListPeers() without interceptor code = %s, want %s (err=%v)", status.Code(err), codes.Unauthenticated, err)
	}
}

func TestSharedAuthStreamInterceptorAllowsValidCredential(t *testing.T) {
	stream := &authTestServerStream{ctx: incomingAuthContext("secret")}
	called := false
	err := SharedAuthStreamInterceptor("secret")(
		nil,
		stream,
		&grpc.StreamServerInfo{FullMethod: "/test.Service/Signal", IsClientStream: true, IsServerStream: true},
		func(_ any, stream grpc.ServerStream) error {
			called = true
			if err := requireSharedAuthContext(stream.Context(), "secret"); err != nil {
				t.Fatalf("authenticated stream context marker error = %v", err)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("stream interceptor error = %v", err)
	}
	if !called {
		t.Fatal("stream handler was not called")
	}
}

func TestGRPCServerOptionsRequiresCertificatePair(t *testing.T) {
	if _, err := GRPCServerOptions("secret", "coordinator.crt", ""); err == nil {
		t.Fatal("GRPCServerOptions() error = nil, want incomplete TLS pair rejection")
	}
}

func TestSharedAuthFailureDoesNotEchoCredential(t *testing.T) {
	const provided = "do-not-echo-this-value"
	err := authorizeSharedKey(incomingAuthContext(provided), "expected-secret")
	if err == nil {
		t.Fatal("authorizeSharedKey() error = nil, want rejection")
	}
	if strings.Contains(err.Error(), provided) {
		t.Fatalf("authentication error echoed provided credential: %v", err)
	}
}

func incomingAuthContext(values ...string) context.Context {
	return metadata.NewIncomingContext(
		context.Background(),
		metadata.MD{clientdto.SharedAuthMetadataKey: values},
	)
}

type authTestServerStream struct {
	ctx context.Context
}

func (s *authTestServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *authTestServerStream) SendHeader(metadata.MD) error { return nil }
func (s *authTestServerStream) SetTrailer(metadata.MD)       {}
func (s *authTestServerStream) Context() context.Context     { return s.ctx }
func (s *authTestServerStream) SendMsg(any) error            { return nil }
func (s *authTestServerStream) RecvMsg(any) error            { return nil }
