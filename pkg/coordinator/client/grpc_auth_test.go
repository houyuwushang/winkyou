package client

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestSharedAuthUnaryClientInterceptorAddsCredential(t *testing.T) {
	interceptor := sharedAuthUnaryClientInterceptor("test-deployment-secret")
	called := false
	err := interceptor(
		context.Background(),
		"/test.Service/Unary",
		nil,
		nil,
		nil,
		func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			called = true
			assertOutgoingSharedAuth(t, ctx, "test-deployment-secret")
			return nil
		},
	)
	if err != nil {
		t.Fatalf("unary interceptor error = %v", err)
	}
	if !called {
		t.Fatal("unary invoker was not called")
	}
}

func TestSharedAuthStreamClientInterceptorAddsCredential(t *testing.T) {
	interceptor := sharedAuthStreamClientInterceptor("test-deployment-secret")
	called := false
	_, err := interceptor(
		context.Background(),
		&grpc.StreamDesc{},
		nil,
		"/test.Service/Stream",
		func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			called = true
			assertOutgoingSharedAuth(t, ctx, "test-deployment-secret")
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("stream interceptor error = %v", err)
	}
	if !called {
		t.Fatal("streamer was not called")
	}
}

func assertOutgoingSharedAuth(t *testing.T, ctx context.Context, want string) {
	t.Helper()
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("outgoing metadata is missing")
	}
	values := md.Get(SharedAuthMetadataKey)
	if len(values) != 1 || values[0] != want {
		t.Fatalf("shared auth metadata = %#v, want [%q]", values, want)
	}
}
