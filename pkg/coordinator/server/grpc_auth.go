package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	clientdto "winkyou/pkg/coordinator/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// SharedAuthUnaryInterceptor requires the deployment-wide shared credential on
// every unary RPC when authKey is configured. An empty key intentionally leaves
// authentication disabled for explicit loopback-only development servers.
func SharedAuthUnaryInterceptor(authKey string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		authenticatedCtx, err := authenticateSharedKey(ctx, authKey)
		if err != nil {
			return nil, err
		}
		return handler(authenticatedCtx, req)
	}
}

// SharedAuthStreamInterceptor applies the same credential check before a
// streaming handler can bind or replace a signaling session.
func SharedAuthStreamInterceptor(authKey string) grpc.StreamServerInterceptor {
	return func(
		srv any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		authenticatedCtx, err := authenticateSharedKey(stream.Context(), authKey)
		if err != nil {
			return err
		}
		return handler(srv, &sharedAuthServerStream{ServerStream: stream, ctx: authenticatedCtx})
	}
}

func authorizeSharedKey(ctx context.Context, expected string) error {
	_, err := authenticateSharedKey(ctx, expected)
	return err
}

func authenticateSharedKey(ctx context.Context, expected string) (context.Context, error) {
	if strings.TrimSpace(expected) == "" {
		return ctx, nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, unauthenticatedError()
	}
	values := md.Get(clientdto.SharedAuthMetadataKey)
	if len(values) != 1 || !sharedKeyMatches(expected, values[0]) {
		return nil, unauthenticatedError()
	}
	authenticatedDigest := sha256.Sum256([]byte(expected))
	return context.WithValue(ctx, sharedAuthContextKey{}, authenticatedDigest), nil
}

// requireSharedAuthContext is a defense-in-depth guard for GRPCService. It
// makes an authenticated service fail closed if it is accidentally registered
// on a grpc.Server without GRPCServerOptions.
func requireSharedAuthContext(ctx context.Context, expected string) error {
	if strings.TrimSpace(expected) == "" {
		return nil
	}
	authenticatedDigest, ok := ctx.Value(sharedAuthContextKey{}).([sha256.Size]byte)
	if !ok {
		return unauthenticatedError()
	}
	expectedDigest := sha256.Sum256([]byte(expected))
	if subtle.ConstantTimeCompare(authenticatedDigest[:], expectedDigest[:]) != 1 {
		return unauthenticatedError()
	}
	return nil
}

func sharedKeyMatches(expected, provided string) bool {
	expectedDigest := sha256.Sum256([]byte(expected))
	providedDigest := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedDigest[:], providedDigest[:]) == 1
}

func unauthenticatedError() error {
	return status.Error(codes.Unauthenticated, "coordinator authentication failed")
}

type sharedAuthContextKey struct{}

type sharedAuthServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *sharedAuthServerStream) Context() context.Context {
	return s.ctx
}
