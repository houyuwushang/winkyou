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
		if err := authorizeSharedKey(ctx, authKey); err != nil {
			return nil, err
		}
		return handler(ctx, req)
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
		if err := authorizeSharedKey(stream.Context(), authKey); err != nil {
			return err
		}
		return handler(srv, stream)
	}
}

func authorizeSharedKey(ctx context.Context, expected string) error {
	if strings.TrimSpace(expected) == "" {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return unauthenticatedError()
	}
	values := md.Get(clientdto.SharedAuthMetadataKey)
	if len(values) != 1 || !sharedKeyMatches(expected, values[0]) {
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
