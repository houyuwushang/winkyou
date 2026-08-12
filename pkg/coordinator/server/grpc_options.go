package server

import (
	"crypto/tls"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GRPCServerOptions builds the coordinator's uniform authentication and
// optional TLS transport options. Listener exposure policy remains the caller's
// responsibility because it depends on the address being bound.
func GRPCServerOptions(authKey, tlsCertPath, tlsKeyPath string) ([]grpc.ServerOption, error) {
	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(SharedAuthUnaryInterceptor(authKey)),
		grpc.ChainStreamInterceptor(SharedAuthStreamInterceptor(authKey)),
	}

	hasCert := strings.TrimSpace(tlsCertPath) != ""
	hasKey := strings.TrimSpace(tlsKeyPath) != ""
	if hasCert != hasKey {
		return nil, fmt.Errorf("TLS certificate and key must be provided together")
	}
	if !hasCert {
		return options, nil
	}

	certificate, err := tls.LoadX509KeyPair(strings.TrimSpace(tlsCertPath), strings.TrimSpace(tlsKeyPath))
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate and key: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	return append(options, grpc.Creds(credentials.NewTLS(tlsConfig))), nil
}
