package main

import "testing"

func TestValidateCoordinatorSecurity(t *testing.T) {
	tests := []struct {
		name     string
		listen   string
		authKey  string
		certPath string
		keyPath  string
		wantErr  bool
	}{
		{name: "ipv4 loopback development", listen: "127.0.0.1:9443"},
		{name: "ipv6 loopback development", listen: "[::1]:9443"},
		{name: "localhost is not a numeric explicit bind", listen: "localhost:9443", wantErr: true},
		{name: "unspecified without security", listen: ":9443", wantErr: true},
		{name: "all interfaces without security", listen: "0.0.0.0:9443", wantErr: true},
		{name: "remote auth without tls", listen: "192.0.2.10:9443", authKey: "secret", wantErr: true},
		{name: "remote tls without auth", listen: "192.0.2.10:9443", certPath: "server.crt", keyPath: "server.key", wantErr: true},
		{name: "remote secured", listen: "192.0.2.10:9443", authKey: "secret", certPath: "server.crt", keyPath: "server.key"},
		{name: "certificate without key", listen: "127.0.0.1:9443", certPath: "server.crt", wantErr: true},
		{name: "invalid listener", listen: "127.0.0.1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCoordinatorSecurity(tt.listen, tt.authKey, tt.certPath, tt.keyPath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateCoordinatorSecurity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
