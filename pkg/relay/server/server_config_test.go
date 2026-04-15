package server

import (
	"net"
	"testing"
)

func TestResolveListenAndRelayBindAddress(t *testing.T) {
	tests := []struct {
		name            string
		listenAddress   string
		relayIP         net.IP
		allowWildcard   bool
		wantErr         bool
		wantListen      string
		wantBind        string
	}{
		{
			name:          "wildcard with relay IP without allow flag",
			listenAddress: ":3478",
			relayIP:       net.ParseIP("203.0.113.10"),
			allowWildcard: false,
			wantErr:       true,
		},
		{
			name:          "wildcard with relay IP with allow flag",
			listenAddress: ":3478",
			relayIP:       net.ParseIP("203.0.113.10"),
			allowWildcard: true,
			wantErr:       false,
			wantListen:    ":3478",
			wantBind:      "0.0.0.0",
		},
		{
			name:          "0.0.0.0 with relay IP without allow flag",
			listenAddress: "0.0.0.0:3478",
			relayIP:       net.ParseIP("203.0.113.10"),
			allowWildcard: false,
			wantErr:       true,
		},
		{
			name:          "concrete IP with relay IP",
			listenAddress: "203.0.113.10:3478",
			relayIP:       net.ParseIP("203.0.113.10"),
			allowWildcard: false,
			wantErr:       false,
			wantListen:    "203.0.113.10:3478",
			wantBind:      "203.0.113.10",
		},
		{
			name:          "wildcard without relay IP",
			listenAddress: ":3478",
			relayIP:       nil,
			allowWildcard: false,
			wantErr:       false,
			wantListen:    ":3478",
			wantBind:      "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listen, bind, err := resolveListenAndRelayBindAddress(tt.listenAddress, tt.relayIP, tt.allowWildcard, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveListenAndRelayBindAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if listen != tt.wantListen {
				t.Errorf("resolveListenAndRelayBindAddress() listen = %v, want %v", listen, tt.wantListen)
			}
			if bind != tt.wantBind {
				t.Errorf("resolveListenAndRelayBindAddress() bind = %v, want %v", bind, tt.wantBind)
			}
		})
	}
}

func TestConfigPortRange(t *testing.T) {
	cfg := Config{
		ListenAddress: "127.0.0.1:3478",
		Realm:         "test",
		Users:         map[string]string{"user": "pass"},
		RelayAddress:  "127.0.0.1",
		MinPort:       50000,
		MaxPort:       50100,
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if srv.cfg.MinPort != 50000 {
		t.Errorf("MinPort = %d, want 50000", srv.cfg.MinPort)
	}
	if srv.cfg.MaxPort != 50100 {
		t.Errorf("MaxPort = %d, want 50100", srv.cfg.MaxPort)
	}
}
