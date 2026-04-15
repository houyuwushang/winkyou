package server

import (
	"net"
	"testing"
)

func TestResolveListenAndRelayBindAddress(t *testing.T) {
	localIPv4 := net.ParseIP("203.0.113.10")
	tests := []struct {
		name         string
		listen       string
		relayIP      net.IP
		hasLocalIP   bool
		wantListen   string
		wantBindAddr string
	}{
		{
			name:         "default wildcard without local relay ip",
			listen:       ":3478",
			relayIP:      localIPv4,
			hasLocalIP:   false,
			wantListen:   ":3478",
			wantBindAddr: "0.0.0.0",
		},
		{
			name:         "default wildcard with local relay ip",
			listen:       ":3478",
			relayIP:      localIPv4,
			hasLocalIP:   true,
			wantListen:   "203.0.113.10:3478",
			wantBindAddr: "203.0.113.10",
		},
		{
			name:         "explicit wildcard with local relay ip",
			listen:       "0.0.0.0:3478",
			relayIP:      localIPv4,
			hasLocalIP:   true,
			wantListen:   "203.0.113.10:3478",
			wantBindAddr: "203.0.113.10",
		},
		{
			name:         "explicit concrete listen host wins",
			listen:       "10.0.0.5:3478",
			relayIP:      localIPv4,
			hasLocalIP:   true,
			wantListen:   "10.0.0.5:3478",
			wantBindAddr: "10.0.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotListen, gotBind := resolveListenAndRelayBindAddress(tt.listen, tt.relayIP, func(net.IP) bool {
				return tt.hasLocalIP
			})
			if gotListen != tt.wantListen {
				t.Fatalf("listen = %q, want %q", gotListen, tt.wantListen)
			}
			if gotBind != tt.wantBindAddr {
				t.Fatalf("bind = %q, want %q", gotBind, tt.wantBindAddr)
			}
		})
	}
}
