package netif

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewBackendSelectionAndDefaultMTU(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		wantType    string
		wantMTU     int
		expectError bool
		errContains string
	}{
		{name: "default-auto", cfg: Config{}, expectError: true, errContains: "auto backend selection failed", wantMTU: 1280},
		{name: "auto", cfg: Config{Backend: "auto", MTU: 1400}, expectError: true, errContains: "auto backend selection failed", wantMTU: 1400},
		{name: "tun", cfg: Config{Backend: "tun", MTU: 1500}, wantType: "tun", wantMTU: 1500},
		{name: "userspace", cfg: Config{Backend: "userspace"}, expectError: true, errContains: "userspace backend not implemented"},
		{name: "proxy", cfg: Config{Backend: "proxy"}, expectError: true, errContains: "proxy backend not implemented"},
		{name: "unknown", cfg: Config{Backend: "magic"}, expectError: true, errContains: "unknown backend"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ni, err := New(tt.cfg)
			if tt.expectError {
				if err == nil {
					if tt.cfg.Backend == "" || tt.cfg.Backend == "auto" {
						_ = ni.Close()
						return
					}
					t.Fatal("expected error")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("error = %q, want contains %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				if tt.cfg.Backend == "tun" {
					t.Skipf("tun unavailable in this environment: %v", err)
				}
				t.Fatalf("New() returned error: %v", err)
			}
			if ni == nil {
				t.Fatal("New() returned nil interface")
			}
			if tt.wantType != "" && ni.Type() != tt.wantType {
				t.Fatalf("Type() = %q, want %q", ni.Type(), tt.wantType)
			}
			if ni.MTU() != tt.wantMTU {
				t.Fatalf("MTU() = %d, want %d", ni.MTU(), tt.wantMTU)
			}
			if ni.Name() == "" {
				t.Fatal("Name() returned empty string")
			}
			_ = ni.Close()
		})
	}
}

func TestAutoSelectorPrioritizesTUNOnSupportedOS(t *testing.T) {
	if !supportsTUN(runtime.GOOS) {
		t.Skip("current OS does not support tun in selector")
	}

	_, err := New(Config{Backend: "auto", MTU: 1280})
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "tun:") {
		t.Fatalf("auto error = %q, want contains tun attempt", err)
	}
}

func TestSetIPValidationAndOverride(t *testing.T) {
	ni := newMemoryInterface(Config{Backend: "userspace", MTU: 1280})

	if err := ni.SetIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)); !errors.Is(err, errIPv4Required) {
		t.Fatalf("SetIP(ipv6) error = %v, want errIPv4Required", err)
	}
	if err := ni.SetIP(net.ParseIP("10.0.0.2"), nil); !errors.Is(err, errMaskRequired) {
		t.Fatalf("SetIP(nil mask) error = %v, want errMaskRequired", err)
	}

	if err := ni.SetIP(net.ParseIP("10.0.0.2"), net.CIDRMask(24, 32)); err != nil {
		t.Fatalf("SetIP(valid) error = %v", err)
	}
	if got := ni.ip.String(); got != "10.0.0.2" {
		t.Fatalf("stored ip = %q, want 10.0.0.2", got)
	}
	if ones, bits := net.IPMask(ni.mask).Size(); ones != 24 || bits != 32 {
		t.Fatalf("stored mask = /%d over %d bits, want /24 over 32 bits", ones, bits)
	}

	if err := ni.SetIP(net.ParseIP("10.0.1.2"), net.CIDRMask(16, 32)); err != nil {
		t.Fatalf("SetIP(override) error = %v", err)
	}
	if got := ni.ip.String(); got != "10.0.1.2" {
		t.Fatalf("overridden ip = %q, want 10.0.1.2", got)
	}
	if ones, bits := net.IPMask(ni.mask).Size(); ones != 16 || bits != 32 {
		t.Fatalf("overridden mask = /%d over %d bits, want /16 over 32 bits", ones, bits)
	}
}

func TestAddRemoveRouteLifecycle(t *testing.T) {
	ni := newMemoryInterface(Config{Backend: "userspace", MTU: 1280})

	if err := ni.AddRoute(nil, nil); !errors.Is(err, errRouteRequired) {
		t.Fatalf("AddRoute(nil) error = %v, want errRouteRequired", err)
	}
	if err := ni.RemoveRoute(nil); !errors.Is(err, errRouteRequired) {
		t.Fatalf("RemoveRoute(nil) error = %v, want errRouteRequired", err)
	}

	_, dst, _ := net.ParseCIDR("10.10.0.25/24")
	if err := ni.AddRoute(dst, net.ParseIP("10.0.0.1")); err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}
	if len(ni.routes) != 1 {
		t.Fatalf("len(routes) = %d, want 1", len(ni.routes))
	}

	key := routeKey(dst)
	if got := ni.routes[key].dst.String(); got != "10.10.0.0/24" {
		t.Fatalf("stored dst = %q, want 10.10.0.0/24", got)
	}
	if got := ni.routes[key].gateway.String(); got != "10.0.0.1" {
		t.Fatalf("stored gateway = %q, want 10.0.0.1", got)
	}

	if err := ni.AddRoute(dst, net.ParseIP("10.0.0.254")); err != nil {
		t.Fatalf("AddRoute(override) error = %v", err)
	}
	if len(ni.routes) != 1 {
		t.Fatalf("len(routes) after override = %d, want 1", len(ni.routes))
	}
	if got := ni.routes[key].gateway.String(); got != "10.0.0.254" {
		t.Fatalf("overridden gateway = %q, want 10.0.0.254", got)
	}

	if err := ni.RemoveRoute(dst); err != nil {
		t.Fatalf("RemoveRoute(existing) error = %v", err)
	}
	if len(ni.routes) != 0 {
		t.Fatalf("len(routes) after remove = %d, want 0", len(ni.routes))
	}
	if err := ni.RemoveRoute(dst); err != nil {
		t.Fatalf("RemoveRoute(missing) error = %v, want nil", err)
	}
}

func TestWriteThenReadPayload(t *testing.T) {
	ni := newMemoryInterface(Config{Backend: "userspace", MTU: 1280})

	payload := []byte("hello packet")
	n, err := ni.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() = %d, want %d", n, len(payload))
	}

	payload[0] = 'X'

	buf := make([]byte, 64)
	n, err = ni.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "hello packet" {
		t.Fatalf("Read() payload = %q, want %q", got, "hello packet")
	}
}

func TestCloseUnblocksRead(t *testing.T) {
	ni := newMemoryInterface(Config{Backend: "userspace", MTU: 1280})

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		_, err := ni.Read(buf)
		done <- err
	}()

	time.Sleep(25 * time.Millisecond)

	if err := ni.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read() after Close error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Read did not exit after Close")
	}
}

func TestCloseIsIdempotentAndOperationsFailAfterClose(t *testing.T) {
	ni := newMemoryInterface(Config{Backend: "userspace", MTU: 1280})
	_, dst, _ := net.ParseCIDR("10.20.0.0/16")

	if err := ni.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := ni.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}

	if _, err := ni.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write() after Close error = %v, want net.ErrClosed", err)
	}
	if err := ni.SetIP(net.ParseIP("10.0.0.2"), net.CIDRMask(24, 32)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetIP() after Close error = %v, want net.ErrClosed", err)
	}
	if err := ni.AddRoute(dst, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AddRoute() after Close error = %v, want net.ErrClosed", err)
	}
	if err := ni.RemoveRoute(dst); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("RemoveRoute() after Close error = %v, want net.ErrClosed", err)
	}
}
