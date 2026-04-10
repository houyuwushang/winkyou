package netif

import (
	"errors"
	"net"
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
	}{
		{name: "default", cfg: Config{}, wantType: "userspace", wantMTU: 1280},
		{name: "auto", cfg: Config{Backend: "auto", MTU: 1400}, wantType: "userspace", wantMTU: 1400},
		{name: "tun", cfg: Config{Backend: "tun", MTU: 1500}, wantType: "tun", wantMTU: 1500},
		{name: "userspace", cfg: Config{Backend: "userspace"}, wantType: "userspace", wantMTU: 1280},
		{name: "proxy", cfg: Config{Backend: "proxy"}, wantType: "proxy", wantMTU: 1280},
		{name: "unknown", cfg: Config{Backend: "magic"}, expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ni, err := New(tt.cfg)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error for unknown backend")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() returned error: %v", err)
			}
			if ni == nil {
				t.Fatal("New() returned nil interface")
			}
			if ni.Type() != tt.wantType {
				t.Fatalf("Type() = %q, want %q", ni.Type(), tt.wantType)
			}
			if ni.MTU() != tt.wantMTU {
				t.Fatalf("MTU() = %d, want %d", ni.MTU(), tt.wantMTU)
			}
			if ni.Name() == "" {
				t.Fatal("Name() returned empty string")
			}
		})
	}
}

func TestSetIPValidationAndOverride(t *testing.T) {
	ni := mustNewMemoryInterface(t, Config{})

	if err := ni.SetIP(net.ParseIP("2001:db8::1"), net.CIDRMask(64, 128)); !errors.Is(err, errIPv4Required) {
		t.Fatalf("SetIP(ipv6) error = %v, want errIPv4Required", err)
	}
	if err := ni.SetIP(net.ParseIP("10.0.0.2"), nil); !errors.Is(err, errMaskRequired) {
		t.Fatalf("SetIP(nil mask) error = %v, want errMaskRequired", err)
	}

	if err := ni.SetIP(net.ParseIP("10.0.0.2"), net.CIDRMask(24, 32)); err != nil {
		t.Fatalf("SetIP(valid) error = %v", err)
	}
	mem := ni.(*memoryInterface)
	if got := mem.ip.String(); got != "10.0.0.2" {
		t.Fatalf("stored ip = %q, want 10.0.0.2", got)
	}
	if ones, bits := net.IPMask(mem.mask).Size(); ones != 24 || bits != 32 {
		t.Fatalf("stored mask = /%d over %d bits, want /24 over 32 bits", ones, bits)
	}

	if err := ni.SetIP(net.ParseIP("10.0.1.2"), net.CIDRMask(16, 32)); err != nil {
		t.Fatalf("SetIP(override) error = %v", err)
	}
	if got := mem.ip.String(); got != "10.0.1.2" {
		t.Fatalf("overridden ip = %q, want 10.0.1.2", got)
	}
	if ones, bits := net.IPMask(mem.mask).Size(); ones != 16 || bits != 32 {
		t.Fatalf("overridden mask = /%d over %d bits, want /16 over 32 bits", ones, bits)
	}
}

func TestAddRemoveRouteLifecycle(t *testing.T) {
	ni := mustNewMemoryInterface(t, Config{})
	mem := ni.(*memoryInterface)

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
	if len(mem.routes) != 1 {
		t.Fatalf("len(routes) = %d, want 1", len(mem.routes))
	}

	key := routeKey(dst)
	if got := mem.routes[key].dst.String(); got != "10.10.0.0/24" {
		t.Fatalf("stored dst = %q, want 10.10.0.0/24", got)
	}
	if got := mem.routes[key].gateway.String(); got != "10.0.0.1" {
		t.Fatalf("stored gateway = %q, want 10.0.0.1", got)
	}

	if err := ni.AddRoute(dst, net.ParseIP("10.0.0.254")); err != nil {
		t.Fatalf("AddRoute(override) error = %v", err)
	}
	if len(mem.routes) != 1 {
		t.Fatalf("len(routes) after override = %d, want 1", len(mem.routes))
	}
	if got := mem.routes[key].gateway.String(); got != "10.0.0.254" {
		t.Fatalf("overridden gateway = %q, want 10.0.0.254", got)
	}

	if err := ni.RemoveRoute(dst); err != nil {
		t.Fatalf("RemoveRoute(existing) error = %v", err)
	}
	if len(mem.routes) != 0 {
		t.Fatalf("len(routes) after remove = %d, want 0", len(mem.routes))
	}
	if err := ni.RemoveRoute(dst); err != nil {
		t.Fatalf("RemoveRoute(missing) error = %v, want nil", err)
	}
}

func TestWriteThenReadPayload(t *testing.T) {
	ni := mustNewMemoryInterface(t, Config{})

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
	ni := mustNewMemoryInterface(t, Config{})

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
	ni := mustNewMemoryInterface(t, Config{})
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

func mustNewMemoryInterface(t *testing.T, cfg Config) NetworkInterface {
	t.Helper()

	ni, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, ok := ni.(*memoryInterface); !ok {
		t.Fatalf("New() returned %T, want *memoryInterface", ni)
	}
	return ni
}
