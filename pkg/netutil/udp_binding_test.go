package netutil

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestResolveUDPBindingEmptyPreservesDefaultRouting(t *testing.T) {
	binding, err := ResolveUDPBinding("  ")
	if err != nil {
		t.Fatalf("ResolveUDPBinding(empty) error = %v", err)
	}
	if binding != nil {
		t.Fatalf("ResolveUDPBinding(empty) = %+v, want nil", binding)
	}
}

func TestResolveUDPBindingRejectsMissingInterface(t *testing.T) {
	_, err := ResolveUDPBinding("winkyou-interface-that-does-not-exist")
	if err == nil || !strings.Contains(err.Error(), "winkyou-interface-that-does-not-exist") {
		t.Fatalf("ResolveUDPBinding(missing) error = %v", err)
	}
}

func TestListenUDP4UsesResolvedInterfaceSource(t *testing.T) {
	binding := testUDPBinding(t)
	conn, err := ListenUDP4(context.Background(), binding, 0)
	if err != nil {
		t.Fatalf("ListenUDP4() error = %v", err)
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	if !local.IP.Equal(binding.LocalIP) {
		t.Fatalf("ListenUDP4() local IP = %s, want %s", local.IP, binding.LocalIP)
	}
}

func testUDPBinding(t *testing.T) *UDPBinding {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces() error = %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		binding, err := ResolveUDPBinding(iface.Name)
		if err == nil {
			return binding
		}
	}
	t.Skip("host has no active non-loopback interface with a usable IPv4 address")
	return nil
}
