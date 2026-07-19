//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

// This test deliberately changes the active Windows loopback address table.
// Keep it opt-in so ordinary unit tests never require elevation or touch host
// networking.
func TestVirtualTCPForwardWindowsPrivilegedLifecycle(t *testing.T) {
	if os.Getenv("WINKYOU_TEST_WINDOWS_ALIAS") != "1" {
		t.Skip("set WINKYOU_TEST_WINDOWS_ALIAS=1 to exercise the active Windows loopback alias")
	}

	virtualIP := randomTestULA(t)
	if virtualAddressPresent(t, virtualIP) {
		t.Fatalf("generated test address %s already exists", virtualIP)
	}
	port := reserveIPv6LoopbackPort(t)
	listen := net.JoinHostPort(virtualIP.String(), port)

	runtime, err := newMeshRuntime(runtimeConfig{
		NodeID: "virtual-facade-test", VirtualIP: "fd7f:7769:6b79::a",
		MeshListen: "off", ControlListen: "off",
		VirtualTCPForwards: []string{listen + "=unreachable-test-peer"},
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = runtime.Close()
		}
		if virtualAddressPresent(t, virtualIP) {
			t.Errorf("test virtual address %s remains after cleanup", virtualIP)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !virtualAddressPresent(t, virtualIP) {
		t.Fatalf("virtual address %s is absent after runtime start", virtualIP)
	}
	forwards := runtime.tcpForwardSnapshot()
	if len(forwards) != 1 || forwards[0].VirtualIP != virtualIP.String() || forwards[0].Listen != listen {
		t.Fatalf("virtual TCP forward snapshot = %+v", forwards)
	}

	connection, err := net.DialTimeout("tcp6", listen, 2*time.Second)
	if err != nil {
		t.Fatalf("ordinary TCP dial to virtual address %s: %v", listen, err)
	}
	_ = connection.Close()

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	deadline := time.Now().Add(2 * time.Second)
	for virtualAddressPresent(t, virtualIP) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if virtualAddressPresent(t, virtualIP) {
		t.Fatalf("virtual address %s remains after runtime close", virtualIP)
	}
}

func TestVirtualTCPForwardWindowsPrivilegedRoutedRoundTrip(t *testing.T) {
	if os.Getenv("WINKYOU_TEST_WINDOWS_ALIAS") != "1" {
		t.Skip("set WINKYOU_TEST_WINDOWS_ALIAS=1 to exercise routed traffic through a Windows loopback alias")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := startVirtualFacadeEcho(t)
	remoteVirtualIP := randomTestULA(t)
	if virtualAddressPresent(t, remoteVirtualIP) {
		t.Fatalf("generated test address %s already exists", remoteVirtualIP)
	}
	port := reserveIPv6LoopbackPort(t)
	virtualListen := net.JoinHostPort(remoteVirtualIP.String(), port)

	runtimeB, err := newMeshRuntime(runtimeConfig{
		NodeID: "B", VirtualIP: remoteVirtualIP.String(),
		MeshListen: "off", ControlListen: "off", TCPTarget: target,
		Lease: 3 * time.Second, RefreshInterval: 50 * time.Millisecond,
		DialRetry: 25 * time.Millisecond, HandshakeTimeout: time.Second,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtimeB.Close() })
	if err := runtimeB.Start(ctx); err != nil {
		t.Fatal(err)
	}

	runtimeA, err := newMeshRuntime(runtimeConfig{
		NodeID: "A", VirtualIP: "fd7e:7769:6b79::a",
		MeshListen: "off", ControlListen: "off",
		VirtualTCPForwards: []string{virtualListen + "=B"},
		Lease:              3 * time.Second,
		RefreshInterval:    50 * time.Millisecond,
		DialRetry:          25 * time.Millisecond,
		HandshakeTimeout:   time.Second,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	closedA := false
	t.Cleanup(func() {
		if !closedA {
			_ = runtimeA.Close()
		}
		if virtualAddressPresent(t, remoteVirtualIP) {
			t.Errorf("routed test virtual address %s remains after cleanup", remoteVirtualIP)
		}
	})
	if err := runtimeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	controlA, controlB := tcpTestConnPair(t)
	dataA, dataB := tcpTestConnPair(t)
	if err := runtimeA.node.AttachStreams("B", controlA, dataA); err != nil {
		t.Fatal(err)
	}
	if err := runtimeB.node.AttachStreams("A", controlB, dataB); err != nil {
		t.Fatal(err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		member, memberOK := runtimeA.node.Member("B")
		route, routeOK := runtimeA.node.DataRoute("B")
		return memberOK && member.VirtualIP == remoteVirtualIP.String() &&
			routeOK && len(route.Path) == 2 && route.Path[0] == "A" && route.Path[1] == "B"
	}); err != nil {
		t.Fatalf(
			"wait for routed virtual-address membership: %v; members=%+v routes=%+v data_routes=%+v neighbors=%+v",
			err, runtimeA.node.Members(), runtimeA.node.Routes(), runtimeA.node.DataRoutes(), runtimeA.node.Neighbors(),
		)
	}

	conn, err := net.DialTimeout("tcp6", virtualListen, 2*time.Second)
	if err != nil {
		t.Fatalf("dial routed virtual address %s: %v", virtualListen, err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("winkyou-virtual-ip-round-trip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if string(reply) != string(payload) {
		t.Fatalf("virtual-address reply = %q, want %q", reply, payload)
	}

	if err := runtimeA.Close(); err != nil {
		t.Fatal(err)
	}
	closedA = true
	if virtualAddressPresent(t, remoteVirtualIP) {
		t.Fatalf("routed test virtual address %s remains after runtime close", remoteVirtualIP)
	}
}

func randomTestULA(t *testing.T) netip.Addr {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	raw[0] = 0xfd
	raw[1] = 0x7f
	return netip.AddrFrom16(raw)
}

func reserveIPv6LoopbackPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(port)
}

func virtualAddressPresent(t *testing.T, want netip.Addr) bool {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addresses, addressErr := iface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			prefix, parseErr := netip.ParsePrefix(address.String())
			if parseErr == nil && prefix.Addr() == want {
				return true
			}
		}
	}
	return false
}

func startVirtualFacadeEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}
