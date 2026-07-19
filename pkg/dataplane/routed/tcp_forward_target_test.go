package routed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"winkyou/pkg/mesh"
)

func TestTCPForwarderTargetUpdateAffectsOnlyNewFlows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeA := newMeshNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeB := newMeshNode(t, mesh.NodeConfig{NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	attachDualTCPPair(t, nodeA, "B", nodeB, "A")
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, ctx, func() bool {
		forward, forwardOK := nodeA.Route("B")
		reverse, reverseOK := nodeB.Route("A")
		return forwardOK && reverseOK &&
			slices.Equal(forward.Path, []string{"A", "B"}) &&
			slices.Equal(reverse.Path, []string{"B", "A"})
	}, "A and B did not learn reciprocal routes")

	oldTarget := startPrefixedLineTarget(t, "old:")
	newTarget := startPrefixedLineTarget(t, "new:")
	endpointA := newEndpoint(t, nodeA)
	endpointB := newEndpoint(t, nodeB)
	forwarderA, err := NewTCPForwarder(endpointA, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderA.Close() })
	forwarderB, err := NewTCPForwarder(endpointB, oldTarget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderB.Close() })
	listener, err := forwarderA.StartListener(ctx, "127.0.0.1:0", "B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	oldFlow, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer oldFlow.Close()
	assertPrefixedLineRoundTrip(t, oldFlow, "before", "old:before\n")

	if err := forwarderB.SetTarget(newTarget); err != nil {
		t.Fatalf("SetTarget(%s) error = %v", newTarget, err)
	}
	if got := forwarderB.Target(); got != newTarget {
		t.Fatalf("Target() = %q, want %q", got, newTarget)
	}

	// The first flow retains the connection it already dialed.
	assertPrefixedLineRoundTrip(t, oldFlow, "after", "old:after\n")

	newFlow, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer newFlow.Close()
	assertPrefixedLineRoundTrip(t, newFlow, "fresh", "new:fresh\n")

	if err := forwarderB.ClearTarget(); err != nil {
		t.Fatalf("ClearTarget() error = %v", err)
	}
	if got := forwarderB.Target(); got != "" {
		t.Fatalf("Target() after ClearTarget = %q, want empty", got)
	}
	assertPrefixedLineRoundTrip(t, oldFlow, "old-cleared", "old:old-cleared\n")
	assertPrefixedLineRoundTrip(t, newFlow, "new-cleared", "new:new-cleared\n")
}

func TestTCPForwarderTargetValidationClearAndClosed(t *testing.T) {
	node := newMeshNode(t, mesh.NodeConfig{NodeID: "target-test"})
	endpoint := newEndpoint(t, node)
	forwarder, err := NewTCPForwarder(endpoint, "")
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{"127.0.0.2:22", "localhost:22", "[::1]:22"} {
		if err := forwarder.SetTarget(target); err != nil {
			t.Fatalf("SetTarget(%q) error = %v", target, err)
		}
		if got := forwarder.Target(); got != target {
			t.Fatalf("Target() = %q, want %q", got, target)
		}
	}

	before := forwarder.Target()
	for _, target := range []string{"192.0.2.1:22", "0.0.0.0:22", "example.com:22"} {
		if err := forwarder.SetTarget(target); err == nil {
			t.Fatalf("SetTarget(%q) unexpectedly succeeded", target)
		}
		if got := forwarder.Target(); got != before {
			t.Fatalf("failed SetTarget changed target to %q, want %q", got, before)
		}
	}
	if _, err := NewTCPForwarder(endpoint, "192.0.2.2:22"); err == nil {
		t.Fatal("NewTCPForwarder accepted a non-loopback target")
	}

	if err := forwarder.ClearTarget(); err != nil {
		t.Fatal(err)
	}
	if got := forwarder.Target(); got != "" {
		t.Fatalf("Target() after ClearTarget = %q, want empty", got)
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.SetTarget("127.0.0.1:22"); !errors.Is(err, ErrTCPForwarderClosed) {
		t.Fatalf("SetTarget after Close error = %v, want %v", err, ErrTCPForwarderClosed)
	}
	if err := forwarder.ClearTarget(); !errors.Is(err, ErrTCPForwarderClosed) {
		t.Fatalf("ClearTarget after Close error = %v, want %v", err, ErrTCPForwarderClosed)
	}
}

func startPrefixedLineTarget(t *testing.T, prefix string) string {
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
				reader := bufio.NewReader(conn)
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil {
						return
					}
					if _, writeErr := fmt.Fprintf(conn, "%s%s", prefix, line); writeErr != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func assertPrefixedLineRoundTrip(t *testing.T, conn net.Conn, payload, want string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "%s\n", payload); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("routed target reply = %q, want %q", got, want)
	}
}
