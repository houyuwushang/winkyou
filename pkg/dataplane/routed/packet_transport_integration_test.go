package routed

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/mesh"
)

func TestRoutedPacketTransportPingAcrossThreeNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var forwardedByB atomic.Int32

	nodeA := newMeshNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond})
	nodeB := newMeshNode(t, mesh.NodeConfig{
		NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind == mesh.EventForwarded && event.Frame.Type == mesh.DataTypePacket {
				forwardedByB.Add(1)
			}
		},
	})
	nodeC := newMeshNode(t, mesh.NodeConfig{NodeID: "C", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond})
	attachDualTCPPair(t, nodeA, "B", nodeB, "A")
	attachDualTCPPair(t, nodeB, "C", nodeC, "B")
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			t.Fatalf("%s.Start() error = %v", node.NodeID(), err)
		}
	}
	waitForCondition(t, ctx, func() bool {
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		return forwardOK && reverseOK &&
			slices.Equal(forward.Path, []string{"A", "B", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "B", "A"})
	}, "A and C did not learn reciprocal routes")

	endpointA := newEndpoint(t, nodeA)
	endpointC := newEndpoint(t, nodeC)
	transportA, err := endpointA.NewPacketTransport("C", "mesh/A-C")
	if err != nil {
		t.Fatal(err)
	}
	defer transportA.Close()
	transportC, err := endpointC.NewPacketTransport("A", "mesh/C-A")
	if err != nil {
		t.Fatal(err)
	}
	defer transportC.Close()

	echoErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1500)
		n, _, readErr := transportC.ReadPacket(ctx, buffer)
		if readErr != nil {
			echoErr <- readErr
			return
		}
		echoErr <- transportC.WritePacket(ctx, append([]byte("PONG:"), buffer[:n]...))
	}()
	if err := transportA.WritePacket(ctx, []byte("PING")); err != nil {
		t.Fatalf("WritePacket(PING) error = %v", err)
	}
	buffer := make([]byte, 1500)
	n, meta, err := transportA.ReadPacket(ctx, buffer)
	if err != nil {
		t.Fatalf("ReadPacket(PONG) error = %v", err)
	}
	if string(buffer[:n]) != "PONG:PING" || meta.PathID != "mesh/A-C" {
		t.Fatalf("packet=%q meta=%#v", buffer[:n], meta)
	}
	if err := <-echoErr; err != nil {
		t.Fatalf("echo error = %v", err)
	}
	waitForCondition(t, ctx, func() bool { return forwardedByB.Load() == 2 }, "B did not observe both packet forwards")
	if got := forwardedByB.Load(); got != 2 {
		t.Fatalf("B forwarded %d packet frames, want 2", got)
	}

	if err := nodeB.RemoveNeighbor("C"); err != nil {
		t.Fatalf("RemoveNeighbor(C) error = %v", err)
	}
	waitForCondition(t, ctx, func() bool {
		_, ok := nodeA.Route("C")
		if ok {
			return false
		}
		return errors.Is(transportA.WritePacket(ctx, []byte("after-close")), mesh.ErrNoRoute)
	}, "A did not withdraw C from both topology and forwarding tables")
}

func newMeshNode(t *testing.T, cfg mesh.NodeConfig) *mesh.Node {
	t.Helper()
	node, err := mesh.NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode(%s) error = %v", cfg.NodeID, err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func newEndpoint(t *testing.T, node *mesh.Node) *Endpoint {
	t.Helper()
	endpoint, err := NewEndpoint(node)
	if err != nil {
		t.Fatalf("NewEndpoint(%s) error = %v", node.NodeID(), err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint
}

func attachDualTCPPair(t *testing.T, left *mesh.Node, leftPeer string, right *mesh.Node, rightPeer string) {
	t.Helper()
	leftControl, rightControl := tcpPair(t)
	leftData, rightData := tcpPair(t)
	if err := left.AttachStreams(leftPeer, leftControl, leftData); err != nil {
		closeTestConns(rightControl, rightData)
		t.Fatalf("%s.AttachStreams(%s) error = %v", left.NodeID(), leftPeer, err)
	}
	if err := right.AttachStreams(rightPeer, rightControl, rightData); err != nil {
		t.Fatalf("%s.AttachStreams(%s) error = %v", right.NodeID(), rightPeer, err)
	}
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type accepted struct {
		conn net.Conn
		err  error
	}
	result := make(chan accepted, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		result <- accepted{conn: conn, err: acceptErr}
	}()
	left, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	right := <-result
	if right.err != nil {
		_ = left.Close()
		t.Fatal(right.err)
	}
	return left, right.conn
}

func closeTestConns(conns ...net.Conn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func waitForCondition(t *testing.T, ctx context.Context, condition func() bool, message string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", message, ctx.Err())
		case <-ticker.C:
		}
	}
}
