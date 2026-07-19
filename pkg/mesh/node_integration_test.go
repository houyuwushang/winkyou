package mesh

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
)

func TestAutonomousTopologyLearnsRouteAndWithdrawsOnEdgeClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	replies := make(chan peercontrol.Message, 1)
	var deliveredAtB atomic.Int32
	var nodeC *Node
	nodeA := mustNode(t, NodeConfig{
		NodeID: "A", VirtualIP: "fd00::a", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnMessage: func(_ context.Context, msg peercontrol.Message) error {
			replies <- msg
			return nil
		},
	})
	nodeB := mustNode(t, NodeConfig{
		NodeID: "B", VirtualIP: "fd00::b", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnMessage: func(context.Context, peercontrol.Message) error {
			deliveredAtB.Add(1)
			return nil
		},
	})
	nodeC = mustNode(t, NodeConfig{
		NodeID: "C", VirtualIP: "fd00::c", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnMessage: func(messageCtx context.Context, msg peercontrol.Message) error {
			if msg.Type != peercontrol.TypeControlEchoRequest || msg.ControlEcho == nil {
				return nil
			}
			reply := peercontrol.NewControlEchoReply(
				"C", msg.From, msg.ControlEcho.ID, msg.ControlEcho.Payload, msg.PathVector, 8,
			)
			return nodeC.Send(messageCtx, reply)
		},
	})

	attachTCPPair(t, nodeA.router, "B", nodeB.router, "A")
	attachTCPPair(t, nodeB.router, "C", nodeC.router, "B")
	for _, node := range []*Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			t.Fatalf("%s.Start() error = %v", node.nodeID, err)
		}
	}

	eventually(t, ctx, func() bool {
		member, memberOK := nodeA.Member("C")
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		return memberOK && member.VirtualIP == "fd00::c" && forwardOK && reverseOK &&
			forward.NextHop == "B" && forward.HopCount == 2 &&
			slices.Equal(forward.Path, []string{"A", "B", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "B", "A"})
	}, "A and C did not learn reciprocal routes")

	request := peercontrol.NewControlEchoRequest("A", "C", "dynamic-route", []byte("auto-discovered"), 8)
	if err := nodeA.Send(ctx, request); err != nil {
		t.Fatalf("A.Send() error = %v", err)
	}
	select {
	case reply := <-replies:
		if reply.ControlEcho == nil || string(reply.ControlEcho.Payload) != "auto-discovered" {
			t.Fatalf("reply = %#v", reply)
		}
		if !slices.Equal(reply.ControlEcho.RequestPath, []string{"A", "B", "C"}) ||
			!slices.Equal(reply.PathVector, []string{"C", "B", "A"}) {
			t.Fatalf("request path=%v reply path=%v", reply.ControlEcho.RequestPath, reply.PathVector)
		}
	case <-ctx.Done():
		t.Fatalf("dynamic echo timed out: %v", ctx.Err())
	}
	if got := deliveredAtB.Load(); got != 0 {
		t.Fatalf("B delivered %d application messages, want 0", got)
	}

	if err := nodeB.RemoveNeighbor("C"); err != nil {
		t.Fatalf("B.RemoveNeighbor(C) error = %v", err)
	}
	eventually(t, ctx, func() bool {
		_, routeOK := nodeA.Route("C")
		_, memberOK := nodeA.Member("C")
		if routeOK || !memberOK {
			return false
		}
		requestAfterClose := peercontrol.NewControlEchoRequest("A", "C", "after-close", nil, 8)
		return errors.Is(nodeA.Send(ctx, requestAfterClose), ErrNoRoute)
	}, "A did not withdraw C from topology and forwarding tables while retaining its member record")
}

func mustNode(t *testing.T, cfg NodeConfig) *Node {
	t.Helper()
	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode(%s) error = %v", cfg.NodeID, err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func eventually(t *testing.T, ctx context.Context, condition func() bool, message string) {
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
