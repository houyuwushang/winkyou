package mesh

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
)

func TestRoutedEchoThreeNodesOverRealSockets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	requestAtC := make(chan peercontrol.Message, 1)
	replyAtA := make(chan peercontrol.Message, 1)
	var deliveredAtB atomic.Int32
	var forwardedAtB atomic.Int32

	var nodeC *Router
	nodeA := mustRouter(t, Config{
		NodeID: "A",
		OnMessage: func(_ context.Context, msg peercontrol.Message) error {
			replyAtA <- msg
			return nil
		},
	})
	nodeB := mustRouter(t, Config{
		NodeID: "B",
		OnMessage: func(context.Context, peercontrol.Message) error {
			deliveredAtB.Add(1)
			return nil
		},
		OnEvent: func(event Event) {
			if event.Kind == EventForwarded {
				forwardedAtB.Add(1)
			}
		},
	})
	nodeC = mustRouter(t, Config{
		NodeID: "C",
		OnMessage: func(ctx context.Context, msg peercontrol.Message) error {
			requestAtC <- msg
			if msg.Type != peercontrol.TypeControlEchoRequest || msg.ControlEcho == nil {
				return fmt.Errorf("unexpected message at C: %s", msg.Type)
			}
			reply := peercontrol.NewControlEchoReply(
				"C",
				msg.From,
				msg.ControlEcho.ID,
				msg.ControlEcho.Payload,
				msg.PathVector,
				8,
			)
			return nodeC.Send(ctx, reply)
		},
	})

	attachTCPPair(t, nodeA, "B", nodeB, "A")
	attachTCPPair(t, nodeB, "C", nodeC, "B")
	if err := nodeA.SetRoute("C", "B"); err != nil {
		t.Fatalf("A.SetRoute() error = %v", err)
	}
	if err := nodeC.SetRoute("A", "B"); err != nil {
		t.Fatalf("C.SetRoute() error = %v", err)
	}

	request := peercontrol.NewControlEchoRequest("A", "C", "three-node-echo", []byte("hello-mesh"), 8)
	if err := nodeA.Send(ctx, request); err != nil {
		t.Fatalf("A.Send() error = %v", err)
	}

	var receivedRequest peercontrol.Message
	select {
	case receivedRequest = <-requestAtC:
	case <-ctx.Done():
		t.Fatalf("C did not receive request: %v", ctx.Err())
	}
	if !slices.Equal(receivedRequest.PathVector, []string{"A", "B", "C"}) {
		t.Fatalf("request path = %v, want [A B C]", receivedRequest.PathVector)
	}
	if receivedRequest.HopLimit != 7 {
		t.Fatalf("request hop limit = %d, want 7", receivedRequest.HopLimit)
	}

	var receivedReply peercontrol.Message
	select {
	case receivedReply = <-replyAtA:
	case <-ctx.Done():
		t.Fatalf("A did not receive reply: %v", ctx.Err())
	}
	if receivedReply.Type != peercontrol.TypeControlEchoReply || receivedReply.ControlEcho == nil {
		t.Fatalf("reply = %#v", receivedReply)
	}
	if string(receivedReply.ControlEcho.Payload) != "hello-mesh" {
		t.Fatalf("reply payload = %q", receivedReply.ControlEcho.Payload)
	}
	if !slices.Equal(receivedReply.ControlEcho.RequestPath, []string{"A", "B", "C"}) {
		t.Fatalf("reported request path = %v", receivedReply.ControlEcho.RequestPath)
	}
	if !slices.Equal(receivedReply.PathVector, []string{"C", "B", "A"}) {
		t.Fatalf("reply path = %v, want [C B A]", receivedReply.PathVector)
	}
	if got := deliveredAtB.Load(); got != 0 {
		t.Fatalf("B delivered %d payloads, want 0", got)
	}
	if got := forwardedAtB.Load(); got != 2 {
		t.Fatalf("B forwarded %d messages, want 2", got)
	}
}

func mustRouter(t *testing.T, cfg Config) *Router {
	t.Helper()
	router, err := NewRouter(cfg)
	if err != nil {
		t.Fatalf("NewRouter(%s) error = %v", cfg.NodeID, err)
	}
	t.Cleanup(func() { _ = router.Close() })
	return router
}

func attachTCPPair(t *testing.T, left *Router, leftPeer string, right *Router, rightPeer string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()
	leftConn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	result := <-accepted
	if result.err != nil {
		_ = leftConn.Close()
		t.Fatalf("Accept() error = %v", result.err)
	}
	if err := left.AttachStream(leftPeer, leftConn); err != nil {
		_ = result.conn.Close()
		t.Fatalf("%s.AttachStream(%s) error = %v", left.NodeID(), leftPeer, err)
	}
	if err := right.AttachStream(rightPeer, result.conn); err != nil {
		t.Fatalf("%s.AttachStream(%s) error = %v", right.NodeID(), rightPeer, err)
	}
}
