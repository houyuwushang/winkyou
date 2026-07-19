package mesh

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"winkyou/pkg/peercontrol"
)

type recordingSession struct {
	peerID string

	mu       sync.Mutex
	messages []peercontrol.Message
	closed   bool
}

func (s *recordingSession) PeerID() string { return s.peerID }

func (s *recordingSession) Send(_ context.Context, msg peercontrol.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.messages = append(s.messages, cloneMessage(msg))
	return nil
}

func (s *recordingSession) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *recordingSession) snapshot() []peercontrol.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]peercontrol.Message(nil), s.messages...)
}

func TestRouterForwardsByStaticRoute(t *testing.T) {
	router := newTestRouter(t, "B", nil)
	fromA := &recordingSession{peerID: "A"}
	toC := &recordingSession{peerID: "C"}
	addTestNeighbor(t, router, fromA)
	addTestNeighbor(t, router, toC)
	if err := router.SetRoute("C", "C"); err != nil {
		t.Fatalf("SetRoute() error = %v", err)
	}

	msg := peercontrol.NewControlEchoRequest("A", "C", "echo-1", []byte("opaque"), 8)
	msg.Seq = 7
	if err := router.HandleInbound(context.Background(), "A", msg); err != nil {
		t.Fatalf("HandleInbound() error = %v", err)
	}

	got := toC.snapshot()
	if len(got) != 1 {
		t.Fatalf("forwarded message count = %d, want 1", len(got))
	}
	if got[0].HopLimit != 7 || !slices.Equal(got[0].PathVector, []string{"A", "B"}) {
		t.Fatalf("forwarded route header = hop_limit:%d path:%v", got[0].HopLimit, got[0].PathVector)
	}
	if string(got[0].ControlEcho.Payload) != "opaque" {
		t.Fatalf("forwarded payload = %q", got[0].ControlEcho.Payload)
	}
}

func TestRouterRejectsDuplicateHopLimitLoopAndUnknownRoute(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Router, *recordingSession)
		message   func() peercontrol.Message
		wantErr   error
	}{
		{
			name: "duplicate",
			configure: func(router *Router, _ *recordingSession) {
				if err := router.SetRoute("C", "C"); err != nil {
					t.Fatalf("SetRoute() error = %v", err)
				}
			},
			message: func() peercontrol.Message {
				msg := peercontrol.NewControlEchoRequest("A", "C", "duplicate", nil, 8)
				msg.Seq = 10
				return msg
			},
			wantErr: ErrDuplicate,
		},
		{
			name: "hop limit",
			configure: func(router *Router, _ *recordingSession) {
				if err := router.SetRoute("C", "C"); err != nil {
					t.Fatalf("SetRoute() error = %v", err)
				}
			},
			message: func() peercontrol.Message {
				msg := peercontrol.NewControlEchoRequest("A", "C", "ttl", nil, 1)
				msg.Seq = 11
				return msg
			},
			wantErr: ErrHopLimitExceeded,
		},
		{
			name: "loop",
			message: func() peercontrol.Message {
				msg := peercontrol.NewControlEchoRequest("A", "C", "loop", nil, 8)
				msg.Seq = 12
				msg.PathVector = []string{"A", "B"}
				return msg
			},
			wantErr: ErrLoopDetected,
		},
		{
			name: "unknown route",
			message: func() peercontrol.Message {
				msg := peercontrol.NewControlEchoRequest("A", "D", "no-route", nil, 8)
				msg.Seq = 13
				return msg
			},
			wantErr: ErrNoRoute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newTestRouter(t, "B", nil)
			fromA := &recordingSession{peerID: "A"}
			toC := &recordingSession{peerID: "C"}
			addTestNeighbor(t, router, fromA)
			addTestNeighbor(t, router, toC)
			if tt.configure != nil {
				tt.configure(router, toC)
			}

			msg := tt.message()
			if tt.wantErr == ErrDuplicate {
				if err := router.HandleInbound(context.Background(), "A", msg); err != nil {
					t.Fatalf("first HandleInbound() error = %v", err)
				}
			}
			err := router.HandleInbound(context.Background(), "A", msg)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("HandleInbound() error = %v, want %v", err, tt.wantErr)
			}
			wantForwarded := 0
			if tt.wantErr == ErrDuplicate {
				wantForwarded = 1
			}
			if got := len(toC.snapshot()); got != wantForwarded {
				t.Fatalf("forwarded count = %d, want %d", got, wantForwarded)
			}
		})
	}
}

func TestRouterRejectsMessageFromUnknownNeighbor(t *testing.T) {
	router := newTestRouter(t, "B", nil)
	msg := peercontrol.NewControlEchoRequest("A", "C", "unknown-peer", nil, 8)
	msg.Seq = 20

	err := router.HandleInbound(context.Background(), "A", msg)
	if !errors.Is(err, ErrUnknownNeighbor) {
		t.Fatalf("HandleInbound() error = %v, want %v", err, ErrUnknownNeighbor)
	}
}

func newTestRouter(t *testing.T, nodeID string, onMessage LocalHandler) *Router {
	t.Helper()
	router, err := NewRouter(Config{NodeID: nodeID, OnMessage: onMessage})
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	t.Cleanup(func() { _ = router.Close() })
	return router
}

func addTestNeighbor(t *testing.T, router *Router, session NeighborSession) {
	t.Helper()
	if err := router.AddNeighbor(session); err != nil {
		t.Fatalf("AddNeighbor(%s) error = %v", session.PeerID(), err)
	}
}
