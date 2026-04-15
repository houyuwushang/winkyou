package session

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
)

type fakeTransport struct {
	closeOnce sync.Once
	closed    bool
}

func (f *fakeTransport) ReadPacket(context.Context, []byte) (int, transport.PacketMeta, error) {
	return 0, transport.PacketMeta{}, nil
}

func (f *fakeTransport) WritePacket(context.Context, []byte) error { return nil }
func (f *fakeTransport) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000}
}
func (f *fakeTransport) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2000}
}
func (f *fakeTransport) Close() error {
	f.closeOnce.Do(func() { f.closed = true })
	return nil
}

type fakeStrategy struct {
	transport transport.PacketTransport
}

func (f *fakeStrategy) Name() string { return "fake" }
func (f *fakeStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "plan-1", Strategy: "fake"}}, nil
}
func (f *fakeStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	return solver.Result{
		Transport: f.transport,
		Summary: solver.PathSummary{
			PathID:         "fake/path",
			ConnectionType: "direct",
			RemoteAddr:     f.transport.RemoteAddr(),
		},
	}, nil
}
func (f *fakeStrategy) Close() error { return nil }

type fakeBinder struct {
	mu          sync.Mutex
	boundPeer   string
	unboundPeer string
}

func (b *fakeBinder) Bind(context.Context, string, transport.PacketTransport) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.boundPeer = "node-b"
	return nil
}

func (b *fakeBinder) Unbind(context.Context, string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unboundPeer = "node-b"
	return nil
}

type fakeSender struct{}

func (fakeSender) Send(context.Context, string, solver.Message) error { return nil }

func TestSessionVerticalSliceBindsAndClosesTransport(t *testing.T) {
	transport := &fakeTransport{}
	binder := &fakeBinder{}
	bound := make(chan solver.Result, 1)

	s, err := New(Config{
		SessionID:      "session/node-a/node-b",
		LocalNodeID:    "node-a",
		PeerID:         "node-b",
		Initiator:      true,
		Strategy:       &fakeStrategy{transport: transport},
		Binder:         binder,
		Sender:         fakeSender{},
		GatherTimeout:  time.Second,
		ConnectTimeout: time.Second,
		CheckTimeout:   time.Second,
		Hooks: Hooks{
			OnBound: func(result solver.Result) {
				bound <- result
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case result := <-bound:
		if result.Summary.PathID != "fake/path" {
			t.Fatalf("OnBound() path_id = %q, want fake/path", result.Summary.PathID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnBound()")
	}

	if state := s.State(); state != StateBound {
		t.Fatalf("State() = %q, want %q", state, StateBound)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if binder.boundPeer != "node-b" || binder.unboundPeer != "node-b" {
		t.Fatalf("binder calls = bind:%q unbind:%q, want node-b/node-b", binder.boundPeer, binder.unboundPeer)
	}
	if !transport.closed {
		t.Fatal("transport.Close() was not called")
	}
}
