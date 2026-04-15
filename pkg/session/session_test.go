package session

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
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

func (f *fakeStrategy) Name() string { return "fake_strategy" }
func (f *fakeStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "plan-1", Strategy: "fake_strategy"}}, nil
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

type fakeSender struct {
	mu       sync.Mutex
	messages []solver.Message
}

func (s *fakeSender) Send(_ context.Context, _ string, msg solver.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, msg)
	return nil
}

func (s *fakeSender) Messages() []solver.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]solver.Message, len(s.messages))
	copy(out, s.messages)
	return out
}

func TestSessionVerticalSliceBindsClosesTransportAndSendsCapability(t *testing.T) {
	transport := &fakeTransport{}
	binder := &fakeBinder{}
	sender := &fakeSender{}
	bound := make(chan solver.Result, 1)

	s, err := New(Config{
		SessionID:   "session/node-a/node-b",
		LocalNodeID: "node-a",
		PeerID:      "node-b",
		Initiator:   true,
		Strategy:    &fakeStrategy{transport: transport},
		Binder:      binder,
		Sender:      sender,
		RunTimeout:  3 * time.Second,
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

	messages := sender.Messages()
	if len(messages) == 0 {
		t.Fatal("expected Start() to send at least one message")
	}
	if messages[0].Kind != solver.MessageKindEnvelope || messages[0].Type != rproto.MsgTypeCapability {
		t.Fatalf("first message = %+v, want capability envelope", messages[0])
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

func TestSessionCapabilityExchangeUpdatesSnapshotIdempotently(t *testing.T) {
	transport := &fakeTransport{}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:   "session/node-a/node-b",
		LocalNodeID: "node-a",
		PeerID:      "node-b",
		Initiator:   true,
		Strategy:    &fakeStrategy{transport: transport},
		Sender:      sender,
		RunTimeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	envelope := rproto.SessionEnvelope{
		SessionID: "session/node-a/node-b",
		FromNode:  "node-b",
		ToNode:    "node-a",
		MsgType:   rproto.MsgTypeCapability,
		Seq:       1,
		Payload:   rproto.MustPayload(rproto.Capability{Strategies: []string{"legacy_ice_udp", "legacy_ice_udp"}}),
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}

	msg := solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Namespace:  envelopeNamespace,
		Type:       rproto.MsgTypeCapability,
		Payload:    payload,
		ReceivedAt: time.Now(),
	}
	if err := s.HandleMessage(context.Background(), msg); err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), msg); err != nil {
		t.Fatalf("HandleMessage() duplicate error = %v", err)
	}

	snapshot := s.Snapshot()
	if got := snapshot.LocalCapability.Strategies; len(got) != 1 || got[0] != "fake_strategy" {
		t.Fatalf("LocalCapability = %#v, want fake_strategy", snapshot.LocalCapability)
	}
	if got := snapshot.RemoteCapability.Strategies; len(got) != 1 || got[0] != "legacy_ice_udp" {
		t.Fatalf("RemoteCapability = %#v, want legacy_ice_udp", snapshot.RemoteCapability)
	}
	if snapshot.LastEnvelopeType != rproto.MsgTypeCapability {
		t.Fatalf("LastEnvelopeType = %q, want %q", snapshot.LastEnvelopeType, rproto.MsgTypeCapability)
	}
	if snapshot.LastEnvelopeAt.IsZero() {
		t.Fatal("LastEnvelopeAt should be set")
	}
}
