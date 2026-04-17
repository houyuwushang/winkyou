package session

import (
	"context"
	"encoding/json"
	"net"
	"slices"
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
	name      string
	transport transport.PacketTransport
	mu        sync.Mutex
	planCalls int
	execCalls int
}

func (f *fakeStrategy) Name() string { return f.name }
func (f *fakeStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	f.mu.Lock()
	f.planCalls++
	f.mu.Unlock()
	return []solver.Plan{{ID: "plan-1", Strategy: f.name}}, nil
}
func (f *fakeStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	f.mu.Lock()
	f.execCalls++
	f.mu.Unlock()
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

func (f *fakeStrategy) Counts() (planCalls, execCalls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.planCalls, f.execCalls
}

type fakeResolver struct {
	local      rproto.Capability
	strategy   solver.Strategy
	selection  Selection
	err        error
	mu         sync.Mutex
	resolveCnt int
	lastRemote rproto.Capability
}

func (r *fakeResolver) LocalCapability() rproto.Capability {
	return cloneCapability(r.local)
}

func (r *fakeResolver) Resolve(remote rproto.Capability, initiator bool) (solver.Strategy, Selection, error) {
	_ = initiator
	r.mu.Lock()
	r.resolveCnt++
	r.lastRemote = cloneCapability(remote)
	r.mu.Unlock()
	if r.err != nil {
		return nil, Selection{}, r.err
	}
	return r.strategy, r.selection, nil
}

func (r *fakeResolver) Snapshot() (int, rproto.Capability) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolveCnt, cloneCapability(r.lastRemote)
}

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
	failures int
}

func (s *fakeSender) Send(_ context.Context, _ string, msg solver.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures > 0 {
		s.failures--
		return context.DeadlineExceeded
	}
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

func (s *fakeSender) Failing(times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = times
}

func TestSessionStartCapabilitySelectionAndPathCommit(t *testing.T) {
	transport := &fakeTransport{}
	strategy := &fakeStrategy{name: "legacy_ice_udp", transport: transport}
	resolver := &fakeResolver{
		local:     rproto.Capability{Strategies: []string{"future_quic", "legacy_ice_udp"}},
		strategy:  strategy,
		selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true},
	}
	binder := &fakeBinder{}
	sender := &fakeSender{}
	bound := make(chan solver.Result, 1)
	stateCh := make(chan State, 8)

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              resolver,
		Binder:                binder,
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
		Hooks: Hooks{
			OnStateChange: func(state State) {
				stateCh <- state
			},
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

	messages := sender.Messages()
	if len(messages) == 0 {
		t.Fatal("expected Start() to send at least one message")
	}
	if messages[0].Kind != solver.MessageKindEnvelope || messages[0].Type != rproto.MsgTypeCapability {
		t.Fatalf("first message = %+v, want capability envelope", messages[0])
	}

	remoteCapability := rproto.SessionEnvelope{
		SessionID: "session/node-a/node-b",
		FromNode:  "node-b",
		ToNode:    "node-a",
		MsgType:   rproto.MsgTypeCapability,
		Seq:       1,
		Payload:   rproto.MustPayload(rproto.Capability{Strategies: []string{"legacy_ice_udp"}}),
	}
	payload, err := rproto.MarshalEnvelope(remoteCapability)
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Namespace:  envelopeNamespace,
		Type:       rproto.MsgTypeCapability,
		Payload:    payload,
		ReceivedAt: time.Now(),
	}); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}

	select {
	case result := <-bound:
		if result.Summary.PathID != "fake/path" {
			t.Fatalf("OnBound() path_id = %q, want fake/path", result.Summary.PathID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnBound()")
	}

	snapshot := s.Snapshot()
	if got := snapshot.LocalCapability.Strategies; len(got) != 2 || !slices.Equal(got, []string{"future_quic", "legacy_ice_udp"}) {
		t.Fatalf("LocalCapability = %#v, want future_quic+legacy_ice_udp", snapshot.LocalCapability)
	}
	if got := snapshot.RemoteCapability.Strategies; len(got) != 1 || got[0] != "legacy_ice_udp" {
		t.Fatalf("RemoteCapability = %#v, want legacy_ice_udp", snapshot.RemoteCapability)
	}
	if snapshot.SelectedStrategy != "legacy_ice_udp" {
		t.Fatalf("SelectedStrategy = %q, want legacy_ice_udp", snapshot.SelectedStrategy)
	}
	if !snapshot.SelectionNegotiated {
		t.Fatal("SelectionNegotiated = false, want true")
	}
	if snapshot.CapabilityExchangeAt.IsZero() {
		t.Fatal("CapabilityExchangeAt should be set")
	}

	resolveCalls, lastRemote := resolver.Snapshot()
	if resolveCalls != 1 {
		t.Fatalf("Resolve() calls = %d, want 1", resolveCalls)
	}
	if got := lastRemote.Strategies; len(got) != 1 || got[0] != "legacy_ice_udp" {
		t.Fatalf("resolver remote capability = %#v, want legacy_ice_udp", lastRemote)
	}

	messages = sender.Messages()
	if len(messages) < 2 {
		t.Fatalf("outbound messages = %d, want at least capability + path_commit", len(messages))
	}
	pathCommitMsg, ok := findEnvelopeMessage(messages, rproto.MsgTypePathCommit)
	if !ok {
		t.Fatalf("messages = %+v, want path_commit envelope", messages)
	}
	if _, ok := findEnvelopeMessage(messages, rproto.MsgTypeObservation); !ok {
		t.Fatalf("messages = %+v, want at least one observation envelope", messages)
	}
	envelope, err := rproto.UnmarshalEnvelope(pathCommitMsg.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(path_commit) error = %v", err)
	}
	var pathCommit rproto.PathCommit
	if err := json.Unmarshal(envelope.Payload, &pathCommit); err != nil {
		t.Fatalf("decode path_commit: %v", err)
	}
	if pathCommit.Strategy != "legacy_ice_udp" || pathCommit.PathID != "fake/path" || pathCommit.ConnectionType != "direct" {
		t.Fatalf("path_commit = %#v, want legacy_ice_udp/fake/path/direct", pathCommit)
	}

	states := collectStates(stateCh)
	if !slices.Contains(states, StateCapabilityExchange) || !slices.Contains(states, StateSelecting) || !slices.Contains(states, StateBound) {
		t.Fatalf("state transitions = %v, want capability_exchange/selecting/bound", states)
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

func TestSessionCapabilityAndPathCommitUpdatesSnapshotIdempotently(t *testing.T) {
	transport := &fakeTransport{}
	sender := &fakeSender{}
	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: &fakeStrategy{name: "legacy_ice_udp", transport: transport}, selection: Selection{StrategyName: "legacy_ice_udp"}},
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	now := time.Now()
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp", "legacy_ice_udp"}}, now)); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp", "legacy_ice_udp"}}, now)); err != nil {
		t.Fatalf("HandleMessage(duplicate capability) error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypePathCommit, 2, rproto.PathCommit{Strategy: "legacy_ice_udp", PathID: "remote/path", ConnectionType: "relay"}, now.Add(time.Second))); err != nil {
		t.Fatalf("HandleMessage(path_commit) error = %v", err)
	}

	snapshot := s.Snapshot()
	if got := snapshot.RemoteCapability.Strategies; len(got) != 1 || got[0] != "legacy_ice_udp" {
		t.Fatalf("RemoteCapability = %#v, want legacy_ice_udp", snapshot.RemoteCapability)
	}
	if snapshot.LastEnvelopeType != rproto.MsgTypePathCommit {
		t.Fatalf("LastEnvelopeType = %q, want %q", snapshot.LastEnvelopeType, rproto.MsgTypePathCommit)
	}
	if snapshot.LastPathCommit.PathID != "remote/path" || snapshot.LastPathCommit.Strategy != "legacy_ice_udp" || snapshot.LastPathCommit.ConnectionType != "relay" {
		t.Fatalf("LastPathCommit = %#v, want remote/path legacy_ice_udp relay", snapshot.LastPathCommit)
	}
	if snapshot.LastPathCommitAt.IsZero() {
		t.Fatal("LastPathCommitAt should be set")
	}
}

func TestSessionStartFailureCanRetry(t *testing.T) {
	transport := &fakeTransport{}
	strategy := &fakeStrategy{name: "legacy_ice_udp", transport: transport}
	sender := &fakeSender{}
	sender.Failing(1)

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp"}},
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err == nil {
		t.Fatal("first Start() error = nil, want failure")
	}
	if state := s.State(); state != StateFailed {
		t.Fatalf("State() after failed start = %q, want %q", state, StateFailed)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("second Start() error = %v, want nil", err)
	}

	waitForState(t, s, StateBound)

	planCalls, execCalls := strategy.Counts()
	if planCalls != 1 {
		t.Fatalf("Plan() calls = %d, want 1", planCalls)
	}
	if execCalls != 1 {
		t.Fatalf("Execute() calls = %d, want 1", execCalls)
	}
	messages := sender.Messages()
	if _, ok := findEnvelopeMessage(messages, rproto.MsgTypeCapability); !ok {
		t.Fatalf("messages = %+v, want capability envelope", messages)
	}
	if _, ok := findEnvelopeMessage(messages, rproto.MsgTypePathCommit); !ok {
		t.Fatalf("messages = %+v, want path_commit envelope", messages)
	}
	if _, ok := findEnvelopeMessage(messages, rproto.MsgTypeObservation); !ok {
		t.Fatalf("messages = %+v, want observation envelope", messages)
	}
}

func TestSessionStartIsNoOpAfterSuccess(t *testing.T) {
	transport := &fakeTransport{}
	strategy := &fakeStrategy{name: "legacy_ice_udp", transport: transport}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp"}},
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	waitForState(t, s, StateBound)

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}

	planCalls, execCalls := strategy.Counts()
	if planCalls != 1 {
		t.Fatalf("Plan() calls = %d, want 1", planCalls)
	}
	if execCalls != 1 {
		t.Fatalf("Execute() calls = %d, want 1", execCalls)
	}
	messages := sender.Messages()
	if _, ok := findEnvelopeMessage(messages, rproto.MsgTypeCapability); !ok {
		t.Fatalf("messages = %+v, want capability envelope", messages)
	}
	if _, ok := findEnvelopeMessage(messages, rproto.MsgTypePathCommit); !ok {
		t.Fatalf("messages = %+v, want path_commit envelope", messages)
	}
	if _, ok := findEnvelopeMessage(messages, rproto.MsgTypeObservation); !ok {
		t.Fatalf("messages = %+v, want observation envelope", messages)
	}
}

func envelopeMessage(t *testing.T, sessionID, from, to, msgType string, seq uint64, payload any, receivedAt time.Time) solver.Message {
	t.Helper()
	raw, err := rproto.MarshalEnvelope(rproto.SessionEnvelope{
		SessionID: sessionID,
		FromNode:  from,
		ToNode:    to,
		MsgType:   msgType,
		Seq:       seq,
		Payload:   rproto.MustPayload(payload),
	})
	if err != nil {
		t.Fatalf("MarshalEnvelope(%s) error = %v", msgType, err)
	}
	return solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Namespace:  envelopeNamespace,
		Type:       msgType,
		Payload:    raw,
		ReceivedAt: receivedAt,
	}
}

func waitForState(t *testing.T, s *Session, want State) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if state := s.State(); state == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("State() = %q, want %q", s.State(), want)
}

func collectStates(ch <-chan State) []State {
	var states []State
	for {
		select {
		case state := <-ch:
			states = append(states, state)
		default:
			return states
		}
	}
}

func findEnvelopeMessage(messages []solver.Message, msgType string) (solver.Message, bool) {
	for _, msg := range messages {
		if msg.Kind == solver.MessageKindEnvelope && msg.Type == msgType {
			return msg, true
		}
	}
	return solver.Message{}, false
}
