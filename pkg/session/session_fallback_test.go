package session

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

func TestSessionOrderedStrategyFallbackBindsSecondStrategy(t *testing.T) {
	firstErr := errors.New("first strategy failed")
	first := &failingFallbackStrategy{name: "legacy_ice_udp", err: firstErr}
	second := &successfulFallbackStrategy{name: "relay_only", transport: &fakeTransport{}}
	resolver := &orderedFallbackResolver{
		local: rproto.Capability{Strategies: []string{first.name, second.name}},
		candidates: []StrategyCandidate{
			{Name: first.name, Strategy: first, Selection: Selection{StrategyName: first.name, Negotiated: true}},
			{Name: second.name, Strategy: second, Selection: Selection{StrategyName: second.name, Negotiated: true}},
		},
	}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              resolver,
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{first.name, second.name}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateBound)

	snapshot := s.Snapshot()
	if got := snapshot.SelectedStrategy; got != second.name {
		t.Fatalf("SelectedStrategy = %q, want %q", got, second.name)
	}
	if got, want := snapshot.LastStrategyOrder, []string{first.name, second.name}; !slices.Equal(got, want) {
		t.Fatalf("LastStrategyOrder = %#v, want %#v", got, want)
	}
	if got := snapshot.LastStrategyOrderReason; got != "resolver_order" {
		t.Fatalf("LastStrategyOrderReason = %q, want resolver_order", got)
	}
	if first.execCount() != 1 {
		t.Fatalf("first exec count = %d, want 1", first.execCount())
	}
	if first.closeCount() != 1 {
		t.Fatalf("first close count = %d, want 1", first.closeCount())
	}
	if second.execCount() != 1 {
		t.Fatalf("second exec count = %d, want 1", second.execCount())
	}

	pathCommitMsg := waitForEnvelopeMessage(t, sender.Messages, rproto.MsgTypePathCommit)
	envelope, err := rproto.UnmarshalEnvelope(pathCommitMsg.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(path_commit) error = %v", err)
	}
	pathCommit := mustDecodePathCommit(t, envelope.Payload)
	if pathCommit.Strategy != second.name {
		t.Fatalf("path_commit strategy = %q, want %q", pathCommit.Strategy, second.name)
	}
	if !hasObservation(s.Observations(), first.name, "strategy_failed") {
		t.Fatalf("observations = %#v, want first strategy_failed", s.Observations())
	}
	if !hasObservation(s.Observations(), second.name, "path_committed") {
		t.Fatalf("observations = %#v, want second path_committed", s.Observations())
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestSessionOrderedStrategyFallbackFailsWhenAllStrategiesFail(t *testing.T) {
	first := &failingFallbackStrategy{name: "legacy_ice_udp", err: errors.New("first strategy failed")}
	second := &failingFallbackStrategy{name: "relay_only", err: errors.New("second strategy failed")}
	resolver := &orderedFallbackResolver{
		local: rproto.Capability{Strategies: []string{first.name, second.name}},
		candidates: []StrategyCandidate{
			{Name: first.name, Strategy: first, Selection: Selection{StrategyName: first.name, Negotiated: true}},
			{Name: second.name, Strategy: second, Selection: Selection{StrategyName: second.name, Negotiated: true}},
		},
	}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              resolver,
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{first.name, second.name}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateFailed)

	if !hasObservation(s.Observations(), first.name, "strategy_failed") {
		t.Fatalf("observations = %#v, want first strategy_failed", s.Observations())
	}
	if !hasObservation(s.Observations(), second.name, "strategy_failed") {
		t.Fatalf("observations = %#v, want second strategy_failed", s.Observations())
	}
	if first.closeCount() != 1 || second.closeCount() != 1 {
		t.Fatalf("close counts = first:%d second:%d, want 1/1", first.closeCount(), second.closeCount())
	}
}

func TestSessionFallbackDiscardsPendingStrategyMessagesBeforeNextStrategy(t *testing.T) {
	first := &failingFallbackStrategy{name: "legacy_ice_udp", err: errors.New("first strategy failed")}
	second := &messageHandlingFallbackStrategy{
		successfulFallbackStrategy: successfulFallbackStrategy{name: "relay_only", transport: &fakeTransport{}},
	}
	resolver := &orderedFallbackResolver{
		local: rproto.Capability{Strategies: []string{first.name, second.name}},
		candidates: []StrategyCandidate{
			{Name: first.name, Strategy: first, Selection: Selection{StrategyName: first.name, Negotiated: true}},
			{Name: second.name, Strategy: second, Selection: Selection{StrategyName: second.name, Negotiated: true}},
		},
	}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              resolver,
		Sender:                &fakeSender{},
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.HandleMessage(context.Background(), solver.Message{
		Kind: solver.MessageKindStrategy,
		Type: "stale_first_strategy_message",
	}); err != nil {
		t.Fatalf("HandleMessage(strategy) error = %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{first.name, second.name}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateBound)

	if second.handledCount() != 0 {
		t.Fatalf("second handled pending strategy messages = %d, want 0", second.handledCount())
	}
}

type orderedFallbackResolver struct {
	local      rproto.Capability
	candidates []StrategyCandidate
}

func (r *orderedFallbackResolver) LocalCapability() rproto.Capability {
	return cloneCapability(r.local)
}

func (r *orderedFallbackResolver) Resolve(remote rproto.Capability, initiator bool) (solver.Strategy, Selection, error) {
	_ = remote
	_ = initiator
	if len(r.candidates) == 0 {
		return nil, Selection{}, errors.New("no candidates")
	}
	return r.candidates[0].Strategy, r.candidates[0].Selection, nil
}

func (r *orderedFallbackResolver) ResolveAll(input ResolveInput) ([]StrategyCandidate, error) {
	_ = input
	return append([]StrategyCandidate(nil), r.candidates...), nil
}

type failingFallbackStrategy struct {
	name string
	err  error

	mu     sync.Mutex
	execs  int
	closes int
}

func (s *failingFallbackStrategy) Name() string { return s.name }

func (s *failingFallbackStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: s.name + "/plan", Strategy: s.name}}, nil
}

func (s *failingFallbackStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	s.mu.Lock()
	s.execs++
	s.mu.Unlock()
	if s.err != nil {
		return solver.Result{}, s.err
	}
	return solver.Result{}, errors.New("fallback strategy failed")
}

func (s *failingFallbackStrategy) Close() error {
	s.mu.Lock()
	s.closes++
	s.mu.Unlock()
	return nil
}

func (s *failingFallbackStrategy) execCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execs
}

func (s *failingFallbackStrategy) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

type successfulFallbackStrategy struct {
	name      string
	transport *fakeTransport

	mu    sync.Mutex
	execs int
}

func (s *successfulFallbackStrategy) Name() string { return s.name }

func (s *successfulFallbackStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: s.name + "/plan", Strategy: s.name}}, nil
}

func (s *successfulFallbackStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	s.mu.Lock()
	s.execs++
	s.mu.Unlock()
	return solver.Result{
		Transport: s.transport,
		Summary: solver.PathSummary{
			PathID:         s.name + "/path",
			ConnectionType: "relay",
			RemoteAddr:     s.transport.RemoteAddr(),
		},
	}, nil
}

func (s *successfulFallbackStrategy) Close() error { return nil }

func (s *successfulFallbackStrategy) execCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execs
}

type messageHandlingFallbackStrategy struct {
	successfulFallbackStrategy

	mu      sync.Mutex
	handled int
}

func (s *messageHandlingFallbackStrategy) HandleMessage(context.Context, solver.SessionIO, solver.Message) error {
	s.mu.Lock()
	s.handled++
	s.mu.Unlock()
	return nil
}

func (s *messageHandlingFallbackStrategy) handledCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handled
}

func hasObservation(observations []solver.Observation, strategy, event string) bool {
	for _, obs := range observations {
		if obs.Strategy == strategy && obs.Event == event {
			return true
		}
	}
	return false
}
