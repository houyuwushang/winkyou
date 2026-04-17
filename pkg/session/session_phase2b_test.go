package session

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	solverstore "winkyou/pkg/solver/store"
)

type executorFactoryStrategy struct {
	name       string
	plans      []solver.Plan
	executors  map[string]*scriptedExecutor
	execCalled bool
}

func (s *executorFactoryStrategy) Name() string { return s.name }

func (s *executorFactoryStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return append([]solver.Plan(nil), s.plans...), nil
}

func (s *executorFactoryStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	s.execCalled = true
	return solver.Result{}, errors.New("strategy Execute should not be called when ExecutorFactory is implemented")
}

func (s *executorFactoryStrategy) NewExecutor(plan solver.Plan) (solver.PlanExecutor, error) {
	executor := s.executors[plan.ID]
	if executor == nil {
		return nil, errors.New("missing scripted executor")
	}
	return executor, nil
}

func (s *executorFactoryStrategy) Close() error { return nil }

type scriptedExecutor struct {
	mu             sync.Mutex
	started        chan struct{}
	messageHandled chan struct{}
	result         solver.Result
	execErr        error
	waitForMessage bool
	messages       []solver.Message
	closed         bool
}

func newScriptedExecutor(result solver.Result, execErr error) *scriptedExecutor {
	return &scriptedExecutor{
		started:        make(chan struct{}),
		messageHandled: make(chan struct{}),
		result:         result,
		execErr:        execErr,
	}
}

func (e *scriptedExecutor) Execute(ctx context.Context, sess solver.SessionIO) (solver.Result, error) {
	_ = sess
	select {
	case <-e.started:
	default:
		close(e.started)
	}
	if e.waitForMessage {
		select {
		case <-e.messageHandled:
		case <-ctx.Done():
			return solver.Result{}, ctx.Err()
		}
	}
	if e.execErr != nil {
		return solver.Result{}, e.execErr
	}
	return e.result, nil
}

func (e *scriptedExecutor) HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error {
	_ = ctx
	_ = sess
	e.mu.Lock()
	e.messages = append(e.messages, msg)
	e.mu.Unlock()
	select {
	case <-e.messageHandled:
	default:
		close(e.messageHandled)
	}
	return nil
}

func (e *scriptedExecutor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

func (e *scriptedExecutor) snapshot() (messages int, closed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.messages), e.closed
}

type callbackSender struct {
	mu       sync.Mutex
	messages []solver.Message
	sendFn   func(msg solver.Message) error
}

func (s *callbackSender) Send(_ context.Context, _ string, msg solver.Message) error {
	s.mu.Lock()
	s.messages = append(s.messages, msg)
	s.mu.Unlock()
	if s.sendFn != nil {
		return s.sendFn(msg)
	}
	return nil
}

func (s *callbackSender) Messages() []solver.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]solver.Message, len(s.messages))
	copy(out, s.messages)
	return out
}

type observationStrategy struct {
	name      string
	transport solver.Result
}

func (s *observationStrategy) Name() string { return s.name }

func (s *observationStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "obs-plan", Strategy: s.name}}, nil
}

func (s *observationStrategy) Execute(ctx context.Context, sess solver.SessionIO, plan solver.Plan) (solver.Result, error) {
	_ = sess.ReportObservation(ctx, solver.Observation{
		Strategy:       s.name,
		PlanID:         plan.ID,
		Event:          "strategy_observed",
		ConnectionType: s.transport.Summary.ConnectionType,
		PathID:         s.transport.Summary.PathID,
		LocalAddr:      addrString(s.transport.Transport.LocalAddr()),
		RemoteAddr:     addrString(s.transport.Summary.RemoteAddr),
		Details: map[string]string{
			"source": "strategy_execute",
		},
	})
	return s.transport, nil
}

func (s *observationStrategy) Close() error { return nil }

func TestSessionUsesPlanScopedExecutorsAndClosesLosers(t *testing.T) {
	relayTransport := &fakeTransport{}
	directTransport := &fakeTransport{}
	strategy := &executorFactoryStrategy{
		name: "legacy_ice_udp",
		plans: []solver.Plan{
			{ID: "plan-relay", Strategy: "legacy_ice_udp"},
			{ID: "plan-direct", Strategy: "legacy_ice_udp"},
		},
		executors: map[string]*scriptedExecutor{
			"plan-relay": newScriptedExecutor(solver.Result{
				Transport: relayTransport,
				Summary: solver.PathSummary{
					PathID:         "relay/path",
					ConnectionType: "relay",
					RemoteAddr:     relayTransport.RemoteAddr(),
				},
			}, nil),
			"plan-direct": newScriptedExecutor(solver.Result{
				Transport: directTransport,
				Summary: solver.PathSummary{
					PathID:         "direct/path",
					ConnectionType: "direct",
					RemoteAddr:     directTransport.RemoteAddr(),
				},
			}, nil),
		},
	}
	sender := &callbackSender{}
	bound := make(chan solver.Result, 1)
	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                sender,
		RunTimeout:            2 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
		Hooks: Hooks{
			OnBound: func(result solver.Result) {
				bound <- result
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case result := <-bound:
		if result.Summary.PathID != "direct/path" {
			t.Fatalf("OnBound() path_id = %q, want direct/path", result.Summary.PathID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bound result")
	}

	if strategy.execCalled {
		t.Fatal("strategy Execute() was called, want plan-scoped executors")
	}
	if !relayTransport.closed {
		t.Fatal("non-winning relay transport was not closed")
	}
	if directTransport.closed {
		t.Fatal("winning direct transport should stay open until Session.Close()")
	}
	if _, closed := strategy.executors["plan-relay"].snapshot(); !closed {
		t.Fatal("relay executor was not closed")
	}
	if _, closed := strategy.executors["plan-direct"].snapshot(); !closed {
		t.Fatal("direct executor was not closed after handing off transport")
	}
}

func TestSessionRoutesMessagesToActiveExecutorAndDoesNotPolluteNextCandidate(t *testing.T) {
	firstExec := newScriptedExecutor(solver.Result{}, errors.New("first candidate failed"))
	firstExec.waitForMessage = true
	secondExec := newScriptedExecutor(solver.Result{
		Transport: &fakeTransport{},
		Summary: solver.PathSummary{
			PathID:         "clean/path",
			ConnectionType: "direct",
			RemoteAddr:     (&fakeTransport{}).RemoteAddr(),
		},
	}, nil)
	strategy := &executorFactoryStrategy{
		name: "legacy_ice_udp",
		plans: []solver.Plan{
			{ID: "plan-fail", Strategy: "legacy_ice_udp"},
			{ID: "plan-clean", Strategy: "legacy_ice_udp"},
		},
		executors: map[string]*scriptedExecutor{
			"plan-fail":  firstExec,
			"plan-clean": secondExec,
		},
	}
	sender := &callbackSender{}
	bound := make(chan solver.Result, 1)
	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                sender,
		RunTimeout:            2 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
		Hooks: Hooks{
			OnBound: func(result solver.Result) {
				bound <- result
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case <-firstExec.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first executor to start")
	}
	if err := s.HandleMessage(context.Background(), solver.Message{Kind: solver.MessageKindStrategy, Namespace: "test", Type: "kick", Payload: []byte("first")}); err != nil {
		t.Fatalf("HandleMessage(strategy) error = %v", err)
	}
	select {
	case <-firstExec.messageHandled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first executor message")
	}

	select {
	case result := <-bound:
		if result.Summary.PathID != "clean/path" {
			t.Fatalf("OnBound() path_id = %q, want clean/path", result.Summary.PathID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second executor success")
	}

	if got, _ := firstExec.snapshot(); got != 1 {
		t.Fatalf("first executor messages = %d, want 1", got)
	}
	if got, _ := secondExec.snapshot(); got != 0 {
		t.Fatalf("second executor messages = %d, want 0", got)
	}
}

func TestSessionObservationFlowsFromStrategyToSinkAndRemote(t *testing.T) {
	localTransport := &fakeTransport{}
	remoteSender := &callbackSender{}
	remoteSession, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-b",
		PeerID:                "node-a",
		Initiator:             false,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}, selection: Selection{StrategyName: "legacy_ice_udp"}},
		Sender:                remoteSender,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}

	sink := solverstore.NewObservationStore("")
	localSender := &callbackSender{
		sendFn: func(msg solver.Message) error {
			if msg.Kind == solver.MessageKindEnvelope && msg.Type == rproto.MsgTypeObservation {
				return remoteSession.HandleMessage(context.Background(), msg)
			}
			return nil
		},
	}
	localStrategy := &observationStrategy{
		name: "legacy_ice_udp",
		transport: solver.Result{
			Transport: localTransport,
			Summary: solver.PathSummary{
				PathID:         "observed/path",
				ConnectionType: "direct",
				RemoteAddr:     localTransport.RemoteAddr(),
			},
		},
	}
	localSession, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: localStrategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                localSender,
		ObservationSink:       sink,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}

	if err := localSession.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := localSession.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForState(t, localSession, StateBound)

	localObs := localSession.Observations()
	if len(localObs) == 0 {
		t.Fatal("local Observations() is empty")
	}
	if !containsObservationEvent(localObs, "strategy_observed") {
		t.Fatalf("local observations = %+v, want strategy_observed", localObs)
	}
	if got := sink.List(); len(got) == 0 || !containsObservationEvent(got, "strategy_observed") {
		t.Fatalf("sink observations = %+v, want strategy_observed", got)
	}
	if !containsObservationEnvelope(localSender.Messages()) {
		t.Fatalf("outbound messages = %+v, want observation envelope", localSender.Messages())
	}

	remoteObs := remoteSession.RemoteObservations()
	if len(remoteObs) == 0 || !containsObservationEvent(remoteObs, "strategy_observed") {
		t.Fatalf("remote observations = %+v, want strategy_observed", remoteObs)
	}
}

func containsObservationEvent(list []solver.Observation, event string) bool {
	for _, obs := range list {
		if obs.Event == event {
			return true
		}
	}
	return false
}

func containsObservationEnvelope(messages []solver.Message) bool {
	for _, msg := range messages {
		if msg.Kind != solver.MessageKindEnvelope || msg.Type != rproto.MsgTypeObservation {
			continue
		}
		envelope, err := rproto.UnmarshalEnvelope(msg.Payload)
		if err != nil {
			continue
		}
		var obs rproto.Observation
		if err := json.Unmarshal(envelope.Payload, &obs); err != nil {
			continue
		}
		if obs.Event == "strategy_observed" {
			return true
		}
	}
	return false
}
