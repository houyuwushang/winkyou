package session

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	pmodel "winkyou/pkg/probe/model"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type fakeProbeRunner struct {
	mu         sync.Mutex
	calls      int
	lastScript pmodel.Script
	result     pmodel.Result
	err        error
	delay      time.Duration
}

func (r *fakeProbeRunner) Run(ctx context.Context, script pmodel.Script) (pmodel.Result, error) {
	if r.delay > 0 {
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return pmodel.Result{}, ctx.Err()
		case <-timer.C:
		}
	}

	r.mu.Lock()
	r.calls++
	r.lastScript = script
	result := r.result
	err := r.err
	r.mu.Unlock()

	if result.ScriptType == "" {
		result.ScriptType = script.ScriptType
	}
	if result.PlanID == "" {
		result.PlanID = script.PlanID
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now()
	}
	return result, err
}

func (r *fakeProbeRunner) snapshot() (int, pmodel.Script) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, r.lastScript
}

type rankingExecutorStrategy struct {
	name       string
	plans      []solver.Plan
	executors  map[string]*scriptedExecutor
	mu         sync.Mutex
	execOrder  []string
	rankInputs []solver.RankInput
}

func (s *rankingExecutorStrategy) Name() string { return s.name }

func (s *rankingExecutorStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return append([]solver.Plan(nil), s.plans...), nil
}

func (s *rankingExecutorStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	return solver.Result{}, errors.New("rankingExecutorStrategy Execute should not be called")
}

func (s *rankingExecutorStrategy) Close() error { return nil }

func (s *rankingExecutorStrategy) NewExecutor(plan solver.Plan) (solver.PlanExecutor, error) {
	s.mu.Lock()
	s.execOrder = append(s.execOrder, plan.ID)
	s.mu.Unlock()
	executor := s.executors[plan.ID]
	if executor == nil {
		return nil, errors.New("missing executor")
	}
	return executor, nil
}

func (s *rankingExecutorStrategy) RankPlans(_ context.Context, input solver.RankInput, plans []solver.Plan) (solver.RankedPlans, error) {
	s.mu.Lock()
	s.rankInputs = append(s.rankInputs, input)
	s.mu.Unlock()
	if input.LastProbeResult != nil && input.LastProbeResult.Success {
		return solver.RankedPlans{
			Plans:  []solver.Plan{plans[1], plans[0]},
			Reason: "probe_success_prefers_second_plan",
		}, nil
	}
	return solver.RankedPlans{Plans: append([]solver.Plan(nil), plans...), Reason: "no_probe_signal"}, nil
}

func (s *rankingExecutorStrategy) BuildPreflightProbe(context.Context, solver.ProbeInput) (*solver.ProbeScript, solver.ProbePolicy, error) {
	return &solver.ProbeScript{
		ScriptType: pmodel.ScriptTypePreflight,
		PlanID:     "probe/preflight",
		Steps: []solver.ProbeStep{
			{
				Action: "report",
				Params: map[string]string{
					"event":       "probe_ready",
					"script_type": pmodel.ScriptTypePreflight,
					"strategy":    s.name,
				},
			},
		},
	}, solver.ProbePolicy{Optional: true, Timeout: 200 * time.Millisecond, Reason: "test_probe"}, nil
}

func (s *rankingExecutorStrategy) snapshot() ([]string, []solver.RankInput) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.execOrder...), append([]solver.RankInput(nil), s.rankInputs...)
}

func TestSessionProbeScriptRoundTrip(t *testing.T) {
	localSender := &callbackSender{}
	remoteSender := &callbackSender{}
	remoteRunner := &fakeProbeRunner{
		result: pmodel.Result{
			Success: true,
			Events: []solver.Observation{
				{Strategy: pmodel.StrategyName, PlanID: "probe/manual", Event: "script_completed", Timestamp: time.Now()},
			},
		},
	}

	var local, remote *Session
	localSender.sendFn = func(msg solver.Message) error { return remote.HandleMessage(context.Background(), msg) }
	remoteSender.sendFn = func(msg solver.Message) error { return local.HandleMessage(context.Background(), msg) }

	var err error
	local, err = New(Config{
		SessionID:   "session/node-a/node-b",
		LocalNodeID: "node-a",
		PeerID:      "node-b",
		Initiator:   true,
		Resolver:    &fakeResolver{local: probeCapability(), strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:      localSender,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}
	remote, err = New(Config{
		SessionID:   "session/node-a/node-b",
		LocalNodeID: "node-b",
		PeerID:      "node-a",
		Initiator:   false,
		Resolver:    &fakeResolver{local: probeCapability(), strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:      remoteSender,
		ProbeRunner: remoteRunner,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}

	if err := local.sendProbeScript(context.Background(), pmodel.Script{
		ScriptType: "manual_test",
		PlanID:     "probe/manual",
		Steps:      []pmodel.Step{{Type: pmodel.StepReport, Event: "script_completed"}},
	}); err != nil {
		t.Fatalf("sendProbeScript() error = %v", err)
	}

	waitForProbeResult(t, local, "manual_test")

	calls, script := remoteRunner.snapshot()
	if calls != 1 {
		t.Fatalf("ProbeRunner calls = %d, want 1", calls)
	}
	if script.ScriptType != "manual_test" || script.PlanID != "probe/manual" {
		t.Fatalf("ProbeRunner script = %+v, want manual_test/probe/manual", script)
	}

	localSnapshot := local.Snapshot()
	if !localSnapshot.LastProbeResult.Success || localSnapshot.LastProbeResult.ScriptType != "manual_test" {
		t.Fatalf("local LastProbeResult = %+v, want successful manual_test result", localSnapshot.LastProbeResult)
	}
	if !containsObservationEvent(local.Observations(), "probe_script_sent") || !containsObservationEvent(local.Observations(), "probe_result_received") {
		t.Fatalf("local observations = %+v, want probe_script_sent + probe_result_received", local.Observations())
	}
	if !containsObservationEvent(remote.Observations(), "probe_script_received") ||
		!containsObservationEvent(remote.Observations(), "probe_script_started") ||
		!containsObservationEvent(remote.Observations(), "probe_script_succeeded") {
		t.Fatalf("remote observations = %+v, want probe receive/start/succeed", remote.Observations())
	}
}

func TestSessionPreflightProbeSuccessDoesNotBlockStrategyFlow(t *testing.T) {
	localSender := &callbackSender{}
	remoteSender := &callbackSender{}
	localRunner := &fakeProbeRunner{result: pmodel.Result{Success: true}}
	remoteRunner := &fakeProbeRunner{result: pmodel.Result{Success: true, Events: []solver.Observation{{Strategy: pmodel.StrategyName, Event: "probe_ready", Timestamp: time.Now()}}}}
	localTransport := &fakeTransport{}
	remoteTransport := &fakeTransport{}
	localStrategy := &planningProbeStrategy{fakeStrategy: fakeStrategy{name: "legacy_ice_udp", transport: localTransport}}

	var local, remote *Session
	localSender.sendFn = func(msg solver.Message) error { return remote.HandleMessage(context.Background(), msg) }
	remoteSender.sendFn = func(msg solver.Message) error { return local.HandleMessage(context.Background(), msg) }

	var err error
	remote, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-b",
		PeerID:                "node-a",
		Initiator:             false,
		Resolver:              &fakeResolver{local: probeCapability(), strategy: &fakeStrategy{name: "legacy_ice_udp", transport: remoteTransport}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                remoteSender,
		ProbeRunner:           remoteRunner,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
		PreflightProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}
	local, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: probeCapability(), strategy: localStrategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                localSender,
		ProbeRunner:           localRunner,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
		PreflightProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}

	if err := remote.Start(context.Background()); err != nil {
		t.Fatalf("remote Start() error = %v", err)
	}
	if err := local.Start(context.Background()); err != nil {
		t.Fatalf("local Start() error = %v", err)
	}

	waitForState(t, local, StateBound)

	snapshot := local.Snapshot()
	if !snapshot.PreflightProbeAttempted || !snapshot.PreflightProbeSucceeded {
		t.Fatalf("preflight flags = attempted:%t succeeded:%t, want true/true", snapshot.PreflightProbeAttempted, snapshot.PreflightProbeSucceeded)
	}
	if snapshot.LastProbeResult.ScriptType != pmodel.ScriptTypePreflight || !snapshot.LastProbeResult.Success {
		t.Fatalf("LastProbeResult = %+v, want successful preflight result", snapshot.LastProbeResult)
	}
	if _, ok := findEnvelopeMessage(localSender.Messages(), rproto.MsgTypeProbeScript); !ok {
		t.Fatalf("local sender messages = %+v, want probe_script envelope", localSender.Messages())
	}
	if !containsObservationEvent(local.Observations(), "probe_script_sent") {
		t.Fatalf("local observations = %+v, want probe_script_sent", local.Observations())
	}
}

func TestSessionPreflightProbeTimeoutFallsBackToCandidateLoop(t *testing.T) {
	localSender := &callbackSender{}
	remoteSender := &callbackSender{}
	remoteRunner := &fakeProbeRunner{result: pmodel.Result{Success: true}}
	localTransport := &fakeTransport{}
	remoteTransport := &fakeTransport{}
	localStrategy := &planningProbeStrategy{fakeStrategy: fakeStrategy{name: "legacy_ice_udp", transport: localTransport}}

	var local, remote *Session
	localSender.sendFn = func(msg solver.Message) error { return remote.HandleMessage(context.Background(), msg) }
	remoteSender.sendFn = func(msg solver.Message) error {
		if msg.Kind == solver.MessageKindEnvelope && msg.Type == rproto.MsgTypeProbeResult {
			return nil
		}
		return local.HandleMessage(context.Background(), msg)
	}

	var err error
	remote, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-b",
		PeerID:                "node-a",
		Initiator:             false,
		Resolver:              &fakeResolver{local: probeCapability(), strategy: &fakeStrategy{name: "legacy_ice_udp", transport: remoteTransport}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                remoteSender,
		ProbeRunner:           remoteRunner,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
		PreflightProbeTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}
	local, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: probeCapability(), strategy: localStrategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                localSender,
		ProbeRunner:           &fakeProbeRunner{result: pmodel.Result{Success: true}},
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
		PreflightProbeTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}

	if err := remote.Start(context.Background()); err != nil {
		t.Fatalf("remote Start() error = %v", err)
	}
	if err := local.Start(context.Background()); err != nil {
		t.Fatalf("local Start() error = %v", err)
	}

	waitForState(t, local, StateBound)

	snapshot := local.Snapshot()
	if !snapshot.PreflightProbeAttempted || snapshot.PreflightProbeSucceeded {
		t.Fatalf("preflight flags = attempted:%t succeeded:%t, want true/false", snapshot.PreflightProbeAttempted, snapshot.PreflightProbeSucceeded)
	}
	if !containsObservationEvent(local.Observations(), "probe_failed") {
		t.Fatalf("local observations = %+v, want probe_failed", local.Observations())
	}
}

func TestSessionSkipsPreflightWithoutNegotiatedProbeFeatures(t *testing.T) {
	localSender := &callbackSender{}
	remoteSender := &callbackSender{}
	localTransport := &fakeTransport{}
	remoteTransport := &fakeTransport{}

	var local, remote *Session
	localSender.sendFn = func(msg solver.Message) error { return remote.HandleMessage(context.Background(), msg) }
	remoteSender.sendFn = func(msg solver.Message) error { return local.HandleMessage(context.Background(), msg) }

	var err error
	remote, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-b",
		PeerID:                "node-a",
		Initiator:             false,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: &fakeStrategy{name: "legacy_ice_udp", transport: remoteTransport}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                remoteSender,
		ProbeRunner:           &fakeProbeRunner{result: pmodel.Result{Success: true}},
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}
	local, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: probeCapability(), strategy: &fakeStrategy{name: "legacy_ice_udp", transport: localTransport}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                localSender,
		ProbeRunner:           &fakeProbeRunner{result: pmodel.Result{Success: true}},
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}

	if err := remote.Start(context.Background()); err != nil {
		t.Fatalf("remote Start() error = %v", err)
	}
	if err := local.Start(context.Background()); err != nil {
		t.Fatalf("local Start() error = %v", err)
	}

	waitForState(t, local, StateBound)

	if _, ok := findEnvelopeMessage(localSender.Messages(), rproto.MsgTypeProbeScript); ok {
		t.Fatalf("local sender messages = %+v, want no probe_script envelope", localSender.Messages())
	}
	snapshot := local.Snapshot()
	if snapshot.PreflightProbeAttempted {
		t.Fatalf("PreflightProbeAttempted = true, want false")
	}
}

func TestSessionSkipsPreflightWithoutLocalProbeSupport(t *testing.T) {
	localSender := &callbackSender{}
	remoteSender := &callbackSender{}

	var local, remote *Session
	localSender.sendFn = func(msg solver.Message) error { return remote.HandleMessage(context.Background(), msg) }
	remoteSender.sendFn = func(msg solver.Message) error { return local.HandleMessage(context.Background(), msg) }

	var err error
	remote, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-b",
		PeerID:                "node-a",
		Initiator:             false,
		Resolver:              &fakeResolver{local: probeCapability(), strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                remoteSender,
		ProbeRunner:           &fakeProbeRunner{result: pmodel.Result{Success: true}},
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}
	local, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                localSender,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}

	if err := remote.Start(context.Background()); err != nil {
		t.Fatalf("remote Start() error = %v", err)
	}
	if err := local.Start(context.Background()); err != nil {
		t.Fatalf("local Start() error = %v", err)
	}

	waitForState(t, local, StateBound)

	if _, ok := findEnvelopeMessage(localSender.Messages(), rproto.MsgTypeProbeScript); ok {
		t.Fatalf("local sender messages = %+v, want no probe_script envelope", localSender.Messages())
	}
	if local.Snapshot().PreflightProbeAttempted {
		t.Fatalf("PreflightProbeAttempted = true, want false")
	}
}

func TestSessionUsesRankedPlanOrderAndRecordsSnapshot(t *testing.T) {
	localSender := &callbackSender{}
	remoteSender := &callbackSender{}
	localProbeRunner := &fakeProbeRunner{result: pmodel.Result{Success: true}}
	remoteProbeRunner := &fakeProbeRunner{result: pmodel.Result{Success: true}}
	relayTransport := &fakeTransport{}
	directTransport := &fakeTransport{}
	strategy := &rankingExecutorStrategy{
		name: "ranked_strategy",
		plans: []solver.Plan{
			{ID: "plan-relay", Strategy: "ranked_strategy"},
			{ID: "plan-direct", Strategy: "ranked_strategy"},
		},
		executors: map[string]*scriptedExecutor{
			"plan-relay": newScriptedExecutor(solver.Result{
				Transport: relayTransport,
				Summary:   solver.PathSummary{PathID: "relay/path", ConnectionType: "relay", RemoteAddr: relayTransport.RemoteAddr()},
			}, nil),
			"plan-direct": newScriptedExecutor(solver.Result{
				Transport: directTransport,
				Summary:   solver.PathSummary{PathID: "direct/path", ConnectionType: "direct", RemoteAddr: directTransport.RemoteAddr()},
			}, nil),
		},
	}

	var local, remote *Session
	localSender.sendFn = func(msg solver.Message) error { return remote.HandleMessage(context.Background(), msg) }
	remoteSender.sendFn = func(msg solver.Message) error { return local.HandleMessage(context.Background(), msg) }

	var err error
	remote, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-b",
		PeerID:                "node-a",
		Initiator:             false,
		Resolver:              &fakeResolver{local: probeCapability("ranked_strategy"), strategy: &fakeStrategy{name: "ranked_strategy", transport: &fakeTransport{}}, selection: Selection{StrategyName: "ranked_strategy", Negotiated: true}},
		Sender:                remoteSender,
		ProbeRunner:           remoteProbeRunner,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
		PreflightProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}
	local, err = New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: probeCapability("ranked_strategy"), strategy: strategy, selection: Selection{StrategyName: "ranked_strategy", Negotiated: true}},
		Sender:                localSender,
		ProbeRunner:           localProbeRunner,
		RunTimeout:            time.Second,
		CapabilityWaitTimeout: time.Second,
		PreflightProbeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}

	if err := remote.Start(context.Background()); err != nil {
		t.Fatalf("remote Start() error = %v", err)
	}
	if err := local.Start(context.Background()); err != nil {
		t.Fatalf("local Start() error = %v", err)
	}

	waitForState(t, local, StateBound)

	order, inputs := strategy.snapshot()
	if !slices.Equal(order, []string{"plan-direct", "plan-relay"}) {
		t.Fatalf("execution order = %v, want [plan-direct plan-relay]", order)
	}
	if len(inputs) == 0 || inputs[0].LastProbeResult == nil || !inputs[0].LastProbeResult.Success {
		t.Fatalf("rank inputs = %+v, want successful LastProbeResult", inputs)
	}
	snapshot := local.Snapshot()
	if !slices.Equal(snapshot.LastPlanOrder, []string{"plan-direct", "plan-relay"}) {
		t.Fatalf("LastPlanOrder = %v, want [plan-direct plan-relay]", snapshot.LastPlanOrder)
	}
	if snapshot.LastPlanOrderReason != "probe_success_prefers_second_plan" {
		t.Fatalf("LastPlanOrderReason = %q, want probe_success_prefers_second_plan", snapshot.LastPlanOrderReason)
	}
	if !containsObservationEvent(local.Observations(), "plan_ordered") {
		t.Fatalf("local observations = %+v, want plan_ordered", local.Observations())
	}
	if !relayTransport.closed {
		t.Fatal("relay losing transport was not closed")
	}
}

func waitForProbeResult(t *testing.T, s *Session, scriptType string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := s.Snapshot()
		if snapshot.LastProbeResult.ScriptType == scriptType {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("LastProbeResult.ScriptType = %q, want %q", s.Snapshot().LastProbeResult.ScriptType, scriptType)
}

func probeCapability(strategies ...string) rproto.Capability {
	if len(strategies) == 0 {
		strategies = []string{"legacy_ice_udp"}
	}
	return rproto.Capability{
		Strategies: strategies,
		Features: []string{
			rproto.FeatureProbeLabV1,
			rproto.FeatureProbeScriptV1,
		},
	}
}
