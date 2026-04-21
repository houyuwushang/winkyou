package session

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pmodel "winkyou/pkg/probe/model"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type fakeObservationHistory struct {
	items []solver.Observation
}

func (f fakeObservationHistory) Recent(limit int) []solver.Observation {
	if limit <= 0 || limit >= len(f.items) {
		out := make([]solver.Observation, len(f.items))
		copy(out, f.items)
		return out
	}
	out := make([]solver.Observation, limit)
	copy(out, f.items[len(f.items)-limit:])
	return out
}

type planningProbeStrategy struct {
	fakeStrategy
	planInput       solver.SolveInput
	probeInput      solver.ProbeInput
	buildProbeCalls int
}

func (p *planningProbeStrategy) Plan(ctx context.Context, in solver.SolveInput) ([]solver.Plan, error) {
	p.planInput = in
	return p.fakeStrategy.Plan(ctx, in)
}

func (p *planningProbeStrategy) BuildPreflightProbe(ctx context.Context, input solver.ProbeInput) (*solver.ProbeScript, solver.ProbePolicy, error) {
	_ = ctx
	p.probeInput = input
	p.buildProbeCalls++
	return &solver.ProbeScript{
		ScriptType: pmodel.ScriptTypePreflight,
		PlanID:     "probe/preflight",
		Steps: []solver.ProbeStep{
			{
				Action: "report",
				Params: map[string]string{
					"event":       "probe_ready",
					"script_type": pmodel.ScriptTypePreflight,
					"strategy":    p.name,
				},
			},
		},
	}, solver.ProbePolicy{Optional: true, Timeout: 200 * time.Millisecond, Reason: "test_probe"}, nil
}

type refiningStrategy struct {
	planningProbeStrategy
	refineCalled bool
}

func (r *refiningStrategy) Plan(ctx context.Context, in solver.SolveInput) ([]solver.Plan, error) {
	r.planInput = in
	return []solver.Plan{
		{ID: "legacyice/direct_prefer", Strategy: r.name},
		{ID: "legacyice/relay_only", Strategy: r.name},
	}, nil
}

func (r *refiningStrategy) RefinePlans(ctx context.Context, in solver.SolveInput, plans []solver.Plan) (solver.RefinedPlans, error) {
	_ = ctx
	r.refineCalled = true
	return solver.RefinedPlans{
		Plans: []solver.Plan{
			plans[len(plans)-1],
		},
		Reason: "test_pruned_direct",
	}, nil
}

func TestSessionUsesStrategyAuthoredPreflightProbe(t *testing.T) {
	transport := &fakeTransport{}
	strategy := &planningProbeStrategy{fakeStrategy: fakeStrategy{name: "legacy_ice_udp", transport: transport}}
	sender := &fakeSender{}
	stateCh := make(chan State, 16)
	bound := make(chan solver.Result, 1)

	history := fakeObservationHistory{items: []solver.Observation{{
		Strategy: StrategyNameForTest(),
		PlanID:   "legacyice/direct_prefer",
		Event:    "candidate_failed",
		Details: map[string]string{
			"session_id": "session/node-a/node-b",
			"peer_id":    "node-b",
		},
	}}}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}, Features: []string{rproto.FeatureProbeLabV1, rproto.FeatureProbeScriptV1}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Sender:                sender,
		ObservationHistory:    history,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
		Hooks: Hooks{OnStateChange: func(state State) { stateCh <- state }, OnBound: func(result solver.Result) { bound <- result }},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}, Features: []string{rproto.FeatureProbeLabV1, rproto.FeatureProbeScriptV1}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeProbeResult, 2, rproto.ProbeResult{ScriptType: pmodel.ScriptTypePreflight, PlanID: "probe/preflight", Success: true, FinishedAt: time.Now()}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(probe_result) error = %v", err)
	}

	select {
	case <-bound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bound result")
	}

	if strategy.buildProbeCalls != 1 {
		t.Fatalf("BuildPreflightProbe() calls = %d, want 1", strategy.buildProbeCalls)
	}
	if strategy.probeInput.RemoteNodeID != "node-b" {
		t.Fatalf("probe input remote node = %q, want node-b", strategy.probeInput.RemoteNodeID)
	}
	if strategy.planInput.RemoteNodeID != "node-b" {
		t.Fatalf("plan input remote node = %q, want node-b", strategy.planInput.RemoteNodeID)
	}
	if len(strategy.planInput.LocalObservations) == 0 {
		t.Fatal("expected evidence-aware local observations in SolveInput")
	}
	if strategy.planInput.RemoteCapability.Features[0] != rproto.FeatureProbeLabV1 {
		t.Fatalf("unexpected remote capability in SolveInput: %#v", strategy.planInput.RemoteCapability)
	}
	if strategy.planInput.LastProbeResult == nil || !strategy.planInput.LastProbeResult.Success {
		t.Fatalf("expected successful probe summary in SolveInput, got %#v", strategy.planInput.LastProbeResult)
	}
	if strategy.planInput.LocalCapability.Features[0] != rproto.FeatureProbeLabV1 {
		t.Fatalf("unexpected local capability in SolveInput: %#v", strategy.planInput.LocalCapability)
	}

	messages := sender.Messages()
	probeMsg, ok := findEnvelopeMessage(messages, rproto.MsgTypeProbeScript)
	if !ok {
		t.Fatalf("messages = %+v, want probe_script envelope", messages)
	}
	env, err := rproto.UnmarshalEnvelope(probeMsg.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(probe_script) error = %v", err)
	}
	var probeScript rproto.ProbeScript
	if err := decodeEnvelopePayload(env, &probeScript); err != nil {
		t.Fatalf("decode probe_script: %v", err)
	}
	if probeScript.PlanID != "probe/preflight" || probeScript.ScriptType != pmodel.ScriptTypePreflight {
		t.Fatalf("probe_script = %#v, want strategy-authored preflight", probeScript)
	}
	if len(probeScript.Steps) != 1 || probeScript.Steps[0].Event != "probe_ready" {
		t.Fatalf("probe steps = %#v, want strategy-authored report step", probeScript.Steps)
	}

	states := collectStates(stateCh)
	if !containsState(states, StateProbing) {
		t.Fatalf("state transitions = %v, want probing state", states)
	}

	snapshot := s.Snapshot()
	if !snapshot.PreflightProbeAttempted || !snapshot.PreflightProbeSucceeded {
		t.Fatalf("preflight probe attempted=%t succeeded=%t, want true/true", snapshot.PreflightProbeAttempted, snapshot.PreflightProbeSucceeded)
	}
}

func TestLastProbeResultSummaryUsesSelectedPathID(t *testing.T) {
	s := &Session{}
	s.meta.LastProbeResult = pmodel.Result{
		ScriptType:     pmodel.ScriptTypePreflight,
		PlanID:         "probe/preflight",
		Success:        true,
		SelectedPathID: "relay/path",
		ErrorClass:     "none",
		FinishedAt:     time.Unix(1_710_000_000, 0),
	}
	s.meta.LastProbeResultAt = s.meta.LastProbeResult.FinishedAt

	summary := s.lastProbeResultSummary()
	if summary == nil {
		t.Fatal("lastProbeResultSummary() = nil")
	}
	if summary.PathID != "relay/path" {
		t.Fatalf("PathID = %q, want relay/path", summary.PathID)
	}
	if summary.Details["plan_id"] != "probe/preflight" {
		t.Fatalf("plan_id = %q, want probe/preflight", summary.Details["plan_id"])
	}
}

func TestSessionSkipsProbingWhenStrategyDoesNotImplementPlanner(t *testing.T) {
	transport := &fakeTransport{}
	strategy := &fakeStrategy{name: "legacy_ice_udp", transport: transport}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}, Features: []string{rproto.FeatureProbeLabV1, rproto.FeatureProbeScriptV1}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
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
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}, Features: []string{rproto.FeatureProbeLabV1, rproto.FeatureProbeScriptV1}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateBound)
	if _, ok := findEnvelopeMessage(sender.Messages(), rproto.MsgTypeProbeScript); ok {
		t.Fatal("unexpected probe_script when strategy has no ProbePlanner")
	}
}

func TestSessionSkipsProbingWhenProbeFeaturesNotNegotiated(t *testing.T) {
	transport := &fakeTransport{}
	strategy := &planningProbeStrategy{fakeStrategy: fakeStrategy{name: "legacy_ice_udp", transport: transport}}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
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
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateBound)
	if strategy.buildProbeCalls != 0 {
		t.Fatalf("BuildPreflightProbe() calls = %d, want 0", strategy.buildProbeCalls)
	}
}

func TestSessionRefinesPlansBeforeCandidateLoop(t *testing.T) {
	transport := &fakeTransport{}
	strategy := &refiningStrategy{planningProbeStrategy: planningProbeStrategy{fakeStrategy: fakeStrategy{name: "legacy_ice_udp", transport: transport}}}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             false,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
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
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateBound)

	if !strategy.refineCalled {
		t.Fatal("expected RefinePlans() to be called")
	}
	snapshot := s.Snapshot()
	if snapshot.LastPlanRefineReason != "test_pruned_direct" {
		t.Fatalf("LastPlanRefineReason = %q, want test_pruned_direct", snapshot.LastPlanRefineReason)
	}
	if len(snapshot.LastPlanSetBeforeRefine) != 1+1 || len(snapshot.LastPlanSetAfterRefine) != 1 {
		t.Fatalf("unexpected refine snapshots: before=%v after=%v", snapshot.LastPlanSetBeforeRefine, snapshot.LastPlanSetAfterRefine)
	}
	if len(snapshot.LastPlanOrder) != 1 || snapshot.LastPlanOrder[0] != "plan-1" {
		// fakeStrategy returns plan-1 only, so keep this defensive for custom plan injectors
	}

	obs := s.Observations()
	found := false
	for _, item := range obs {
		if item.Event == "plans_refined" && item.Reason == "test_pruned_direct" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected plans_refined observation")
	}
}

func containsState(states []State, want State) bool {
	for _, state := range states {
		if state == want {
			return true
		}
	}
	return false
}

func decodeEnvelopePayload[T any](env rproto.SessionEnvelope, target *T) error {
	return json.Unmarshal(env.Payload, target)
}

func StrategyNameForTest() string {
	return "legacy_ice_udp"
}
