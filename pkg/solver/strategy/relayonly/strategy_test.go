package relayonly

import (
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
)

type recordingICEAgent struct {
	gatherErr error
}

func (a *recordingICEAgent) GatherCandidates(context.Context) ([]nat.Candidate, error) {
	return nil, a.gatherErr
}

func (a *recordingICEAgent) GetLocalCredentials() (string, string, error) {
	return "ufrag", "pwd", nil
}

func (a *recordingICEAgent) SetRemoteCredentials(string, string) error {
	return nil
}

func (a *recordingICEAgent) SetRemoteCandidates([]nat.Candidate) error {
	return nil
}

func (a *recordingICEAgent) Connect(context.Context) (nat.SelectedTransport, *nat.CandidatePair, error) {
	return nil, nil, context.Canceled
}

func (a *recordingICEAgent) Close() error {
	return nil
}

type recordingSessionIO struct {
	observations []solver.Observation
}

func (io *recordingSessionIO) Send(context.Context, solver.Message) error {
	return nil
}

func (io *recordingSessionIO) ReportObservation(_ context.Context, obs solver.Observation) error {
	io.observations = append(io.observations, obs)
	return nil
}

func TestPlanReturnsSingleRelayOnlyPlan(t *testing.T) {
	strategy := New(Config{})
	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %d, want 1", len(plans))
	}
	plan := plans[0]
	if plan.ID != PlanID || plan.Strategy != StrategyName {
		t.Fatalf("plan = %#v, want relay-only plan identity", plan)
	}
	if plan.Metadata["mode"] != "relay_only" {
		t.Fatalf("plan metadata = %#v, want mode=relay_only", plan.Metadata)
	}
}

func TestExecutorForcesRelayAndReportsRelayOnlyStrategy(t *testing.T) {
	gatherErr := errors.New("stop after agent request")
	var requests []legacyice.AgentRequest
	strategy := New(Config{
		NewICEAgent: func(ctx context.Context, req legacyice.AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			requests = append(requests, req)
			return &recordingICEAgent{gatherErr: gatherErr}, nil
		},
		GatherTimeout:  100 * time.Millisecond,
		ConnectTimeout: 100 * time.Millisecond,
	})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	io := &recordingSessionIO{}
	_, err = strategy.Execute(context.Background(), io, plans[0])
	if !errors.Is(err, gatherErr) {
		t.Fatalf("Execute() error = %v, want gather error", err)
	}
	if len(requests) != 1 {
		t.Fatalf("agent requests = %d, want 1", len(requests))
	}
	if !requests[0].ForceRelay {
		t.Fatalf("agent request = %+v, want ForceRelay=true", requests[0])
	}

	events := map[string]solver.Observation{}
	for _, obs := range io.observations {
		events[obs.Event] = obs
	}
	for _, event := range []string{"candidate_started", "candidate_failed"} {
		obs, ok := events[event]
		if !ok {
			t.Fatalf("observations = %#v, want %s", io.observations, event)
		}
		if obs.Strategy != StrategyName {
			t.Fatalf("%s strategy = %q, want %q", event, obs.Strategy, StrategyName)
		}
		if obs.PlanID != PlanID {
			t.Fatalf("%s plan_id = %q, want %q", event, obs.PlanID, PlanID)
		}
	}
}

func TestBuildPreflightProbeUsesRelayOnlyStrategyDetail(t *testing.T) {
	strategy := New(Config{})
	script, _, err := strategy.BuildPreflightProbe(context.Background(), solver.ProbeInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	})
	if err != nil {
		t.Fatalf("BuildPreflightProbe() error = %v", err)
	}
	for _, step := range script.Steps {
		if step.Params["strategy"] == StrategyName {
			return
		}
	}
	t.Fatalf("probe steps = %#v, want strategy=%q detail", script.Steps, StrategyName)
}

func TestNewExecutorRejectsNonRelayOnlyPlan(t *testing.T) {
	strategy := New(Config{})
	if _, err := strategy.NewExecutor(solver.Plan{ID: "legacyice/direct_prefer", Strategy: legacyice.StrategyName}); err == nil {
		t.Fatal("NewExecutor() error = nil, want unsupported plan error")
	}
}

func TestStrategyName(t *testing.T) {
	if got := New(Config{}).Name(); got != StrategyName {
		t.Fatalf("Name() = %q, want %q", got, StrategyName)
	}
}
