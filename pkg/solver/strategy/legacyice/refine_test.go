package legacyice

import (
	"context"
	"slices"
	"testing"
	"time"

	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

func TestStrategyRefinePlansPrunesDirectUnderStrongRelayEvidence(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	refined, err := strategy.RefinePlans(context.Background(), solver.SolveInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		LocalObservations: []solver.Observation{
			observationForRanking("legacyice/direct_prefer", "candidate_failed", "", "node-b"),
			observationForRanking("legacyice/direct_prefer", "candidate_failed", "", "node-b"),
			observationForRanking("legacyice/relay_only", "candidate_succeeded", "relay", "node-b"),
		},
		LastProbeResult: &solver.ProbeResultSummary{
			ScriptType: pmodel.ScriptTypePreflight,
			Success:    false,
			FinishedAt: time.Now(),
		},
	}, plans)
	if err != nil {
		t.Fatalf("RefinePlans() error = %v", err)
	}
	if !slices.Equal(planIDs(refined.Plans), []string{"legacyice/relay_only"}) {
		t.Fatalf("refined plans = %v, want relay_only only", planIDs(refined.Plans))
	}
	if refined.Reason != "strong_relay_evidence_prune_direct" {
		t.Fatalf("Reason = %q, want strong_relay_evidence_prune_direct", refined.Reason)
	}
}

func TestStrategyRefinePlansKeepsDirectWhenRemoteEvidenceIsStaleOrUnscoped(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	tests := []struct {
		name               string
		remoteObservations []solver.Observation
	}{
		{
			name: "cross session",
			remoteObservations: []solver.Observation{
				observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-x/node-y", "node-a"),
				observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-x/node-y", "node-a"),
				observationWithScope(planIDRelayOnly, "candidate_succeeded", "relay", "session/node-x/node-y", "node-a"),
			},
		},
		{
			name: "cross peer",
			remoteObservations: []solver.Observation{
				observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-a/node-b", "node-x"),
				observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-a/node-b", "node-x"),
				observationWithScope(planIDRelayOnly, "candidate_succeeded", "relay", "session/node-a/node-b", "node-x"),
			},
		},
		{
			name: "unscoped",
			remoteObservations: []solver.Observation{
				unscopedObservation(planIDDirectPrefer, "candidate_failed", ""),
				unscopedObservation(planIDDirectPrefer, "candidate_failed", ""),
				unscopedObservation(planIDRelayOnly, "candidate_succeeded", "relay"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refined, err := strategy.RefinePlans(context.Background(), solver.SolveInput{
				LocalNodeID:        "node-a",
				SessionID:          "session/node-a/node-b",
				RemoteNodeID:       "node-b",
				RemoteObservations: tt.remoteObservations,
			}, plans)
			if err != nil {
				t.Fatalf("RefinePlans() error = %v", err)
			}
			if !slices.Equal(planIDs(refined.Plans), planIDs(plans)) {
				t.Fatalf("refined plans = %v, want default order %v", planIDs(refined.Plans), planIDs(plans))
			}
			if refined.Reason != "no_refinement" {
				t.Fatalf("Reason = %q, want no_refinement", refined.Reason)
			}
		})
	}
}

func TestStrategyRefinePlansKeepsPlansWithoutStrongEvidence(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	refined, err := strategy.RefinePlans(context.Background(), solver.SolveInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		LocalObservations: []solver.Observation{
			observationForRanking("legacyice/direct_prefer", "candidate_failed", "", "node-b"),
			observationForRanking("legacyice/relay_only", "candidate_succeeded", "relay", "node-b"),
		},
	}, plans)
	if err != nil {
		t.Fatalf("RefinePlans() error = %v", err)
	}
	if !slices.Equal(planIDs(refined.Plans), planIDs(plans)) {
		t.Fatalf("refined plans = %v, want default order %v", planIDs(refined.Plans), planIDs(plans))
	}
	if refined.Reason != "no_refinement" {
		t.Fatalf("Reason = %q, want no_refinement", refined.Reason)
	}
}

func TestStrategyBuildPreflightProbeReturnsStrategyAuthoredScript(t *testing.T) {
	strategy := New(Config{})

	script, policy, err := strategy.BuildPreflightProbe(context.Background(), solver.ProbeInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		Initiator:    true,
		LocalObservations: []solver.Observation{
			observationForRanking(planIDDirectPrefer, "candidate_failed", "", "node-b"),
			observationForRanking(planIDDirectPrefer, "candidate_failed", "", "node-b"),
			observationForRanking(planIDRelayOnly, "candidate_succeeded", "relay", "node-b"),
		},
	})
	if err != nil {
		t.Fatalf("BuildPreflightProbe() error = %v", err)
	}
	if script == nil {
		t.Fatal("BuildPreflightProbe() returned nil script")
	}
	if script.ScriptType != pmodel.ScriptTypePreflight {
		t.Fatalf("ScriptType = %q, want %q", script.ScriptType, pmodel.ScriptTypePreflight)
	}
	if script.PlanID != "probe/preflight" {
		t.Fatalf("PlanID = %q, want probe/preflight", script.PlanID)
	}
	if len(script.Steps) == 0 {
		t.Fatal("expected strategy-authored probe steps")
	}
	report := script.Steps[len(script.Steps)-1].Params
	if report["session_id"] != "session/node-a/node-b" || report["remote_node_id"] != "node-b" {
		t.Fatalf("probe report params = %#v, want session and remote node details", report)
	}
	if report["evidence_hint"] != "strong_relay_only" {
		t.Fatalf("evidence_hint = %q, want strong_relay_only", report["evidence_hint"])
	}
	if report["direct_failures"] != "2" || report["relay_successes"] != "1" {
		t.Fatalf("probe evidence counters = %#v, want direct_failures=2 relay_successes=1", report)
	}
	if !policy.Optional {
		t.Fatal("expected preflight probe to be optional")
	}
	if policy.Reason == "" {
		t.Fatal("expected probe policy reason")
	}
}
