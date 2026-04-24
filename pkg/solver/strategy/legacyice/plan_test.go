package legacyice

import (
	"context"
	"slices"
	"testing"
	"time"

	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

func TestStrategyPlanKeepsDefaultWithoutStrongEvidence(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		LocalObservations: []solver.Observation{
			observationForRanking(planIDDirectPrefer, "candidate_failed", "", "node-b"),
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if !slices.Equal(planIDs(plans), []string{planIDDirectPrefer, planIDRelayOnly}) {
		t.Fatalf("plans = %v, want conservative direct+relay fallback", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "insufficient_evidence" {
		t.Fatalf("direct plan evidence_hint = %q, want insufficient_evidence", got)
	}
}

func TestStrategyPlanPrunesDirectUnderStrongRelayEvidence(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		LocalObservations: []solver.Observation{
			observationForRanking(planIDDirectPrefer, "candidate_failed", "", "node-b"),
			observationForRanking(planIDDirectPrefer, "candidate_failed", "", "node-b"),
			observationForRanking(planIDRelayOnly, "candidate_succeeded", "relay", "node-b"),
		},
		LastProbeResult: &solver.ProbeResultSummary{
			ScriptType: pmodel.ScriptTypePreflight,
			Success:    false,
			FinishedAt: time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if !slices.Equal(planIDs(plans), []string{planIDRelayOnly}) {
		t.Fatalf("plans = %v, want relay_only only under strong relay evidence", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "strong_relay_only" {
		t.Fatalf("relay plan evidence_hint = %q, want strong_relay_only", got)
	}
}

func TestStrategyPlanKeepsDirectFirstAfterDirectSuccess(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		LocalObservations: []solver.Observation{
			observationForRanking(planIDDirectPrefer, "path_selected", "direct", "node-b"),
			observationForRanking(planIDRelayOnly, "candidate_succeeded", "relay", "node-b"),
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if !slices.Equal(planIDs(plans), []string{planIDDirectPrefer, planIDRelayOnly}) {
		t.Fatalf("plans = %v, want direct-first dual plan after direct success", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "direct_success" {
		t.Fatalf("direct plan evidence_hint = %q, want direct_success", got)
	}
}
