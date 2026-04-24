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
		LocalNodeID:  "node-a",
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

func TestStrategyPlanPrunesDirectUnderScopedRemoteRelayEvidence(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		RemoteObservations: []solver.Observation{
			observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-a/node-b", "node-a"),
			observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-a/node-b", "node-a"),
			observationWithScope(planIDRelayOnly, "candidate_succeeded", "relay", "session/node-a/node-b", "node-a"),
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
		t.Fatalf("plans = %v, want relay_only only under scoped remote relay evidence", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "strong_relay_only" {
		t.Fatalf("relay plan evidence_hint = %q, want strong_relay_only", got)
	}
}

func TestStrategyPlanIgnoresRemoteRelayEvidenceFromOtherSessionForPruning(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		RemoteObservations: []solver.Observation{
			observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-x/node-y", "node-a"),
			observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-x/node-y", "node-a"),
			observationWithScope(planIDRelayOnly, "candidate_succeeded", "relay", "session/node-x/node-y", "node-a"),
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if !slices.Equal(planIDs(plans), []string{planIDDirectPrefer, planIDRelayOnly}) {
		t.Fatalf("plans = %v, want direct+relay when remote evidence is from another session", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "insufficient_evidence" {
		t.Fatalf("direct plan evidence_hint = %q, want insufficient_evidence", got)
	}
}

func TestStrategyPlanIgnoresRemoteRelayEvidenceFromOtherPeerForPruning(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		RemoteObservations: []solver.Observation{
			observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-a/node-b", "node-x"),
			observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-a/node-b", "node-x"),
			observationWithScope(planIDRelayOnly, "candidate_succeeded", "relay", "session/node-a/node-b", "node-x"),
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if !slices.Equal(planIDs(plans), []string{planIDDirectPrefer, planIDRelayOnly}) {
		t.Fatalf("plans = %v, want direct+relay when remote evidence is from another peer", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "insufficient_evidence" {
		t.Fatalf("direct plan evidence_hint = %q, want insufficient_evidence", got)
	}
}

func TestStrategyPlanDoesNotPruneDirectFromUnscopedRemoteRelayEvidence(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		RemoteObservations: []solver.Observation{
			unscopedObservation(planIDDirectPrefer, "candidate_failed", ""),
			unscopedObservation(planIDDirectPrefer, "candidate_failed", ""),
			unscopedObservation(planIDRelayOnly, "candidate_succeeded", "relay"),
		},
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if !slices.Equal(planIDs(plans), []string{planIDDirectPrefer, planIDRelayOnly}) {
		t.Fatalf("plans = %v, want direct+relay when remote evidence is unscoped", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got == "strong_relay_only" {
		t.Fatalf("direct plan evidence_hint = %q, want non-destructive hint", got)
	}
}

func TestStrategyPlanKeepsDirectFirstAfterDirectSuccess(t *testing.T) {
	strategy := New(Config{})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		LocalNodeID:  "node-a",
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
