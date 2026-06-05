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

	if !slices.Equal(planIDs(plans), planIDs(defaultPlans())) {
		t.Fatalf("plans = %v, want conservative direct+public-direct+relay fallback", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "insufficient_evidence" {
		t.Fatalf("direct plan evidence_hint = %q, want insufficient_evidence", got)
	}
}

func TestStrategyPlanOmitsRelayWhenRelayDisabled(t *testing.T) {
	strategy := New(Config{RelayDisabled: true})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if !slices.Equal(planIDs(plans), []string{planIDDirectPrefer, planIDPublicDirect}) {
		t.Fatalf("plans = %v, want direct_prefer + public_direct", planIDs(plans))
	}
}

func TestStrategyPlanSplitsPublicEndpointHintsByLocalBasePort(t *testing.T) {
	strategy := New(Config{
		PublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:41001/192.168.1.20:40001",
		},
	})

	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	wantIDs := []string{
		planIDDirectPrefer,
		"legacyice/public_direct_hint_1",
		"legacyice/public_direct_hint_2",
		planIDRelayOnly,
	}
	if !slices.Equal(planIDs(plans), wantIDs) {
		t.Fatalf("plans = %v, want split public-direct hint plans %v", planIDs(plans), wantIDs)
	}
	if got := plans[1].Metadata[planMetadataPublicEndpointHints]; got != "117.48.146.2:41000/192.168.1.20:40000" {
		t.Fatalf("first hint plan metadata = %q, want first local-base port hint", got)
	}
	if got := plans[2].Metadata[planMetadataPublicEndpointHints]; got != "117.48.146.3:41001/192.168.1.20:40001" {
		t.Fatalf("second hint plan metadata = %q, want second local-base port hint", got)
	}
}

func TestStrategyPlanKeepsPublicDirectUnderStrongRelayEvidence(t *testing.T) {
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

	if !slices.Equal(planIDs(plans), []string{planIDPublicDirect, planIDRelayOnly}) {
		t.Fatalf("plans = %v, want public_direct + relay_only under strong relay evidence", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "strong_relay_preferred" {
		t.Fatalf("public_direct plan evidence_hint = %q, want strong_relay_preferred", got)
	}
}

func TestStrategyPlanKeepsPublicDirectUnderScopedRemoteRelayEvidence(t *testing.T) {
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

	if !slices.Equal(planIDs(plans), []string{planIDPublicDirect, planIDRelayOnly}) {
		t.Fatalf("plans = %v, want public_direct + relay_only under scoped remote relay evidence", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "strong_relay_preferred" {
		t.Fatalf("public_direct plan evidence_hint = %q, want strong_relay_preferred", got)
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

	if !slices.Equal(planIDs(plans), planIDs(defaultPlans())) {
		t.Fatalf("plans = %v, want direct+public-direct+relay when remote evidence is from another session", planIDs(plans))
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

	if !slices.Equal(planIDs(plans), planIDs(defaultPlans())) {
		t.Fatalf("plans = %v, want direct+public-direct+relay when remote evidence is from another peer", planIDs(plans))
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

	if !slices.Equal(planIDs(plans), planIDs(defaultPlans())) {
		t.Fatalf("plans = %v, want direct+public-direct+relay when remote evidence is unscoped", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got == "strong_relay_preferred" {
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

	if !slices.Equal(planIDs(plans), planIDs(defaultPlans())) {
		t.Fatalf("plans = %v, want direct-first plan order after direct success", planIDs(plans))
	}
	if got := plans[0].Metadata["evidence_hint"]; got != "direct_success" {
		t.Fatalf("direct plan evidence_hint = %q, want direct_success", got)
	}
}
