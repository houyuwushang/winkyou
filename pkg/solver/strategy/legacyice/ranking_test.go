package legacyice

import (
	"context"
	"slices"
	"testing"
	"time"

	pmodel "winkyou/pkg/probe/model"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

func TestStrategyRankPlansPrefersRelayAfterDirectFailures(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	ranked, err := strategy.RankPlans(context.Background(), solver.RankInput{
		LocalNodeID:      "node-a",
		SessionID:        "session/node-a/node-b",
		RemoteNodeID:     "node-b",
		RemoteCapability: rproto.Capability{Strategies: []string{StrategyName}},
		LocalObservations: []solver.Observation{
			observationForRanking("legacyice/direct_prefer", "candidate_failed", "", "node-b"),
			observationForRanking("legacyice/relay_only", "candidate_succeeded", "relay", "node-b"),
		},
	}, plans)
	if err != nil {
		t.Fatalf("RankPlans() error = %v", err)
	}
	if !slices.Equal(planIDs(ranked.Plans), []string{"legacyice/relay_only", "legacyice/direct_prefer"}) {
		t.Fatalf("ranked plans = %v, want relay_only first", planIDs(ranked.Plans))
	}
	if ranked.Reason != "recent_direct_failure_with_relay_success" {
		t.Fatalf("Reason = %q, want recent_direct_failure_with_relay_success", ranked.Reason)
	}
}

func TestStrategyRankPlansKeepsDirectFirstAfterDirectSuccess(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	ranked, err := strategy.RankPlans(context.Background(), solver.RankInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		LocalObservations: []solver.Observation{
			observationForRanking("legacyice/direct_prefer", "path_selected", "direct", "node-b"),
		},
	}, plans)
	if err != nil {
		t.Fatalf("RankPlans() error = %v", err)
	}
	if !slices.Equal(planIDs(ranked.Plans), planIDs(plans)) {
		t.Fatalf("ranked plans = %v, want default order %v", planIDs(ranked.Plans), planIDs(plans))
	}
	if ranked.Reason != "recent_direct_success" {
		t.Fatalf("Reason = %q, want recent_direct_success", ranked.Reason)
	}
}

func TestStrategyRankPlansKeepsDefaultWithoutHistory(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	ranked, err := strategy.RankPlans(context.Background(), solver.RankInput{}, plans)
	if err != nil {
		t.Fatalf("RankPlans() error = %v", err)
	}
	if !slices.Equal(planIDs(ranked.Plans), planIDs(plans)) {
		t.Fatalf("ranked plans = %v, want default order %v", planIDs(ranked.Plans), planIDs(plans))
	}
	if ranked.Reason != "no_relevant_history" {
		t.Fatalf("Reason = %q, want no_relevant_history", ranked.Reason)
	}
}

func TestStrategyRankPlansUsesSuccessfulPreflightAsNeutralSignal(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	ranked, err := strategy.RankPlans(context.Background(), solver.RankInput{
		LastProbeResult: &solver.ProbeResultSummary{
			ScriptType: pmodel.ScriptTypePreflight,
			Success:    true,
			FinishedAt: time.Now(),
		},
	}, plans)
	if err != nil {
		t.Fatalf("RankPlans() error = %v", err)
	}
	if !slices.Equal(planIDs(ranked.Plans), planIDs(plans)) {
		t.Fatalf("ranked plans = %v, want default order %v", planIDs(ranked.Plans), planIDs(plans))
	}
	if ranked.Reason != "preflight_ok_default" {
		t.Fatalf("Reason = %q, want preflight_ok_default", ranked.Reason)
	}
}

func TestStrategyRankPlansIgnoresCrossSessionRemoteEvidence(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	ranked, err := strategy.RankPlans(context.Background(), solver.RankInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		RemoteObservations: []solver.Observation{
			observationWithScope(planIDDirectPrefer, "candidate_failed", "", "session/node-x/node-y", "node-a"),
			observationWithScope(planIDRelayOnly, "candidate_succeeded", "relay", "session/node-x/node-y", "node-a"),
		},
	}, plans)
	if err != nil {
		t.Fatalf("RankPlans() error = %v", err)
	}
	if !slices.Equal(planIDs(ranked.Plans), planIDs(plans)) {
		t.Fatalf("ranked plans = %v, want default order %v", planIDs(ranked.Plans), planIDs(plans))
	}
	if ranked.Reason != "no_relevant_history" {
		t.Fatalf("Reason = %q, want no_relevant_history", ranked.Reason)
	}
}

func TestStrategyRankPlansCanUseUnscopedRemoteEvidenceAsWeakHint(t *testing.T) {
	strategy := New(Config{})
	plans := defaultPlans()

	ranked, err := strategy.RankPlans(context.Background(), solver.RankInput{
		LocalNodeID:  "node-a",
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
		RemoteObservations: []solver.Observation{
			unscopedObservation(planIDDirectPrefer, "candidate_failed", ""),
			unscopedObservation(planIDRelayOnly, "candidate_succeeded", "relay"),
		},
	}, plans)
	if err != nil {
		t.Fatalf("RankPlans() error = %v", err)
	}
	if !slices.Equal(planIDs(ranked.Plans), []string{planIDRelayOnly, planIDDirectPrefer}) {
		t.Fatalf("ranked plans = %v, want weak relay hint to rank relay first", planIDs(ranked.Plans))
	}
	if ranked.Reason != "recent_direct_failure_with_relay_success" {
		t.Fatalf("Reason = %q, want recent_direct_failure_with_relay_success", ranked.Reason)
	}
}

func defaultPlans() []solver.Plan {
	return []solver.Plan{
		{ID: "legacyice/direct_prefer", Strategy: StrategyName},
		{ID: "legacyice/relay_only", Strategy: StrategyName},
	}
}

func observationForRanking(planID, event, connectionType, peerID string) solver.Observation {
	return observationWithScope(planID, event, connectionType, "session/node-a/node-b", peerID)
}

func observationWithScope(planID, event, connectionType, sessionID, peerID string) solver.Observation {
	return solver.Observation{
		Strategy:       StrategyName,
		PlanID:         planID,
		Event:          event,
		ConnectionType: connectionType,
		Details: map[string]string{
			"session_id": sessionID,
			"peer_id":    peerID,
		},
	}
}

func unscopedObservation(planID, event, connectionType string) solver.Observation {
	return solver.Observation{
		Strategy:       StrategyName,
		PlanID:         planID,
		Event:          event,
		ConnectionType: connectionType,
	}
}

func planIDs(plans []solver.Plan) []string {
	ids := make([]string, 0, len(plans))
	for _, plan := range plans {
		ids = append(ids, plan.ID)
	}
	return ids
}
