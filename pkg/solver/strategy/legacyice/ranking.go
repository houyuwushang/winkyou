package legacyice

import (
	"context"
	"strings"

	"winkyou/pkg/solver"
)

func (s *Strategy) RankPlans(_ context.Context, input solver.RankInput, plans []solver.Plan) (solver.RankedPlans, error) {
	ordered := append([]solver.Plan(nil), plans...)
	evidence := summarizeRankEvidence(input)
	hasDirect := hasDirectPlan(plans)
	hasRelay := hasPlan(plans, planIDRelayOnly)

	switch {
	case hasDirect && hasRelay && evidence.relayPreferred():
		return solver.RankedPlans{
			Plans:  reorderPlans(plans, planIDRelayOnly, planIDDirectPrefer, planIDPublicDirect),
			Reason: "recent_direct_failure_with_relay_success",
		}, nil
	case evidence.directSuccessful():
		return solver.RankedPlans{Plans: ordered, Reason: "recent_direct_success"}, nil
	case evidence.PreflightSuccess:
		return solver.RankedPlans{Plans: ordered, Reason: "preflight_ok_default"}, nil
	default:
		return solver.RankedPlans{Plans: ordered, Reason: "no_relevant_history"}, nil
	}
}

func isDirectSuccess(obs solver.Observation) bool {
	switch obs.Event {
	case "candidate_succeeded", "path_selected", "path_committed":
		return strings.EqualFold(obs.ConnectionType, "direct")
	default:
		return false
	}
}

func isRelaySuccess(obs solver.Observation) bool {
	switch obs.Event {
	case "candidate_succeeded", "path_selected", "path_committed":
		return strings.EqualFold(obs.ConnectionType, "relay")
	default:
		return false
	}
}

func reorderPlans(plans []solver.Plan, orderedIDs ...string) []solver.Plan {
	seen := make(map[string]struct{}, len(orderedIDs))
	ordered := make([]solver.Plan, 0, len(plans))
	found := false
	for _, planID := range orderedIDs {
		for _, plan := range plans {
			if plan.ID != planID {
				continue
			}
			ordered = append(ordered, plan)
			seen[plan.ID] = struct{}{}
			found = true
			break
		}
	}
	if !found {
		return append([]solver.Plan(nil), plans...)
	}
	for _, plan := range plans {
		if _, ok := seen[plan.ID]; ok {
			continue
		}
		ordered = append(ordered, plan)
	}
	return ordered
}

func hasPlan(plans []solver.Plan, planID string) bool {
	for _, plan := range plans {
		if plan.ID == planID {
			return true
		}
	}
	return false
}

func hasDirectPlan(plans []solver.Plan) bool {
	for _, plan := range plans {
		if isDirectPlanID(plan.ID) {
			return true
		}
	}
	return false
}
