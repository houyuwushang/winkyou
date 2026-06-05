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
	hasPublicEndpointHints := len(s.cfg.PublicEndpointHints) > 0

	switch {
	case !s.cfg.RelayDisabled && hasDirect && hasRelay && evidence.relayPreferred() && hasPublicEndpointHints:
		return solver.RankedPlans{
			Plans:  reorderPlans(plans, planIDRelayOnly, planIDPublicDirect, planIDDirectPrefer),
			Reason: "recent_relay_success_with_public_endpoint_hints",
		}, nil
	case !s.cfg.RelayDisabled && hasDirect && hasRelay && evidence.relayPreferred():
		return solver.RankedPlans{
			Plans:  reorderPlans(plans, planIDRelayOnly, planIDDirectPrefer, planIDPublicDirect),
			Reason: "recent_direct_failure_with_relay_success",
		}, nil
	case evidence.directSuccessful():
		return solver.RankedPlans{Plans: ordered, Reason: "recent_direct_success"}, nil
	case hasDirect && hasPublicDirectPlan(plans) && hasPublicEndpointHints:
		return solver.RankedPlans{
			Plans:  reorderPlans(plans, planIDPublicDirect, planIDDirectPrefer, planIDRelayOnly),
			Reason: "public_endpoint_hints_first",
		}, nil
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
			if !planMatchesOrderedID(plan.ID, planID) {
				continue
			}
			if _, ok := seen[plan.ID]; ok {
				continue
			}
			ordered = append(ordered, plan)
			seen[plan.ID] = struct{}{}
			found = true
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

func planMatchesOrderedID(planID, orderedID string) bool {
	if orderedID == planIDPublicDirect {
		return isPublicDirectPlanID(planID)
	}
	return planID == orderedID
}

func hasPlan(plans []solver.Plan, planID string) bool {
	for _, plan := range plans {
		if plan.ID == planID {
			return true
		}
	}
	return false
}

func hasPublicDirectPlan(plans []solver.Plan) bool {
	for _, plan := range plans {
		if isPublicDirectPlanID(plan.ID) {
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
