package legacyice

import (
	"context"

	"winkyou/pkg/solver"
)

func (s *Strategy) RankPlans(_ context.Context, input solver.RankInput, plans []solver.Plan) (solver.RankedPlans, error) {
	ordered := append([]solver.Plan(nil), plans...)
	evidence := summarizeRankEvidence(input)
	hasDirect := hasPlan(plans, planIDDirectPrefer)
	hasRelay := hasPlan(plans, planIDRelayOnly)

	switch {
	case hasDirect && hasRelay && evidence.relayPreferred():
		return solver.RankedPlans{
			Plans:  reorderPlans(plans, planIDRelayOnly, planIDDirectPrefer),
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
	if obs.Event == "candidate_succeeded" {
		return true
	}
	return obs.Event == "path_selected" && obs.ConnectionType == "direct"
}

func isRelaySuccess(obs solver.Observation) bool {
	if obs.Event == "candidate_succeeded" {
		return true
	}
	return obs.Event == "path_selected" && obs.ConnectionType == "relay"
}

func reorderPlans(plans []solver.Plan, firstID, secondID string) []solver.Plan {
	var (
		first       solver.Plan
		second      solver.Plan
		foundFirst  bool
		foundSecond bool
	)
	for _, plan := range plans {
		switch plan.ID {
		case firstID:
			first = plan
			foundFirst = true
		case secondID:
			second = plan
			foundSecond = true
		}
	}
	if !foundFirst || !foundSecond {
		return append([]solver.Plan(nil), plans...)
	}
	ordered := make([]solver.Plan, 0, len(plans))
	ordered = append(ordered, first, second)
	for _, plan := range plans {
		if plan.ID == firstID || plan.ID == secondID {
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
