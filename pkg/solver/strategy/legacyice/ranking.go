package legacyice

import (
	"context"

	"winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

func (s *Strategy) RankPlans(_ context.Context, input solver.RankInput, plans []solver.Plan) (solver.RankedPlans, error) {
	ordered := append([]solver.Plan(nil), plans...)
	observations := make([]solver.Observation, 0, len(input.LocalObservations)+len(input.RemoteObservations))

	solveInput := solver.SolveInput{
		SessionID:    input.SessionID,
		RemoteNodeID: input.RemoteNodeID,
	}

	for _, obs := range input.LocalObservations {
		if relevantObservationForSession(solveInput, obs) {
			observations = append(observations, obs)
		}
	}
	for _, obs := range input.RemoteObservations {
		if obs.Strategy == "" || obs.Strategy == StrategyName {
			observations = append(observations, obs)
		}
	}

	var directFailures, directSuccesses, relaySuccesses int
	for _, obs := range observations {
		switch {
		case obs.PlanID == "legacyice/direct_prefer" && obs.Event == "candidate_failed":
			directFailures++
		case obs.PlanID == "legacyice/direct_prefer" && isDirectSuccess(obs):
			directSuccesses++
		case obs.PlanID == "legacyice/relay_only" && isRelaySuccess(obs):
			relaySuccesses++
		}
	}

	hasDirect := hasPlan(plans, "legacyice/direct_prefer")
	hasRelay := hasPlan(plans, "legacyice/relay_only")

	switch {
	case hasDirect && hasRelay && directFailures > 0 && relaySuccesses > 0:
		return solver.RankedPlans{
			Plans:  reorderPlans(plans, "legacyice/relay_only", "legacyice/direct_prefer"),
			Reason: "recent_direct_failure_with_relay_success",
		}, nil
	case directSuccesses > 0:
		return solver.RankedPlans{Plans: ordered, Reason: "recent_direct_success"}, nil
	case input.LastProbeResult != nil && input.LastProbeResult.ScriptType == model.ScriptTypePreflight && input.LastProbeResult.Success:
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
