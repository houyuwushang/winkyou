package legacyice

import (
	"context"

	"winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

func (s *Strategy) RefinePlans(ctx context.Context, input solver.SolveInput, plans []solver.Plan) (solver.RefinedPlans, error) {
	_ = ctx

	// Collect evidence from observations
	observations := make([]solver.Observation, 0, len(input.LocalObservations)+len(input.RemoteObservations))
	for _, obs := range input.LocalObservations {
		if relevantObservationForSession(input, obs) {
			observations = append(observations, obs)
		}
	}
	for _, obs := range input.RemoteObservations {
		if obs.Strategy == "" || obs.Strategy == StrategyName {
			observations = append(observations, obs)
		}
	}

	// Count evidence signals
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

	// Check preflight probe result
	preflightPositive := false
	if input.LastProbeResult != nil && input.LastProbeResult.ScriptType == model.ScriptTypePreflight && input.LastProbeResult.Success {
		preflightPositive = true
	}

	// Strong evidence for relay-only: prune direct_prefer
	if directFailures >= 2 && relaySuccesses > 0 && !preflightPositive && directSuccesses == 0 {
		refined := make([]solver.Plan, 0, len(plans))
		for _, plan := range plans {
			if plan.ID == "legacyice/direct_prefer" {
				continue
			}
			refined = append(refined, plan)
		}
		if len(refined) < len(plans) {
			return solver.RefinedPlans{
				Plans:  refined,
				Reason: "strong_relay_evidence_prune_direct",
			}, nil
		}
	}

	// No refinement needed
	return solver.RefinedPlans{
		Plans:  append([]solver.Plan(nil), plans...),
		Reason: "no_refinement",
	}, nil
}
