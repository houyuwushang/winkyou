package legacyice

import (
	"context"

	"winkyou/pkg/solver"
)

func (s *Strategy) RefinePlans(ctx context.Context, input solver.SolveInput, plans []solver.Plan) (solver.RefinedPlans, error) {
	_ = ctx

	evidence := summarizeSolveEvidence(input)
	if evidence.strongRelayOnly() {
		refined := make([]solver.Plan, 0, len(plans))
		for _, plan := range plans {
			if plan.ID == planIDDirectPrefer {
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

	return solver.RefinedPlans{
		Plans:  append([]solver.Plan(nil), plans...),
		Reason: "no_refinement",
	}, nil
}
