package relayonly

import (
	"context"
	"fmt"

	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
)

const (
	StrategyName = "relay_only"
	PlanID       = "relayonly/turn_relay"
)

type Config = legacyice.Config

type Strategy struct {
	legacy *legacyice.Strategy
}

func New(cfg Config) *Strategy {
	return &Strategy{legacy: legacyice.New(cfg)}
}

func (s *Strategy) Name() string {
	return StrategyName
}

func (s *Strategy) Plan(ctx context.Context, in solver.SolveInput) ([]solver.Plan, error) {
	if s == nil || s.legacy == nil {
		return nil, fmt.Errorf("relayonly: strategy is nil")
	}
	legacyPlans, err := s.legacy.Plan(ctx, in)
	if err != nil {
		return nil, err
	}

	plan := solver.Plan{
		ID:       PlanID,
		Strategy: StrategyName,
		Metadata: map[string]string{
			"transport":   "ice_udp",
			"mode":        "relay_only",
			"description": "Force TURN relay-only connection",
		},
	}
	for _, legacyPlan := range legacyPlans {
		if legacyPlan.Metadata["mode"] != "relay_only" {
			continue
		}
		for key, value := range legacyPlan.Metadata {
			if key == "description" {
				continue
			}
			plan.Metadata[key] = value
		}
		break
	}
	return []solver.Plan{plan}, nil
}

func (s *Strategy) NewExecutor(plan solver.Plan) (solver.PlanExecutor, error) {
	if s == nil || s.legacy == nil {
		return nil, fmt.Errorf("relayonly: strategy is nil")
	}
	if plan.ID != PlanID {
		return nil, fmt.Errorf("relayonly: unsupported plan %q", plan.ID)
	}
	next := plan
	next.Strategy = StrategyName
	next.Metadata = cloneMetadata(plan.Metadata)
	if next.Metadata == nil {
		next.Metadata = map[string]string{}
	}
	next.Metadata["mode"] = "relay_only"
	return s.legacy.NewExecutor(next)
}

func (s *Strategy) Execute(ctx context.Context, sess solver.SessionIO, plan solver.Plan) (solver.Result, error) {
	executor, err := s.NewExecutor(plan)
	if err != nil {
		return solver.Result{}, err
	}
	defer executor.Close()
	return executor.Execute(ctx, sess)
}

func (s *Strategy) BuildPreflightProbe(ctx context.Context, input solver.ProbeInput) (*solver.ProbeScript, solver.ProbePolicy, error) {
	if s == nil || s.legacy == nil {
		return nil, solver.ProbePolicy{}, fmt.Errorf("relayonly: strategy is nil")
	}
	script, policy, err := s.legacy.BuildPreflightProbe(ctx, input)
	if err != nil || script == nil {
		return script, policy, err
	}
	next := *script
	next.Steps = append([]solver.ProbeStep(nil), script.Steps...)
	for i := range next.Steps {
		next.Steps[i].Params = cloneMetadata(next.Steps[i].Params)
		if next.Steps[i].Params["strategy"] == legacyice.StrategyName {
			next.Steps[i].Params["strategy"] = StrategyName
		}
	}
	return &next, policy, nil
}

func (s *Strategy) Close() error {
	if s == nil || s.legacy == nil {
		return nil
	}
	return s.legacy.Close()
}

func cloneMetadata(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
