package legacyice

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"winkyou/pkg/solver"
)

const StrategyName = "legacy_ice_udp"

type Strategy struct {
	cfg Config

	mu     sync.Mutex
	input  solver.SolveInput
	closed bool
}

func New(cfg Config) *Strategy {
	return &Strategy{cfg: cfg.withDefaults()}
}

func (s *Strategy) Name() string {
	return StrategyName
}

func (s *Strategy) Plan(ctx context.Context, in solver.SolveInput) ([]solver.Plan, error) {
	_ = ctx
	s.mu.Lock()
	s.input = in
	s.mu.Unlock()

	plans := s.basePlans()
	evidence := summarizeSolveEvidence(in)
	if !s.cfg.RelayDisabled && evidence.strongRelayEvidence() {
		plans = pruneDirectPreferPlan(plans)
		if len(plans) == 0 {
			return nil, fmt.Errorf("legacyice: no plans available after relay evidence pruning")
		}
	}

	return annotatePlanEvidence(plans, evidence.hint()), nil
}

func (s *Strategy) basePlans() []solver.Plan {
	plans := []solver.Plan{
		{
			ID:       planIDDirectPrefer,
			Strategy: s.Name(),
			Metadata: map[string]string{
				"transport":   "ice_udp",
				"mode":        string(modeDirectPrefer),
				"description": "Prefer direct connection, allow relay fallback",
			},
		},
	}
	plans = append(plans, s.publicDirectPlans()...)
	if !s.cfg.RelayDisabled || s.cfg.ForceRelay {
		plans = append(plans, solver.Plan{
			ID:       planIDRelayOnly,
			Strategy: s.Name(),
			Metadata: map[string]string{
				"transport":   "ice_udp",
				"mode":        string(modeRelayOnly),
				"description": "Force relay-only connection",
			},
		})
	}
	return plans
}

func (s *Strategy) publicDirectPlans() []solver.Plan {
	groups, unspecific, split := splitPublicEndpointHintsByLocalBase(s.cfg.PublicEndpointHints)
	if !split {
		return []solver.Plan{newPublicDirectPlan(s.Name(), planIDPublicDirect, nil, "Try public direct candidates only")}
	}

	plans := make([]solver.Plan, 0, len(groups)+1)
	for i, group := range groups {
		planID := fmt.Sprintf("%s_hint_%d", planIDPublicDirect, i+1)
		description := fmt.Sprintf("Try public direct endpoint hint group %d", i+1)
		plans = append(plans, newPublicDirectPlan(s.Name(), planID, group.hints, description))
	}
	if len(unspecific) > 0 {
		plans = append(plans, newPublicDirectPlan(s.Name(), planIDPublicDirect, unspecific, "Try public direct candidates without local base"))
	}
	return plans
}

func newPublicDirectPlan(strategyName, planID string, hints []string, description string) solver.Plan {
	metadata := map[string]string{
		"transport":   "ice_udp",
		"mode":        string(modePublicDirect),
		"description": description,
	}
	if len(hints) > 0 {
		metadata[planMetadataPublicEndpointHints] = joinPublicEndpointHintsMetadata(hints)
	}
	return solver.Plan{
		ID:       planID,
		Strategy: strategyName,
		Metadata: metadata,
	}
}

type endpointHintPlanGroup struct {
	hints []string
}

func splitPublicEndpointHintsByLocalBase(values []string) ([]endpointHintPlanGroup, []string, bool) {
	byLocalBase := make(map[string][]string)
	var unspecific []string
	for _, raw := range values {
		value := normalizePublicEndpointHintValue(raw)
		if value == "" {
			continue
		}
		hint, err := parsePublicEndpointHint(value)
		if err != nil {
			return nil, nil, false
		}
		if !hint.local.IsValid() {
			unspecific = append(unspecific, value)
			continue
		}
		localBase := hint.local.String()
		byLocalBase[localBase] = append(byLocalBase[localBase], value)
	}
	if len(byLocalBase) <= 1 {
		return nil, nil, false
	}

	localBases := make([]string, 0, len(byLocalBase))
	for localBase := range byLocalBase {
		localBases = append(localBases, localBase)
	}
	sort.Strings(localBases)

	groups := make([]endpointHintPlanGroup, 0, len(localBases))
	for _, localBase := range localBases {
		hints := append([]string(nil), byLocalBase[localBase]...)
		sort.Strings(hints)
		groups = append(groups, endpointHintPlanGroup{
			hints: hints,
		})
	}
	return groups, unspecific, true
}

func annotatePlanEvidence(plans []solver.Plan, hint string) []solver.Plan {
	out := make([]solver.Plan, 0, len(plans))
	for _, plan := range plans {
		next := plan
		next.Metadata = make(map[string]string, len(plan.Metadata)+1)
		for k, v := range plan.Metadata {
			next.Metadata[k] = v
		}
		next.Metadata["evidence_hint"] = hint
		out = append(out, next)
	}
	return out
}

func pruneDirectPreferPlan(plans []solver.Plan) []solver.Plan {
	out := make([]solver.Plan, 0, len(plans))
	for _, plan := range plans {
		if plan.ID == planIDDirectPrefer {
			continue
		}
		out = append(out, plan)
	}
	return out
}

func (s *Strategy) NewExecutor(plan solver.Plan) (solver.PlanExecutor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("legacyice: strategy closed")
	}
	execCfg, err := executorConfigForPlan(plan, s.cfg)
	if err != nil {
		return nil, err
	}
	return newExecutor(s.cfg, s.input, plan, execCfg), nil
}

func (s *Strategy) Execute(ctx context.Context, sess solver.SessionIO, plan solver.Plan) (solver.Result, error) {
	executor, err := s.NewExecutor(plan)
	if err != nil {
		return solver.Result{}, err
	}
	defer executor.Close()
	return executor.Execute(ctx, sess)
}

func (s *Strategy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
