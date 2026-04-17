package legacyice

import (
	"context"
	"fmt"
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

	return []solver.Plan{
		{
			ID:       "legacyice/direct_prefer",
			Strategy: s.Name(),
			Metadata: map[string]string{
				"transport":   "ice_udp",
				"mode":        string(modeDirectPrefer),
				"description": "Prefer direct connection, allow relay fallback",
			},
		},
		{
			ID:       "legacyice/relay_only",
			Strategy: s.Name(),
			Metadata: map[string]string{
				"transport":   "ice_udp",
				"mode":        string(modeRelayOnly),
				"description": "Force relay-only connection",
			},
		},
	}, nil
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
