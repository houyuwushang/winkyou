package tcpframed

import (
	"context"
	"fmt"
	"sync"

	"winkyou/pkg/solver"
)

const (
	StrategyName = "tcp_framed"
	PlanID       = "tcpframed/direct"
)

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

	return []solver.Plan{{
		ID:       PlanID,
		Strategy: StrategyName,
		Metadata: map[string]string{
			"transport":   StrategyName,
			"mode":        "direct_explicit",
			"description": "Use an explicitly reachable TCP framed stream",
		},
	}}, nil
}

func (s *Strategy) NewExecutor(plan solver.Plan) (solver.PlanExecutor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("tcpframed: strategy closed")
	}
	if plan.ID != PlanID {
		return nil, fmt.Errorf("tcpframed: unsupported plan %q", plan.ID)
	}
	input := s.input
	return newExecutor(s.cfg, input, plan), nil
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
