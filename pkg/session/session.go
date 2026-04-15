package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type Session struct {
	cfg Config

	sm       *StateMachine
	io       *solverIO
	runCtx   context.Context
	startMu  sync.Mutex
	started  bool
	closeMu  sync.Mutex
	closed   bool
	lastPlan solver.Plan
	lastRes  solver.Result
}

type solverIO struct {
	cfg Config
}

func New(cfg Config) (*Session, error) {
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("session: session_id is required")
	}
	if cfg.PeerID == "" {
		return nil, fmt.Errorf("session: peer_id is required")
	}
	if cfg.Strategy == nil {
		return nil, fmt.Errorf("session: strategy is required")
	}
	if cfg.Sender == nil {
		return nil, fmt.Errorf("session: sender is required")
	}
	return &Session{
		cfg: cfg,
		sm:  NewStateMachine(StateNew),
		io:  &solverIO{cfg: cfg},
	}, nil
}

func (s *Session) ID() string {
	return s.cfg.SessionID
}

func (s *Session) State() State {
	return s.sm.State()
}

func (s *Session) Start(ctx context.Context) error {
	s.startMu.Lock()
	if s.started {
		s.startMu.Unlock()
		return nil
	}
	s.started = true
	s.startMu.Unlock()

	s.transition(StatePlanning)
	plans, err := s.cfg.Strategy.Plan(ctx, solver.SolveInput{
		SessionID:    s.cfg.SessionID,
		LocalNodeID:  s.cfg.LocalNodeID,
		RemoteNodeID: s.cfg.PeerID,
		Initiator:    s.cfg.Initiator,
	})
	if err != nil {
		s.fail(err)
		return err
	}
	if len(plans) == 0 {
		err = fmt.Errorf("session: strategy %s returned no plans", s.cfg.Strategy.Name())
		s.fail(err)
		return err
	}
	s.lastPlan = plans[0]
	s.runCtx = ctx

	go s.execute(plans[0])
	return nil
}

func (s *Session) execute(plan solver.Plan) {
	s.transition(StateExecuting)
	execCtx := s.runCtx
	if execCtx == nil {
		execCtx = context.Background()
	}
	if timeout := s.executionTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(execCtx, timeout)
		defer cancel()
	}

	result, err := s.cfg.Strategy.Execute(execCtx, s.io, plan)
	if err != nil {
		s.fail(err)
		return
	}
	s.lastRes = result

	if s.cfg.Binder != nil {
		s.transition(StateBinding)
		if err := s.cfg.Binder.Bind(context.Background(), s.cfg.PeerID, result.Transport); err != nil {
			if result.Transport != nil {
				_ = result.Transport.Close()
			}
			s.fail(err)
			return
		}
	}

	s.transition(StateBound)
	if s.cfg.Hooks.OnBound != nil {
		s.cfg.Hooks.OnBound(result)
	}
}

func (s *Session) HandleMessage(ctx context.Context, msg solver.Message) error {
	handler, ok := s.cfg.Strategy.(solver.MessageHandler)
	if !ok {
		return nil
	}
	return handler.HandleMessage(ctx, s.io, msg)
}

func (s *Session) Close() error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	s.closeMu.Unlock()

	s.transition(StateClosed)
	if s.cfg.Binder != nil {
		_ = s.cfg.Binder.Unbind(context.Background(), s.cfg.PeerID)
	}
	if s.lastRes.Transport != nil {
		_ = s.lastRes.Transport.Close()
		s.lastRes.Transport = nil
	}
	if s.cfg.Strategy != nil {
		return s.cfg.Strategy.Close()
	}
	return nil
}

func (s *Session) transition(next State) {
	s.sm.Transition(next)
	if s.cfg.Hooks.OnStateChange != nil {
		s.cfg.Hooks.OnStateChange(next)
	}
}

func (s *Session) fail(err error) {
	s.transition(StateFailed)
	if s.cfg.Hooks.OnError != nil && err != nil {
		s.cfg.Hooks.OnError(err)
	}
}

func (io *solverIO) Send(ctx context.Context, msg solver.Message) error {
	return io.cfg.Sender.Send(ctx, io.cfg.PeerID, msg)
}

func (io *solverIO) NewLegacyICEAgent(ctx context.Context, controlling bool) (nat.ICEAgent, error) {
	if io.cfg.NewLegacyICEAgent == nil {
		return nil, fmt.Errorf("session: legacy ICE agent factory is nil")
	}
	return io.cfg.NewLegacyICEAgent(ctx, controlling)
}

func (io *solverIO) GatherTimeout() time.Duration {
	return io.cfg.GatherTimeout
}

func (io *solverIO) ConnectTimeout() time.Duration {
	return io.cfg.ConnectTimeout
}

func (io *solverIO) CheckTimeout() time.Duration {
	return io.cfg.CheckTimeout
}

func (s *Session) executionTimeout() time.Duration {
	total := s.cfg.GatherTimeout + s.cfg.ConnectTimeout + s.cfg.CheckTimeout
	if total <= 0 {
		return 0
	}
	return total
}
