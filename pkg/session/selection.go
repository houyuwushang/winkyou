package session

import (
	"context"
	"fmt"

	"winkyou/pkg/solver"
)

func (s *Session) setActiveExecutor(planID string, executor solver.PlanExecutor) {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	s.activePlan = planID
	s.executor = executor
}

func (s *Session) clearActiveExecutor(executor solver.PlanExecutor) {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	if s.executor == executor {
		s.executor = nil
		s.activePlan = ""
	}
}

func (s *Session) selectStrategy(ctx context.Context) (solver.Strategy, error) {
	s.transition(StateCapabilityExchange)
	remoteCapability, err := s.waitForRemoteCapability(ctx)
	if err != nil {
		return nil, err
	}

	s.transition(StateSelecting)
	strategy, selection, err := s.cfg.Resolver.Resolve(remoteCapability, s.cfg.Initiator)
	if err != nil {
		return nil, err
	}
	if strategy == nil {
		return nil, fmt.Errorf("session: resolver returned nil strategy")
	}
	s.setSelectedStrategy(strategy, selection)
	return strategy, nil
}

func (s *Session) setSelectedStrategy(strategy solver.Strategy, selection Selection) {
	s.strategyMu.Lock()
	s.strategy = strategy
	s.strategyMu.Unlock()

	s.metaMu.Lock()
	s.meta.SelectedStrategy = selection.StrategyName
	s.meta.SelectionNegotiated = selection.Negotiated
	s.metaMu.Unlock()
}

func (s *Session) selectedStrategyName() string {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return s.meta.SelectedStrategy
}

func (s *Session) currentStrategy() solver.Strategy {
	s.strategyMu.RLock()
	defer s.strategyMu.RUnlock()
	return s.strategy
}

func (s *Session) currentExecutor() solver.PlanExecutor {
	s.strategyMu.RLock()
	defer s.strategyMu.RUnlock()
	return s.executor
}

func (s *Session) strategyHandler() (strategyMessageTarget, bool) {
	s.strategyMu.RLock()
	defer s.strategyMu.RUnlock()
	if s.executor != nil {
		return s.executor, false
	}
	if s.strategy == nil {
		return nil, true
	}
	if _, ok := s.strategy.(solver.ExecutorFactory); ok {
		return nil, true
	}
	handler, ok := s.strategy.(solver.MessageHandler)
	if !ok {
		return nil, false
	}
	return handler, false
}

func (s *Session) enqueueStrategyMessage(msg solver.Message) {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	s.pending = append(s.pending, cloneMessage(msg))
}

func (s *Session) flushPendingStrategyMessages(ctx context.Context, handler strategyMessageTarget) error {
	if handler == nil {
		return nil
	}
	for {
		s.strategyMu.Lock()
		pending := append([]solver.Message(nil), s.pending...)
		s.pending = nil
		s.strategyMu.Unlock()

		if len(pending) == 0 {
			return nil
		}
		for _, msg := range pending {
			if err := handler.HandleMessage(ctx, s.io, msg); err != nil {
				return err
			}
		}
	}
}

func (s *Session) discardPendingStrategyMessages() {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	s.pending = nil
}
