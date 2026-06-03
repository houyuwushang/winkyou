package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

func (s *Session) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	s.startMu.Lock()
	if s.startCond == nil {
		s.startCond = sync.NewCond(&s.startMu)
	}
	for s.starting {
		s.startCond.Wait()
	}
	if s.started {
		s.startMu.Unlock()
		return nil
	}

	runCtx, runCancel := context.WithCancel(ctx)
	s.starting = true
	s.runCtx = runCtx
	s.runCancel = runCancel
	s.startMu.Unlock()

	startSucceeded := false
	defer func() {
		s.startMu.Lock()
		if startSucceeded {
			s.started = true
		} else {
			if s.runCancel != nil {
				s.runCancel()
				s.runCancel = nil
			}
			s.runCtx = nil
		}
		s.starting = false
		s.startCond.Broadcast()
		s.startMu.Unlock()
	}()

	if err := s.sendCapability(ctx); err != nil {
		s.fail(err)
		return err
	}

	startSucceeded = true
	go s.run(runCtx)
	return nil
}

func (s *Session) run(ctx context.Context) {
	if err := s.selectAndExecute(ctx); err != nil {
		if errors.Is(err, context.Canceled) && s.State() == StateClosed {
			return
		}
		s.fail(err)
	}
}

func (s *Session) Close() error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	s.closeMu.Unlock()

	s.startMu.Lock()
	runCancel := s.runCancel
	s.runCancel = nil
	s.runCtx = nil
	s.startMu.Unlock()
	if runCancel != nil {
		runCancel()
	}

	s.transition(StateClosed)
	if executor := s.currentExecutor(); executor != nil {
		_ = executor.Close()
	}
	if s.cfg.Binder != nil {
		_ = s.cfg.Binder.Unbind(context.Background(), s.cfg.PeerID)
	}
	if s.lastRes.Transport != nil {
		_ = s.lastRes.Transport.Close()
		s.lastRes.Transport = nil
	}
	if strategy := s.currentStrategy(); strategy != nil {
		return strategy.Close()
	}
	return nil
}

func (s *Session) transition(next State) {
	s.sm.Transition(next)
	s.metaMu.Lock()
	s.meta.State = next
	s.metaMu.Unlock()
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

func (s *Session) executionTimeout() time.Duration {
	return s.cfg.RunTimeout
}

func (s *Session) capabilityWaitTimeout() time.Duration {
	if s.cfg.CapabilityWaitTimeout > 0 {
		return s.cfg.CapabilityWaitTimeout
	}
	return defaultCapabilityWaitTimeout
}

func (s *Session) runContext() context.Context {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	return s.runCtx
}
