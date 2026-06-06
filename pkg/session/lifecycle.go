package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

func (s *Session) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("session: nil context")
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
	s.executeMu.Lock()
	defer s.executeMu.Unlock()
	if err := s.selectAndExecute(ctx); err != nil {
		if errors.Is(err, context.Canceled) && s.State() == StateClosed {
			return
		}
		s.fail(err)
	}
}

func (s *Session) ImproveProtectedDirect(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("session: nil context")
	}
	if !s.shouldProtectDirectStandby() {
		return false, nil
	}

	s.startMu.Lock()
	started := s.started
	runCtx := s.runCtx
	s.startMu.Unlock()
	if !started {
		return false, fmt.Errorf("session: not started")
	}
	if runCtx != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-runCtx.Done():
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	s.executeMu.Lock()
	defer s.executeMu.Unlock()
	if s.State() != StateBound {
		return false, nil
	}

	if err := s.sendCapability(ctx); err != nil {
		return false, err
	}
	found, err := s.selectAndBindProtectedDirect(ctx)
	if !found && s.State() != StateBound && s.State() != StateClosed {
		s.transition(StateBound)
	}
	return found, err
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
		s.ignoreCleanupError(s.runCleanup(executor.Close))
	}
	if s.cfg.Binder != nil {
		s.ignoreCleanupError(s.runCleanupWithContext(func(ctx context.Context) error {
			return s.cfg.Binder.Unbind(ctx, s.cfg.PeerID)
		}))
	}
	if s.lastRes.Transport != nil {
		transport := s.lastRes.Transport
		s.lastRes.Transport = nil
		s.clearBoundTransportMessageTarget()
		s.ignoreCleanupError(s.runCleanup(transport.Close))
	}
	s.closeRetainedOutcomes()
	if strategy := s.currentStrategy(); strategy != nil {
		return s.runCleanup(strategy.Close)
	}
	return nil
}

func (s *Session) transition(next State) {
	if err := s.sm.Transition(next); err != nil {
		s.notifyError(err)
		return
	}
	s.metaMu.Lock()
	s.meta.State = next
	s.metaMu.Unlock()
	if s.cfg.Hooks.OnStateChange != nil {
		s.cfg.Hooks.OnStateChange(next)
	}
}

func (s *Session) fail(err error) {
	s.transition(StateFailed)
	s.notifyError(err)
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

func (s *Session) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = s.runContext()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, defaultOperationTimeout)
}

func (s *Session) cleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCleanupTimeout)
}

func (s *Session) runCleanup(fn func() error) error {
	ctx, cancel := s.cleanupContext()
	defer cancel()

	return runWithContext(ctx, fn)
}

func (s *Session) runCleanupWithContext(fn func(context.Context) error) error {
	ctx, cancel := s.cleanupContext()
	defer cancel()

	return runWithContext(ctx, func() error {
		return fn(ctx)
	})
}

func runWithContext(ctx context.Context, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) ignoreCleanupError(err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		s.notifyError(err)
	}
}

func (s *Session) notifyError(err error) {
	if s.cfg.Hooks.OnError != nil && err != nil {
		s.cfg.Hooks.OnError(err)
	}
}
