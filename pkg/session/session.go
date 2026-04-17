package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

const defaultCapabilityWaitTimeout = 2 * time.Second

type Session struct {
	cfg Config

	sm        *StateMachine
	io        *solverIO
	runCtx    context.Context
	runCancel context.CancelFunc

	startMu   sync.Mutex
	startCond *sync.Cond
	started   bool
	starting  bool
	closeMu   sync.Mutex
	closed    bool

	metaMu sync.RWMutex
	meta   Snapshot
	seq    uint64

	strategyMu sync.RWMutex
	strategy   solver.Strategy
	pending    []solver.Message
	activePlan string
	executor   solver.PlanExecutor

	capabilityCh chan struct{}

	lastPlan solver.Plan
	lastRes  solver.Result

	obsMu        sync.Mutex
	observations []solver.Observation
	remoteObs    []solver.Observation
}

type solverIO struct {
	cfg     Config
	session *Session
}

type strategyMessageTarget interface {
	HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error
}

func New(cfg Config) (*Session, error) {
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("session: session_id is required")
	}
	if cfg.PeerID == "" {
		return nil, fmt.Errorf("session: peer_id is required")
	}
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("session: resolver is required")
	}
	if cfg.Sender == nil {
		return nil, fmt.Errorf("session: sender is required")
	}

	localCapability := normalizeCapability(cfg.Resolver.LocalCapability())
	if len(localCapability.Strategies) == 0 {
		return nil, fmt.Errorf("session: resolver returned no local strategies")
	}

	s := &Session{
		cfg:          cfg,
		sm:           NewStateMachine(StateNew),
		io:           &solverIO{cfg: cfg},
		capabilityCh: make(chan struct{}, 1),
		meta: Snapshot{
			SessionID:       cfg.SessionID,
			PeerID:          cfg.PeerID,
			State:           StateNew,
			LocalCapability: localCapability,
		},
	}
	s.io.session = s
	return s, nil
}

func (s *Session) ID() string {
	return s.cfg.SessionID
}

func (s *Session) State() State {
	return s.sm.State()
}

func (s *Session) Snapshot() Snapshot {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return Snapshot{
		SessionID:            s.meta.SessionID,
		PeerID:               s.meta.PeerID,
		State:                s.meta.State,
		LocalCapability:      cloneCapability(s.meta.LocalCapability),
		RemoteCapability:     cloneCapability(s.meta.RemoteCapability),
		SelectedStrategy:     s.meta.SelectedStrategy,
		SelectionNegotiated:  s.meta.SelectionNegotiated,
		CapabilityExchangeAt: s.meta.CapabilityExchangeAt,
		LastPathCommit:       clonePathCommit(s.meta.LastPathCommit),
		LastPathCommitAt:     s.meta.LastPathCommitAt,
		LastEnvelopeType:     s.meta.LastEnvelopeType,
		LastEnvelopeAt:       s.meta.LastEnvelopeAt,
	}
}

func (s *Session) Observations() []solver.Observation {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	out := make([]solver.Observation, len(s.observations))
	copy(out, s.observations)
	return out
}

func (s *Session) RemoteObservations() []solver.Observation {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	out := make([]solver.Observation, len(s.remoteObs))
	copy(out, s.remoteObs)
	return out
}

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

func (s *Session) selectAndExecute(ctx context.Context) error {
	strategy, err := s.selectStrategy(ctx)
	if err != nil {
		return err
	}

	s.transition(StatePlanning)
	plans, err := strategy.Plan(ctx, solver.SolveInput{
		SessionID:    s.cfg.SessionID,
		LocalNodeID:  s.cfg.LocalNodeID,
		RemoteNodeID: s.cfg.PeerID,
		Initiator:    s.cfg.Initiator,
	})
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		return fmt.Errorf("session: strategy %s returned no plans", strategy.Name())
	}

	if _, usesExecutors := strategy.(solver.ExecutorFactory); !usesExecutors {
		handler, _ := strategy.(solver.MessageHandler)
		if err := s.flushPendingStrategyMessages(ctx, handler); err != nil {
			return err
		}
	}

	// Execute candidate loop with budget
	budget := solver.DefaultBudget()
	outcomes := s.executeCandidateLoop(strategy, plans, budget)

	// Select best outcome
	best := solver.SelectBestOutcome(outcomes)
	if best == nil {
		// Collect error info from all outcomes
		var lastErr error
		for _, o := range outcomes {
			if o.Err != nil {
				lastErr = o.Err
			}
		}
		if lastErr != nil {
			s.fail(lastErr)
		} else {
			s.fail(fmt.Errorf("session: no successful candidate from %d plans", len(plans)))
		}
		return nil
	}

	// Mark selected
	best.Selected = true
	best.SelectionReason = "highest_score"
	s.lastPlan = best.Plan
	s.lastRes = *best.Result
	s.emitObservation(context.Background(), solver.Observation{
		Strategy:       best.Plan.Strategy,
		PlanID:         best.Plan.ID,
		Event:          "path_selected",
		PathID:         best.Result.Summary.PathID,
		ConnectionType: best.Result.Summary.ConnectionType,
		LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
		RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
		Reason:         best.SelectionReason,
		Details: map[string]string{
			"score": fmt.Sprintf("%d", best.Score),
		},
	})

	// Clean up non-selected transports
	for i := range outcomes {
		if !outcomes[i].Selected && outcomes[i].Result != nil && outcomes[i].Result.Transport != nil {
			_ = outcomes[i].Result.Transport.Close()
		}
	}

	// Bind the winner
	if s.cfg.Binder != nil {
		s.transition(StateBinding)
		if err := s.cfg.Binder.Bind(context.Background(), s.cfg.PeerID, best.Result.Transport); err != nil {
			_ = best.Result.Transport.Close()
			s.fail(err)
			return nil
		}
		s.emitObservation(context.Background(), solver.Observation{
			Strategy:       best.Plan.Strategy,
			PlanID:         best.Plan.ID,
			Event:          "bind_succeeded",
			PathID:         best.Result.Summary.PathID,
			ConnectionType: best.Result.Summary.ConnectionType,
			LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
			RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
			Reason:         s.cfg.PeerID,
		})
	}

	// Send path commit
	if err := s.sendPathCommit(context.Background(), *best.Result); err != nil {
		if s.cfg.Binder != nil {
			_ = s.cfg.Binder.Unbind(context.Background(), s.cfg.PeerID)
		}
		_ = best.Result.Transport.Close()
		s.lastRes.Transport = nil
		s.fail(err)
		return nil
	}
	s.emitObservation(context.Background(), solver.Observation{
		Strategy:       best.Plan.Strategy,
		PlanID:         best.Plan.ID,
		Event:          "path_committed",
		PathID:         best.Result.Summary.PathID,
		ConnectionType: best.Result.Summary.ConnectionType,
		LocalAddr:      addrString(best.Result.Transport.LocalAddr()),
		RemoteAddr:     addrString(best.Result.Summary.RemoteAddr),
	})

	s.transition(StateBound)
	if s.cfg.Hooks.OnBound != nil {
		s.cfg.Hooks.OnBound(*best.Result)
	}
	return nil
}

func (s *Session) executeCandidateLoop(strategy solver.Strategy, plans []solver.Plan, budget solver.ExecutionBudget) []solver.CandidateOutcome {
	outcomes := make([]solver.CandidateOutcome, 0, len(plans))
	budgetStart := time.Now()

	maxCandidates := budget.MaxCandidates
	if maxCandidates <= 0 || maxCandidates > len(plans) {
		maxCandidates = len(plans)
	}

	for i := 0; i < maxCandidates; i++ {
		plan := plans[i]

		// Check time budget
		if budget.TimeBudget > 0 && time.Since(budgetStart) >= budget.TimeBudget {
			break
		}

		s.emitObservation(context.Background(), solver.Observation{
			Strategy:  plan.Strategy,
			PlanID:    plan.ID,
			Event:     "candidate_planned",
			TimeoutMS: durationMS(s.executionTimeout()),
			Details: map[string]string{
				"candidate_index": fmt.Sprintf("%d", i),
				"candidate_total": fmt.Sprintf("%d", maxCandidates),
			},
		})
		outcome := s.executeCandidate(strategy, plan)
		outcomes = append(outcomes, outcome)
	}

	// Score all outcomes
	for i := range outcomes {
		outcomes[i].Score = solver.ScoreOutcome(outcomes[i])
	}

	return outcomes
}

func (s *Session) executeCandidate(strategy solver.Strategy, plan solver.Plan) solver.CandidateOutcome {
	startTime := time.Now()
	initialObsCount := s.localObservationCount()
	outcome := solver.CandidateOutcome{
		Plan:   plan,
		PlanID: plan.ID,
	}

	s.transition(StateExecuting)
	execCtx := s.runContext()
	if execCtx == nil {
		execCtx = context.Background()
	}
	if timeout := s.executionTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(execCtx, timeout)
		defer cancel()
	}

	result, err := s.executePlan(execCtx, strategy, plan)
	outcome.FinishedAt = time.Now()
	outcome.ExecutionDur = time.Since(startTime)
	outcome.ObservationCount = s.localObservationCount() - initialObsCount

	if err != nil {
		outcome.Err = err
		outcome.ErrorClass = classifyError(err)
		return outcome
	}

	outcome.Result = &result
	outcome.PathID = result.Summary.PathID
	return outcome
}

func (s *Session) executePlan(ctx context.Context, strategy solver.Strategy, plan solver.Plan) (solver.Result, error) {
	factory, ok := strategy.(solver.ExecutorFactory)
	if !ok {
		return strategy.Execute(ctx, s.io, plan)
	}

	executor, err := factory.NewExecutor(plan)
	if err != nil {
		return solver.Result{}, err
	}
	s.setActiveExecutor(plan.ID, executor)
	defer func() {
		s.clearActiveExecutor(executor)
		s.discardPendingStrategyMessages()
		_ = executor.Close()
	}()
	if err := s.flushPendingStrategyMessages(ctx, executor); err != nil {
		return solver.Result{}, err
	}
	return executor.Execute(ctx, s.io)
}

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

func (s *Session) localObservationCount() int {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return len(s.observations)
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
		return "timeout"
	case strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no route"):
		return "unreachable"
	case strings.Contains(errStr, "context canceled"):
		return "canceled"
	default:
		return "unknown"
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

func (s *Session) HandleMessage(ctx context.Context, msg solver.Message) error {
	switch msg.Kind {
	case solver.MessageKindEnvelope:
		if msg.Namespace != "" && msg.Namespace != envelopeNamespace {
			return nil
		}
		return s.handleEnvelopeMessage(msg)
	case solver.MessageKindStrategy:
		target, pending := s.strategyHandler()
		if pending || target == nil {
			s.enqueueStrategyMessage(msg)
			return nil
		}
		return target.HandleMessage(ctx, s.io, msg)
	default:
		return nil
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

func (s *Session) sendCapability(ctx context.Context) error {
	envelope, err := s.newEnvelope(rproto.MsgTypeCapability, s.localCapability())
	if err != nil {
		return err
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}
	return s.io.Send(ctx, solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Namespace:  envelopeNamespace,
		Type:       rproto.MsgTypeCapability,
		Payload:    payload,
		ReceivedAt: time.Now(),
	})
}

func (s *Session) sendPathCommit(ctx context.Context, result solver.Result) error {
	envelope, err := s.newEnvelope(rproto.MsgTypePathCommit, rproto.PathCommit{
		Strategy:       s.selectedStrategyName(),
		PathID:         result.Summary.PathID,
		ConnectionType: result.Summary.ConnectionType,
	})
	if err != nil {
		return err
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}
	return s.io.Send(ctx, solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Namespace:  envelopeNamespace,
		Type:       rproto.MsgTypePathCommit,
		Payload:    payload,
		ReceivedAt: time.Now(),
	})
}

func (s *Session) handleEnvelopeMessage(msg solver.Message) error {
	envelope, err := rproto.UnmarshalEnvelope(msg.Payload)
	if err != nil {
		return err
	}
	if envelope.SessionID != s.cfg.SessionID {
		return nil
	}

	receivedAt := msg.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}

	s.metaMu.Lock()
	s.meta.LastEnvelopeType = envelope.MsgType
	s.meta.LastEnvelopeAt = receivedAt
	s.metaMu.Unlock()

	switch envelope.MsgType {
	case rproto.MsgTypeCapability:
		var capability rproto.Capability
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &capability); err != nil {
				return fmt.Errorf("session: decode capability: %w", err)
			}
		}
		s.setRemoteCapability(capability, receivedAt)
	case rproto.MsgTypePathCommit:
		var pathCommit rproto.PathCommit
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &pathCommit); err != nil {
				return fmt.Errorf("session: decode path commit: %w", err)
			}
		}
		s.setRemotePathCommit(pathCommit, receivedAt)
	case rproto.MsgTypeObservation:
		var obs rproto.Observation
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &obs); err != nil {
				return fmt.Errorf("session: decode observation: %w", err)
			}
		}
		s.recordRemoteObservation(obs, receivedAt)
	}
	return nil
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

func (s *Session) localCapability() rproto.Capability {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return cloneCapability(s.meta.LocalCapability)
}

func (s *Session) remoteCapability() rproto.Capability {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return cloneCapability(s.meta.RemoteCapability)
}

func (s *Session) waitForRemoteCapability(ctx context.Context) (rproto.Capability, error) {
	if capability := s.remoteCapability(); len(capability.Strategies) > 0 {
		return capability, nil
	}

	timeout := s.capabilityWaitTimeout()
	if timeout <= 0 {
		return rproto.Capability{}, nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return rproto.Capability{}, ctx.Err()
		case <-timer.C:
			return s.remoteCapability(), nil
		case <-s.capabilityCh:
			if capability := s.remoteCapability(); len(capability.Strategies) > 0 {
				return capability, nil
			}
		}
	}
}

func (s *Session) setRemoteCapability(capability rproto.Capability, receivedAt time.Time) {
	normalized := normalizeCapability(capability)

	s.metaMu.Lock()
	s.meta.RemoteCapability = normalized
	if !receivedAt.IsZero() {
		s.meta.CapabilityExchangeAt = receivedAt
	}
	s.metaMu.Unlock()

	if len(normalized.Strategies) > 0 {
		select {
		case s.capabilityCh <- struct{}{}:
		default:
		}
	}
}

func (s *Session) setRemotePathCommit(pathCommit rproto.PathCommit, receivedAt time.Time) {
	snapshot := PathCommitSnapshot{
		Strategy:       pathCommit.Strategy,
		PathID:         pathCommit.PathID,
		ConnectionType: pathCommit.ConnectionType,
	}
	s.metaMu.Lock()
	s.meta.LastPathCommit = snapshot
	if !receivedAt.IsZero() {
		s.meta.LastPathCommitAt = receivedAt
	}
	s.metaMu.Unlock()
}

func (s *Session) recordRemoteObservation(obs rproto.Observation, receivedAt time.Time) {
	solverObs := solver.Observation{
		Strategy:       obs.Strategy,
		PlanID:         obs.PlanID,
		Event:          obs.Event,
		PathID:         obs.PathID,
		ConnectionType: obs.ConnectionType,
		LocalAddr:      obs.LocalAddr,
		RemoteAddr:     obs.RemoteAddr,
		LocalKind:      obs.LocalKind,
		RemoteKind:     obs.RemoteKind,
		ErrorClass:     obs.ErrorClass,
		Reason:         obs.Reason,
		TimeoutMS:      obs.TimeoutMS,
		Details:        obs.Details,
		Timestamp:      obs.Timestamp,
	}
	if solverObs.Timestamp.IsZero() {
		solverObs.Timestamp = receivedAt
	}

	s.obsMu.Lock()
	s.remoteObs = appendObservation(s.remoteObs, solverObs, 100)
	s.obsMu.Unlock()
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

func (s *Session) newEnvelope(msgType string, payload any) (rproto.SessionEnvelope, error) {
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	s.seq++
	return rproto.SessionEnvelope{
		SessionID: s.cfg.SessionID,
		FromNode:  s.cfg.LocalNodeID,
		ToNode:    s.cfg.PeerID,
		MsgType:   msgType,
		Seq:       s.seq,
		Payload:   rproto.MustPayload(payload),
	}, nil
}

func (io *solverIO) Send(ctx context.Context, msg solver.Message) error {
	return io.cfg.Sender.Send(ctx, io.cfg.PeerID, msg)
}

func (io *solverIO) ReportObservation(ctx context.Context, obs solver.Observation) error {
	if io.session == nil {
		return nil
	}
	return io.session.reportObservation(ctx, obs)
}

func (s *Session) reportObservation(ctx context.Context, obs solver.Observation) error {
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}

	s.obsMu.Lock()
	s.observations = appendObservation(s.observations, obs, 100)
	s.obsMu.Unlock()
	if s.cfg.ObservationSink != nil {
		if err := s.cfg.ObservationSink.Record(obs); err != nil {
			return err
		}
	}

	envelope, err := s.newEnvelope(rproto.MsgTypeObservation, rproto.Observation{
		Strategy:       obs.Strategy,
		PlanID:         obs.PlanID,
		Event:          obs.Event,
		PathID:         obs.PathID,
		ConnectionType: obs.ConnectionType,
		LocalAddr:      obs.LocalAddr,
		RemoteAddr:     obs.RemoteAddr,
		LocalKind:      obs.LocalKind,
		RemoteKind:     obs.RemoteKind,
		ErrorClass:     obs.ErrorClass,
		Reason:         obs.Reason,
		TimeoutMS:      obs.TimeoutMS,
		Details:        obs.Details,
		Timestamp:      obs.Timestamp,
	})
	if err != nil {
		return err
	}

	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}

	return s.io.Send(ctx, solver.Message{
		Kind:      solver.MessageKindEnvelope,
		Namespace: envelopeNamespace,
		Type:      rproto.MsgTypeObservation,
		Payload:   payload,
	})
}

func (s *Session) emitObservation(ctx context.Context, obs solver.Observation) {
	if ctx == nil {
		ctx = context.Background()
	}
	_ = s.reportObservation(ctx, obs)
}

func appendObservation(list []solver.Observation, obs solver.Observation, limit int) []solver.Observation {
	list = append(list, obs)
	if limit > 0 && len(list) > limit {
		list = list[len(list)-limit:]
	}
	return list
}

func durationMS(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return d.Milliseconds()
}

func addrString(addr any) string {
	switch v := addr.(type) {
	case nil:
		return ""
	case string:
		return v
	case interface{ String() string }:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func cloneCapability(capability rproto.Capability) rproto.Capability {
	return rproto.Capability{Strategies: append([]string(nil), capability.Strategies...)}
}

func normalizeCapability(capability rproto.Capability) rproto.Capability {
	if len(capability.Strategies) == 0 {
		return rproto.Capability{}
	}
	seen := make(map[string]struct{}, len(capability.Strategies))
	strategies := make([]string, 0, len(capability.Strategies))
	for _, strategy := range capability.Strategies {
		if strategy == "" {
			continue
		}
		if _, ok := seen[strategy]; ok {
			continue
		}
		seen[strategy] = struct{}{}
		strategies = append(strategies, strategy)
	}
	slices.Sort(strategies)
	return rproto.Capability{Strategies: strategies}
}

func clonePathCommit(pathCommit PathCommitSnapshot) PathCommitSnapshot {
	return PathCommitSnapshot{
		Strategy:       pathCommit.Strategy,
		PathID:         pathCommit.PathID,
		ConnectionType: pathCommit.ConnectionType,
	}
}

func cloneMessage(msg solver.Message) solver.Message {
	return solver.Message{
		Kind:       msg.Kind,
		Namespace:  msg.Namespace,
		Type:       msg.Type,
		Payload:    append([]byte(nil), msg.Payload...),
		ReceivedAt: msg.ReceivedAt,
	}
}
