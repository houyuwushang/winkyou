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

	pmodel "winkyou/pkg/probe/model"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

const defaultCapabilityWaitTimeout = 2 * time.Second
const defaultPreflightProbeTimeout = 500 * time.Millisecond

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

	capabilityCh  chan struct{}
	probeResultCh chan probeResultSignal

	lastPlan solver.Plan
	lastRes  solver.Result

	obsMu        sync.Mutex
	observations []solver.Observation
	remoteObs    []solver.Observation
}

type probeResultSignal struct {
	result pmodel.Result
	at     time.Time
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
		cfg:           cfg,
		sm:            NewStateMachine(StateNew),
		io:            &solverIO{cfg: cfg},
		capabilityCh:  make(chan struct{}, 1),
		probeResultCh: make(chan probeResultSignal, 8),
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
		SessionID:               s.meta.SessionID,
		PeerID:                  s.meta.PeerID,
		State:                   s.meta.State,
		LocalCapability:         cloneCapability(s.meta.LocalCapability),
		RemoteCapability:        cloneCapability(s.meta.RemoteCapability),
		SelectedStrategy:        s.meta.SelectedStrategy,
		SelectionNegotiated:     s.meta.SelectionNegotiated,
		CapabilityExchangeAt:    s.meta.CapabilityExchangeAt,
		LastPathCommit:          clonePathCommit(s.meta.LastPathCommit),
		LastPathCommitAt:        s.meta.LastPathCommitAt,
		LastEnvelopeType:        s.meta.LastEnvelopeType,
		LastEnvelopeAt:          s.meta.LastEnvelopeAt,
		LastProbeScriptType:     s.meta.LastProbeScriptType,
		LastProbeScriptAt:       s.meta.LastProbeScriptAt,
		LastProbeResult:         cloneProbeResult(s.meta.LastProbeResult),
		LastProbeResultAt:       s.meta.LastProbeResultAt,
		LastPlanOrder:           append([]string(nil), s.meta.LastPlanOrder...),
		LastPlanOrderReason:     s.meta.LastPlanOrderReason,
		LastPlanSetBeforeRefine: append([]string(nil), s.meta.LastPlanSetBeforeRefine...),
		LastPlanSetAfterRefine:  append([]string(nil), s.meta.LastPlanSetAfterRefine...),
		LastPlanRefineReason:    s.meta.LastPlanRefineReason,
		PreflightProbeAttempted: s.meta.PreflightProbeAttempted,
		PreflightProbeSucceeded: s.meta.PreflightProbeSucceeded,
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

	if err := s.runStrategyPreflightProbe(ctx, strategy); err != nil {
		s.emitObservation(context.Background(), solver.Observation{
			Strategy:   strategy.Name(),
			Event:      "probe_failed",
			ErrorClass: classifyError(err),
			Reason:     err.Error(),
			Details: map[string]string{
				"script_type": pmodel.ScriptTypePreflight,
				"source":      "preflight_orchestration",
			},
		})
	}

	s.transition(StatePlanning)
	solveInput := s.buildSolveInput()
	plans, err := strategy.Plan(ctx, solveInput)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		return fmt.Errorf("session: strategy %s returned no plans", strategy.Name())
	}

	plansBefore := planIDs(plans)
	plans, refineReason := s.refinePlans(ctx, strategy, solveInput, plans)
	s.recordPlanRefine(plansBefore, planIDs(plans), refineReason)
	if refineReason != "no_refinement" {
		s.emitObservation(context.Background(), solver.Observation{
			Strategy: strategy.Name(),
			Event:    "plans_refined",
			Reason:   refineReason,
			Details: map[string]string{
				"before": strings.Join(plansBefore, ","),
				"after":  strings.Join(planIDs(plans), ","),
			},
		})
	}

	if len(plans) == 0 {
		return fmt.Errorf("session: all plans pruned after refinement")
	}

	plans, orderReason := s.rankPlans(ctx, strategy, plans)
	s.recordPlanOrder(plans, orderReason)
	s.emitObservation(context.Background(), solver.Observation{
		Strategy: strategy.Name(),
		Event:    "plan_ordered",
		Reason:   orderReason,
		Details: map[string]string{
			"order": strings.Join(planIDs(plans), ","),
		},
	})

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
	case rproto.MsgTypeProbeScript:
		var script rproto.ProbeScript
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &script); err != nil {
				return fmt.Errorf("session: decode probe_script: %w", err)
			}
		}
		s.handleProbeScript(receivedAt, script)
	case rproto.MsgTypeProbeResult:
		var result rproto.ProbeResult
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &result); err != nil {
				return fmt.Errorf("session: decode probe_result: %w", err)
			}
		}
		s.handleProbeResult(receivedAt, result)
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

func (s *Session) remoteCapabilitySnapshot() (rproto.Capability, bool) {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return cloneCapability(s.meta.RemoteCapability), !s.meta.CapabilityExchangeAt.IsZero()
}

func (s *Session) waitForRemoteCapability(ctx context.Context) (rproto.Capability, error) {
	if capability, received := s.remoteCapabilitySnapshot(); received {
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
			if capability, received := s.remoteCapabilitySnapshot(); received {
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

	select {
	case s.capabilityCh <- struct{}{}:
	default:
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
	obs.Details = annotateObservationDetails(obs.Details, s.cfg.SessionID, s.cfg.PeerID, s.cfg.Initiator)

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

func (s *Session) preflightProbeTimeout() time.Duration {
	if s.cfg.PreflightProbeTimeout > 0 {
		return s.cfg.PreflightProbeTimeout
	}
	return defaultPreflightProbeTimeout
}

func (s *Session) buildSolveInput() solver.SolveInput {
	return solver.SolveInput{
		SessionID:          s.cfg.SessionID,
		LocalNodeID:        s.cfg.LocalNodeID,
		RemoteNodeID:       s.cfg.PeerID,
		Initiator:          s.cfg.Initiator,
		LocalCapability:    s.localCapability(),
		RemoteCapability:   s.remoteCapability(),
		LocalObservations:  s.localObservationHistory(),
		RemoteObservations: s.RemoteObservations(),
		LastProbeResult:    s.lastProbeResultSummary(),
	}
}

func (s *Session) buildProbeInput() solver.ProbeInput {
	solve := s.buildSolveInput()
	return solver.ProbeInput{
		SessionID:          solve.SessionID,
		LocalNodeID:        solve.LocalNodeID,
		RemoteNodeID:       solve.RemoteNodeID,
		Initiator:          solve.Initiator,
		LocalCapability:    solve.LocalCapability,
		RemoteCapability:   solve.RemoteCapability,
		LocalObservations:  solve.LocalObservations,
		RemoteObservations: solve.RemoteObservations,
		LastProbeResult:    solve.LastProbeResult,
	}
}

func (s *Session) runStrategyPreflightProbe(ctx context.Context, strategy solver.Strategy) error {
	planner, ok := strategy.(solver.ProbePlanner)
	if !ok || !s.cfg.Initiator || !s.probeFeaturesNegotiated() {
		s.setPreflightAttempt(false, false)
		return nil
	}

	script, policy, err := planner.BuildPreflightProbe(ctx, s.buildProbeInput())
	if err != nil {
		s.setPreflightAttempt(true, false)
		return err
	}
	if script == nil {
		s.setPreflightAttempt(false, false)
		return nil
	}

	s.transition(StateProbing)
	s.setPreflightAttempt(true, false)
	localScript := solverProbeScriptToModel(*script)
	sentAt := time.Now()
	if err := s.sendProbeScript(ctx, localScript); err != nil {
		return err
	}

	timeout := policy.Timeout
	if timeout <= 0 {
		timeout = s.preflightProbeTimeout()
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-waitCtx.Done():
			s.setPreflightAttempt(true, false)
			if policy.Optional {
				return waitCtx.Err()
			}
			return waitCtx.Err()
		case signal := <-s.probeResultCh:
			if signal.result.ScriptType != localScript.ScriptType {
				continue
			}
			if signal.at.Before(sentAt) && signal.result.FinishedAt.Before(sentAt) {
				continue
			}
			s.setPreflightAttempt(true, signal.result.Success)
			if !signal.result.Success {
				return fmt.Errorf("session: preflight probe failed: %s", signal.result.ErrorClass)
			}
			return nil
		}
	}
}

func (s *Session) refinePlans(ctx context.Context, strategy solver.Strategy, input solver.SolveInput, plans []solver.Plan) ([]solver.Plan, string) {
	refined := append([]solver.Plan(nil), plans...)
	refiner, ok := strategy.(solver.PlanRefiner)
	if !ok {
		return refined, "no_refinement"
	}
	result, err := refiner.RefinePlans(ctx, input, refined)
	if err != nil {
		return refined, fmt.Sprintf("refiner_error:%s", err.Error())
	}
	if len(result.Plans) == 0 {
		return result.Plans, strings.TrimSpace(result.Reason)
	}
	if !isPlanSubset(plans, result.Plans) {
		return refined, "refiner_invalid_set"
	}
	reason := strings.TrimSpace(result.Reason)
	if reason == "" {
		reason = "strategy_refined"
	}
	return append([]solver.Plan(nil), result.Plans...), reason
}

func (s *Session) setPreflightAttempt(attempted, succeeded bool) {
	s.metaMu.Lock()
	s.meta.PreflightProbeAttempted = attempted
	s.meta.PreflightProbeSucceeded = succeeded
	s.metaMu.Unlock()
}

func (s *Session) probeFeaturesNegotiated() bool {
	local := s.localCapability()
	remote := s.remoteCapability()
	return capabilityHasFeature(local, rproto.FeatureProbeLabV1) &&
		capabilityHasFeature(local, rproto.FeatureProbeScriptV1) &&
		capabilityHasFeature(remote, rproto.FeatureProbeLabV1) &&
		capabilityHasFeature(remote, rproto.FeatureProbeScriptV1)
}

func (s *Session) sendProbeScript(ctx context.Context, script pmodel.Script) error {
	envelope, err := s.newEnvelope(rproto.MsgTypeProbeScript, probeScriptToProto(script))
	if err != nil {
		return err
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil {
		return err
	}
	s.recordProbeScript(script, time.Now())
	s.emitObservation(context.Background(), solver.Observation{
		Strategy: pmodel.StrategyName,
		PlanID:   script.PlanID,
		Event:    "probe_script_sent",
		Reason:   script.ScriptType,
		Details: map[string]string{
			"script_type": script.ScriptType,
			"step_count":  fmt.Sprintf("%d", len(script.Steps)),
		},
	})
	return s.io.Send(ctx, solver.Message{
		Kind:      solver.MessageKindEnvelope,
		Namespace: envelopeNamespace,
		Type:      rproto.MsgTypeProbeScript,
		Payload:   payload,
	})
}

func (s *Session) sendProbeResult(ctx context.Context, result pmodel.Result) error {
	envelope, err := s.newEnvelope(rproto.MsgTypeProbeResult, probeResultToProto(result))
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
		Type:      rproto.MsgTypeProbeResult,
		Payload:   payload,
	})
}

func (s *Session) handleProbeScript(receivedAt time.Time, script rproto.ProbeScript) {
	localScript := probeScriptFromProto(script)
	s.recordProbeScript(localScript, receivedAt)
	s.emitObservation(context.Background(), solver.Observation{
		Strategy: pmodel.StrategyName,
		PlanID:   localScript.PlanID,
		Event:    "probe_script_received",
		Reason:   localScript.ScriptType,
		Details: map[string]string{
			"script_type": localScript.ScriptType,
			"step_count":  fmt.Sprintf("%d", len(localScript.Steps)),
		},
	})

	go s.runProbeScript(localScript)
}

func (s *Session) runProbeScript(script pmodel.Script) {
	s.emitObservation(context.Background(), solver.Observation{
		Strategy: pmodel.StrategyName,
		PlanID:   script.PlanID,
		Event:    "probe_script_started",
		Reason:   script.ScriptType,
		Details: map[string]string{
			"script_type": script.ScriptType,
		},
	})

	if s.cfg.ProbeRunner == nil {
		result := pmodel.Result{
			ScriptType: script.ScriptType,
			PlanID:     script.PlanID,
			Success:    false,
			ErrorClass: "runner_missing",
			FinishedAt: time.Now(),
		}
		s.metaMu.Lock()
		s.meta.LastProbeResult = cloneProbeResult(result)
		s.meta.LastProbeResultAt = result.FinishedAt
		s.metaMu.Unlock()
		s.emitObservation(context.Background(), solver.Observation{
			Strategy:   pmodel.StrategyName,
			PlanID:     script.PlanID,
			Event:      "probe_script_failed",
			ErrorClass: result.ErrorClass,
			Reason:     script.ScriptType,
			Details: map[string]string{
				"script_type": script.ScriptType,
			},
		})
		_ = s.sendProbeResult(context.Background(), result)
		return
	}

	runCtx := s.runContext()
	if runCtx == nil {
		runCtx = context.Background()
	}
	result, err := s.cfg.ProbeRunner.Run(runCtx, script)
	if result.ScriptType == "" {
		result.ScriptType = script.ScriptType
	}
	if result.PlanID == "" {
		result.PlanID = script.PlanID
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now()
	}
	if err != nil && result.ErrorClass == "" {
		result.ErrorClass = classifyError(err)
	}
	s.metaMu.Lock()
	s.meta.LastProbeResult = cloneProbeResult(result)
	s.meta.LastProbeResultAt = result.FinishedAt
	s.metaMu.Unlock()
	for _, obs := range result.Events {
		s.emitObservation(context.Background(), obs)
	}
	if err != nil || !result.Success {
		reason := script.ScriptType
		if err != nil {
			reason = err.Error()
		}
		s.emitObservation(context.Background(), solver.Observation{
			Strategy:   pmodel.StrategyName,
			PlanID:     script.PlanID,
			Event:      "probe_script_failed",
			ErrorClass: result.ErrorClass,
			Reason:     reason,
			Details: map[string]string{
				"script_type": script.ScriptType,
			},
		})
	} else {
		s.emitObservation(context.Background(), solver.Observation{
			Strategy: pmodel.StrategyName,
			PlanID:   script.PlanID,
			Event:    "probe_script_succeeded",
			Reason:   script.ScriptType,
			Details: map[string]string{
				"script_type": script.ScriptType,
			},
		})
	}
	_ = s.sendProbeResult(context.Background(), result)
}

func (s *Session) handleProbeResult(receivedAt time.Time, result rproto.ProbeResult) {
	localResult := probeResultFromProto(result)
	if localResult.FinishedAt.IsZero() {
		localResult.FinishedAt = receivedAt
	}

	s.metaMu.Lock()
	s.meta.LastProbeResult = cloneProbeResult(localResult)
	if !receivedAt.IsZero() {
		s.meta.LastProbeResultAt = receivedAt
	} else {
		s.meta.LastProbeResultAt = localResult.FinishedAt
	}
	s.metaMu.Unlock()

	s.emitObservation(context.Background(), solver.Observation{
		Strategy:       pmodel.StrategyName,
		PlanID:         localResult.PlanID,
		Event:          "probe_result_received",
		PathID:         localResult.SelectedPathID,
		ErrorClass:     localResult.ErrorClass,
		ConnectionType: localResultPathType(localResult),
		Reason:         localResult.ScriptType,
		Details: map[string]string{
			"script_type":      localResult.ScriptType,
			"success":          fmt.Sprintf("%t", localResult.Success),
			"event_count":      fmt.Sprintf("%d", len(localResult.Events)),
			"selected_path_id": localResult.SelectedPathID,
		},
	})

	select {
	case s.probeResultCh <- probeResultSignal{result: localResult, at: receivedAt}:
	default:
	}
}

func (s *Session) recordProbeScript(script pmodel.Script, at time.Time) {
	s.metaMu.Lock()
	s.meta.LastProbeScriptType = script.ScriptType
	if !at.IsZero() {
		s.meta.LastProbeScriptAt = at
	} else {
		s.meta.LastProbeScriptAt = time.Now()
	}
	s.metaMu.Unlock()
}

func (s *Session) rankPlans(ctx context.Context, strategy solver.Strategy, plans []solver.Plan) ([]solver.Plan, string) {
	ordered := append([]solver.Plan(nil), plans...)
	ranker, ok := strategy.(solver.PlanRanker)
	if !ok {
		return ordered, "strategy_default"
	}

	ranked, err := ranker.RankPlans(ctx, solver.RankInput{
		SessionID:          s.cfg.SessionID,
		LocalNodeID:        s.cfg.LocalNodeID,
		RemoteNodeID:       s.cfg.PeerID,
		Initiator:          s.cfg.Initiator,
		RemoteCapability:   s.remoteCapability(),
		LocalObservations:  s.localObservationHistory(),
		RemoteObservations: s.RemoteObservations(),
		LastProbeResult:    s.lastProbeResultSummary(),
	}, ordered)
	if err != nil {
		return ordered, fmt.Sprintf("ranker_error:%s", err.Error())
	}
	if len(ranked.Plans) != len(plans) {
		return ordered, "ranker_invalid_length"
	}
	if !samePlanSet(plans, ranked.Plans) {
		return ordered, "ranker_invalid_set"
	}
	reason := strings.TrimSpace(ranked.Reason)
	if reason == "" {
		reason = "strategy_ranked"
	}
	return append([]solver.Plan(nil), ranked.Plans...), reason
}

func (s *Session) localObservationHistory() []solver.Observation {
	observations := make([]solver.Observation, 0, 128)
	if s.cfg.ObservationHistory != nil {
		observations = append(observations, s.cfg.ObservationHistory.Recent(64)...)
	}
	observations = append(observations, s.Observations()...)
	return observations
}

func (s *Session) lastProbeResultSummary() *solver.ProbeResultSummary {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	if s.meta.LastProbeResultAt.IsZero() && s.meta.LastProbeResult.ScriptType == "" {
		return nil
	}
	summary := solver.ProbeResultSummary{
		ScriptType: s.meta.LastProbeResult.ScriptType,
		Success:    s.meta.LastProbeResult.Success,
		ErrorClass: s.meta.LastProbeResult.ErrorClass,
		PathID:     s.meta.LastProbeResult.SelectedPathID,
		Details: map[string]string{
			"plan_id":     s.meta.LastProbeResult.PlanID,
			"event_count": fmt.Sprintf("%d", len(s.meta.LastProbeResult.Events)),
		},
		FinishedAt: s.meta.LastProbeResult.FinishedAt,
	}
	return &summary
}

func (s *Session) recordPlanOrder(plans []solver.Plan, reason string) {
	s.metaMu.Lock()
	s.meta.LastPlanOrder = planIDs(plans)
	s.meta.LastPlanOrderReason = reason
	s.metaMu.Unlock()
}

func (s *Session) recordPlanRefine(before, after []string, reason string) {
	s.metaMu.Lock()
	s.meta.LastPlanSetBeforeRefine = append([]string(nil), before...)
	s.meta.LastPlanSetAfterRefine = append([]string(nil), after...)
	s.meta.LastPlanRefineReason = reason
	s.metaMu.Unlock()
}

func planIDs(plans []solver.Plan) []string {
	out := make([]string, 0, len(plans))
	for _, plan := range plans {
		out = append(out, plan.ID)
	}
	return out
}

func samePlanSet(left, right []solver.Plan) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, plan := range left {
		counts[plan.ID]++
	}
	for _, plan := range right {
		counts[plan.ID]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func isPlanSubset(original, refined []solver.Plan) bool {
	counts := make(map[string]int, len(original))
	for _, plan := range original {
		counts[plan.ID]++
	}
	for _, plan := range refined {
		counts[plan.ID]--
		if counts[plan.ID] < 0 {
			return false
		}
	}
	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func annotateObservationDetails(details map[string]string, sessionID, peerID string, initiator bool) map[string]string {
	if details == nil {
		details = make(map[string]string, 3)
	} else {
		details = cloneStringMap(details)
	}
	if sessionID != "" {
		details["session_id"] = sessionID
	}
	if peerID != "" {
		details["peer_id"] = peerID
	}
	details["initiator"] = fmt.Sprintf("%t", initiator)
	return details
}

func probeScriptToProto(script pmodel.Script) rproto.ProbeScript {
	steps := make([]rproto.ProbeStep, 0, len(script.Steps))
	for _, step := range script.Steps {
		steps = append(steps, rproto.ProbeStep{
			Type:       step.Type,
			Addr:       step.Addr,
			Payload:    step.Payload,
			Expect:     step.Expect,
			Message:    step.Message,
			Reply:      step.Reply,
			DurationMS: step.DurationMS,
			TimeoutMS:  step.TimeoutMS,
			Event:      step.Event,
			Details:    cloneStringMap(step.Details),
		})
	}
	return rproto.ProbeScript{
		ScriptType: script.ScriptType,
		PlanID:     script.PlanID,
		Steps:      steps,
	}
}

func probeScriptFromProto(script rproto.ProbeScript) pmodel.Script {
	steps := make([]pmodel.Step, 0, len(script.Steps))
	for _, step := range script.Steps {
		steps = append(steps, pmodel.Step{
			Type:       step.Type,
			Addr:       step.Addr,
			Payload:    step.Payload,
			Expect:     step.Expect,
			Message:    step.Message,
			Reply:      step.Reply,
			DurationMS: step.DurationMS,
			TimeoutMS:  step.TimeoutMS,
			Event:      step.Event,
			Details:    cloneStringMap(step.Details),
		})
	}
	return pmodel.Script{
		ScriptType: script.ScriptType,
		PlanID:     script.PlanID,
		Steps:      steps,
	}
}

func probeResultToProto(result pmodel.Result) rproto.ProbeResult {
	events := make([]rproto.Observation, 0, len(result.Events))
	for _, obs := range result.Events {
		events = append(events, rproto.Observation{
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
			Details:        cloneStringMap(obs.Details),
			Timestamp:      obs.Timestamp,
		})
	}
	return rproto.ProbeResult{
		ScriptType:     result.ScriptType,
		PlanID:         result.PlanID,
		Success:        result.Success,
		Events:         events,
		SelectedPathID: result.SelectedPathID,
		ErrorClass:     result.ErrorClass,
		FinishedAt:     result.FinishedAt,
	}
}

func probeResultFromProto(result rproto.ProbeResult) pmodel.Result {
	events := make([]solver.Observation, 0, len(result.Events))
	for _, obs := range result.Events {
		events = append(events, solver.Observation{
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
			Details:        cloneStringMap(obs.Details),
			Timestamp:      obs.Timestamp,
		})
	}
	return pmodel.Result{
		ScriptType:     result.ScriptType,
		PlanID:         result.PlanID,
		Success:        result.Success,
		Events:         events,
		SelectedPathID: result.SelectedPathID,
		ErrorClass:     result.ErrorClass,
		FinishedAt:     result.FinishedAt,
	}
}

func localResultPathType(result pmodel.Result) string {
	for i := len(result.Events) - 1; i >= 0; i-- {
		if result.Events[i].ConnectionType != "" {
			return result.Events[i].ConnectionType
		}
	}
	return ""
}

func solverProbeScriptToModel(script solver.ProbeScript) pmodel.Script {
	steps := make([]pmodel.Step, len(script.Steps))
	for i, step := range script.Steps {
		steps[i] = pmodel.Step{
			Type:       step.Action,
			Addr:       step.Params["addr"],
			Payload:    step.Params["payload"],
			Expect:     step.Params["expect"],
			Message:    step.Params["message"],
			Reply:      step.Params["reply"],
			Event:      step.Params["event"],
			DurationMS: parseIntParam(step.Params["duration_ms"]),
			TimeoutMS:  int(step.Timeout.Milliseconds()),
			Details:    cloneStringMapExcept(step.Params, "addr", "payload", "expect", "message", "reply", "event", "duration_ms"),
		}
	}
	return pmodel.Script{
		ScriptType: script.ScriptType,
		PlanID:     script.PlanID,
		Steps:      steps,
	}
}

func parseIntParam(s string) int {
	if s == "" {
		return 0
	}
	var val int
	fmt.Sscanf(s, "%d", &val)
	return val
}

func cloneStringMapExcept(m map[string]string, except ...string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	excludeSet := make(map[string]struct{}, len(except))
	for _, key := range except {
		excludeSet[key] = struct{}{}
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		if _, excluded := excludeSet[k]; !excluded {
			result[k] = v
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func cloneCapability(capability rproto.Capability) rproto.Capability {
	return rproto.Capability{
		Strategies: append([]string(nil), capability.Strategies...),
		Features:   append([]string(nil), capability.Features...),
	}
}

func normalizeCapability(capability rproto.Capability) rproto.Capability {
	normalized := rproto.Capability{}
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
	normalized.Strategies = strategies

	seen = make(map[string]struct{}, len(capability.Features))
	features := make([]string, 0, len(capability.Features))
	for _, feature := range capability.Features {
		if feature == "" {
			continue
		}
		if _, ok := seen[feature]; ok {
			continue
		}
		seen[feature] = struct{}{}
		features = append(features, feature)
	}
	slices.Sort(features)
	normalized.Features = features
	return normalized
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

func capabilityHasFeature(capability rproto.Capability, feature string) bool {
	for _, candidate := range capability.Features {
		if candidate == feature {
			return true
		}
	}
	return false
}

func cloneProbeResult(result pmodel.Result) pmodel.Result {
	cloned := result
	cloned.Events = make([]solver.Observation, 0, len(result.Events))
	for _, obs := range result.Events {
		obs.Details = cloneStringMap(obs.Details)
		cloned.Events = append(cloned.Events, obs)
	}
	return cloned
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
