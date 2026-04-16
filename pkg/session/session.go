package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

	capabilityCh chan struct{}

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

	return &Session{
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
	}, nil
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
	s.lastPlan = plans[0]

	if err := s.flushPendingStrategyMessages(ctx, strategy); err != nil {
		return err
	}

	s.execute(strategy, plans[0])
	return nil
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

func (s *Session) execute(strategy solver.Strategy, plan solver.Plan) {
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

	result, err := strategy.Execute(execCtx, s.io, plan)
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

	if err := s.sendPathCommit(context.Background(), result); err != nil {
		if s.cfg.Binder != nil {
			_ = s.cfg.Binder.Unbind(context.Background(), s.cfg.PeerID)
		}
		if result.Transport != nil {
			_ = result.Transport.Close()
			s.lastRes.Transport = nil
		}
		s.fail(err)
		return
	}

	s.transition(StateBound)
	if s.cfg.Hooks.OnBound != nil {
		s.cfg.Hooks.OnBound(result)
	}
}

func (s *Session) HandleMessage(ctx context.Context, msg solver.Message) error {
	switch msg.Kind {
	case solver.MessageKindEnvelope:
		if msg.Namespace != "" && msg.Namespace != envelopeNamespace {
			return nil
		}
		return s.handleEnvelopeMessage(msg)
	case solver.MessageKindStrategy:
		strategy, handler, pending := s.strategyHandler()
		if pending || strategy == nil || !handler {
			s.enqueueStrategyMessage(msg)
			return nil
		}
		return strategy.(solver.MessageHandler).HandleMessage(ctx, s.io, msg)
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

func (s *Session) strategyHandler() (solver.Strategy, bool, bool) {
	s.strategyMu.RLock()
	defer s.strategyMu.RUnlock()
	if s.strategy == nil {
		return nil, false, true
	}
	_, ok := s.strategy.(solver.MessageHandler)
	return s.strategy, ok, false
}

func (s *Session) enqueueStrategyMessage(msg solver.Message) {
	s.strategyMu.Lock()
	defer s.strategyMu.Unlock()
	if s.strategy != nil {
		return
	}
	s.pending = append(s.pending, cloneMessage(msg))
}

func (s *Session) flushPendingStrategyMessages(ctx context.Context, strategy solver.Strategy) error {
	handler, ok := strategy.(solver.MessageHandler)
	if !ok {
		s.strategyMu.Lock()
		s.pending = nil
		s.strategyMu.Unlock()
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
