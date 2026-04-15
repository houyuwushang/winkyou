package session

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type Session struct {
	cfg Config

	sm     *StateMachine
	io     *solverIO
	runCtx context.Context

	startMu sync.Mutex
	started bool
	closeMu sync.Mutex
	closed  bool

	metaMu sync.RWMutex
	meta   Snapshot
	seq    uint64

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

	localCapability := rproto.Capability{Strategies: []string{cfg.Strategy.Name()}}
	return &Session{
		cfg: cfg,
		sm:  NewStateMachine(StateNew),
		io:  &solverIO{cfg: cfg},
		meta: Snapshot{
			SessionID:       cfg.SessionID,
			PeerID:          cfg.PeerID,
			State:           StateNew,
			LocalCapability: normalizeCapability(localCapability),
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
		SessionID:        s.meta.SessionID,
		PeerID:           s.meta.PeerID,
		State:            s.meta.State,
		LocalCapability:  cloneCapability(s.meta.LocalCapability),
		RemoteCapability: cloneCapability(s.meta.RemoteCapability),
		LastEnvelopeType: s.meta.LastEnvelopeType,
		LastEnvelopeAt:   s.meta.LastEnvelopeAt,
	}
}

func (s *Session) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	s.startMu.Lock()
	if s.started {
		s.startMu.Unlock()
		return nil
	}
	s.started = true
	s.runCtx = ctx
	s.startMu.Unlock()

	if err := s.sendCapability(ctx); err != nil {
		s.fail(err)
		return err
	}

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
	switch msg.Kind {
	case solver.MessageKindEnvelope:
		if msg.Namespace != "" && msg.Namespace != envelopeNamespace {
			return nil
		}
		return s.handleEnvelopeMessage(msg)
	case solver.MessageKindStrategy:
		handler, ok := s.cfg.Strategy.(solver.MessageHandler)
		if !ok {
			return nil
		}
		return handler.HandleMessage(ctx, s.io, msg)
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

func (s *Session) handleEnvelopeMessage(msg solver.Message) error {
	envelope, err := rproto.UnmarshalEnvelope(msg.Payload)
	if err != nil {
		return err
	}
	if envelope.SessionID != s.cfg.SessionID {
		return nil
	}

	s.metaMu.Lock()
	s.meta.LastEnvelopeType = envelope.MsgType
	if msg.ReceivedAt.IsZero() {
		s.meta.LastEnvelopeAt = time.Now()
	} else {
		s.meta.LastEnvelopeAt = msg.ReceivedAt
	}
	s.metaMu.Unlock()

	switch envelope.MsgType {
	case rproto.MsgTypeCapability:
		var capability rproto.Capability
		if len(envelope.Payload) > 0 {
			if err := json.Unmarshal(envelope.Payload, &capability); err != nil {
				return fmt.Errorf("session: decode capability: %w", err)
			}
		}
		s.setRemoteCapability(capability)
	}
	return nil
}

func (s *Session) executionTimeout() time.Duration {
	return s.cfg.RunTimeout
}

func (s *Session) localCapability() rproto.Capability {
	s.metaMu.RLock()
	defer s.metaMu.RUnlock()
	return cloneCapability(s.meta.LocalCapability)
}

func (s *Session) setRemoteCapability(capability rproto.Capability) {
	normalized := normalizeCapability(capability)
	s.metaMu.Lock()
	s.meta.RemoteCapability = normalized
	s.metaMu.Unlock()
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
