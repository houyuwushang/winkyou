package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	pmodel "winkyou/pkg/probe/model"
	"winkyou/pkg/solver"
)

const defaultCapabilityWaitTimeout = 2 * time.Second

const defaultPreflightProbeTimeout = 500 * time.Millisecond

const defaultOperationTimeout = 2 * time.Second

const defaultCleanupTimeout = 2 * time.Second

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
	executeMu sync.Mutex
	closeMu   sync.Mutex
	closed    bool

	metaMu sync.RWMutex
	meta   Snapshot
	seq    uint64

	strategyMu       sync.RWMutex
	strategy         solver.Strategy
	pending          []solver.Message
	activePlan       string
	executor         solver.PlanExecutor
	boundMsgTarget   strategyMessageTarget
	boundMsgAcceptor solver.MessageAcceptor
	boundMsgPlanID   string

	capabilityCh  chan struct{}
	probeResultCh chan probeResultSignal
	probeResultMu sync.Mutex
	probeResults  map[string]probeResultSignal

	lastPlan solver.Plan
	lastRes  solver.Result
	retained []solver.CandidateOutcome

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
		probeResults:  make(map[string]probeResultSignal),
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
		LastStrategyOrder:       append([]string(nil), s.meta.LastStrategyOrder...),
		LastStrategyOrderReason: s.meta.LastStrategyOrderReason,
		LastPlanSetBeforeRefine: append([]string(nil), s.meta.LastPlanSetBeforeRefine...),
		LastPlanSetAfterRefine:  append([]string(nil), s.meta.LastPlanSetAfterRefine...),
		LastPlanRefineReason:    s.meta.LastPlanRefineReason,
		PreflightProbeAttempted: s.meta.PreflightProbeAttempted,
		PreflightProbeSucceeded: s.meta.PreflightProbeSucceeded,
	}
}
