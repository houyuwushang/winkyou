package shortcut

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/peercontrol"
	"winkyou/pkg/solver"
)

const (
	defaultProbation           = 30 * time.Second
	defaultSolveTimeout        = 60 * time.Second
	defaultAttemptTimeoutSlack = 10 * time.Second
	minCommitRetryInterval     = 100 * time.Millisecond
	maximumCommitRetryInterval = time.Second
	// The aggregate byte limit matches the existing maximum control frame; the
	// count limit separately bounds tiny-message bookkeeping without rejecting
	// a legitimate candidate burst that already fits that frame budget.
	maxPendingSolverMessages = 4096
	maxPendingSolverBytes    = 1 << 20
	maxTimeDuration          = time.Duration(1<<63 - 1)
)

var (
	ErrClosed         = errors.New("shortcut: manager closed")
	ErrAttemptFailed  = errors.New("shortcut: attempt failed")
	ErrUnknownAttempt = errors.New("shortcut: unknown attempt")
	ErrPairBusy       = errors.New("shortcut: pair already has an active attempt")
	ErrSolverBacklog  = errors.New("shortcut: pending solver message backlog exceeded")
)

type Phase string

const (
	PhaseRequested Phase = "requested"
	PhasePreparing Phase = "preparing"
	PhaseReady     Phase = "ready"
	PhaseFiring    Phase = "firing"
	PhaseSolving   Phase = "solving"
	PhaseInstalled Phase = "installed"
	PhaseProbation Phase = "probation"
	PhaseStable    Phase = "stable"
	PhaseFailed    Phase = "failed"
)

type AttemptSpec struct {
	AttemptID     string
	InitiatorID   string
	TargetID      string
	CoordinatorID string
	LocalNodeID   string
	RemoteNodeID  string
	Initiator     bool
}

type StrategyFactory func(AttemptSpec) (solver.Strategy, error)

type Config struct {
	Node            *mesh.Node
	StrategyName    string
	StrategyFactory StrategyFactory
	Probation       time.Duration
	SolveTimeout    time.Duration
	AttemptTimeout  time.Duration
	PacketNeighbor  mesh.PacketNeighborConfig
	OnEvent         func(Event)
}

type Status struct {
	AttemptID      string
	InitiatorID    string
	TargetID       string
	CoordinatorID  string
	Strategy       string
	LocalRole      string
	Phase          Phase
	DirectPeerID   string
	PathSummary    solver.PathSummary
	StartedAt      time.Time
	UpdatedAt      time.Time
	ProbationUntil time.Time
	Failure        string
}

type Event struct {
	At     time.Time
	NodeID string
	Status Status
}

type attemptState struct {
	status          Status
	strategy        solver.Strategy
	plan            solver.Plan
	ready           map[string]bool
	installed       map[string]bool
	stable          map[string]bool
	directAttached  bool
	neighborHandle  mesh.NeighborHandle
	monitorStarted  bool
	watchdogStarted bool
	solveCancel     context.CancelFunc
	pendingSolver   []pendingSolverMessage
	pendingBytes    int
	solverDraining  bool
	changed         chan struct{}
}

type pendingSolverMessage struct {
	from string
	wire wireMessage
	size int
}

type Manager struct {
	node           *mesh.Node
	strategyName   string
	factory        StrategyFactory
	probation      time.Duration
	solveTimeout   time.Duration
	attemptTimeout time.Duration
	packetNeighbor mesh.PacketNeighborConfig
	onEvent        func(Event)
	ctx            context.Context
	cancel         context.CancelFunc
	unregister     func()
	sequence       atomic.Uint64

	mu       sync.Mutex
	closed   bool
	attempts map[string]*attemptState
	wg       sync.WaitGroup
}

func NewManager(config Config) (*Manager, error) {
	if config.Node == nil || config.Node.NodeID() == "" {
		return nil, fmt.Errorf("shortcut: mesh node is required")
	}
	config.StrategyName = strings.TrimSpace(config.StrategyName)
	if config.StrategyName == "" {
		return nil, fmt.Errorf("shortcut: strategy name is required")
	}
	if config.Probation <= 0 {
		config.Probation = defaultProbation
	}
	if config.SolveTimeout <= 0 {
		config.SolveTimeout = defaultSolveTimeout
	}
	config.PacketNeighbor = config.PacketNeighbor.Normalized()
	if config.Probation < config.PacketNeighbor.PeerTimeout {
		return nil, fmt.Errorf(
			"shortcut: probation %s must be at least packet-neighbor peer timeout %s",
			config.Probation,
			config.PacketNeighbor.PeerTimeout,
		)
	}
	if config.AttemptTimeout <= 0 {
		config.AttemptTimeout = defaultAttemptLifecycleTimeout(
			config.SolveTimeout,
			config.Probation,
			config.PacketNeighbor.PeerTimeout,
		)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager := &Manager{
		node:           config.Node,
		strategyName:   config.StrategyName,
		factory:        config.StrategyFactory,
		probation:      config.Probation,
		solveTimeout:   config.SolveTimeout,
		attemptTimeout: config.AttemptTimeout,
		packetNeighbor: config.PacketNeighbor,
		onEvent:        config.OnEvent,
		ctx:            ctx,
		cancel:         cancel,
		attempts:       make(map[string]*attemptState),
	}
	unregister, err := config.Node.RegisterMessageHandler(manager.handleMessage)
	if err != nil {
		cancel()
		return nil, err
	}
	manager.unregister = unregister
	return manager, nil
}

func (m *Manager) Start(ctx context.Context, targetID, coordinatorID string) (*Handle, error) {
	if m == nil {
		return nil, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	targetID = strings.TrimSpace(targetID)
	coordinatorID = strings.TrimSpace(coordinatorID)
	localID := m.node.NodeID()
	if targetID == "" || coordinatorID == "" || targetID == localID || coordinatorID == localID || targetID == coordinatorID {
		return nil, fmt.Errorf("shortcut: local, target, and coordinator nodes must be distinct")
	}
	if m.factory == nil {
		return nil, fmt.Errorf("shortcut: initiator has no strategy factory")
	}
	now := time.Now().UTC()
	attemptID := fmt.Sprintf("%s-%d-%d", localID, now.UnixNano(), m.sequence.Add(1))
	wire := wireMessage{
		AttemptID: attemptID, InitiatorID: localID, TargetID: targetID, CoordinatorID: coordinatorID,
		Strategy: m.strategyName, ProbationMillis: m.probation.Milliseconds(), SentAt: now,
	}
	state := &attemptState{
		status: Status{
			AttemptID: attemptID, InitiatorID: localID, TargetID: targetID, CoordinatorID: coordinatorID,
			Strategy: m.strategyName, LocalRole: "initiator", Phase: PhaseRequested,
			DirectPeerID: targetID, StartedAt: now, UpdatedAt: now,
		},
		changed: make(chan struct{}),
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	for _, existing := range m.attempts {
		if existing.status.Phase != PhaseFailed && sameEndpointPair(existing.status, localID, targetID) {
			existingStatus := cloneStatus(existing.status)
			m.mu.Unlock()
			return nil, fmt.Errorf(
				"%w: attempt %s is %s for %s<->%s",
				ErrPairBusy,
				existingStatus.AttemptID,
				existingStatus.Phase,
				localID,
				targetID,
			)
		}
	}
	if _, ok := m.node.Route(targetID); !ok && !m.node.HasNeighbor(targetID) {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: target %s", mesh.ErrNoRoute, targetID)
	}
	if _, ok := m.node.Route(coordinatorID); !ok && !m.node.HasNeighbor(coordinatorID) {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: coordinator %s", mesh.ErrNoRoute, coordinatorID)
	}
	m.attempts[attemptID] = state
	m.mu.Unlock()
	if !m.startAttemptWatchdog(attemptID) {
		return nil, ErrClosed
	}
	m.emit(state.status)
	if err := m.sendWire(ctx, coordinatorID, typePrepareRequest, wire); err != nil {
		m.failLocal(attemptID, err, false)
		return nil, err
	}
	return &Handle{manager: m, attemptID: attemptID}, nil
}

type Handle struct {
	manager   *Manager
	attemptID string
}

func (h *Handle) ID() string {
	if h == nil {
		return ""
	}
	return h.attemptID
}

func (h *Handle) Status() (Status, bool) {
	if h == nil || h.manager == nil {
		return Status{}, false
	}
	return h.manager.Status(h.attemptID)
}

func (h *Handle) WaitFor(ctx context.Context, phase Phase) (Status, error) {
	if h == nil || h.manager == nil {
		return Status{}, ErrUnknownAttempt
	}
	return h.manager.WaitFor(ctx, h.attemptID, phase)
}

func (m *Manager) Status(attemptID string) (Status, bool) {
	if m == nil {
		return Status{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.attempts[attemptID]
	if state == nil {
		return Status{}, false
	}
	return cloneStatus(state.status), true
}

// IsStableDirectNeighbor reports whether handle is the exact packet-neighbor
// generation installed by a shortcut to peerID after that shortcut completed
// probation. Matching the opaque handle is important: a stable status from an
// older edge must never authorize teardown of a bootstrap stream after a newer
// probationary edge has replaced it.
func (m *Manager) IsStableDirectNeighbor(peerID string, handle mesh.NeighborHandle) bool {
	if m == nil {
		return false
	}
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, state := range m.attempts {
		if state == nil || !state.directAttached || state.status.Phase != PhaseStable ||
			state.status.DirectPeerID != peerID {
			continue
		}
		if state.neighborHandle == handle {
			return true
		}
	}
	return false
}

// Cancel terminates an in-progress attempt. Terminal attempts are intentionally
// idempotent: canceling Stable must not tear down the promoted direct edge, and
// canceling Failed must not repeat cleanup or signaling.
func (m *Manager) Cancel(attemptID string, cause error) error {
	if m == nil {
		return ErrClosed
	}
	attemptID = strings.TrimSpace(attemptID)
	m.mu.Lock()
	state := m.attempts[attemptID]
	if state == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseStable || state.status.Phase == PhaseFailed {
		m.mu.Unlock()
		return nil
	}
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	role := state.status.LocalRole
	wire := wireFromStatus(state.status, m.probation)
	m.mu.Unlock()

	if cause == nil {
		cause = context.Canceled
	}
	if role == "coordinator" {
		ctx, cancel := context.WithTimeout(m.ctx, m.packetNeighbor.WriteTimeout)
		defer cancel()
		m.abortFromCoordinator(ctx, wire, cause)
		return nil
	}
	m.failLocalNonTerminal(attemptID, cause, true)
	return nil
}

func (m *Manager) WaitFor(ctx context.Context, attemptID string, phase Phase) (Status, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		m.mu.Lock()
		state := m.attempts[attemptID]
		if state == nil {
			m.mu.Unlock()
			return Status{}, ErrUnknownAttempt
		}
		status := cloneStatus(state.status)
		changed := state.changed
		m.mu.Unlock()
		if status.Phase == PhaseFailed {
			return status, fmt.Errorf("%w: %s", ErrAttemptFailed, status.Failure)
		}
		if phaseReached(status.Phase, phase) {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, ctx.Err()
		case <-m.ctx.Done():
			return status, ErrClosed
		case <-changed:
		}
	}
}

func (m *Manager) handleMessage(ctx context.Context, message peercontrol.Message) error {
	if message.Type != peercontrol.TypeSessionSignal || message.SessionSignal == nil ||
		message.SessionSignal.Namespace != Namespace || message.SessionSignal.Kind != SignalKind {
		return nil
	}
	wire, err := unmarshalWire(message.SessionSignal.Payload)
	if err != nil {
		return err
	}
	switch message.SessionSignal.Type {
	case typePrepareRequest:
		return m.handlePrepareRequest(ctx, message.From, wire)
	case typePrepare:
		return m.handlePrepare(ctx, message.From, wire)
	case typeReady:
		return m.handleReady(ctx, message.From, wire)
	case typeFire:
		return m.handleFire(message.From, wire)
	case typeSolverMessage:
		return m.handleSolverMessage(ctx, message.From, wire)
	case typeInstalled:
		return m.handleInstalled(message.From, wire)
	case typeCommit:
		return m.handleCommit(ctx, message.From, wire)
	case typeStable:
		return m.handleStable(message.From, wire)
	case typeFailed:
		return m.handleRemoteFailure(ctx, message.From, wire)
	case typeAbort:
		return m.handleAbort(message.From, wire)
	default:
		return fmt.Errorf("shortcut: unsupported signal type %q", message.SessionSignal.Type)
	}
}

func (m *Manager) handlePrepareRequest(ctx context.Context, from string, wire wireMessage) error {
	localID := m.node.NodeID()
	if localID != wire.CoordinatorID || from != wire.InitiatorID {
		return fmt.Errorf("shortcut: invalid PREPARE requester %s for coordinator %s", from, localID)
	}
	now := time.Now().UTC()
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil {
		state = &attemptState{
			status: Status{
				AttemptID: wire.AttemptID, InitiatorID: wire.InitiatorID, TargetID: wire.TargetID,
				CoordinatorID: wire.CoordinatorID, Strategy: wire.Strategy, LocalRole: "coordinator",
				Phase: PhasePreparing, StartedAt: now, UpdatedAt: now,
			},
			ready: make(map[string]bool), installed: make(map[string]bool), stable: make(map[string]bool),
			changed: make(chan struct{}),
		}
		m.attempts[wire.AttemptID] = state
	}
	if state.status.Phase == PhaseStable || state.status.Phase == PhaseFailed {
		m.mu.Unlock()
		return nil
	}
	status := cloneStatus(state.status)
	m.mu.Unlock()
	if !m.startAttemptWatchdog(wire.AttemptID) {
		return ErrClosed
	}
	m.emit(status)
	if err := m.sendWire(ctx, wire.InitiatorID, typePrepare, wire); err != nil {
		m.abortFromCoordinator(ctx, wire, err)
		return err
	}
	if err := m.sendWire(ctx, wire.TargetID, typePrepare, wire); err != nil {
		m.abortFromCoordinator(ctx, wire, err)
		return err
	}
	return nil
}

func (m *Manager) handlePrepare(ctx context.Context, from string, wire wireMessage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	localID := m.node.NodeID()
	if from != wire.CoordinatorID || (localID != wire.InitiatorID && localID != wire.TargetID) {
		return fmt.Errorf("shortcut: invalid PREPARE delivery from %s to %s", from, localID)
	}
	remoteID := wire.TargetID
	role := "initiator"
	initiator := true
	if localID == wire.TargetID {
		remoteID = wire.InitiatorID
		role = "target"
		initiator = false
	}

	now := time.Now().UTC()
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	created := state == nil
	if state == nil {
		state = &attemptState{
			status: Status{
				AttemptID: wire.AttemptID, InitiatorID: wire.InitiatorID, TargetID: wire.TargetID,
				CoordinatorID: wire.CoordinatorID, Strategy: wire.Strategy, LocalRole: role,
				Phase: PhasePreparing, DirectPeerID: remoteID, StartedAt: now, UpdatedAt: now,
			},
			changed: make(chan struct{}),
		}
		m.attempts[wire.AttemptID] = state
	} else {
		if state.status.Phase == PhaseFailed || state.status.Phase == PhaseStable || phaseReached(state.status.Phase, PhaseInstalled) {
			m.mu.Unlock()
			return nil
		}
		if state.strategy != nil {
			ready := state.status.Phase == PhaseReady
			m.mu.Unlock()
			if ready {
				return m.sendWire(ctx, wire.CoordinatorID, typeReady, wire)
			}
			return nil
		}
	}
	preparingStatus := cloneStatus(state.status)
	m.mu.Unlock()
	if !m.startAttemptWatchdog(wire.AttemptID) {
		return ErrClosed
	}
	if created {
		m.emit(preparingStatus)
	}
	if m.factory == nil {
		err := fmt.Errorf("shortcut: endpoint %s has no strategy factory", localID)
		m.failLocal(wire.AttemptID, err, true)
		return err
	}
	spec := AttemptSpec{
		AttemptID: wire.AttemptID, InitiatorID: wire.InitiatorID, TargetID: wire.TargetID,
		CoordinatorID: wire.CoordinatorID, LocalNodeID: localID, RemoteNodeID: remoteID, Initiator: initiator,
	}
	strategy, err := m.factory(spec)
	if err != nil {
		m.failLocal(wire.AttemptID, err, true)
		return err
	}
	if strategy == nil || strategy.Name() != wire.Strategy {
		if strategy != nil {
			_ = strategy.Close()
		}
		err = fmt.Errorf("shortcut: factory strategy mismatch: got %v want %s", strategyName(strategy), wire.Strategy)
		m.failLocal(wire.AttemptID, err, true)
		return err
	}
	planCtx, planCancel := context.WithCancel(ctx)
	m.mu.Lock()
	state = m.attempts[wire.AttemptID]
	if state == nil || m.closed || state.status.Phase == PhaseFailed || state.status.Phase == PhaseStable {
		m.mu.Unlock()
		planCancel()
		_ = strategy.Close()
		return nil
	}
	if state.strategy != nil {
		ready := state.status.Phase == PhaseReady
		m.mu.Unlock()
		planCancel()
		_ = strategy.Close()
		if ready {
			return m.sendWire(ctx, wire.CoordinatorID, typeReady, wire)
		}
		return nil
	}
	state.strategy = strategy
	state.solveCancel = planCancel
	m.mu.Unlock()

	plans, err := strategy.Plan(planCtx, solver.SolveInput{
		SessionID: wire.AttemptID, LocalNodeID: localID, RemoteNodeID: remoteID, Initiator: initiator,
	})
	planCancel()
	if err != nil || len(plans) == 0 {
		if err == nil {
			err = fmt.Errorf("shortcut: strategy returned no plans")
		}
		m.failLocal(wire.AttemptID, err, true)
		return err
	}
	now = time.Now().UTC()
	m.mu.Lock()
	state = m.attempts[wire.AttemptID]
	if state == nil || m.closed || state.status.Phase == PhaseFailed || state.status.Phase == PhaseStable {
		m.mu.Unlock()
		_ = strategy.Close()
		return nil
	}
	state.solveCancel = nil
	state.plan = plans[0]
	state.status = Status{
		AttemptID: wire.AttemptID, InitiatorID: wire.InitiatorID, TargetID: wire.TargetID,
		CoordinatorID: wire.CoordinatorID, Strategy: wire.Strategy, LocalRole: role,
		Phase: PhaseReady, DirectPeerID: remoteID, StartedAt: state.status.StartedAt, UpdatedAt: now,
	}
	if state.status.StartedAt.IsZero() {
		state.status.StartedAt = now
	}
	m.notifyLocked(state)
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	if err := m.sendWire(ctx, wire.CoordinatorID, typeReady, wire); err != nil {
		m.failLocal(wire.AttemptID, err, false)
		return err
	}
	return nil
}

func (m *Manager) handleReady(ctx context.Context, from string, wire wireMessage) error {
	if m.node.NodeID() != wire.CoordinatorID || (from != wire.InitiatorID && from != wire.TargetID) {
		return fmt.Errorf("shortcut: invalid READY from %s", from)
	}
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseStable || state.status.Phase == PhaseFailed {
		m.mu.Unlock()
		return nil
	}
	state.ready[from] = true
	fire := !phaseReached(state.status.Phase, PhaseFiring) &&
		state.ready[wire.InitiatorID] && state.ready[wire.TargetID]
	if fire {
		state.status.Phase = PhaseFiring
		state.status.UpdatedAt = time.Now().UTC()
		m.notifyLocked(state)
	}
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	if !fire {
		return nil
	}
	if err := m.sendWire(ctx, wire.InitiatorID, typeFire, wire); err != nil {
		m.abortFromCoordinator(ctx, wire, err)
		return err
	}
	if err := m.sendWire(ctx, wire.TargetID, typeFire, wire); err != nil {
		m.abortFromCoordinator(ctx, wire, err)
		return err
	}
	return nil
}

func (m *Manager) handleFire(from string, wire wireMessage) error {
	if from != wire.CoordinatorID {
		return fmt.Errorf("shortcut: FIRE did not come from coordinator")
	}
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseFailed || state.status.Phase == PhaseStable {
		m.mu.Unlock()
		return nil
	}
	if state.strategy == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseSolving || phaseReached(state.status.Phase, PhaseInstalled) {
		m.mu.Unlock()
		return nil
	}
	state.status.Phase = PhaseSolving
	// Queue the handoff edge atomically with the phase transition so no solver
	// message can overtake the pre-FIRE backlog before runSolver drains it.
	state.solverDraining = true
	state.status.UpdatedAt = time.Now().UTC()
	m.notifyLocked(state)
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	if !m.startTask(func() { m.runSolver(wire) }) {
		return ErrClosed
	}
	return nil
}

func (m *Manager) runSolver(wire wireMessage) {
	runCtx, runCancel := context.WithCancel(m.ctx)
	defer runCancel()
	solveCtx, solveDeadlineCancel := context.WithTimeout(runCtx, m.solveTimeout)
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil || state.status.Phase != PhaseSolving {
		m.mu.Unlock()
		solveDeadlineCancel()
		return
	}
	// Keep one cancellation authority across solver execution, packet
	// readiness, and INSTALLED delivery. The solver deadline remains a child
	// phase deadline rather than accidentally bounding the readiness phase.
	state.solveCancel = runCancel
	strategy := state.strategy
	plan := state.plan
	remoteID := state.status.DirectPeerID
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if current := m.attempts[wire.AttemptID]; current != nil {
			current.solveCancel = nil
		}
		m.mu.Unlock()
	}()
	if err := m.drainPendingSolverMessages(solveCtx, wire.AttemptID, strategy); err != nil {
		solveDeadlineCancel()
		_ = strategy.Close()
		m.failLocal(wire.AttemptID, err, true)
		return
	}
	result, err := strategy.Execute(solveCtx, &routedSessionIO{manager: m, wire: wire, remoteID: remoteID}, plan)
	solveDeadlineCancel()
	m.mu.Lock()
	if current := m.attempts[wire.AttemptID]; current != nil && current.status.Phase == PhaseSolving {
		// Execute is terminal for strategy signaling. Do not expose an already
		// closed strategy to late messages while packet readiness is pending.
		current.strategy = nil
	}
	m.mu.Unlock()
	_ = strategy.Close()
	if err != nil {
		m.failLocal(wire.AttemptID, err, true)
		return
	}
	m.mu.Lock()
	state = m.attempts[wire.AttemptID]
	active := !m.closed && state != nil && state.status.Phase == PhaseSolving
	m.mu.Unlock()
	if !active {
		if result.Transport != nil {
			_ = result.Transport.Close()
		}
		return
	}
	if result.Transport == nil || !solver.IsProtectedDirectPath(result.Summary) {
		if result.Transport != nil {
			_ = result.Transport.Close()
		}
		m.failLocal(wire.AttemptID, fmt.Errorf("shortcut: solver did not return a protected-direct transport"), true)
		return
	}
	neighborConfig := m.packetNeighbor
	// A solver-produced packet session is usable for its own liveness and
	// direct control during probation, but must not become a graph edge until
	// this exact session has survived the full probation window.
	neighborConfig.DeferAdvertisement = true
	configuredOnClose := neighborConfig.OnClose
	neighborConfig.OnClose = func(peerID string, cause error) {
		if configuredOnClose != nil {
			configuredOnClose(peerID, cause)
		}
		m.handleDirectNeighborClose(wire.AttemptID, peerID, cause)
	}
	neighborHandle, err := m.node.AttachPacketTransportWithHandle(remoteID, result.Transport, neighborConfig)
	if err != nil {
		m.failLocal(wire.AttemptID, fmt.Errorf("shortcut: install direct edge: %w", err), true)
		return
	}
	readinessCtx, readinessCancel := context.WithTimeout(runCtx, neighborConfig.ReadinessTimeout)
	err = m.node.WaitPacketNeighborReady(readinessCtx, neighborHandle)
	readinessCancel()
	if err != nil {
		m.failLocal(wire.AttemptID, fmt.Errorf("shortcut: direct edge readiness: %w", err), true)
		_ = m.node.RemoveNeighborHandle(neighborHandle)
		return
	}
	now := time.Now().UTC()
	m.mu.Lock()
	state = m.attempts[wire.AttemptID]
	if m.closed || state == nil || state.status.Phase != PhaseSolving {
		m.mu.Unlock()
		_ = m.node.RemoveNeighborHandle(neighborHandle)
		return
	}
	state.directAttached = true
	state.neighborHandle = neighborHandle
	state.status.Phase = PhaseInstalled
	state.status.PathSummary = clonePathSummary(result.Summary)
	state.status.UpdatedAt = now
	m.notifyLocked(state)
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	wire.PathID = result.Summary.PathID
	installedCtx, installedCancel := context.WithTimeout(runCtx, neighborConfig.WriteTimeout)
	err = m.sendWire(installedCtx, wire.CoordinatorID, typeInstalled, wire)
	installedCancel()
	if err != nil {
		m.failLocal(wire.AttemptID, err, false)
	}
}

func (m *Manager) handleDirectNeighborClose(attemptID, peerID string, cause error) {
	m.mu.Lock()
	state := m.attempts[attemptID]
	ignore := m.closed || state == nil || state.status.Phase == PhaseFailed || state.status.DirectPeerID != peerID
	m.mu.Unlock()
	if ignore {
		return
	}
	if cause == nil {
		cause = fmt.Errorf("direct edge to %s closed", peerID)
	}
	m.failLocal(attemptID, cause, true)
}

func (m *Manager) handleSolverMessage(ctx context.Context, from string, wire wireMessage) error {
	if wire.SolverMessage == nil {
		return fmt.Errorf("shortcut: solver signal has no message")
	}
	message := *wire.SolverMessage
	message.Payload = append([]byte(nil), message.Payload...)
	message.ReceivedAt = time.Now().UTC()
	wire.SolverMessage = &message
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil || from != state.status.DirectPeerID {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseStable || state.status.Phase == PhaseFailed {
		m.mu.Unlock()
		return nil
	}
	if state.strategy == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	queue := state.status.Phase == PhaseReady ||
		(state.status.Phase == PhaseSolving && state.solverDraining)
	if queue {
		messageSize := wire.encodedSize
		if messageSize <= 0 {
			messageSize = len(message.Namespace) + len(message.Type) + len(message.Payload)
		}
		if len(state.pendingSolver) >= maxPendingSolverMessages ||
			messageSize > maxPendingSolverBytes-state.pendingBytes {
			m.mu.Unlock()
			m.failLocal(wire.AttemptID, ErrSolverBacklog, true)
			return ErrSolverBacklog
		}
		state.pendingSolver = append(state.pendingSolver, pendingSolverMessage{
			from: from,
			wire: wire,
			size: messageSize,
		})
		state.pendingBytes += messageSize
		m.mu.Unlock()
		return nil
	}
	if state.status.Phase != PhaseSolving {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	strategy := state.strategy
	m.mu.Unlock()
	return deliverSolverMessage(ctx, m, strategy, from, wire)
}

func (m *Manager) drainPendingSolverMessages(ctx context.Context, attemptID string, strategy solver.Strategy) error {
	for {
		m.mu.Lock()
		state := m.attempts[attemptID]
		if state == nil || state.strategy == nil || state.status.Phase != PhaseSolving {
			if state != nil {
				state.solverDraining = false
			}
			m.mu.Unlock()
			return ErrUnknownAttempt
		}
		if len(state.pendingSolver) == 0 {
			state.pendingSolver = nil
			state.pendingBytes = 0
			state.solverDraining = false
			m.mu.Unlock()
			return nil
		}
		pending := state.pendingSolver[0]
		state.pendingSolver[0] = pendingSolverMessage{}
		state.pendingSolver = state.pendingSolver[1:]
		state.pendingBytes -= pending.size
		m.mu.Unlock()
		if err := deliverSolverMessage(ctx, m, strategy, pending.from, pending.wire); err != nil {
			m.mu.Lock()
			if current := m.attempts[attemptID]; current != nil {
				current.solverDraining = false
			}
			m.mu.Unlock()
			return err
		}
	}
}

func deliverSolverMessage(ctx context.Context, manager *Manager, strategy solver.Strategy, from string, wire wireMessage) error {
	handler, ok := strategy.(solver.MessageHandler)
	if !ok {
		return fmt.Errorf("shortcut: strategy %s does not handle messages", strategy.Name())
	}
	return handler.HandleMessage(ctx, &routedSessionIO{manager: manager, wire: wire, remoteID: from}, *wire.SolverMessage)
}

func (m *Manager) handleInstalled(from string, wire wireMessage) error {
	if m.node.NodeID() != wire.CoordinatorID || (from != wire.InitiatorID && from != wire.TargetID) {
		return fmt.Errorf("shortcut: invalid INSTALLED from %s", from)
	}
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseStable || state.status.Phase == PhaseFailed {
		m.mu.Unlock()
		return nil
	}
	state.installed[from] = true
	commit := !phaseReached(state.status.Phase, PhaseProbation) &&
		state.installed[wire.InitiatorID] && state.installed[wire.TargetID]
	if commit {
		state.status.Phase = PhaseProbation
		state.status.UpdatedAt = time.Now().UTC()
		state.status.ProbationUntil = state.status.UpdatedAt.Add(time.Duration(wire.ProbationMillis) * time.Millisecond)
		m.notifyLocked(state)
	}
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	if !commit {
		return nil
	}
	if !m.startTask(func() { m.reconcileCommit(wire) }) {
		return ErrClosed
	}
	return nil
}

func (m *Manager) reconcileCommit(wire wireMessage) {
	probation := time.Duration(wire.ProbationMillis) * time.Millisecond
	retry := commitRetryInterval(probation)
	deliveryWindow := commitDeliveryWindow(m.solveTimeout, m.packetNeighbor.PeerTimeout, retry)
	deadline := time.NewTimer(saturatingPositiveDurationSum(
		deliveryWindow,
		probation,
		saturatingPositiveDurationMultiply(retry, 2),
	))
	defer deadline.Stop()
	ticker := time.NewTicker(retry)
	defer ticker.Stop()
	var lastSendErr error
	for {
		m.mu.Lock()
		state := m.attempts[wire.AttemptID]
		if state == nil || state.status.Phase == PhaseFailed || state.status.Phase == PhaseStable {
			m.mu.Unlock()
			return
		}
		if state.status.Phase != PhaseProbation {
			m.mu.Unlock()
			return
		}
		sendInitiator := !state.stable[wire.InitiatorID]
		sendTarget := !state.stable[wire.TargetID]
		m.mu.Unlock()

		// Keep COMMIT reconciliation alive through probation. Once an endpoint
		// becomes Stable, duplicate COMMIT makes it retransmit STABLE. Limiting
		// sends to the initial delivery window can strand the coordinator when
		// the first STABLE crosses a simultaneous bootstrap-edge teardown.
		if sendInitiator {
			if err := m.sendCommit(wire.InitiatorID, wire); err != nil {
				lastSendErr = err
			}
		}
		if sendTarget {
			if err := m.sendCommit(wire.TargetID, wire); err != nil {
				lastSendErr = err
			}
		}
		select {
		case <-m.ctx.Done():
			return
		case <-deadline.C:
			cause := fmt.Errorf("shortcut: COMMIT reconciliation timed out")
			if lastSendErr != nil {
				cause = fmt.Errorf("shortcut: COMMIT reconciliation timed out after send error: %w", lastSendErr)
			}
			m.failCommitReconciliation(wire, cause)
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) sendCommit(destination string, wire wireMessage) error {
	return m.sendWireWithTimeout(destination, typeCommit, wire)
}

func (m *Manager) sendWireWithTimeout(destination, signalType string, wire wireMessage) error {
	ctx, cancel := context.WithTimeout(m.ctx, m.packetNeighbor.WriteTimeout)
	defer cancel()
	return m.sendWire(ctx, destination, signalType, wire)
}

func (m *Manager) failCommitReconciliation(wire wireMessage, cause error) {
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil || state.status.Phase != PhaseProbation {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(
		m.ctx,
		saturatingPositiveDurationMultiply(m.packetNeighbor.WriteTimeout, 2),
	)
	defer cancel()
	m.abortFromCoordinator(ctx, wire, cause)
}

func commitRetryInterval(probation time.Duration) time.Duration {
	interval := probation / 10
	if interval < minCommitRetryInterval {
		return minCommitRetryInterval
	}
	if interval > maximumCommitRetryInterval {
		return maximumCommitRetryInterval
	}
	return interval
}

func commitDeliveryWindow(solveTimeout, peerTimeout, retry time.Duration) time.Duration {
	deliveryWindow := solveTimeout
	if deliveryWindow < peerTimeout {
		deliveryWindow = peerTimeout
	}
	if minimum := 2 * retry; deliveryWindow < minimum {
		deliveryWindow = minimum
	}
	return deliveryWindow
}

func (m *Manager) handleCommit(ctx context.Context, from string, wire wireMessage) error {
	if from != wire.CoordinatorID {
		return fmt.Errorf("shortcut: COMMIT did not come from coordinator")
	}
	now := time.Now().UTC()
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseFailed {
		m.mu.Unlock()
		return nil
	}
	if state.status.Phase == PhaseStable {
		m.mu.Unlock()
		return m.sendWireWithTimeout(wire.CoordinatorID, typeStable, wire)
	}
	if !state.directAttached {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if phaseReached(state.status.Phase, PhaseProbation) {
		m.mu.Unlock()
		return nil
	}
	state.status.Phase = PhaseProbation
	state.status.UpdatedAt = now
	state.status.ProbationUntil = now.Add(time.Duration(wire.ProbationMillis) * time.Millisecond)
	startMonitor := !state.monitorStarted
	state.monitorStarted = true
	m.notifyLocked(state)
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	if startMonitor && !m.startTask(func() { m.monitorProbation(wire) }) {
		return ErrClosed
	}
	return nil
}

func (m *Manager) monitorProbation(wire wireMessage) {
	duration := time.Duration(wire.ProbationMillis) * time.Millisecond
	interval := duration / 10
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	if interval > 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	for {
		m.mu.Lock()
		state := m.attempts[wire.AttemptID]
		if state == nil || state.status.Phase != PhaseProbation {
			m.mu.Unlock()
			return
		}
		peerID := state.status.DirectPeerID
		m.mu.Unlock()
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if !m.node.HasNeighbor(peerID) {
				m.failLocal(wire.AttemptID, fmt.Errorf("direct edge lost during probation; transit path retained"), true)
				return
			}
		case <-timer.C:
			if !m.node.HasNeighbor(peerID) {
				m.failLocal(wire.AttemptID, fmt.Errorf("direct edge lost at probation boundary; transit path retained"), true)
				return
			}
			if !m.completeProbation(wire.AttemptID) {
				return
			}
			_ = m.sendWireWithTimeout(wire.CoordinatorID, typeStable, wire)
			return
		}
	}
}

func (m *Manager) completeProbation(attemptID string) bool {
	m.mu.Lock()
	state := m.attempts[attemptID]
	if m.closed || state == nil || state.status.Phase != PhaseProbation {
		m.mu.Unlock()
		return false
	}
	neighborHandle := state.neighborHandle
	directAttached := state.directAttached
	m.mu.Unlock()

	if !directAttached || !m.node.PromoteNeighborHandle(neighborHandle) {
		m.failLocal(attemptID, fmt.Errorf("shortcut: direct edge changed before probation promotion"), true)
		return false
	}

	m.mu.Lock()
	state = m.attempts[attemptID]
	if m.closed || state == nil || state.status.Phase != PhaseProbation ||
		!state.directAttached || state.neighborHandle != neighborHandle {
		m.mu.Unlock()
		return false
	}
	state.status.Phase = PhaseStable
	state.status.Failure = ""
	state.status.UpdatedAt = time.Now().UTC()
	m.notifyLocked(state)
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	return true
}

func (m *Manager) handleStable(from string, wire wireMessage) error {
	if m.node.NodeID() != wire.CoordinatorID || (from != wire.InitiatorID && from != wire.TargetID) {
		return fmt.Errorf("shortcut: invalid STABLE from %s", from)
	}
	m.mu.Lock()
	state := m.attempts[wire.AttemptID]
	if state == nil {
		m.mu.Unlock()
		return ErrUnknownAttempt
	}
	if state.status.Phase == PhaseFailed || state.status.Phase == PhaseStable {
		m.mu.Unlock()
		return nil
	}
	if state.status.Phase != PhaseProbation {
		m.mu.Unlock()
		return nil
	}
	state.stable[from] = true
	if state.stable[wire.InitiatorID] && state.stable[wire.TargetID] {
		state.status.Phase = PhaseStable
		state.status.UpdatedAt = time.Now().UTC()
		m.notifyLocked(state)
	}
	status := cloneStatus(state.status)
	m.mu.Unlock()
	m.emit(status)
	return nil
}

func (m *Manager) handleRemoteFailure(ctx context.Context, from string, wire wireMessage) error {
	if m.node.NodeID() != wire.CoordinatorID || (from != wire.InitiatorID && from != wire.TargetID) {
		return fmt.Errorf("shortcut: invalid FAILED from %s", from)
	}
	reason := errors.New(wire.Reason)
	if strings.TrimSpace(wire.Reason) == "" {
		reason = ErrAttemptFailed
	}
	m.abortFromCoordinator(ctx, wire, reason)
	return nil
}

func (m *Manager) handleAbort(from string, wire wireMessage) error {
	if from != wire.CoordinatorID {
		return fmt.Errorf("shortcut: ABORT did not come from coordinator")
	}
	m.failLocalNonTerminal(wire.AttemptID, errors.New(wire.Reason), false)
	return nil
}

func (m *Manager) abortFromCoordinator(ctx context.Context, wire wireMessage, cause error) {
	wire.Reason = compactError(cause)
	if !m.failAttempt(wire.AttemptID, cause, false, false) {
		return
	}
	_ = m.sendWire(ctx, wire.InitiatorID, typeAbort, wire)
	_ = m.sendWire(ctx, wire.TargetID, typeAbort, wire)
}

func (m *Manager) failLocal(attemptID string, cause error, notifyCoordinator bool) {
	m.failAttempt(attemptID, cause, notifyCoordinator, true)
}

func (m *Manager) failLocalNonTerminal(attemptID string, cause error, notifyCoordinator bool) {
	m.failAttempt(attemptID, cause, notifyCoordinator, false)
}

func (m *Manager) failAttempt(attemptID string, cause error, notifyCoordinator, includeStable bool) bool {
	reason := compactError(cause)
	m.mu.Lock()
	state := m.attempts[attemptID]
	if state == nil || state.status.Phase == PhaseFailed || (state.status.Phase == PhaseStable && !includeStable) {
		m.mu.Unlock()
		return false
	}
	state.status.Phase = PhaseFailed
	state.status.Failure = reason
	state.status.UpdatedAt = time.Now().UTC()
	coordinatorID := state.status.CoordinatorID
	wire := wireFromStatus(state.status, m.probation)
	strategy := state.strategy
	solveCancel := state.solveCancel
	neighborHandle := state.neighborHandle
	directAttached := state.directAttached
	state.strategy = nil
	state.solveCancel = nil
	state.directAttached = false
	state.pendingSolver = nil
	state.pendingBytes = 0
	state.solverDraining = false
	m.notifyLocked(state)
	status := cloneStatus(state.status)
	m.mu.Unlock()
	if solveCancel != nil {
		solveCancel()
	}
	if strategy != nil {
		_ = strategy.Close()
	}
	if directAttached {
		_ = m.node.RemoveNeighborHandle(neighborHandle)
	}
	m.emit(status)
	if notifyCoordinator && coordinatorID != "" {
		wire.Reason = reason
		_ = m.sendWireWithTimeout(coordinatorID, typeFailed, wire)
	}
	return true
}

func (m *Manager) sendWire(ctx context.Context, destination, signalType string, wire wireMessage) error {
	wire.SentAt = time.Now().UTC()
	raw, err := marshalWire(wire)
	if err != nil {
		return err
	}
	message := peercontrol.NewSessionSignal(m.node.NodeID(), destination, peercontrol.SessionSignal{
		Kind: SignalKind, Namespace: Namespace, Type: signalType, Payload: raw,
	})
	return m.node.Send(ctx, message)
}

func (m *Manager) notifyLocked(state *attemptState) {
	if state.changed != nil {
		close(state.changed)
	}
	state.changed = make(chan struct{})
}

func (m *Manager) startAttemptWatchdog(attemptID string) bool {
	m.mu.Lock()
	state := m.attempts[attemptID]
	if m.closed || state == nil {
		m.mu.Unlock()
		return false
	}
	if state.watchdogStarted {
		m.mu.Unlock()
		return true
	}
	state.watchdogStarted = true
	startedAt := state.status.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
		state.status.StartedAt = startedAt
	}
	deadline := startedAt.Add(m.attemptTimeout)
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		m.watchAttempt(attemptID, deadline)
	}()
	return true
}

func (m *Manager) watchAttempt(attemptID string, deadline time.Time) {
	wait := time.Until(deadline)
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		m.mu.Lock()
		state := m.attempts[attemptID]
		if state == nil || state.status.Phase == PhaseStable || state.status.Phase == PhaseFailed {
			m.mu.Unlock()
			return
		}
		changed := state.changed
		m.mu.Unlock()

		select {
		case <-m.ctx.Done():
			return
		case <-changed:
			continue
		case <-timer.C:
			m.timeoutAttempt(attemptID)
			return
		}
	}
}

func (m *Manager) timeoutAttempt(attemptID string) {
	m.mu.Lock()
	state := m.attempts[attemptID]
	if m.closed || state == nil || state.status.Phase == PhaseStable || state.status.Phase == PhaseFailed {
		m.mu.Unlock()
		return
	}
	role := state.status.LocalRole
	wire := wireFromStatus(state.status, m.probation)
	m.mu.Unlock()

	cause := fmt.Errorf("shortcut: attempt lifecycle timed out after %s", m.attemptTimeout)
	if role == "coordinator" {
		ctx, cancel := context.WithTimeout(
			m.ctx,
			saturatingPositiveDurationMultiply(m.packetNeighbor.WriteTimeout, 2),
		)
		defer cancel()
		m.abortFromCoordinator(ctx, wire, cause)
		return
	}
	m.failLocalNonTerminal(attemptID, cause, true)
}

func (m *Manager) startTask(task func()) bool {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false
	}
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		task()
	}()
	return true
}

func (m *Manager) emit(status Status) {
	if m.onEvent != nil {
		m.onEvent(Event{At: time.Now().UTC(), NodeID: m.node.NodeID(), Status: cloneStatus(status)})
	}
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.cancel()
	strategies := make([]solver.Strategy, 0, len(m.attempts))
	solveCancels := make([]context.CancelFunc, 0, len(m.attempts))
	neighborHandles := make([]mesh.NeighborHandle, 0, len(m.attempts))
	for _, state := range m.attempts {
		if state.strategy != nil {
			strategies = append(strategies, state.strategy)
			state.strategy = nil
		}
		if state.solveCancel != nil {
			solveCancels = append(solveCancels, state.solveCancel)
			state.solveCancel = nil
		}
		if state.directAttached {
			neighborHandles = append(neighborHandles, state.neighborHandle)
			state.directAttached = false
		}
		if state.status.Phase != PhaseFailed && state.status.Phase != PhaseStable {
			state.status.Phase = PhaseFailed
			state.status.Failure = ErrClosed.Error()
			state.status.UpdatedAt = time.Now().UTC()
			m.notifyLocked(state)
		}
	}
	unregister := m.unregister
	m.mu.Unlock()
	if unregister != nil {
		unregister()
	}
	for _, solveCancel := range solveCancels {
		solveCancel()
	}
	for _, strategy := range strategies {
		_ = strategy.Close()
	}
	for _, neighborHandle := range neighborHandles {
		_ = m.node.RemoveNeighborHandle(neighborHandle)
	}
	m.wg.Wait()
	return nil
}

func phaseReached(current, desired Phase) bool {
	rank := map[Phase]int{
		PhaseRequested: 1, PhasePreparing: 2, PhaseReady: 3, PhaseFiring: 4,
		PhaseSolving: 5, PhaseInstalled: 6, PhaseProbation: 7, PhaseStable: 8,
	}
	return rank[current] >= rank[desired] && rank[desired] > 0
}

func defaultAttemptLifecycleTimeout(solveTimeout, probation, peerTimeout time.Duration) time.Duration {
	return saturatingPositiveDurationSum(
		saturatingPositiveDurationMultiply(solveTimeout, 2),
		probation,
		saturatingPositiveDurationMultiply(peerTimeout, 2),
		defaultAttemptTimeoutSlack,
	)
}

func saturatingPositiveDurationMultiply(value time.Duration, factor int64) time.Duration {
	if value <= 0 || factor <= 0 {
		return 0
	}
	if value > maxTimeDuration/time.Duration(factor) {
		return maxTimeDuration
	}
	return value * time.Duration(factor)
}

func saturatingPositiveDurationSum(parts ...time.Duration) time.Duration {
	var total time.Duration
	for _, part := range parts {
		if part <= 0 {
			continue
		}
		if part > maxTimeDuration-total {
			return maxTimeDuration
		}
		total += part
	}
	return total
}

func sameEndpointPair(status Status, left, right string) bool {
	return (status.InitiatorID == left && status.TargetID == right) ||
		(status.InitiatorID == right && status.TargetID == left)
}

func strategyName(strategy solver.Strategy) string {
	if strategy == nil {
		return "<nil>"
	}
	return strategy.Name()
}

func compactError(err error) string {
	if err == nil {
		return "shortcut failed"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "shortcut failed"
	}
	if len(message) > 1024 {
		return message[:1024]
	}
	return message
}

func cloneStatus(status Status) Status {
	status.PathSummary = clonePathSummary(status.PathSummary)
	return status
}

func clonePathSummary(summary solver.PathSummary) solver.PathSummary {
	summary.Dependencies = append([]solver.PathDependency(nil), summary.Dependencies...)
	if summary.Details != nil {
		details := make(map[string]string, len(summary.Details))
		for key, value := range summary.Details {
			details[key] = value
		}
		summary.Details = details
	}
	if summary.Metrics != nil {
		metrics := make(map[string]string, len(summary.Metrics))
		for key, value := range summary.Metrics {
			metrics[key] = value
		}
		summary.Metrics = metrics
	}
	return summary
}

func wireFromStatus(status Status, probation time.Duration) wireMessage {
	return wireMessage{
		AttemptID: status.AttemptID, InitiatorID: status.InitiatorID, TargetID: status.TargetID,
		CoordinatorID: status.CoordinatorID, Strategy: status.Strategy,
		ProbationMillis: probation.Milliseconds(), PathID: status.PathSummary.PathID, SentAt: time.Now().UTC(),
	}
}
