package selfhosted

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/nat"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/recoverycard"
	"winkyou/pkg/transport/iceadapter"
)

const PathID = "selfbootstrap/direct"

var (
	ErrNoCandidate      = errors.New("selfbootstrap: no usable cached endpoint")
	ErrAlreadyReachable = errors.New("selfbootstrap: peer became reachable")
)

type State string

const (
	StateReachable   State = "reachable"
	StateWaitingHint State = "waiting_hint"
	StateScheduled   State = "scheduled"
	StatePunching    State = "punching"
	StateHello       State = "peer_hello"
	StateInstalling  State = "installing"
	StateAttached    State = "attached"
)

type PeerStatus struct {
	PeerID               string    `json:"peer_id"`
	State                State     `json:"state"`
	Candidate            string    `json:"candidate,omitempty"`
	CandidateGroup       string    `json:"candidate_group,omitempty"`
	CandidateIndex       int       `json:"candidate_index,omitempty"`
	CandidateTotal       int       `json:"candidate_total,omitempty"`
	CandidateEndpoints   int       `json:"candidate_endpoints,omitempty"`
	CandidateFailures    uint32    `json:"candidate_failures,omitempty"`
	AttemptID            string    `json:"attempt_id,omitempty"`
	AttemptWindowOrdinal int64     `json:"attempt_window_ordinal,omitempty"`
	AttemptWindowStart   time.Time `json:"attempt_window_start,omitempty"`
	AttemptWindowEnd     time.Time `json:"attempt_window_end,omitempty"`
	Attempts             uint64    `json:"attempts"`
	LastAttemptAt        time.Time `json:"last_attempt_at,omitempty"`
	NextAttemptAt        time.Time `json:"next_attempt_at,omitempty"`
	LastSuccessAt        time.Time `json:"last_success_at,omitempty"`
	PunchMethod          string    `json:"punch_method,omitempty"`
	LearnedRemote        string    `json:"learned_remote,omitempty"`
	FailureStage         string    `json:"failure_stage,omitempty"`
	LastError            string    `json:"last_error,omitempty"`
}

type Event struct {
	At                   time.Time
	PeerID               string
	State                State
	AttemptID            string
	Candidate            string
	CandidateGroup       string
	CandidateIndex       int
	CandidateTotal       int
	CandidateEndpoints   int
	CandidateFailures    uint32
	AttemptWindowOrdinal int64
	AttemptWindowStart   time.Time
	AttemptWindowEnd     time.Time
	PunchMethod          string
	LearnedRemote        string
	FailureStage         string
	// StableNeighbor identifies the exact packet-neighbor generation installed
	// after the cached-endpoint punch and authenticated peer hello completed.
	// It is intentionally populated only for StateAttached events.
	StableNeighbor mesh.NeighborHandle
	Err            error
}

type CardStore interface {
	Load() (recoverycard.Card, error)
	Update(func(*recoverycard.Card) error) error
}

type PunchFunc func(context.Context, puncher.Config) (*puncher.Result, error)

type Config struct {
	Node            *mesh.Node
	Store           CardStore
	PeerIDs         []string
	SharedSecret    []byte
	PacketNeighbor  mesh.PacketNeighborConfig
	AttemptWindow   time.Duration
	AttemptCycle    time.Duration
	HelloTimeout    time.Duration
	HelloInterval   time.Duration
	HelloSettle     time.Duration
	SocketCount     int
	BirthdayTargets int
	BirthdayLo      int
	BirthdayHi      int
	RoundDelay      time.Duration
	PunchGrace      time.Duration
	PredictSockets  int
	PredictSpan     int
	AllowNonPublic  bool
	Punch           PunchFunc
	Now             func() time.Time
	OnEvent         func(Event)
}

func (c Config) normalized() (Config, error) {
	if c.Node == nil {
		return Config{}, fmt.Errorf("selfbootstrap: mesh node is required")
	}
	if c.Store == nil {
		return Config{}, fmt.Errorf("selfbootstrap: recovery card store is required")
	}
	if c.AttemptWindow <= 0 {
		c.AttemptWindow = 45 * time.Second
	}
	if c.AttemptCycle <= 0 {
		c.AttemptCycle = time.Minute
	}
	if c.HelloTimeout <= 0 {
		c.HelloTimeout = 8 * time.Second
	}
	if c.HelloInterval <= 0 {
		c.HelloInterval = 200 * time.Millisecond
	}
	if c.HelloSettle <= 0 {
		c.HelloSettle = time.Second
	}
	if c.AttemptCycle <= c.AttemptWindow {
		return Config{}, fmt.Errorf("selfbootstrap: attempt cycle %s must exceed active window %s", c.AttemptCycle, c.AttemptWindow)
	}
	if c.HelloInterval >= c.HelloTimeout {
		return Config{}, fmt.Errorf("selfbootstrap: hello interval %s must be shorter than hello timeout %s", c.HelloInterval, c.HelloTimeout)
	}
	if c.HelloSettle >= c.HelloTimeout {
		return Config{}, fmt.Errorf("selfbootstrap: hello settle time %s must be shorter than hello timeout %s", c.HelloSettle, c.HelloTimeout)
	}
	if c.SocketCount <= 0 {
		c.SocketCount = 128
	}
	if c.BirthdayTargets <= 0 {
		c.BirthdayTargets = 48
	}
	if c.BirthdayLo <= 0 {
		c.BirthdayLo = 1024
	}
	if c.BirthdayHi <= 0 {
		c.BirthdayHi = 65535
	}
	if c.BirthdayLo > 65535 || c.BirthdayHi > 65535 || c.BirthdayHi < c.BirthdayLo {
		return Config{}, fmt.Errorf("selfbootstrap: birthday port range %d..%d is invalid", c.BirthdayLo, c.BirthdayHi)
	}
	if c.RoundDelay <= 0 {
		c.RoundDelay = 300 * time.Millisecond
	}
	if c.PunchGrace <= 0 {
		c.PunchGrace = 3 * time.Second
	}
	// Express the reservation as subtractions so extreme duration values cannot
	// overflow while being added together.
	if c.AttemptWindow <= c.HelloTimeout ||
		c.AttemptWindow-c.HelloTimeout <= c.PunchGrace ||
		c.AttemptWindow-c.HelloTimeout-c.PunchGrace <= time.Second {
		return Config{}, fmt.Errorf("selfbootstrap: attempt window %s must leave more than 1s after hello timeout %s and punch grace %s", c.AttemptWindow, c.HelloTimeout, c.PunchGrace)
	}
	if c.PredictSockets <= 0 {
		c.PredictSockets = 64
	}
	if c.PredictSpan <= 0 {
		c.PredictSpan = 16
	}
	if c.Punch == nil {
		c.Punch = puncher.Punch
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	c.PacketNeighbor = c.PacketNeighbor.Normalized()

	seen := make(map[string]struct{}, len(c.PeerIDs))
	peers := make([]string, 0, len(c.PeerIDs))
	for _, raw := range c.PeerIDs {
		peerID := strings.TrimSpace(raw)
		if peerID == "" || peerID == c.Node.NodeID() {
			return Config{}, fmt.Errorf("selfbootstrap: peer IDs must be non-empty and differ from local node")
		}
		if _, exists := seen[peerID]; exists {
			return Config{}, fmt.Errorf("selfbootstrap: duplicate peer %q", peerID)
		}
		seen[peerID] = struct{}{}
		peers = append(peers, peerID)
	}
	if len(peers) == 0 {
		return Config{}, fmt.Errorf("selfbootstrap: at least one peer is required")
	}
	sort.Strings(peers)
	c.PeerIDs = peers
	c.SharedSecret = append([]byte(nil), c.SharedSecret...)
	return c, nil
}

type peerRuntime struct {
	id                     string
	key                    [32]byte
	wake                   chan struct{}
	attemptCancel          context.CancelCauseFunc
	lastAttemptWindow      time.Time
	candidateFailures      map[string]uint32
	resetCandidateFailures atomic.Bool
}

func (p *peerRuntime) consumeCandidateFailureReset() bool {
	if p == nil || !p.resetCandidateFailures.Swap(false) {
		return false
	}
	clear(p.candidateFailures)
	return true
}

type candidateSelection struct {
	Group         candidateGroup
	Index         int
	Total         int
	Failures      uint32
	WindowOrdinal int64
}

type candidateAttemptError struct {
	stage    string
	penalize bool
	err      error
}

func (e *candidateAttemptError) Error() string { return e.err.Error() }
func (e *candidateAttemptError) Unwrap() error { return e.err }

type Engine struct {
	cfg    Config
	bootID string

	mu         sync.Mutex
	peers      map[string]*peerRuntime
	statuses   map[string]PeerStatus
	ctx        context.Context
	cancel     context.CancelFunc
	unregister func()
	started    bool
	closed     bool
	wg         sync.WaitGroup
	sequence   atomic.Uint64
}

func New(config Config) (*Engine, error) {
	cfg, err := config.normalized()
	if err != nil {
		return nil, err
	}
	bootID, err := newEngineBootID()
	if err != nil {
		return nil, err
	}
	engine := &Engine{
		cfg: cfg, bootID: bootID, peers: make(map[string]*peerRuntime, len(cfg.PeerIDs)),
		statuses: make(map[string]PeerStatus, len(cfg.PeerIDs)),
	}
	for _, peerID := range cfg.PeerIDs {
		key, err := pairKey(cfg.Node.NodeID(), peerID, cfg.SharedSecret)
		if err != nil {
			return nil, err
		}
		engine.peers[peerID] = &peerRuntime{
			id: peerID, key: key, wake: make(chan struct{}, 1),
			candidateFailures: make(map[string]uint32),
		}
		engine.statuses[peerID] = PeerStatus{PeerID: peerID, State: StateWaitingHint}
	}
	return engine, nil
}

func newEngineBootID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("selfbootstrap: create engine boot ID: %w", err)
	}
	return fmt.Sprintf("%x", raw), nil
}

func (e *Engine) nextAttemptID(peerID string, windowStart time.Time) string {
	return fmt.Sprintf(
		"selfboot-%s-%s-%s-%d-%d",
		e.cfg.Node.NodeID(), peerID, e.bootID, windowStart.Unix(), e.sequence.Add(1),
	)
}

func (e *Engine) Start(parent context.Context) error {
	if e == nil {
		return fmt.Errorf("selfbootstrap: engine is required")
	}
	if parent == nil {
		parent = context.Background()
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return mesh.ErrClosed
	}
	if e.started {
		e.mu.Unlock()
		return fmt.Errorf("selfbootstrap: engine already started")
	}
	if _, err := e.cfg.Store.Load(); err != nil {
		e.mu.Unlock()
		return fmt.Errorf("selfbootstrap: load recovery card: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	e.ctx, e.cancel, e.started = ctx, cancel, true
	e.mu.Unlock()

	unregister, err := e.cfg.Node.RegisterTopologyHandler(e.Notify)
	if err != nil {
		cancel()
		e.mu.Lock()
		e.started = false
		e.mu.Unlock()
		return fmt.Errorf("selfbootstrap: register topology handler: %w", err)
	}
	e.mu.Lock()
	if e.closed {
		e.started = false
		e.mu.Unlock()
		unregister()
		cancel()
		return mesh.ErrClosed
	}
	e.unregister = unregister
	peers := make([]*peerRuntime, 0, len(e.peers))
	for _, peer := range e.peers {
		peers = append(peers, peer)
	}
	// Add before releasing the lifecycle lock. Close cannot enter Wait while a
	// concurrent Start is still about to add these workers.
	e.wg.Add(len(peers))
	e.mu.Unlock()
	for _, peer := range peers {
		go func(state *peerRuntime) {
			defer e.wg.Done()
			e.runPeer(ctx, state)
		}(peer)
	}
	e.Notify()
	return nil
}

func (e *Engine) Notify() {
	if e == nil {
		return
	}
	type peerAttempt struct {
		peer   *peerRuntime
		cancel context.CancelCauseFunc
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	peers := make([]peerAttempt, 0, len(e.peers))
	for _, peer := range e.peers {
		peers = append(peers, peerAttempt{peer: peer, cancel: peer.attemptCancel})
	}
	e.mu.Unlock()
	for _, attempt := range peers {
		// Node queries may take router/topology locks. Keep them outside the
		// engine lock so topology and neighbor-close callbacks cannot create a
		// lock-order cycle with Snapshot, Close, or an attempt teardown.
		if attempt.cancel != nil && e.reachable(attempt.peer.id) {
			attempt.cancel(ErrAlreadyReachable)
		}
		select {
		case attempt.peer.wake <- struct{}{}:
		default:
		}
	}
}

func (e *Engine) Snapshot() []PeerStatus {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	result := make([]PeerStatus, 0, len(e.statuses))
	for _, status := range e.statuses {
		result = append(result, status)
	}
	e.mu.Unlock()
	sort.Slice(result, func(i, j int) bool { return result[i].PeerID < result[j].PeerID })
	return result
}

func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	cancel := e.cancel
	unregister := e.unregister
	var attemptCancels []context.CancelCauseFunc
	for _, peer := range e.peers {
		if peer.attemptCancel != nil {
			attemptCancels = append(attemptCancels, peer.attemptCancel)
		}
	}
	e.mu.Unlock()
	if unregister != nil {
		unregister()
	}
	if cancel != nil {
		cancel()
	}
	for _, stop := range attemptCancels {
		stop(context.Canceled)
	}
	e.wg.Wait()
}

func (e *Engine) runPeer(ctx context.Context, peer *peerRuntime) {
	for {
		if ctx.Err() != nil {
			return
		}
		if peer.consumeCandidateFailureReset() {
			e.setStatus(peer.id, func(status *PeerStatus) { status.CandidateFailures = 0 })
		}
		if e.reachable(peer.id) {
			e.setStatus(peer.id, func(status *PeerStatus) {
				status.State = StateReachable
				status.AttemptID = ""
				status.NextAttemptAt = time.Time{}
				status.FailureStage = ""
				status.LastError = ""
			})
			if !waitForWake(ctx, peer.wake, 30*time.Second) {
				return
			}
			continue
		}

		card, err := e.cfg.Store.Load()
		if err != nil {
			e.setFailure(peer, candidateSelection{}, "card_load", fmt.Errorf("load recovery card: %w", err))
			if !waitForWake(ctx, peer.wake, e.cfg.AttemptCycle) {
				return
			}
			continue
		}
		peerCard, found := recoveryPeer(card, peer.id)
		portfolio := buildCandidatePortfolio(peerCard, e.cfg.AllowNonPublic)
		if !found || len(portfolio.Groups) == 0 {
			e.setStatus(peer.id, func(status *PeerStatus) {
				status.State = StateWaitingHint
				clearCandidateStatus(status)
				status.AttemptID = ""
				status.NextAttemptAt = time.Time{}
				status.FailureStage = ""
				status.LastError = ErrNoCandidate.Error()
			})
			if !waitForWake(ctx, peer.wake, 30*time.Second) {
				return
			}
			continue
		}

		now := e.cfg.Now()
		windowStart, windowEnd, active, windowOrdinal := attemptWindowDetails(
			peer.key, now, e.cfg.AttemptCycle, e.cfg.AttemptWindow,
		)
		role := selfBootstrapPunchRole(e.cfg.Node.NodeID(), peer.id)
		selection, _ := selectRecoveryCandidate(peer, portfolio, windowOrdinal, role)
		alreadyTried := peer.lastAttemptWindow.Equal(windowStart)
		minimumRemaining := e.cfg.HelloTimeout + e.cfg.PunchGrace + time.Second
		if !active || alreadyTried || windowEnd.Sub(now) <= minimumRemaining {
			next := windowStart
			nextOrdinal := windowOrdinal
			if active || !now.Before(windowStart) {
				next = windowStart.Add(e.cfg.AttemptCycle)
				nextOrdinal++
			}
			planned, _ := selectRecoveryCandidate(peer, portfolio, nextOrdinal, role)
			e.setStatus(peer.id, func(status *PeerStatus) {
				status.State = StateScheduled
				status.AttemptID = ""
				if !alreadyTried {
					applyCandidateSelection(status, planned)
					status.AttemptWindowStart = next
					status.AttemptWindowEnd = next.Add(e.cfg.AttemptWindow)
					status.PunchMethod = ""
					status.LearnedRemote = ""
					status.FailureStage = ""
					status.LastError = ""
				}
				status.NextAttemptAt = next
			})
			if !waitUntilOrWake(ctx, peer.wake, next, e.cfg.Now) {
				return
			}
			continue
		}

		// A pair gets at most one candidate group per deterministic window. The
		// absolute window ordinal and complementary roles choose one coordinate
		// in the bounded candidate cross-product, so asymmetric local histories
		// still meet without either endpoint running ahead independently.
		peer.lastAttemptWindow = windowStart
		if err := e.runAttempt(ctx, peer, card, peerCard, selection, windowStart, windowEnd); err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, ErrAlreadyReachable) {
				e.setSuperseded(peer, selection)
				continue
			}
			stage, penalize := candidateFailureInfo(err)
			if penalize {
				peer.candidateFailures[selection.Group.ID]++
				selection.Failures = peer.candidateFailures[selection.Group.ID]
			}
			e.setFailure(peer, selection, stage, err)
		}
	}
}

func (e *Engine) runAttempt(
	parent context.Context,
	peer *peerRuntime,
	card recoverycard.Card,
	peerCard recoverycard.Peer,
	selection candidateSelection,
	windowStart, windowEnd time.Time,
) error {
	if e.reachable(peer.id) {
		return ErrAlreadyReachable
	}
	if len(selection.Group.Anchors) == 0 {
		return newCandidateAttemptError("candidate", false, fmt.Errorf("selfbootstrap: selected candidate group has no endpoint anchors"))
	}
	candidate := selection.Group.Anchors[0].Endpoint
	punchConfig := e.punchConfig(peer.key, card, peerCard, selection.Group)
	attemptID := e.nextAttemptID(peer.id, windowStart)
	deadlineCtx, stopDeadline := context.WithDeadline(parent, windowEnd)
	attemptCtx, cancel := context.WithCancelCause(deadlineCtx)
	e.mu.Lock()
	peer.attemptCancel = cancel
	e.mu.Unlock()
	defer func() {
		cancel(nil)
		stopDeadline()
		e.mu.Lock()
		peer.attemptCancel = nil
		e.mu.Unlock()
	}()
	// Close the topology-notification gap between runPeer's reachability check
	// and publishing attemptCancel. A route that appeared in that interval may
	// already have fired its notification before there was a cancel function.
	if e.reachable(peer.id) {
		cancel(ErrAlreadyReachable)
		return ErrAlreadyReachable
	}

	e.setStatus(peer.id, func(status *PeerStatus) {
		status.State = StatePunching
		applyCandidateSelection(status, selection)
		status.AttemptID = attemptID
		status.AttemptWindowStart = windowStart
		status.AttemptWindowEnd = windowEnd
		status.Attempts++
		status.LastAttemptAt = e.cfg.Now().UTC()
		status.NextAttemptAt = time.Time{}
		status.PunchMethod = punchConfig.Method
		status.LearnedRemote = ""
		status.FailureStage = ""
		status.LastError = ""
	})
	e.emit(peer.id, StatePunching, attemptID, candidate.AddrPort, nil)

	punchDeadline := windowEnd.Add(-e.cfg.HelloTimeout)
	if !punchDeadline.After(e.cfg.Now()) {
		return newCandidateAttemptError("window", false, fmt.Errorf("selfbootstrap: attempt window has no punch time remaining"))
	}
	punchCtx, stopPunch := context.WithDeadline(attemptCtx, punchDeadline)
	result, err := e.cfg.Punch(punchCtx, punchConfig)
	stopPunch()
	if errors.Is(context.Cause(attemptCtx), ErrAlreadyReachable) {
		if result != nil && result.Conn != nil {
			_ = result.Conn.Close()
		}
		return ErrAlreadyReachable
	}
	if err != nil {
		if e.reachable(peer.id) {
			return ErrAlreadyReachable
		}
		// Only a punch deadline is negative reachability evidence. Immediate
		// bind/socket/configuration failures are local and must not make a remote
		// candidate look worse, even though the absolute schedule will advance.
		penalize := errors.Is(err, context.DeadlineExceeded)
		return newCandidateAttemptError("punch", penalize, fmt.Errorf("selfbootstrap: punch %s: %w", candidate.AddrPort, err))
	}
	if result == nil || result.Conn == nil || result.RemoteAddr == nil || result.LocalAddr == nil {
		if result != nil && result.Conn != nil {
			_ = result.Conn.Close()
		}
		return newCandidateAttemptError("punch", false, fmt.Errorf("selfbootstrap: punch returned an incomplete result"))
	}
	conn := result.Connected()
	owned := true
	defer func() {
		if owned {
			_ = conn.Close()
		}
	}()

	e.setStatus(peer.id, func(status *PeerStatus) { status.State = StateHello })
	e.emit(peer.id, StateHello, attemptID, candidate.AddrPort, nil)
	helloCtx, stopHello := context.WithDeadline(attemptCtx, windowEnd)
	err = authenticatePeer(helloCtx, conn, e.cfg.Node.NodeID(), peer.id, peer.key, pairSession(peer.key), helloConfig{
		Interval: e.cfg.HelloInterval, Settle: e.cfg.HelloSettle,
	})
	stopHello()
	if errors.Is(context.Cause(attemptCtx), ErrAlreadyReachable) {
		return ErrAlreadyReachable
	}
	if err != nil {
		if e.reachable(peer.id) {
			return ErrAlreadyReachable
		}
		return newCandidateAttemptError("peer_hello", true, fmt.Errorf("selfbootstrap: peer hello: %w", err))
	}
	if e.reachable(peer.id) {
		return ErrAlreadyReachable
	}

	e.setStatus(peer.id, func(status *PeerStatus) { status.State = StateInstalling })
	e.emit(peer.id, StateInstalling, attemptID, candidate.AddrPort, nil)
	neighborConfig := e.cfg.PacketNeighbor
	// Keep the new session out of the routed graph until the exact
	// authenticated attachment is installed. This prevents another node from
	// using a half-installed self-bootstrap edge as transit.
	neighborConfig.DeferAdvertisement = true
	configuredOnClose := neighborConfig.OnClose
	closeEvent := e.event(peer.id, StateScheduled, attemptID, candidate.AddrPort, mesh.NeighborHandle{}, nil)
	closeEvent.LearnedRemote = result.RemoteAddr.String()
	closeEvent.FailureStage = "neighbor_closed"
	neighborConfig.OnClose = func(peerID string, cause error) {
		if configuredOnClose != nil {
			configuredOnClose(peerID, cause)
		}
		if e.cfg.OnEvent != nil {
			event := closeEvent
			event.At = e.cfg.Now().UTC()
			event.PeerID = peerID
			event.Err = cause
			e.cfg.OnEvent(event)
		}
		e.Notify()
	}
	packetTransport := iceadapter.New(conn, PathID)
	owned = false // AttachPacketTransportWithHandle consumes packetTransport on every return path.
	neighborHandle, err := e.cfg.Node.AttachPacketTransportWithHandle(peer.id, packetTransport, neighborConfig)
	if err != nil {
		if e.reachable(peer.id) {
			return ErrAlreadyReachable
		}
		return newCandidateAttemptError("install", false, fmt.Errorf("selfbootstrap: attach packet neighbor: %w", err))
	}
	if !e.cfg.Node.PromoteNeighborHandle(neighborHandle) {
		_ = e.cfg.Node.RemoveNeighborHandle(neighborHandle)
		return newCandidateAttemptError("promote", false, fmt.Errorf("selfbootstrap: authenticated packet neighbor changed before promotion"))
	}

	succeededAt := e.cfg.Now().UTC()
	e.setStatus(peer.id, func(status *PeerStatus) {
		status.State = StateAttached
		status.LastSuccessAt = succeededAt
		status.NextAttemptAt = time.Time{}
		status.LearnedRemote = result.RemoteAddr.String()
		status.CandidateFailures = 0
		status.FailureStage = ""
		status.LastError = ""
	})
	delete(peer.candidateFailures, selection.Group.ID)
	e.emitAttached(peer.id, attemptID, result.RemoteAddr.String(), neighborHandle, nil)
	observation := Observation{
		PeerID: peer.id, RemoteAddr: result.RemoteAddr, LocalAddr: result.LocalAddr,
		Source: "selfbootstrap", RemoteNAT: learnedRemoteNAT(peerCard, result.RemoteAddr),
		LocalNAT: card.LocalNAT, At: succeededAt,
	}
	if err := e.Observe(observation); err != nil {
		e.emitAttached(peer.id, attemptID, result.RemoteAddr.String(), neighborHandle, fmt.Errorf("persist successful endpoint: %w", err))
	}
	return nil
}

func (e *Engine) punchConfig(
	key [32]byte,
	card recoverycard.Card,
	peer recoverycard.Peer,
	group candidateGroup,
) puncher.Config {
	primary := group.Anchors[0]
	candidate := primary.Endpoint
	pattern := toNATPattern(candidate.NAT.Pattern)
	report := nat.PortAllocationReport{Pattern: pattern, Delta: candidate.NAT.Delta}
	targets := make([]int, 0, len(group.Anchors)+e.cfg.PredictSpan+3)
	seenTargets := make(map[int]struct{}, cap(targets))
	appendTarget := func(port int) {
		if port < 1 || port > 65535 {
			return
		}
		if _, exists := seenTargets[port]; exists {
			return
		}
		seenTargets[port] = struct{}{}
		targets = append(targets, port)
	}
	for _, anchor := range group.Anchors {
		appendTarget(int(anchor.AddrPort.Port()))
	}
	sockets := e.cfg.SocketCount
	birthdayN := e.cfg.BirthdayTargets
	method := "cached_birthday"
	if pattern == nat.PortAllocationPreserving || pattern == nat.PortAllocationSequential {
		for _, predicted := range report.PredictMappedPorts(int(primary.AddrPort.Port()), e.cfg.PredictSpan) {
			appendTarget(predicted)
		}
		sockets = e.cfg.PredictSockets
		birthdayN = 0
		method = "cached_predictive"
	}
	localPort := 0
	if card.LocalNAT.Pattern == recoverycard.PortPatternPreserving {
		localPort = int(peer.LastSuccessfulLocalBindPort)
	}
	return puncher.Config{
		RemoteIP: net.IP(group.IP.AsSlice()), TargetPorts: targets,
		Session: pairSession(key), Role: selfBootstrapPunchRole(e.cfg.Node.NodeID(), peer.NodeID),
		SocketCount: sockets, LocalPort: localPort,
		BirthdayN: birthdayN, BirthdayLo: e.cfg.BirthdayLo, BirthdayHi: e.cfg.BirthdayHi,
		Burst: 1, RoundDelay: e.cfg.RoundDelay, Method: method, GracePeriod: e.cfg.PunchGrace,
	}
}

func selfBootstrapPunchRole(localID, peerID string) puncher.Role {
	if localID < peerID {
		return puncher.RoleSelector
	}
	return puncher.RoleReceiver
}

func (e *Engine) reachable(peerID string) bool {
	if e.cfg.Node.HasNeighbor(peerID) {
		return true
	}
	_, ok := e.cfg.Node.Route(peerID)
	return ok
}

func (e *Engine) setStatus(peerID string, update func(*PeerStatus)) {
	e.mu.Lock()
	status := e.statuses[peerID]
	if status.PeerID == "" {
		status.PeerID = peerID
	}
	update(&status)
	e.statuses[peerID] = status
	e.mu.Unlock()
}

func (e *Engine) setFailure(peer *peerRuntime, selection candidateSelection, stage string, err error) {
	next := nextAttemptWindow(peer.key, e.cfg.Now(), e.cfg.AttemptCycle, e.cfg.AttemptWindow)
	failedAttemptID := ""
	e.setStatus(peer.id, func(status *PeerStatus) {
		failedAttemptID = status.AttemptID
		status.State = StateScheduled
		if selection.Total > 0 {
			applyCandidateSelection(status, selection)
		} else {
			clearCandidateStatus(status)
		}
		status.AttemptID = ""
		status.NextAttemptAt = next
		status.FailureStage = stage
		status.LastError = compactError(err)
	})
	candidate := ""
	if len(selection.Group.Anchors) > 0 {
		candidate = selection.Group.Anchors[0].Endpoint.AddrPort
	}
	e.emit(peer.id, StateScheduled, failedAttemptID, candidate, err)
}

func (e *Engine) setSuperseded(peer *peerRuntime, selection candidateSelection) {
	stillReachable := e.reachable(peer.id)
	next := nextAttemptWindow(peer.key, e.cfg.Now(), e.cfg.AttemptCycle, e.cfg.AttemptWindow)
	state := StateScheduled
	if stillReachable {
		state = StateReachable
	}
	attemptID := ""
	e.setStatus(peer.id, func(status *PeerStatus) {
		attemptID = status.AttemptID
		if attemptID == "" {
			return
		}
		status.State = state
		status.AttemptID = ""
		status.FailureStage = "superseded_route"
		status.LastError = ""
		if stillReachable {
			status.NextAttemptAt = time.Time{}
		} else {
			status.NextAttemptAt = next
		}
	})
	if attemptID == "" {
		return
	}
	candidate := ""
	if len(selection.Group.Anchors) > 0 {
		candidate = selection.Group.Anchors[0].Endpoint.AddrPort
	}
	e.emit(peer.id, state, attemptID, candidate, nil)
}

func (e *Engine) emit(peerID string, state State, attemptID, candidate string, err error) {
	if e.cfg.OnEvent == nil {
		return
	}
	e.cfg.OnEvent(e.event(peerID, state, attemptID, candidate, mesh.NeighborHandle{}, err))
}

func (e *Engine) emitAttached(peerID, attemptID, candidate string, handle mesh.NeighborHandle, err error) {
	if e.cfg.OnEvent == nil {
		return
	}
	e.cfg.OnEvent(e.event(peerID, StateAttached, attemptID, candidate, handle, err))
}

func (e *Engine) event(peerID string, state State, attemptID, candidate string, handle mesh.NeighborHandle, err error) Event {
	e.mu.Lock()
	status := e.statuses[peerID]
	e.mu.Unlock()
	return Event{
		At: e.cfg.Now().UTC(), PeerID: peerID, State: state,
		AttemptID: attemptID, Candidate: candidate,
		CandidateGroup: status.CandidateGroup, CandidateIndex: status.CandidateIndex,
		CandidateTotal: status.CandidateTotal, CandidateEndpoints: status.CandidateEndpoints,
		CandidateFailures:    status.CandidateFailures,
		AttemptWindowOrdinal: status.AttemptWindowOrdinal,
		AttemptWindowStart:   status.AttemptWindowStart, AttemptWindowEnd: status.AttemptWindowEnd,
		PunchMethod: status.PunchMethod, LearnedRemote: status.LearnedRemote,
		FailureStage: status.FailureStage, StableNeighbor: handle, Err: err,
	}
}

func compactError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	if len(text) > 512 {
		text = text[:512]
	}
	return text
}

func recoveryPeer(card recoverycard.Card, peerID string) (recoverycard.Peer, bool) {
	for _, peer := range card.Peers {
		if peer.NodeID == peerID {
			return peer, true
		}
	}
	return recoverycard.Peer{}, false
}

func learnedRemoteNAT(peer recoverycard.Peer, remote net.Addr) recoverycard.NATModel {
	learned, err := addrPortFromNetAddr(remote)
	if err != nil {
		return recoverycard.NATModel{Pattern: recoverycard.PortPatternUnknown}
	}
	var newestSameIP recoverycard.Endpoint
	for _, endpoint := range peer.Endpoints {
		address, ok := candidateAddrPort(endpoint.AddrPort, true)
		if !ok || address.Addr() != learned.Addr() {
			continue
		}
		if address == learned {
			return endpoint.NAT
		}
		if newestSameIP.LastSuccessAt.IsZero() || endpoint.LastSuccessAt.After(newestSameIP.LastSuccessAt) {
			newestSameIP = endpoint
		}
	}
	if !newestSameIP.LastSuccessAt.IsZero() {
		return newestSameIP.NAT
	}
	return recoverycard.NATModel{Pattern: recoverycard.PortPatternUnknown}
}

func selectRecoveryCandidate(
	peer *peerRuntime,
	portfolio candidatePortfolio,
	windowOrdinal int64,
	role puncher.Role,
) (candidateSelection, bool) {
	if peer == nil || len(portfolio.Groups) == 0 {
		return candidateSelection{}, false
	}
	activeGroups := make(map[string]struct{}, len(portfolio.Groups))
	for _, group := range portfolio.Groups {
		activeGroups[group.ID] = struct{}{}
	}
	for id := range peer.candidateFailures {
		if _, active := activeGroups[id]; !active {
			delete(peer.candidateFailures, id)
		}
	}

	selected := recoveryCandidateScheduleIndex(windowOrdinal, role, len(portfolio.Groups))
	selectedFailures := peer.candidateFailures[portfolio.Groups[selected].ID]
	return candidateSelection{
		Group: portfolio.Groups[selected], Index: selected + 1,
		Total: len(portfolio.Groups), Failures: selectedFailures, WindowOrdinal: windowOrdinal,
	}, true
}

// recoveryCandidateScheduleIndex maps an absolute pair-window ordinal onto one
// axis of a 4x4 cross-product. The selector advances on the fast axis and the
// receiver on the slow axis. Every 16 consecutive windows therefore cover all
// retained rank combinations, even when the two cards rank the working remote
// endpoint differently. Smaller portfolios repeat their ranks via modulo.
func recoveryCandidateScheduleIndex(windowOrdinal int64, role puncher.Role, groupCount int) int {
	if groupCount <= 1 {
		return 0
	}
	const scheduleSize = int64(maxCandidateGroups * maxCandidateGroups)
	phase := windowOrdinal % scheduleSize
	if phase < 0 {
		phase += scheduleSize
	}
	coordinate := phase % int64(maxCandidateGroups)
	if role == puncher.RoleReceiver {
		coordinate = phase / int64(maxCandidateGroups)
	}
	return int(coordinate) % groupCount
}

func applyCandidateSelection(status *PeerStatus, selection candidateSelection) {
	if status == nil || len(selection.Group.Anchors) == 0 {
		return
	}
	status.Candidate = selection.Group.Anchors[0].Endpoint.AddrPort
	status.CandidateGroup = selection.Group.ID
	status.CandidateIndex = selection.Index
	status.CandidateTotal = selection.Total
	status.CandidateEndpoints = len(selection.Group.Anchors)
	status.CandidateFailures = selection.Failures
	status.AttemptWindowOrdinal = selection.WindowOrdinal
}

func clearCandidateStatus(status *PeerStatus) {
	if status == nil {
		return
	}
	status.Candidate = ""
	status.CandidateGroup = ""
	status.CandidateIndex = 0
	status.CandidateTotal = 0
	status.CandidateEndpoints = 0
	status.CandidateFailures = 0
	status.AttemptWindowOrdinal = 0
	status.AttemptWindowStart = time.Time{}
	status.AttemptWindowEnd = time.Time{}
	status.PunchMethod = ""
	status.LearnedRemote = ""
}

func newCandidateAttemptError(stage string, penalize bool, err error) error {
	return &candidateAttemptError{stage: stage, penalize: penalize, err: err}
}

func candidateFailureInfo(err error) (string, bool) {
	var attemptErr *candidateAttemptError
	if errors.As(err, &attemptErr) {
		return attemptErr.stage, attemptErr.penalize
	}
	return "attempt", false
}

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

func isPublicIPv4(address netip.Addr) bool {
	address = address.Unmap()
	return address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !carrierGradeNAT.Contains(address)
}

func toNATPattern(pattern recoverycard.PortPattern) nat.PortAllocationPattern {
	switch pattern {
	case recoverycard.PortPatternPreserving:
		return nat.PortAllocationPreserving
	case recoverycard.PortPatternSequential:
		return nat.PortAllocationSequential
	case recoverycard.PortPatternRandom:
		return nat.PortAllocationRandom
	default:
		return nat.PortAllocationUnknown
	}
}

func attemptWindow(key [32]byte, now time.Time, cycle, active time.Duration) (time.Time, time.Time, bool) {
	start, end, activeNow, _ := attemptWindowDetails(key, now, cycle, active)
	return start, end, activeNow
}

func attemptWindowDetails(key [32]byte, now time.Time, cycle, active time.Duration) (time.Time, time.Time, bool, int64) {
	cycleNanos := cycle.Nanoseconds()
	offset := int64(binary.BigEndian.Uint64(key[:8]) % uint64(cycleNanos))
	nowNanos := now.UnixNano()
	shifted := nowNanos - offset
	index := shifted / cycleNanos
	if shifted < 0 && shifted%cycleNanos != 0 {
		index--
	}
	start := time.Unix(0, index*cycleNanos+offset).In(now.Location())
	end := start.Add(active)
	return start, end, !now.Before(start) && now.Before(end), index
}

func nextAttemptWindow(key [32]byte, now time.Time, cycle, active time.Duration) time.Time {
	start, end, activeNow := attemptWindow(key, now, cycle, active)
	if activeNow && end.Sub(now) > 0 {
		return start.Add(cycle)
	}
	if now.Before(start) {
		return start
	}
	return start.Add(cycle)
}

func waitForWake(ctx context.Context, wake <-chan struct{}, duration time.Duration) bool {
	if duration <= 0 {
		duration = time.Second
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	case <-timer.C:
		return true
	}
}

func waitUntilOrWake(ctx context.Context, wake <-chan struct{}, target time.Time, now func() time.Time) bool {
	delay := target.Sub(now())
	if delay <= 0 {
		return true
	}
	return waitForWake(ctx, wake, delay)
}

type Observation struct {
	PeerID     string
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Source     string
	RemoteNAT  recoverycard.NATModel
	LocalNAT   recoverycard.NATModel
	At         time.Time
}

// Observe persists one verified direct path. It is safe to call from both the
// self-bootstrap engine and the normal coordinator-driven shortcut lifecycle.
func (e *Engine) Observe(observation Observation) error {
	if e == nil {
		return fmt.Errorf("selfbootstrap: engine is required")
	}
	peerID := strings.TrimSpace(observation.PeerID)
	if _, ok := e.peers[peerID]; !ok {
		return fmt.Errorf("selfbootstrap: observation peer %q is not configured", peerID)
	}
	remote, err := addrPortFromNetAddr(observation.RemoteAddr)
	if err != nil {
		return fmt.Errorf("selfbootstrap: remote endpoint: %w", err)
	}
	local, err := addrPortFromNetAddr(observation.LocalAddr)
	if err != nil {
		return fmt.Errorf("selfbootstrap: local endpoint: %w", err)
	}
	at := observation.At.UTC()
	if at.IsZero() {
		at = e.cfg.Now().UTC()
	}
	source := strings.TrimSpace(observation.Source)
	if source == "" {
		source = "successful_path"
	}
	localNAT := normalizeNATModel(observation.LocalNAT, at)
	remoteNAT := normalizeNATModel(observation.RemoteNAT, at)
	err = e.cfg.Store.Update(func(card *recoverycard.Card) error {
		if card.Version == 0 {
			card.Version = recoverycard.CurrentVersion
			card.NodeID = e.cfg.Node.NodeID()
		}
		updatedAt := latestTime(card.UpdatedAt, at, localNAT.ObservedAt, remoteNAT.ObservedAt)
		card.UpdatedAt = updatedAt
		if card.LocalNAT.ObservedAt.IsZero() || !localNAT.ObservedAt.Before(card.LocalNAT.ObservedAt) {
			card.LocalNAT = localNAT
		}
		localPort := local.Port()
		peerIndex := -1
		for i := range card.Peers {
			if card.Peers[i].NodeID == peerID {
				peerIndex = i
				break
			}
		}
		if peerIndex < 0 {
			if len(card.Peers) >= recoverycard.MaxPeers {
				evictOldestPeer(card, "")
			}
			card.Peers = append(card.Peers, recoverycard.Peer{NodeID: peerID})
			peerIndex = len(card.Peers) - 1
		}
		peer := &card.Peers[peerIndex]
		latestForPeer := peer.LastSuccessAt.IsZero() || !at.Before(peer.LastSuccessAt)
		if latestForPeer {
			peer.LastSuccessfulLocalBindPort = localPort
			if err := rememberLocalBindPort(card, localPort, peerID); err != nil {
				return err
			}
			// Bounded-port eviction may have removed older peer records and moved
			// the backing slice. Reacquire the protected current peer.
			peerIndex = indexOfPeer(card.Peers, peerID)
			if peerIndex < 0 {
				return fmt.Errorf("selfbootstrap: current peer %q was evicted while retaining bind port", peerID)
			}
			peer = &card.Peers[peerIndex]
		}
		endpointIndex := -1
		for i := range peer.Endpoints {
			if peer.Endpoints[i].AddrPort == remote.String() {
				endpointIndex = i
				break
			}
		}
		endpoint := recoverycard.Endpoint{
			AddrPort: remote.String(), ObservedAt: at, Source: source,
			NAT: remoteNAT, LastSuccessAt: at,
		}
		if endpointIndex >= 0 {
			// A delayed callback must not replace newer endpoint metadata or NAT
			// evidence with an older observation.
			if !peer.Endpoints[endpointIndex].LastSuccessAt.After(at) {
				peer.Endpoints[endpointIndex] = endpoint
			}
		} else {
			peer.Endpoints = append(peer.Endpoints, endpoint)
		}
		sort.SliceStable(peer.Endpoints, func(i, j int) bool {
			return peer.Endpoints[i].LastSuccessAt.After(peer.Endpoints[j].LastSuccessAt)
		})
		if len(peer.Endpoints) > recoverycard.MaxEndpointsPerPeer {
			peer.Endpoints = peer.Endpoints[:recoverycard.MaxEndpointsPerPeer]
		}
		peer.LastSuccessAt = newestEndpointSuccess(peer.Endpoints)
		sort.SliceStable(card.Peers, func(i, j int) bool { return card.Peers[i].NodeID < card.Peers[j].NodeID })
		card.LastSuccessAt = newestPeerSuccess(card.Peers)
		card.UpdatedAt = latestTime(card.UpdatedAt, card.LastSuccessAt, card.LocalNAT.ObservedAt)
		return nil
	})
	if err == nil {
		e.peers[peerID].resetCandidateFailures.Store(true)
		e.Notify()
	}
	return err
}

func normalizeNATModel(model recoverycard.NATModel, at time.Time) recoverycard.NATModel {
	switch model.Pattern {
	case recoverycard.PortPatternUnknown, recoverycard.PortPatternPreserving,
		recoverycard.PortPatternSequential, recoverycard.PortPatternRandom:
	default:
		model.Pattern = recoverycard.PortPatternUnknown
	}
	if model.Pattern != recoverycard.PortPatternSequential {
		model.Delta = 0
	}
	if model.Pattern == recoverycard.PortPatternSequential && model.Delta == 0 {
		model.Pattern = recoverycard.PortPatternUnknown
	}
	if math.IsNaN(model.Confidence) || math.IsInf(model.Confidence, 0) || model.Confidence < 0 || model.Confidence > 1 {
		model.Confidence = 0
	}
	if model.ObservedAt.IsZero() || model.ObservedAt.After(at) {
		model.ObservedAt = at
	} else {
		model.ObservedAt = model.ObservedAt.UTC()
	}
	return model
}

func addrPortFromNetAddr(address net.Addr) (netip.AddrPort, error) {
	if address == nil {
		return netip.AddrPort{}, fmt.Errorf("address is required")
	}
	if udp, ok := address.(*net.UDPAddr); ok {
		parsed, ok := netip.AddrFromSlice(udp.IP)
		if !ok || udp.Port < 1 || udp.Port > 65535 {
			return netip.AddrPort{}, fmt.Errorf("invalid UDP address %v", address)
		}
		return netip.AddrPortFrom(parsed.Unmap(), uint16(udp.Port)), nil
	}
	parsed, err := netip.ParseAddrPort(address.String())
	if err != nil || parsed.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid address %q", address.String())
	}
	return parsed, nil
}

func containsPort(ports []uint16, port uint16) bool {
	for _, current := range ports {
		if current == port {
			return true
		}
	}
	return false
}

// rememberLocalBindPort keeps a bounded, recency-ordered history. When all
// slots are still referenced, the schema cannot represent another distinct
// current bind port; retain the newest success by evicting the oldest complete
// peer group that depends on one old port. protectedPeer is never evicted.
func rememberLocalBindPort(card *recoverycard.Card, port uint16, protectedPeer string) error {
	for i, current := range card.LocalBindPorts {
		if current != port {
			continue
		}
		copy(card.LocalBindPorts[i:], card.LocalBindPorts[i+1:])
		card.LocalBindPorts[len(card.LocalBindPorts)-1] = port
		return nil
	}
	if len(card.LocalBindPorts) < recoverycard.MaxLocalBindPorts {
		card.LocalBindPorts = append(card.LocalBindPorts, port)
		return nil
	}
	references := make(map[uint16]int, len(card.Peers))
	for _, peer := range card.Peers {
		if peer.LastSuccessfulLocalBindPort != 0 {
			references[peer.LastSuccessfulLocalBindPort]++
		}
	}
	for i, current := range card.LocalBindPorts {
		if references[current] != 0 {
			continue
		}
		copy(card.LocalBindPorts[i:], card.LocalBindPorts[i+1:])
		card.LocalBindPorts[len(card.LocalBindPorts)-1] = port
		return nil
	}

	// Every slot is live. Choose the port whose newest dependent peer is oldest,
	// then evict the entire group so no remaining record references a missing
	// bind port.
	victimPort := uint16(0)
	victimNewest := time.Time{}
	for _, candidate := range card.LocalBindPorts {
		candidateNewest := time.Time{}
		protected := false
		for _, peer := range card.Peers {
			if peer.LastSuccessfulLocalBindPort != candidate {
				continue
			}
			if peer.NodeID == protectedPeer {
				protected = true
				break
			}
			candidateNewest = latestTime(candidateNewest, peer.LastSuccessAt)
		}
		if protected {
			continue
		}
		if victimPort == 0 || candidateNewest.Before(victimNewest) {
			victimPort = candidate
			victimNewest = candidateNewest
		}
	}
	if victimPort == 0 {
		return fmt.Errorf("selfbootstrap: no bind-port history slot can be freed for peer %q", protectedPeer)
	}
	peers := card.Peers[:0]
	for _, peer := range card.Peers {
		if peer.LastSuccessfulLocalBindPort != victimPort {
			peers = append(peers, peer)
		}
	}
	card.Peers = peers
	for i, current := range card.LocalBindPorts {
		if current != victimPort {
			continue
		}
		copy(card.LocalBindPorts[i:], card.LocalBindPorts[i+1:])
		card.LocalBindPorts[len(card.LocalBindPorts)-1] = port
		return nil
	}
	return fmt.Errorf("selfbootstrap: selected bind-port victim %d is absent from history", victimPort)
}

func indexOfPeer(peers []recoverycard.Peer, peerID string) int {
	for i := range peers {
		if peers[i].NodeID == peerID {
			return i
		}
	}
	return -1
}

func evictOldestPeer(card *recoverycard.Card, protectedPeer string) {
	victim := -1
	for i := range card.Peers {
		if card.Peers[i].NodeID == protectedPeer {
			continue
		}
		if victim < 0 || card.Peers[i].LastSuccessAt.Before(card.Peers[victim].LastSuccessAt) {
			victim = i
		}
	}
	if victim >= 0 {
		card.Peers = append(card.Peers[:victim], card.Peers[victim+1:]...)
	}
}

func newestEndpointSuccess(endpoints []recoverycard.Endpoint) time.Time {
	result := time.Time{}
	for _, endpoint := range endpoints {
		result = latestTime(result, endpoint.LastSuccessAt)
	}
	return result
}

func newestPeerSuccess(peers []recoverycard.Peer) time.Time {
	result := time.Time{}
	for _, peer := range peers {
		result = latestTime(result, peer.LastSuccessAt)
	}
	return result
}

func latestTime(values ...time.Time) time.Time {
	result := time.Time{}
	for _, value := range values {
		if value.After(result) {
			result = value.UTC()
		}
	}
	return result
}

func NATModelFromStrings(pattern, delta string, observedAt time.Time) recoverycard.NATModel {
	model := recoverycard.NATModel{Pattern: recoverycard.PortPattern(strings.TrimSpace(pattern)), ObservedAt: observedAt.UTC()}
	if parsed, err := strconv.Atoi(strings.TrimSpace(delta)); err == nil {
		model.Delta = parsed
	}
	return normalizeNATModel(model, observedAt.UTC())
}
