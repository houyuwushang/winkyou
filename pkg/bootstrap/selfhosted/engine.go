package selfhosted

import (
	"context"
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
	PeerID        string    `json:"peer_id"`
	State         State     `json:"state"`
	Candidate     string    `json:"candidate,omitempty"`
	AttemptID     string    `json:"attempt_id,omitempty"`
	Attempts      uint64    `json:"attempts"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
}

type Event struct {
	At        time.Time
	PeerID    string
	State     State
	AttemptID string
	Candidate string
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
	id            string
	key           [32]byte
	wake          chan struct{}
	attemptCancel context.CancelFunc
	lastWindow    time.Time
	lastCandidate string
}

type Engine struct {
	cfg Config

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
	engine := &Engine{
		cfg: cfg, peers: make(map[string]*peerRuntime, len(cfg.PeerIDs)),
		statuses: make(map[string]PeerStatus, len(cfg.PeerIDs)),
	}
	for _, peerID := range cfg.PeerIDs {
		key, err := pairKey(cfg.Node.NodeID(), peerID, cfg.SharedSecret)
		if err != nil {
			return nil, err
		}
		engine.peers[peerID] = &peerRuntime{id: peerID, key: key, wake: make(chan struct{}, 1)}
		engine.statuses[peerID] = PeerStatus{PeerID: peerID, State: StateWaitingHint}
	}
	return engine, nil
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
		cancel context.CancelFunc
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
			attempt.cancel()
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
	var attemptCancels []context.CancelFunc
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
		stop()
	}
	e.wg.Wait()
}

func (e *Engine) runPeer(ctx context.Context, peer *peerRuntime) {
	for {
		if ctx.Err() != nil {
			return
		}
		if e.reachable(peer.id) {
			e.setStatus(peer.id, func(status *PeerStatus) {
				status.State = StateReachable
				status.AttemptID = ""
				status.NextAttemptAt = time.Time{}
				status.LastError = ""
			})
			if !waitForWake(ctx, peer.wake, 30*time.Second) {
				return
			}
			continue
		}

		card, err := e.cfg.Store.Load()
		if err != nil {
			e.setFailure(peer.id, "", fmt.Errorf("load recovery card: %w", err))
			if !waitForWake(ctx, peer.wake, e.cfg.AttemptCycle) {
				return
			}
			continue
		}
		candidate, peerCard, ok := selectCandidate(card, peer.id, e.cfg.AllowNonPublic)
		if !ok {
			e.setStatus(peer.id, func(status *PeerStatus) {
				status.State = StateWaitingHint
				status.Candidate = ""
				status.AttemptID = ""
				status.NextAttemptAt = time.Time{}
				status.LastError = ErrNoCandidate.Error()
			})
			if !waitForWake(ctx, peer.wake, 30*time.Second) {
				return
			}
			continue
		}

		now := e.cfg.Now()
		windowStart, windowEnd, active := attemptWindow(peer.key, now, e.cfg.AttemptCycle, e.cfg.AttemptWindow)
		candidateKey := candidate.AddrPort
		alreadyTried := peer.lastWindow.Equal(windowStart) && peer.lastCandidate == candidateKey
		minimumRemaining := e.cfg.HelloTimeout + e.cfg.PunchGrace + time.Second
		if !active || alreadyTried || windowEnd.Sub(now) <= minimumRemaining {
			next := windowStart
			if active || !now.Before(windowStart) {
				next = windowStart.Add(e.cfg.AttemptCycle)
			}
			e.setStatus(peer.id, func(status *PeerStatus) {
				status.State = StateScheduled
				status.Candidate = candidate.AddrPort
				status.AttemptID = ""
				status.NextAttemptAt = next
			})
			if !waitUntilOrWake(ctx, peer.wake, next, e.cfg.Now) {
				return
			}
			continue
		}

		peer.lastWindow, peer.lastCandidate = windowStart, candidateKey
		if err := e.runAttempt(ctx, peer, card, peerCard, candidate, windowStart, windowEnd); err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, ErrAlreadyReachable) {
				continue
			}
			e.setFailure(peer.id, candidate.AddrPort, err)
		}
	}
}

func (e *Engine) runAttempt(
	parent context.Context,
	peer *peerRuntime,
	card recoverycard.Card,
	peerCard recoverycard.Peer,
	candidate recoverycard.Endpoint,
	windowStart, windowEnd time.Time,
) error {
	if e.reachable(peer.id) {
		return ErrAlreadyReachable
	}
	address, err := netip.ParseAddrPort(candidate.AddrPort)
	if err != nil {
		return err
	}
	attemptID := fmt.Sprintf("selfboot-%s-%s-%d-%d", e.cfg.Node.NodeID(), peer.id, windowStart.Unix(), e.sequence.Add(1))
	attemptCtx, cancel := context.WithDeadline(parent, windowEnd)
	e.mu.Lock()
	peer.attemptCancel = cancel
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		peer.attemptCancel = nil
		e.mu.Unlock()
	}()

	e.setStatus(peer.id, func(status *PeerStatus) {
		status.State = StatePunching
		status.Candidate = candidate.AddrPort
		status.AttemptID = attemptID
		status.Attempts++
		status.LastAttemptAt = e.cfg.Now().UTC()
		status.NextAttemptAt = time.Time{}
		status.LastError = ""
	})
	e.emit(peer.id, StatePunching, attemptID, candidate.AddrPort, nil)

	punchDeadline := windowEnd.Add(-e.cfg.HelloTimeout)
	if !punchDeadline.After(e.cfg.Now()) {
		return fmt.Errorf("selfbootstrap: attempt window has no punch time remaining")
	}
	punchCtx, stopPunch := context.WithDeadline(attemptCtx, punchDeadline)
	result, err := e.cfg.Punch(punchCtx, e.punchConfig(peer.key, card, peerCard, candidate, address))
	stopPunch()
	if err != nil {
		if e.reachable(peer.id) {
			return ErrAlreadyReachable
		}
		return fmt.Errorf("selfbootstrap: punch %s: %w", candidate.AddrPort, err)
	}
	if result == nil || result.Conn == nil || result.RemoteAddr == nil || result.LocalAddr == nil {
		if result != nil && result.Conn != nil {
			_ = result.Conn.Close()
		}
		return fmt.Errorf("selfbootstrap: punch returned an incomplete result")
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
	if err != nil {
		if e.reachable(peer.id) {
			return ErrAlreadyReachable
		}
		return fmt.Errorf("selfbootstrap: peer hello: %w", err)
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
	neighborConfig.OnClose = func(peerID string, cause error) {
		if configuredOnClose != nil {
			configuredOnClose(peerID, cause)
		}
		e.emit(peerID, StateScheduled, attemptID, candidate.AddrPort, cause)
		e.Notify()
	}
	packetTransport := iceadapter.New(conn, PathID)
	owned = false // AttachPacketTransportWithHandle consumes packetTransport on every return path.
	neighborHandle, err := e.cfg.Node.AttachPacketTransportWithHandle(peer.id, packetTransport, neighborConfig)
	if err != nil {
		if e.reachable(peer.id) {
			return ErrAlreadyReachable
		}
		return fmt.Errorf("selfbootstrap: attach packet neighbor: %w", err)
	}
	if !e.cfg.Node.PromoteNeighborHandle(neighborHandle) {
		_ = e.cfg.Node.RemoveNeighborHandle(neighborHandle)
		return fmt.Errorf("selfbootstrap: authenticated packet neighbor changed before promotion")
	}

	succeededAt := e.cfg.Now().UTC()
	e.setStatus(peer.id, func(status *PeerStatus) {
		status.State = StateAttached
		status.LastSuccessAt = succeededAt
		status.NextAttemptAt = time.Time{}
		status.LastError = ""
	})
	e.emitAttached(peer.id, attemptID, result.RemoteAddr.String(), neighborHandle, nil)
	observation := Observation{
		PeerID: peer.id, RemoteAddr: result.RemoteAddr, LocalAddr: result.LocalAddr,
		Source: "selfbootstrap", RemoteNAT: candidate.NAT, LocalNAT: card.LocalNAT, At: succeededAt,
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
	candidate recoverycard.Endpoint,
	address netip.AddrPort,
) puncher.Config {
	pattern := toNATPattern(candidate.NAT.Pattern)
	report := nat.PortAllocationReport{Pattern: pattern, Delta: candidate.NAT.Delta}
	targets := []int{int(address.Port())}
	sockets := e.cfg.SocketCount
	birthdayN := e.cfg.BirthdayTargets
	method := "cached_birthday"
	if pattern == nat.PortAllocationPreserving || pattern == nat.PortAllocationSequential {
		if predicted := report.PredictMappedPorts(int(address.Port()), e.cfg.PredictSpan); len(predicted) > 0 {
			targets = predicted
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
		RemoteIP: net.IP(address.Addr().AsSlice()), TargetPorts: targets,
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

func (e *Engine) setFailure(peerID, candidate string, err error) {
	next := nextAttemptWindow(e.peers[peerID].key, e.cfg.Now(), e.cfg.AttemptCycle, e.cfg.AttemptWindow)
	e.setStatus(peerID, func(status *PeerStatus) {
		status.State = StateScheduled
		status.Candidate = candidate
		status.AttemptID = ""
		status.NextAttemptAt = next
		status.LastError = compactError(err)
	})
	e.emit(peerID, StateScheduled, "", candidate, err)
}

func (e *Engine) emit(peerID string, state State, attemptID, candidate string, err error) {
	if e.cfg.OnEvent == nil {
		return
	}
	e.cfg.OnEvent(Event{
		At: e.cfg.Now().UTC(), PeerID: peerID, State: state,
		AttemptID: attemptID, Candidate: candidate, Err: err,
	})
}

func (e *Engine) emitAttached(peerID, attemptID, candidate string, handle mesh.NeighborHandle, err error) {
	if e.cfg.OnEvent == nil {
		return
	}
	e.cfg.OnEvent(Event{
		At: e.cfg.Now().UTC(), PeerID: peerID, State: StateAttached,
		AttemptID: attemptID, Candidate: candidate, StableNeighbor: handle, Err: err,
	})
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

func selectCandidate(card recoverycard.Card, peerID string, allowNonPublic bool) (recoverycard.Endpoint, recoverycard.Peer, bool) {
	for _, peer := range card.Peers {
		if peer.NodeID != peerID {
			continue
		}
		endpoints := append([]recoverycard.Endpoint(nil), peer.Endpoints...)
		sort.SliceStable(endpoints, func(i, j int) bool {
			return endpoints[i].LastSuccessAt.After(endpoints[j].LastSuccessAt)
		})
		for _, endpoint := range endpoints {
			address, err := netip.ParseAddrPort(endpoint.AddrPort)
			if err != nil || !address.Addr().Is4() || address.Port() == 0 {
				continue
			}
			if !allowNonPublic && !isPublicIPv4(address.Addr()) {
				continue
			}
			return endpoint, peer, true
		}
		return recoverycard.Endpoint{}, peer, false
	}
	return recoverycard.Endpoint{}, recoverycard.Peer{}, false
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
	return start, end, !now.Before(start) && now.Before(end)
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
