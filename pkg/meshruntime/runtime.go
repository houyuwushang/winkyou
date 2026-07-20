package meshruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/bootstrap/selfhosted"
	"winkyou/pkg/mesh"
	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/peercontrol"
	"winkyou/pkg/recoverycard"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/birthdaypunch"
)

const (
	// Public-NAT field links can briefly stop delivering packets when the host is
	// descheduled or the access network changes queues/routes. Five missed
	// one-second keepalives proved too aggressive: one local pause withdrew every
	// direct edge at once. Keep the keepalive frequent for NAT state, but require
	// thirty seconds of total receive silence before withdrawing an adjacency.
	defaultKeepAliveInterval = time.Second
	defaultPeerTimeout       = 30 * time.Second
	defaultProbation         = 35 * time.Second
	tcpFrameRecoveryMargin   = 15 * time.Second
	maxTimeDuration          = time.Duration(1<<63 - 1)
)

// Config describes one autonomous mesh runtime. The string slices intentionally
// retain the field-tested meshnode flag grammar so the standalone command and
// product adapters share one validation path.
type Config struct {
	NodeID        string
	VirtualIP     string
	MeshListen    string
	ControlListen string
	InitialPeers  []string
	// MaintainedPeers declares direct edges that should be kept alive. Routed
	// repair is owned by the lexicographically smaller endpoint; coordinator-less
	// self-bootstrap runs on both endpoints because UDP hole punching requires
	// both peers to transmit in the same deterministic window.
	MaintainedPeers []string
	STUNServers     []string
	TCPTarget       string
	TCPForwards     []string
	// VirtualTCPForwards exposes selected remote services on their advertised
	// ULA addresses. The Windows implementation temporarily owns /128 aliases
	// on the loopback interface; it is a TCP facade, not a packet interface.
	VirtualTCPForwards []string

	Lease                     time.Duration
	RefreshInterval           time.Duration
	DialRetry                 time.Duration
	HandshakeTimeout          time.Duration
	ProbeSamples              int
	EndpointTimeout           time.Duration
	PunchTimeout              time.Duration
	StartLead                 time.Duration
	SolveTimeout              time.Duration
	AttemptTimeout            time.Duration
	Probation                 time.Duration
	KeepAliveInterval         time.Duration
	PeerTimeout               time.Duration
	RecoveryDebounce          time.Duration
	RecoveryMinBackoff        time.Duration
	RecoveryMaxBackoff        time.Duration
	RecoveryStableReset       time.Duration
	TCPFrameTimeout           time.Duration
	RecoveryCardPath          string
	SelfBootstrapSecretFile   string
	SelfBootstrapWindow       time.Duration
	SelfBootstrapCycle        time.Duration
	SelfBootstrapHelloTimeout time.Duration

	strategyName                string
	strategyFactory             shortcut.StrategyFactory
	tcpForwardSpecs             []tcpForwardSpec
	virtualAliasManager         virtualAliasManager
	virtualAliasOwnership       *VirtualAliasOwnership
	selfBootstrapAllowNonPublic bool
	selfBootstrapPunchGrace     time.Duration
	selfBootstrapHelloInterval  time.Duration
	selfBootstrapHelloSettle    time.Duration
	selfBootstrapRoundDelay     time.Duration
}

// runtimeConfig is retained as an internal name for the migrated implementation
// and its white-box tests.
type runtimeConfig = Config

// Options controls process-local integration without changing mesh protocol or
// topology configuration.
type Options struct {
	EventWriter           io.Writer
	ShutdownToken         string
	VirtualAliasOwnership *VirtualAliasOwnership
}

// VirtualAliasOwnership identifies one process generation within a stable
// autonomous runtime. On Windows it lets virtual TCP loopback aliases survive
// a hard process exit without allowing unrelated Wink instances to adopt them.
type VirtualAliasOwnership struct {
	Scope          string
	InstanceID     string
	PID            int
	ProcessStartID string
	StoreDir       string
}

func (c runtimeConfig) normalized() (runtimeConfig, error) {
	c.NodeID = strings.TrimSpace(c.NodeID)
	c.VirtualIP = strings.TrimSpace(c.VirtualIP)
	c.MeshListen = normalizeListen(c.MeshListen)
	c.ControlListen = normalizeListen(c.ControlListen)
	if c.NodeID == "" {
		return runtimeConfig{}, fmt.Errorf("--id is required")
	}
	if c.Lease <= 0 {
		c.Lease = 15 * time.Second
	}
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = c.Lease / 5
	}
	if c.DialRetry <= 0 {
		c.DialRetry = time.Second
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 5 * time.Second
	}
	if c.EndpointTimeout <= 0 {
		// A full multi-server STUN probe can legitimately take more than 20s
		// when one provider is filtered. Keep the faster peer waiting long
		// enough for the slower peer to finish probing and advertise its endpoint.
		c.EndpointTimeout = 60 * time.Second
	}
	if c.PunchTimeout <= 0 {
		c.PunchTimeout = 90 * time.Second
	}
	if c.StartLead <= 0 {
		c.StartLead = time.Second
	}
	if c.SolveTimeout <= 0 {
		c.SolveTimeout = 150 * time.Second
	}
	if c.KeepAliveInterval <= 0 {
		c.KeepAliveInterval = defaultKeepAliveInterval
	}
	if c.PeerTimeout <= 0 {
		c.PeerTimeout = defaultPeerTimeout
	}
	if c.Probation <= 0 {
		c.Probation = defaultProbation
	}
	if c.Probation < c.PeerTimeout {
		return runtimeConfig{}, fmt.Errorf("probation %s must be at least peer timeout %s", c.Probation, c.PeerTimeout)
	}
	if c.AttemptTimeout <= 0 {
		// The protocol can spend one solve window reaching INSTALLED and a
		// second window reconciling COMMIT before probation completes.
		c.AttemptTimeout = saturatingPositiveDurationSum(
			saturatingPositiveDurationMultiply(c.SolveTimeout, 2),
			c.Probation,
			saturatingPositiveDurationMultiply(c.PeerTimeout, 2),
			10*time.Second,
		)
	}
	if c.RecoveryDebounce <= 0 {
		c.RecoveryDebounce = 250 * time.Millisecond
	}
	if c.RecoveryMinBackoff <= 0 {
		c.RecoveryMinBackoff = 2 * time.Second
	}
	if c.RecoveryMaxBackoff <= 0 {
		c.RecoveryMaxBackoff = time.Minute
	}
	if c.RecoveryMaxBackoff < c.RecoveryMinBackoff {
		return runtimeConfig{}, fmt.Errorf("recovery maximum backoff %s must be at least minimum %s", c.RecoveryMaxBackoff, c.RecoveryMinBackoff)
	}
	if c.RecoveryStableReset <= 0 {
		c.RecoveryStableReset = c.Probation
	}
	minimumFrameTimeout := saturatingPositiveDurationSum(
		saturatingPositiveDurationMultiply(c.PeerTimeout, 2),
		tcpFrameRecoveryMargin,
	)
	if c.TCPFrameTimeout <= 0 {
		// With a one-way failure, the receiving endpoint can keep the reverse
		// adjacency alive for one full peer timeout after the sender has already
		// switched routes. Keep a frame alive across both detection windows plus
		// a convergence margin.
		c.TCPFrameTimeout = minimumFrameTimeout
	}
	if c.TCPFrameTimeout < minimumFrameTimeout {
		return runtimeConfig{}, fmt.Errorf(
			"TCP frame timeout %s must be at least %s (two peer timeouts plus %s)",
			c.TCPFrameTimeout, minimumFrameTimeout, tcpFrameRecoveryMargin,
		)
	}
	if c.strategyName == "" {
		c.strategyName = birthdaypunch.StrategyName
	}
	if err := normalizeTCPConfig(&c); err != nil {
		return runtimeConfig{}, err
	}
	if c.strategyFactory == nil {
		strategyConfig := birthdaypunch.Config{
			STUNServers: append([]string(nil), c.STUNServers...), ProbeSamples: c.ProbeSamples,
			EndpointTimeout: c.EndpointTimeout, PunchTimeout: c.PunchTimeout, StartLead: c.StartLead,
		}
		c.strategyFactory = func(shortcut.AttemptSpec) (solver.Strategy, error) {
			return birthdaypunch.New(strategyConfig), nil
		}
	}
	seenPeers := make(map[string]struct{}, len(c.InitialPeers))
	for _, spec := range c.InitialPeers {
		peerID, _, err := parsePeerSpec(spec)
		if err != nil {
			return runtimeConfig{}, err
		}
		if peerID == c.NodeID {
			return runtimeConfig{}, fmt.Errorf("node cannot bootstrap to itself")
		}
		if _, exists := seenPeers[peerID]; exists {
			return runtimeConfig{}, fmt.Errorf("duplicate initial peer %q", peerID)
		}
		seenPeers[peerID] = struct{}{}
	}
	maintained := make([]string, 0, len(c.MaintainedPeers))
	seenMaintained := make(map[string]struct{}, len(c.MaintainedPeers))
	for _, raw := range c.MaintainedPeers {
		peerID := strings.TrimSpace(raw)
		if peerID == "" {
			return runtimeConfig{}, fmt.Errorf("maintained peer ID must not be empty")
		}
		if peerID == c.NodeID {
			return runtimeConfig{}, fmt.Errorf("node cannot maintain a direct edge to itself")
		}
		if _, exists := seenMaintained[peerID]; exists {
			return runtimeConfig{}, fmt.Errorf("duplicate maintained peer %q", peerID)
		}
		seenMaintained[peerID] = struct{}{}
		maintained = append(maintained, peerID)
	}
	sort.Strings(maintained)
	c.MaintainedPeers = maintained
	c.RecoveryCardPath = strings.TrimSpace(c.RecoveryCardPath)
	c.SelfBootstrapSecretFile = strings.TrimSpace(c.SelfBootstrapSecretFile)
	if c.RecoveryCardPath == "" && c.SelfBootstrapSecretFile != "" {
		return runtimeConfig{}, fmt.Errorf("--self-bootstrap-secret-file requires --recovery-card")
	}
	if c.RecoveryCardPath != "" && len(c.MaintainedPeers) == 0 {
		return runtimeConfig{}, fmt.Errorf("--recovery-card requires at least one --maintain-peer")
	}
	return c, nil
}

func normalizeListen(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "off") || strings.EqualFold(value, "none") || value == "-" {
		return ""
	}
	return value
}

type runtimeCounters struct {
	controlForwarded atomic.Uint64
	controlDropped   atomic.Uint64
	dataForwarded    atomic.Uint64
	dataDropped      atomic.Uint64
	solverForwarded  atomic.Uint64
}

// Runtime owns one autonomous mesh node and all of its bootstrap, recovery,
// routed-service, control-API, and system-alias resources.
type Runtime struct {
	cfg           runtimeConfig
	log           *eventLog
	shutdownToken string
	done          chan struct{}

	node          *mesh.Node
	shortcuts     *shortcut.Manager
	recovery      *recoverySupervisor
	selfBootstrap *selfhosted.Engine
	recoveryStore *recoverycard.Store
	echo          *echoService
	connectors    *bootstrapConnectors
	bootstrap     *bootstrapServer
	httpServer    *http.Server
	tcp           *tcpRuntime

	startedAt time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	counters  runtimeCounters

	shortcutMu       sync.Mutex
	shortcutStatuses map[string]shortcut.Status

	mu        sync.Mutex
	started   bool
	closed    bool
	closeOnce sync.Once
}

// meshRuntime preserves the implementation's historical internal name for
// package-local tests while callers use Runtime.
type meshRuntime = Runtime

// New builds a reusable autonomous mesh runtime. Start must be called exactly
// once; Close is idempotent and may be retried after transient alias cleanup
// failures.
func New(config Config, options Options) (*Runtime, error) {
	return newMeshRuntimeWithOptions(config, options)
}

func newMeshRuntime(config runtimeConfig, output io.Writer) (*meshRuntime, error) {
	return newMeshRuntimeWithOptions(config, Options{EventWriter: output})
}

func newMeshRuntimeWithOptions(config runtimeConfig, options Options) (*meshRuntime, error) {
	cfg, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if options.VirtualAliasOwnership != nil {
		ownership := *options.VirtualAliasOwnership
		cfg.virtualAliasOwnership = &ownership
	}
	runtime := &meshRuntime{
		cfg: cfg, log: newEventLog(cfg.NodeID, options.EventWriter), echo: newEchoService(cfg.NodeID),
		shutdownToken: options.ShutdownToken, done: make(chan struct{}),
		shortcutStatuses: make(map[string]shortcut.Status),
	}
	node, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: cfg.NodeID, VirtualIP: cfg.VirtualIP, Lease: cfg.Lease, RefreshInterval: cfg.RefreshInterval,
		OnMessage: runtime.echo.handle, OnEvent: runtime.handleMeshEvent, OnDataEvent: runtime.handleDataEvent,
	})
	if err != nil {
		return nil, err
	}
	runtime.node = node
	runtime.echo.setNode(node)
	tcpRuntime, err := newTCPRuntime(cfg, node)
	if err != nil {
		_ = node.Close()
		return nil, err
	}
	runtime.tcp = tcpRuntime
	packetNeighbor := mesh.PacketNeighborConfig{
		KeepAliveInterval: cfg.KeepAliveInterval,
		PeerTimeout:       cfg.PeerTimeout,
		ReadPollInterval:  minDuration(500*time.Millisecond, cfg.KeepAliveInterval),
		WriteTimeout:      2 * time.Second,
	}
	manager, err := shortcut.NewManager(shortcut.Config{
		Node: node, StrategyName: cfg.strategyName, StrategyFactory: cfg.strategyFactory,
		Probation: cfg.Probation, SolveTimeout: cfg.SolveTimeout, AttemptTimeout: cfg.AttemptTimeout,
		PacketNeighbor: packetNeighbor,
		OnEvent:        runtime.handleShortcutEvent,
	})
	if err != nil {
		if runtime.tcp != nil {
			_ = runtime.tcp.Close()
		}
		_ = node.Close()
		return nil, err
	}
	runtime.shortcuts = manager
	runtime.recovery = newRecoverySupervisor(cfg, node, manager, runtime.log)
	if cfg.RecoveryCardPath != "" {
		store, err := recoverycard.NewStore(cfg.RecoveryCardPath, cfg.NodeID)
		if err != nil {
			_ = manager.Close()
			if runtime.tcp != nil {
				_ = runtime.tcp.Close()
			}
			_ = node.Close()
			return nil, err
		}
		secret, err := readSelfBootstrapSecret(cfg.SelfBootstrapSecretFile)
		if err != nil {
			_ = manager.Close()
			if runtime.tcp != nil {
				_ = runtime.tcp.Close()
			}
			_ = node.Close()
			return nil, err
		}
		engine, err := selfhosted.New(selfhosted.Config{
			Node: node, Store: store, PeerIDs: cfg.MaintainedPeers, SharedSecret: secret,
			PacketNeighbor: packetNeighbor, AttemptWindow: cfg.SelfBootstrapWindow,
			AttemptCycle: cfg.SelfBootstrapCycle, HelloTimeout: cfg.SelfBootstrapHelloTimeout,
			AllowNonPublic: cfg.selfBootstrapAllowNonPublic, PunchGrace: cfg.selfBootstrapPunchGrace,
			HelloInterval: cfg.selfBootstrapHelloInterval, HelloSettle: cfg.selfBootstrapHelloSettle,
			RoundDelay: cfg.selfBootstrapRoundDelay,
			OnEvent:    runtime.handleSelfBootstrapEvent,
		})
		if err != nil {
			_ = manager.Close()
			if runtime.tcp != nil {
				_ = runtime.tcp.Close()
			}
			_ = node.Close()
			return nil, err
		}
		runtime.recoveryStore = store
		runtime.selfBootstrap = engine
	}
	return runtime, nil
}

func readSelfBootstrapSecret(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read self-bootstrap secret file: %w", err)
	}
	secret := bytes.TrimSpace(raw)
	if len(secret) == 0 {
		return nil, fmt.Errorf("self-bootstrap secret file is empty")
	}
	return append([]byte(nil), secret...), nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
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

func (r *meshRuntime) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return mesh.ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return fmt.Errorf("meshnode %s already started", r.cfg.NodeID)
	}
	r.ctx, r.cancel = context.WithCancel(parent)
	r.started = true
	r.startedAt = time.Now().UTC()
	r.mu.Unlock()

	if err := r.node.Start(r.ctx); err != nil {
		return errors.Join(err, r.Close())
	}
	if r.cfg.MeshListen != "" {
		server, err := startBootstrapServer(r.ctx, r.node, r.cfg.MeshListen, r.cfg.HandshakeTimeout, r.log)
		if err != nil {
			return errors.Join(fmt.Errorf("listen for bootstrap streams: %w", err), r.Close())
		}
		r.bootstrap = server
	}
	r.connectors = newBootstrapConnectors(r.ctx, r.node, r.cfg.DialRetry, r.cfg.HandshakeTimeout, r.log)
	for _, spec := range r.cfg.InitialPeers {
		peerID, address, _ := parsePeerSpec(spec)
		if err := r.connectors.Add(peerID, address); err != nil {
			return errors.Join(err, r.Close())
		}
	}
	if r.selfBootstrap != nil {
		if err := r.selfBootstrap.Start(r.ctx); err != nil {
			return errors.Join(fmt.Errorf("start peer self-bootstrap: %w", err), r.Close())
		}
	}
	if r.recovery != nil {
		if err := r.recovery.Start(r.ctx); err != nil {
			return errors.Join(fmt.Errorf("start direct-edge recovery: %w", err), r.Close())
		}
	}
	if r.tcp != nil {
		if err := r.tcp.Start(r.ctx, r.log); err != nil {
			return errors.Join(fmt.Errorf("start routed TCP forwards: %w", err), r.Close())
		}
	}
	if r.cfg.ControlListen != "" {
		server, err := startControlServer(r.ctx, r, r.cfg.ControlListen)
		if err != nil {
			return errors.Join(fmt.Errorf("listen for control API: %w", err), r.Close())
		}
		r.httpServer = server
	}
	r.log.write("runtime_started", map[string]any{
		"mesh_listen": r.MeshAddr(), "control_listen": r.ControlAddr(), "strategy": r.cfg.strategyName,
		"maintained_peers":    append([]string(nil), r.cfg.MaintainedPeers...),
		"self_bootstrap":      r.selfBootstrap != nil,
		"self_bootstrap_auth": r.selfBootstrapAuthMode(),
	})
	return nil
}

func (r *meshRuntime) selfBootstrapAuthMode() string {
	if r == nil || r.selfBootstrap == nil {
		return "disabled"
	}
	if r.cfg.SelfBootstrapSecretFile == "" {
		return "trusted_node_ids_no_secret"
	}
	return "shared_secret"
}

func (r *meshRuntime) MeshAddr() string {
	if r == nil || r.bootstrap == nil {
		return ""
	}
	return r.bootstrap.Addr()
}

func (r *meshRuntime) ControlAddr() string {
	if r == nil || r.httpServer == nil {
		return ""
	}
	if value := r.httpServer.Addr; value != "" {
		return value
	}
	return r.cfg.ControlListen
}

var closedRuntimeDone = func() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}()

// Done is closed after the runtime has completed its one-shot shutdown pass.
// A subsequent Close may still retry a transient system-alias cleanup failure.
func (r *meshRuntime) Done() <-chan struct{} {
	if r == nil || r.done == nil {
		return closedRuntimeDone
	}
	return r.done
}

func (r *meshRuntime) handleMeshEvent(event mesh.Event) {
	switch event.Kind {
	case mesh.EventForwarded:
		r.counters.controlForwarded.Add(1)
		if event.Message.Type == peercontrol.TypeSessionSignal && event.Message.SessionSignal != nil &&
			event.Message.SessionSignal.Namespace == shortcut.Namespace &&
			event.Message.SessionSignal.Type == shortcut.SignalTypeSolverMessage {
			r.counters.solverForwarded.Add(1)
		}
	case mesh.EventDropped:
		r.counters.controlDropped.Add(1)
		r.log.write("control_dropped", map[string]any{
			"from": event.Message.From, "to": event.Message.To, "type": event.Message.Type,
			"error": errorString(event.DecisionErr),
		})
	}
}

func (r *meshRuntime) handleDataEvent(event mesh.DataEvent) {
	switch event.Kind {
	case mesh.EventForwarded:
		r.counters.dataForwarded.Add(1)
	case mesh.EventDropped:
		r.counters.dataDropped.Add(1)
		r.log.write("data_dropped", map[string]any{
			"source": event.Frame.Source, "destination": event.Frame.Destination,
			"type": event.Frame.Type, "error": errorString(event.DecisionErr),
		})
	}
}

func (r *meshRuntime) handleShortcutEvent(event shortcut.Event) {
	r.shortcutMu.Lock()
	r.shortcutStatuses[event.Status.AttemptID] = event.Status
	r.shortcutMu.Unlock()
	if r.recovery != nil {
		r.recovery.ObserveShortcut(event.Status)
	}
	if r.selfBootstrap != nil && event.Status.Phase == shortcut.PhaseStable {
		r.observeShortcutForSelfBootstrap(event.Status)
	}
	r.log.write("shortcut_phase", map[string]any{
		"attempt_id":  event.Status.AttemptID,
		"initiator":   event.Status.InitiatorID,
		"target":      event.Status.TargetID,
		"coordinator": event.Status.CoordinatorID,
		"role":        event.Status.LocalRole,
		"phase":       event.Status.Phase,
		"failure":     event.Status.Failure,
		"path_id":     event.Status.PathSummary.PathID,
		"remote_addr": addrString(event.Status.PathSummary.RemoteAddr),
	})
}

func (r *meshRuntime) observeShortcutForSelfBootstrap(status shortcut.Status) {
	if status.DirectPeerID == "" || status.PathSummary.RemoteAddr == nil {
		return
	}
	localRaw := strings.TrimSpace(status.PathSummary.Details["local_addr"])
	if localRaw == "" {
		return
	}
	localAddr, err := net.ResolveUDPAddr("udp", localRaw)
	if err != nil {
		r.log.write("selfbootstrap_observe_failed", map[string]any{
			"peer_id": status.DirectPeerID, "error": err.Error(),
		})
		return
	}
	at := status.UpdatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	err = r.selfBootstrap.Observe(selfhosted.Observation{
		PeerID: status.DirectPeerID, RemoteAddr: status.PathSummary.RemoteAddr, LocalAddr: localAddr,
		Source: "birthday_shortcut", At: at,
		LocalNAT: selfhosted.NATModelFromStrings(
			status.PathSummary.Details["local_nat_pattern"], status.PathSummary.Details["local_nat_delta"], at,
		),
		RemoteNAT: selfhosted.NATModelFromStrings(
			status.PathSummary.Details["remote_nat_pattern"], status.PathSummary.Details["remote_nat_delta"], at,
		),
	})
	if err != nil {
		r.log.write("selfbootstrap_observe_failed", map[string]any{
			"peer_id": status.DirectPeerID, "error": err.Error(),
		})
	}
}

func (r *meshRuntime) handleSelfBootstrapEvent(event selfhosted.Event) {
	if r.recovery != nil && event.State == selfhosted.StateAttached {
		r.recovery.ObserveStablePacket(event.PeerID, event.StableNeighbor)
	}
	r.log.write("selfbootstrap_state", map[string]any{
		"peer_id": event.PeerID, "state": event.State, "attempt_id": event.AttemptID,
		"candidate": event.Candidate, "candidate_group": event.CandidateGroup,
		"candidate_index": event.CandidateIndex, "candidate_total": event.CandidateTotal,
		"candidate_endpoints": event.CandidateEndpoints, "candidate_failures": event.CandidateFailures,
		"attempt_window_ordinal": event.AttemptWindowOrdinal,
		"attempt_window_start":   event.AttemptWindowStart, "attempt_window_end": event.AttemptWindowEnd,
		"punch_method": event.PunchMethod, "learned_remote": event.LearnedRemote,
		"failure_stage": event.FailureStage, "error": errorString(event.Err),
	})
}

func addrString(address any) string {
	if address == nil {
		return ""
	}
	return fmt.Sprint(address)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (r *meshRuntime) shortcutSnapshot() []shortcut.Status {
	r.shortcutMu.Lock()
	defer r.shortcutMu.Unlock()
	result := make([]shortcut.Status, 0, len(r.shortcutStatuses))
	for _, status := range r.shortcutStatuses {
		result = append(result, status)
	}
	return result
}

func (r *meshRuntime) Close() error {
	if r == nil {
		return nil
	}
	var closeErr error
	closedRuntime := false
	r.closeOnce.Do(func() {
		closedRuntime = true
		defer close(r.done)
		r.mu.Lock()
		r.closed = true
		cancel := r.cancel
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if r.httpServer != nil {
			ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			closeErr = errors.Join(closeErr, r.httpServer.Shutdown(ctx))
			stop()
		}
		if r.selfBootstrap != nil {
			r.selfBootstrap.Close()
		}
		if r.recovery != nil {
			r.recovery.Close()
		}
		if r.connectors != nil {
			r.connectors.Close()
		}
		if r.bootstrap != nil {
			closeErr = errors.Join(closeErr, r.bootstrap.Close())
		}
		if r.tcp != nil {
			closeErr = errors.Join(closeErr, r.tcp.Close())
		}
		if r.shortcuts != nil {
			closeErr = errors.Join(closeErr, r.shortcuts.Close())
		}
		if r.node != nil {
			closeErr = errors.Join(closeErr, r.node.Close())
		}
		r.log.write("runtime_stopped", map[string]any{"error": errorString(closeErr)})
	})
	if !closedRuntime && r.tcp != nil {
		// Most runtime resources are intentionally one-shot. The Windows virtual
		// TCP alias manager is different: a transient netsh/probe failure must be
		// retryable by a supervisor calling Close again. tcpRuntime.Close is
		// idempotent and retries only that pending cleanup once already closed.
		return r.tcp.Close()
	}
	return closeErr
}
