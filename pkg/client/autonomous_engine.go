package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/logger"
	"winkyou/pkg/meshruntime"
	"winkyou/pkg/processidentity"
)

const autonomousStateSyncInterval = 2 * time.Second

var ErrAutonomousPeerMutationUnsupported = errors.New("client autonomous mesh: runtime peer mutation is not exposed by Engine yet")

// autonomousEngine adapts the coordinator-independent graph runtime to the
// long-running wink CLI lifecycle. It intentionally does not embed the legacy
// coordinator/WireGuard engine: the two modes share the Engine contract and
// runtime-state format, not their resource state machines.
type autonomousEngine struct {
	cfg       config.Config
	log       logger.Logger
	statePath string

	instanceID     string
	processStartID string
	shutdownToken  string

	lifecycleMu    sync.Mutex
	mu             sync.RWMutex
	started        bool
	state          EngineState
	lastError      string
	runtime        *meshruntime.Runtime
	statusHandlers []func(*EngineStatus)
	peerHandlers   []func(*PeerStatus, PeerEvent)
	loopCancel     context.CancelFunc
	wg             sync.WaitGroup
	writeState     func(string, *RuntimeState) error
}

func newAutonomousEngine(cfg config.Config, log logger.Logger, statePath string) (Engine, error) {
	processStartID, err := processidentity.Current()
	if err != nil {
		return nil, fmt.Errorf("client autonomous mesh: identify current process: %w", err)
	}
	instanceID, err := randomRuntimeCredential(16)
	if err != nil {
		return nil, fmt.Errorf("client autonomous mesh: generate instance id: %w", err)
	}
	shutdownToken, err := randomRuntimeCredential(32)
	if err != nil {
		return nil, fmt.Errorf("client autonomous mesh: generate shutdown token: %w", err)
	}
	return &autonomousEngine{
		cfg: cfg, log: log, statePath: strings.TrimSpace(statePath),
		instanceID: instanceID, processStartID: processStartID, shutdownToken: shutdownToken,
		state: EngineStateStopped, writeState: WriteRuntimeState,
	}, nil
}

func randomRuntimeCredential(size int) (string, error) {
	if size <= 0 {
		return "", fmt.Errorf("credential size must be positive")
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (e *autonomousEngine) Start(ctx context.Context) (err error) {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return ErrEngineAlreadyStarted
	}
	e.started = true
	e.state = EngineStateStarting
	e.lastError = ""
	e.mu.Unlock()
	e.notifyStatus()

	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		e.mu.Lock()
		runtime := e.runtime
		e.runtime = nil
		e.loopCancel = nil
		e.mu.Unlock()
		if runtime != nil {
			if closeErr := closeAutonomousRuntime(runtime); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
		if e.statePath != "" {
			if removeErr := RemoveRuntimeStateIfInstance(e.statePath, e.instanceID); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("remove failed autonomous runtime state: %w", removeErr))
				e.log.Warn("failed to remove autonomous mesh runtime state after startup failure", logger.Error(removeErr), logger.String("path", e.statePath))
			}
		}
		e.mu.Lock()
		e.started = false
		e.state = EngineStateStopped
		e.lastError = errorString(err)
		e.mu.Unlock()
		e.notifyStatus()
	}()

	runtime, err := meshruntime.New(e.runtimeConfig(), meshruntime.Options{
		EventWriter:   autonomousEventWriter{log: e.log},
		ShutdownToken: e.shutdownToken,
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.runtime = runtime
	e.state = EngineStateConnecting
	e.mu.Unlock()
	e.notifyStatus()

	if err := runtime.Start(ctx); err != nil {
		return err
	}

	loopCtx, loopCancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.loopCancel = loopCancel
	e.state = EngineStateConnected
	e.mu.Unlock()
	if err := e.persistState(); err != nil {
		loopCancel()
		return fmt.Errorf("client autonomous mesh: persist initial runtime state: %w", err)
	}
	e.startStateLoop(loopCtx, runtime.Done())
	e.notifyStatus()
	cleanup = false
	return nil
}

func (e *autonomousEngine) Stop() error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()

	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return nil
	}
	e.state = EngineStateStopping
	loopCancel := e.loopCancel
	runtime := e.runtime
	e.mu.Unlock()
	e.notifyStatus()

	if loopCancel != nil {
		loopCancel()
	}
	e.wg.Wait()

	var closeErr error
	if runtime != nil {
		closeErr = closeAutonomousRuntime(runtime)
	}
	if closeErr != nil {
		e.mu.Lock()
		e.lastError = closeErr.Error()
		e.mu.Unlock()
		persistErr := e.persistState()
		e.notifyStatus()
		return errors.Join(closeErr, persistErr)
	}

	var removeErr error
	if e.statePath != "" {
		removeErr = RemoveRuntimeStateIfInstance(e.statePath, e.instanceID)
	}
	if removeErr != nil {
		e.mu.Lock()
		e.lastError = removeErr.Error()
		e.mu.Unlock()
		e.notifyStatus()
		return removeErr
	}

	e.mu.Lock()
	e.started = false
	e.state = EngineStateStopped
	e.lastError = ""
	e.runtime = nil
	e.loopCancel = nil
	e.mu.Unlock()
	e.notifyStatus()
	return nil
}

func closeAutonomousRuntime(runtime *meshruntime.Runtime) error {
	if runtime == nil {
		return nil
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := runtime.Close()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("client autonomous mesh: close runtime after retries: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *autonomousEngine) Done() <-chan struct{} {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	return runtime.Done()
}

func (e *autonomousEngine) Status() *EngineStatus {
	e.mu.RLock()
	runtime := e.runtime
	state := e.state
	lastError := e.lastError
	e.mu.RUnlock()
	if runtime == nil {
		return e.emptyStatus(state, lastError)
	}
	return e.engineStatus(runtime.Status(), state, lastError)
}

func (e *autonomousEngine) GetPeers() []*PeerStatus {
	e.mu.RLock()
	runtime := e.runtime
	e.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	return e.peerStatuses(runtime.Status())
}

func (e *autonomousEngine) ConnectToPeer(string) error {
	return ErrAutonomousPeerMutationUnsupported
}

func (e *autonomousEngine) DisconnectFromPeer(string) error {
	return ErrAutonomousPeerMutationUnsupported
}

func (e *autonomousEngine) OnStatusChange(handler func(status *EngineStatus)) {
	if handler == nil {
		return
	}
	e.mu.Lock()
	e.statusHandlers = append(e.statusHandlers, handler)
	e.mu.Unlock()
}

func (e *autonomousEngine) OnPeerChange(handler func(peer *PeerStatus, event PeerEvent)) {
	if handler == nil {
		return
	}
	e.mu.Lock()
	e.peerHandlers = append(e.peerHandlers, handler)
	e.mu.Unlock()
}

func (e *autonomousEngine) runtimeConfig() meshruntime.Config {
	mesh := e.cfg.AutonomousMesh
	initialPeers := make([]string, 0, len(mesh.BootstrapPeers))
	for _, peer := range mesh.BootstrapPeers {
		initialPeers = append(initialPeers, strings.TrimSpace(peer.NodeID)+"="+strings.TrimSpace(peer.Address))
	}
	tcpForwards := make([]string, 0, len(mesh.TCPForwards))
	for _, forward := range mesh.TCPForwards {
		tcpForwards = append(tcpForwards, strings.TrimSpace(forward.Listen)+"="+strings.TrimSpace(forward.RemoteID))
	}
	virtualTCPForwards := make([]string, 0, len(mesh.VirtualTCPForwards))
	for _, forward := range mesh.VirtualTCPForwards {
		virtualTCPForwards = append(virtualTCPForwards, strings.TrimSpace(forward.Listen)+"="+strings.TrimSpace(forward.RemoteID))
	}
	return meshruntime.Config{
		NodeID: mesh.NodeID, VirtualIP: mesh.VirtualIP,
		MeshListen: mesh.Listen, ControlListen: mesh.ControlListen,
		InitialPeers: initialPeers, MaintainedPeers: append([]string(nil), mesh.MaintainPeers...),
		STUNServers: append([]string(nil), e.cfg.NAT.STUNServers...),
		TCPTarget:   mesh.TCPTarget, TCPForwards: tcpForwards, VirtualTCPForwards: virtualTCPForwards,
		RecoveryCardPath: mesh.RecoveryCard, RecoveryDebounce: mesh.RecoveryDebounce,
		SelfBootstrapSecretFile: mesh.SelfBootstrapSecretFile,
	}
}

func (e *autonomousEngine) emptyStatus(state EngineState, lastError string) *EngineStatus {
	ip, network := hostNetwork(e.cfg.AutonomousMesh.VirtualIP)
	return &EngineStatus{
		Mode: "autonomous_mesh", State: state,
		NodeID: e.cfg.AutonomousMesh.NodeID, NodeName: firstNonEmptyString(e.cfg.Node.Name, e.cfg.AutonomousMesh.NodeID),
		VirtualIP: ip, NetworkCIDR: network, Backend: "userspace-mesh", NATType: "mesh-managed",
		InfrastructureCoordinatorStarted: false, LastError: lastError,
	}
}

func (e *autonomousEngine) engineStatus(status meshruntime.Status, state EngineState, lastError string) *EngineStatus {
	ip, network := hostNetwork(status.VirtualIP)
	return &EngineStatus{
		Mode: "autonomous_mesh", State: state,
		NodeID: status.NodeID, NodeName: firstNonEmptyString(e.cfg.Node.Name, status.NodeID),
		VirtualIP: ip, NetworkCIDR: network, Backend: "userspace-mesh", NATType: "mesh-managed",
		InfrastructureCoordinatorStarted: status.InfrastructureUp,
		MeshListen:                       status.MeshListen, ControlListen: status.ControlListen,
		StartedAt: status.StartedAt, Uptime: time.Since(status.StartedAt),
		ConnectedPeers: len(status.Routes), LastError: lastError,
	}
}

func (e *autonomousEngine) peerStatuses(status meshruntime.Status) []*PeerStatus {
	type peerParts struct {
		member     *meshruntime.MemberStatus
		route      *meshruntime.RouteStatus
		maintained *meshruntime.MaintainedPeerStatus
		bootstrap  string
		neighbor   bool
	}
	parts := map[string]*peerParts{}
	ensure := func(id string) *peerParts {
		id = strings.TrimSpace(id)
		if id == "" || id == status.NodeID {
			return nil
		}
		if parts[id] == nil {
			parts[id] = &peerParts{}
		}
		return parts[id]
	}
	for i := range status.Members {
		member := status.Members[i]
		if part := ensure(member.NodeID); part != nil {
			memberCopy := member
			part.member = &memberCopy
		}
	}
	for i := range status.Routes {
		route := status.Routes[i]
		if part := ensure(route.Destination); part != nil {
			routeCopy := route
			part.route = &routeCopy
		}
	}
	for _, id := range status.Neighbors {
		if part := ensure(id); part != nil {
			part.neighbor = true
		}
	}
	for i := range status.MaintainedPeers {
		maintained := status.MaintainedPeers[i]
		if part := ensure(maintained.PeerID); part != nil {
			maintainedCopy := maintained
			part.maintained = &maintainedCopy
		}
	}
	for _, bootstrap := range status.SelfBootstrap {
		if part := ensure(bootstrap.PeerID); part != nil {
			part.bootstrap = string(bootstrap.State)
		}
	}

	ids := make([]string, 0, len(parts))
	for id := range parts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	peers := make([]*PeerStatus, 0, len(ids))
	for _, id := range ids {
		part := parts[id]
		peer := &PeerStatus{NodeID: id, Name: id, State: PeerStateDisconnected, DataState: PeerDataStateStale}
		if part.member != nil {
			peer.VirtualIP = net.ParseIP(strings.TrimSpace(part.member.VirtualIP))
		}
		if part.route != nil {
			peer.State = PeerStateConnected
			peer.ControlState = PeerControlStateConnected
			peer.DataState = PeerDataStateAlive
			peer.RouteNextHop = part.route.NextHop
			peer.RoutePath = append([]string(nil), part.route.Path...)
			peer.RouteHopCount = part.route.HopCount
			peer.Latency = time.Duration(part.route.RTTMillis) * time.Millisecond
			peer.ConnectionType = ConnectionTypeMeshRoute
		}
		if part.neighbor && peer.NeighborKind == "" {
			peer.NeighborKind = "neighbor"
		}
		if part.maintained != nil {
			peer.MaintainedState = fmt.Sprint(part.maintained.State)
			peer.NeighborKind = fmt.Sprint(part.maintained.NeighborKind)
			peer.ProtectedDirect = part.maintained.ProtectedDirect
			if len(part.maintained.RoutePath) > 0 {
				peer.RoutePath = append([]string(nil), part.maintained.RoutePath...)
				peer.RouteHopCount = part.maintained.RouteHopCount
			}
			if peer.ProtectedDirect {
				peer.ConnectionType = ConnectionTypeDirect
				peer.LastPathRole = "protected_direct"
			}
			peer.LastPathID = part.maintained.AttemptID
			peer.LastPathDetails = map[string]string{
				"coordinator_id": part.maintained.CoordinatorID,
				"attempt_phase":  fmt.Sprint(part.maintained.AttemptPhase),
			}
		}
		peer.SelfBootstrapState = part.bootstrap
		peers = append(peers, peer)
	}
	return peers
}

func hostNetwork(raw string) (net.IP, *net.IPNet) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return nil, nil
	}
	bits := 128
	canonical := ip.To16()
	if ipv4 := ip.To4(); ipv4 != nil {
		bits = 32
		canonical = ipv4
	}
	return append(net.IP(nil), canonical...), &net.IPNet{IP: append(net.IP(nil), canonical...), Mask: net.CIDRMask(bits, bits)}
}

func (e *autonomousEngine) startStateLoop(ctx context.Context, runtimeDone <-chan struct{}) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(autonomousStateSyncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-runtimeDone:
				e.mu.Lock()
				if e.started {
					e.state = EngineStateStopping
				}
				e.mu.Unlock()
				e.notifyStatus()
				return
			case <-ticker.C:
				if err := e.persistState(); err != nil {
					e.log.Warn("failed to persist autonomous mesh runtime state", logger.Error(err), logger.String("path", e.statePath))
				}
			}
		}
	}()
}

func (e *autonomousEngine) persistState() error {
	e.mu.RLock()
	started := e.started
	statePath := e.statePath
	runtime := e.runtime
	e.mu.RUnlock()
	if !started || runtime == nil || statePath == "" {
		return nil
	}
	status := e.Status()
	peers := e.GetPeers()
	state := newRuntimeStateSnapshot(status, peers)
	state.InstanceID = e.instanceID
	state.ProcessStartID = e.processStartID
	runtimeStatus := runtime.Status()
	state.ControlEndpoint = runtimeStatus.ControlListen
	state.ShutdownToken = e.shutdownToken
	writeState := e.writeState
	if writeState == nil {
		writeState = WriteRuntimeState
	}
	return writeState(statePath, state)
}

func (e *autonomousEngine) notifyStatus() {
	status := e.Status()
	e.mu.RLock()
	handlers := append([]func(*EngineStatus){}, e.statusHandlers...)
	e.mu.RUnlock()
	for _, handler := range handlers {
		handler(status)
	}
}

type autonomousEventWriter struct{ log logger.Logger }

func (w autonomousEventWriter) Write(payload []byte) (int, error) {
	if w.log != nil {
		if line := strings.TrimSpace(string(payload)); line != "" {
			w.log.Info("autonomous mesh event", logger.String("event", line))
		}
	}
	return len(payload), nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
