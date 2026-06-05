package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/config"
	coordclient "winkyou/pkg/coordinator/client"
	"winkyou/pkg/logger"
	"winkyou/pkg/nat"
	"winkyou/pkg/netif"
	"winkyou/pkg/netutil"
	probelab "winkyou/pkg/probe/lab"
	solverstore "winkyou/pkg/solver/store"
	"winkyou/pkg/tunnel"
)

var (
	ErrEngineAlreadyStarted = errors.New("client engine already started")
	ErrEngineNotStarted     = errors.New("client engine not started")
	ErrPeerNotFound         = errors.New("client engine peer not found")
)

const (
	defaultHeartbeatInterval = 10 * time.Second
	defaultStateSyncInterval = 5 * time.Second
	defaultFreshnessWindow   = 20 * time.Second
)

type engine struct {
	cfg       config.Config
	log       logger.Logger
	statePath string

	mu             sync.RWMutex
	started        bool
	status         EngineStatus
	peers          map[string]*PeerStatus
	statusHandlers []func(status *EngineStatus)
	peerHandlers   []func(peer *PeerStatus, event PeerEvent)
	peerMgr        *peerManager

	privateKey    tunnel.PrivateKey
	netif         netif.NetworkInterface
	tun           tunnel.Tunnel
	nat           nat.NATTraversal
	coord         coordclient.CoordinatorClient
	pingConn      *net.UDPConn
	inbandConn    *net.UDPConn
	inbandSeq     uint64
	inbandSignals map[string][]cachedInbandSignal
	inbandSeen    map[string]time.Time

	observationStore           *solverstore.ObservationStore
	runtimePublicEndpointHints []string

	runCtx    context.Context
	runCancel context.CancelFunc
	wg        sync.WaitGroup
}

func NewEngine(cfg *config.Config, log logger.Logger, statePath string) (Engine, error) {
	merged := config.Default()
	if cfg != nil {
		merged = *cfg
	}
	if err := merged.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = logger.Nop()
	}

	return &engine{
		cfg:       merged,
		log:       log,
		statePath: strings.TrimSpace(statePath),
		peers:     make(map[string]*PeerStatus),
		status: EngineStatus{
			State:          EngineStateStopped,
			NodeName:       merged.Node.Name,
			Backend:        merged.NetIf.Backend,
			CoordinatorURL: merged.Coordinator.URL,
			NATType:        nat.NATTypeUnknown.String(),
		},
	}, nil
}

func (e *engine) Start(ctx context.Context) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}

	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return ErrEngineAlreadyStarted
	}
	e.started = true
	e.mu.Unlock()

	e.setState(EngineStateStarting, "")

	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		e.cleanupResources()
		e.mu.Lock()
		e.started = false
		e.mu.Unlock()
		e.setState(EngineStateStopped, errorString(err))
		e.logCleanupError("remove runtime state", RemoveRuntimeState(e.statePath), logger.String("path", e.statePath))
		e.logCleanupError("remove observation state", e.removeObservationState())
	}()

	if strings.TrimSpace(e.cfg.Coordinator.URL) == "" {
		err = fmt.Errorf("client engine: coordinator.url is required")
		return err
	}

	privateKey, err := loadOrGeneratePrivateKey(e.cfg.WireGuard.PrivateKey)
	if err != nil {
		return err
	}
	e.privateKey = privateKey

	ni, err := netif.New(netif.Config{
		Backend: e.cfg.NetIf.Backend,
		MTU:     e.cfg.NetIf.MTU,
	})
	if err != nil {
		return err
	}
	e.netif = ni

	e.setState(EngineStateConnecting, "")

	coord, err := coordclient.NewClient(&coordclient.Config{
		URL:     e.cfg.Coordinator.URL,
		AuthKey: e.cfg.Coordinator.AuthKey,
		Timeout: e.cfg.Coordinator.Timeout,
		Retry:   coordclient.DefaultConfig().Retry,
		TLS: coordclient.TLSConfig{
			InsecureSkipVerify: e.cfg.Coordinator.TLS.InsecureSkipVerify,
			CAFile:             e.cfg.Coordinator.TLS.CAFile,
		},
	})
	if err != nil {
		return err
	}
	e.coord = coord
	e.coord.OnPeerUpdate(e.handlePeerUpdate)
	e.coord.OnSignal(e.handleSignal)

	reg, err := e.coord.Register(ctx, &coordclient.RegisterRequest{
		PublicKey: privateKey.PublicKey().String(),
		Name:      e.cfg.Node.Name,
		AuthKey:   e.cfg.Coordinator.AuthKey,
		Metadata:  e.registrationMetadata(),
	})
	if err != nil {
		return err
	}

	virtualIP, networkCIDR, err := parseVirtualNetwork(reg.VirtualIP, reg.NetworkCIDR)
	if err != nil {
		return err
	}
	if err := e.netif.SetIP(virtualIP, networkCIDR.Mask); err != nil {
		return err
	}

	tun, err := tunnel.New(tunnel.Config{
		Interface:  e.netif,
		PrivateKey: privateKey,
		ListenPort: e.cfg.WireGuard.ListenPort,
	})
	if err != nil {
		return err
	}
	e.tun = tun
	if err := e.tun.Start(); err != nil {
		return err
	}

	natTraversal, err := nat.NewNATTraversal(&nat.Config{
		STUNServers: append([]string(nil), e.cfg.NAT.STUNServers...),
		TURNServers: toNATTURNServers(e.cfg.NAT.TURNServers),
	})
	if err != nil {
		return err
	}
	e.nat = natTraversal
	e.initObservationStore()
	e.initPeerManager()

	natType := nat.NATTypeUnknown
	var runtimePublicEndpointHints []string
	detectCtx, cancelDetect := context.WithTimeout(ctx, 3*time.Second)
	defer cancelDetect()
	if report, detectErr := e.nat.DetectSTUNMapping(detectCtx); detectErr == nil {
		natType = report.NATType
		runtimePublicEndpointHints = runtimePublicEndpointHintsFromReport(e.cfg.NAT, report)
		if len(runtimePublicEndpointHints) > 0 {
			e.log.Info("using runtime public endpoint hints from STUN mapping", logger.String("hints", strings.Join(runtimePublicEndpointHints, ",")))
		}
	} else {
		e.log.Warn("nat detection failed", logger.Error(detectErr))
	}

	e.mu.Lock()
	e.status.NodeID = reg.NodeID
	e.status.PublicKey = privateKey.PublicKey().String()
	e.status.VirtualIP = append(net.IP(nil), virtualIP...)
	e.status.NetworkCIDR = cloneIPNet(networkCIDR)
	e.status.Backend = e.netif.Type()
	e.status.CoordinatorURL = e.cfg.Coordinator.URL
	e.status.NATType = natType.String()
	e.status.StartedAt = time.Now()
	e.runtimePublicEndpointHints = append([]string(nil), runtimePublicEndpointHints...)
	e.mu.Unlock()

	runCtx, runCancel := context.WithCancel(context.Background())
	e.runCtx = runCtx
	e.runCancel = runCancel
	e.startTunnelEventLoop()
	if strings.EqualFold(e.netif.Type(), "tun") {
		if err := e.startPingResponder(virtualIP); err != nil {
			return err
		}
	}
	if err := e.startInbandControl(virtualIP); err != nil {
		e.log.Warn("in-band peer control disabled", logger.Error(err))
	}

	if err := e.refreshPeers(ctx); err != nil {
		e.log.Warn("initial peer refresh failed", logger.Error(err))
	}

	if err := e.coord.StartHeartbeat(runCtx, heartbeatInterval(e.cfg)); err != nil {
		return err
	}

	e.startStateLoop()
	e.setState(EngineStateConnected, "")
	cleanup = false
	return nil
}

func (e *engine) initObservationStore() {
	if e.observationStore != nil {
		return
	}
	store := solverstore.NewObservationStore(e.observationStorePath())
	if err := store.LoadFromFile(); err != nil {
		e.log.Debug("failed to load observation history", logger.Error(err), logger.String("path", e.observationStorePath()))
	}
	e.observationStore = store
}

func (e *engine) observationStorePath() string {
	if strings.TrimSpace(e.statePath) == "" {
		return ""
	}
	dir := filepath.Dir(e.statePath)
	base := strings.TrimSuffix(filepath.Base(e.statePath), filepath.Ext(e.statePath))
	if base == "" || base == "." {
		base = "wink-runtime"
	}
	return filepath.Join(dir, base+".observations.jsonl")
}

func (e *engine) probeRunner() *probelab.Runner {
	return &probelab.Runner{}
}

func (e *engine) Stop() error {
	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return nil
	}
	e.started = false
	runCancel := e.runCancel
	coord := e.coord
	pingConn := e.pingConn
	inbandConn := e.inbandConn
	e.pingConn = nil
	e.inbandConn = nil
	e.mu.Unlock()

	e.setState(EngineStateStopping, "")

	if runCancel != nil {
		runCancel()
	}
	if coord != nil {
		coord.StopHeartbeat()
	}
	if pingConn != nil {
		e.logCleanupError("close ping responder", pingConn.Close())
	}
	if inbandConn != nil {
		e.logCleanupError("close in-band peer control", inbandConn.Close())
	}

	e.wg.Wait()
	e.cleanupResources()

	e.setState(EngineStateStopped, "")
	if err := RemoveRuntimeState(e.statePath); err != nil {
		return err
	}
	return e.removeObservationState()
}

func (e *engine) Status() *EngineStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cloneStatusLocked()
}

func (e *engine) GetPeers() []*PeerStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	peers := make([]*PeerStatus, 0, len(e.peers))
	for _, peer := range e.peers {
		peers = append(peers, clonePeerStatus(peer))
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].NodeID < peers[j].NodeID
	})
	return peers
}

func (e *engine) ConnectToPeer(nodeID string) error {
	e.mu.RLock()
	_, ok := e.peers[nodeID]
	e.mu.RUnlock()
	if !ok {
		return ErrPeerNotFound
	}
	e.startPeerConnect(nodeID)
	return nil
}

func (e *engine) DisconnectFromPeer(nodeID string) error {
	e.mu.RLock()
	_, ok := e.peers[nodeID]
	e.mu.RUnlock()
	if !ok {
		return ErrPeerNotFound
	}
	e.cleanupPeer(nodeID)
	return nil
}

func (e *engine) OnStatusChange(handler func(status *EngineStatus)) {
	if handler == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.statusHandlers = append(e.statusHandlers, handler)
}

func (e *engine) OnPeerChange(handler func(peer *PeerStatus, event PeerEvent)) {
	if handler == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.peerHandlers = append(e.peerHandlers, handler)
}

func (e *engine) refreshPeers(ctx context.Context) error {
	e.mu.RLock()
	coord := e.coord
	e.mu.RUnlock()
	if coord == nil {
		return ErrEngineNotStarted
	}
	peers, err := coord.ListPeers(ctx, coordclient.WithOnlineOnly(false))
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if peer == nil || peer.NodeID == e.currentNodeID() {
			continue
		}
		e.upsertPeer(peer, PeerEventUpsert)
		if peer.Online {
			e.startPeerConnect(peer.NodeID)
		}
	}
	return nil
}

func (e *engine) upsertPeer(peer *coordclient.PeerInfo, event PeerEvent) {
	e.mu.Lock()
	updated := toPeerStatus(peer)
	current, ok := e.peers[updated.NodeID]
	var routeSync *peerAdvertisedRouteSync
	if ok {
		oldSnapshot := clonePeerStatus(current)
		now := time.Now()
		coordinatorOnline := peer.Online
		dataPlaneHealthy := peerDataPlaneHealthyAt(current, now)
		inbandHeartbeatHealthy := peerInbandHeartbeatHealthyAt(current, now)
		updated.State = current.State
		updated.ControlState = current.ControlState
		updated.DataState = current.DataState
		updated.ConnectionType = current.ConnectionType
		updated.ICEState = current.ICEState
		updated.LocalCandidate = current.LocalCandidate
		updated.RemoteCandidate = current.RemoteCandidate
		updated.LastHandshake = current.LastHandshake
		updated.TxBytes = current.TxBytes
		updated.RxBytes = current.RxBytes
		updated.TransportTxPackets = current.TransportTxPackets
		updated.TransportTxBytes = current.TransportTxBytes
		updated.TransportRxPackets = current.TransportRxPackets
		updated.TransportRxBytes = current.TransportRxBytes
		updated.TransportLastError = current.TransportLastError
		updated.MultipathEnabled = current.MultipathEnabled
		updated.PrimaryPathID = current.PrimaryPathID
		updated.ProtectedDirectPathID = current.ProtectedDirectPathID
		updated.StandbyPathIDs = append([]string(nil), current.StandbyPathIDs...)
		updated.ActivePathID = current.ActivePathID
		updated.LastFailoverAt = current.LastFailoverAt
		updated.LastInbandHeartbeatAt = current.LastInbandHeartbeatAt
		updated.LastInbandPathHealthAt = current.LastInbandPathHealthAt
		updated.LastPathID = current.LastPathID
		updated.LastPathStrategy = current.LastPathStrategy
		updated.LastPathPlanID = current.LastPathPlanID
		updated.LastPathRole = current.LastPathRole
		updated.LastPathDependencies = append([]string(nil), current.LastPathDependencies...)
		updated.LastPathDetails = cloneStringMap(current.LastPathDetails)
		updated.LastPathEndpoint = current.LastPathEndpoint
		updated.LastPathConnType = current.LastPathConnType
		updated.LastPathUpdatedAt = current.LastPathUpdatedAt
		if coordinatorOnline {
			updated.ControlState = PeerControlStateConnected
		} else if inbandHeartbeatHealthy {
			updated.ControlState = PeerControlStateDegraded
		} else {
			updated.ControlState = PeerControlStateDisconnected
		}
		if !coordinatorOnline && !dataPlaneHealthy {
			updated.State = PeerStateDisconnected
			updated.DataState = PeerDataStateStale
		}
		if !coordinatorOnline && dataPlaneHealthy && updated.TransportLastError == "" {
			updated.State = PeerStateConnected
			updated.DataState = PeerDataStateAlive
		}
		if updated.ControlState == "" {
			if coordinatorOnline {
				updated.ControlState = PeerControlStateConnected
			} else {
				updated.ControlState = PeerControlStateDisconnected
			}
		}
		if updated.DataState == "" {
			if coordinatorOnline {
				updated.DataState = PeerDataStateConnecting
			} else {
				updated.DataState = PeerDataStateStale
			}
		}
		if updated.Endpoint == nil {
			updated.Endpoint = netutil.CloneUDPAddr(current.Endpoint)
		}
		if shouldReconcilePeerAdvertisedRoutes(oldSnapshot, updated) {
			routeSync = &peerAdvertisedRouteSync{
				oldPeer: oldSnapshot,
				newPeer: clonePeerStatus(updated),
			}
		}
	}
	e.peers[updated.NodeID] = updated
	snapshot := clonePeerStatus(updated)
	handlers := append([]func(peer *PeerStatus, event PeerEvent){}, e.peerHandlers...)
	e.updateStatusCountersLocked()
	e.mu.Unlock()

	for _, handler := range handlers {
		handler(snapshot, event)
	}
	if routeSync != nil {
		e.reconcilePeerAdvertisedRoutes(routeSync)
	}
	e.persistState()
}

func (e *engine) setState(state EngineState, errText string) {
	e.mu.Lock()
	e.status.State = state
	e.status.LastError = strings.TrimSpace(errText)
	e.updateStatusCountersLocked()
	snapshot := e.cloneStatusLocked()
	handlers := append([]func(status *EngineStatus){}, e.statusHandlers...)
	e.mu.Unlock()

	for _, handler := range handlers {
		handler(snapshot)
	}
	e.persistState()
}

func (e *engine) updateStatusCountersLocked() {
	e.syncTunnelPeerStateLocked()
	e.applyPeerHealthStateLocked(time.Now())

	connected := 0
	for _, peer := range e.peers {
		if peer.State == PeerStateConnected {
			connected++
		}
	}
	e.status.ConnectedPeers = connected
	e.status.Uptime = uptimeSince(e.status.StartedAt)
	if e.tun != nil {
		stats := e.tun.GetStats()
		if stats != nil {
			e.status.BytesSent = stats.TxBytes
			e.status.BytesRecv = stats.RxBytes
		}
	}
}

func (e *engine) syncTunnelPeerStateLocked() {
	if e.tun == nil || len(e.peers) == 0 {
		return
	}

	tunnelPeers := e.tun.GetPeers()
	if len(tunnelPeers) == 0 {
		return
	}

	byPublicKey := make(map[string]*tunnel.PeerStatus, len(tunnelPeers))
	for _, tunnelPeer := range tunnelPeers {
		if tunnelPeer == nil {
			continue
		}
		byPublicKey[tunnelPeer.PublicKey.String()] = tunnelPeer
	}

	for _, peer := range e.peers {
		if peer == nil {
			continue
		}
		tunnelPeer := byPublicKey[peer.PublicKey]
		if tunnelPeer == nil {
			continue
		}
		peer.TxBytes = tunnelPeer.TxBytes
		peer.RxBytes = tunnelPeer.RxBytes
		peer.TransportTxPackets = tunnelPeer.TransportTxPackets
		peer.TransportTxBytes = tunnelPeer.TransportTxBytes
		peer.TransportRxPackets = tunnelPeer.TransportRxPackets
		peer.TransportRxBytes = tunnelPeer.TransportRxBytes
		peer.TransportLastError = tunnelPeer.TransportLastError
		peer.MultipathEnabled = tunnelPeer.MultipathEnabled
		peer.PrimaryPathID = tunnelPeer.PrimaryPathID
		peer.ProtectedDirectPathID = tunnelPeer.ProtectedDirectPathID
		peer.StandbyPathIDs = append([]string(nil), tunnelPeer.StandbyPathIDs...)
		peer.ActivePathID = tunnelPeer.ActivePathID
		peer.LastFailoverAt = tunnelPeer.LastFailoverAt
		if tunnelPeer.TransportLastError != "" {
			peer.DataState = PeerDataStateFailed
		}
		if tunnelPeer.Endpoint != nil {
			peer.Endpoint = netutil.CloneUDPAddr(tunnelPeer.Endpoint)
		}
		if !tunnelPeer.LastHandshake.IsZero() {
			peer.LastHandshake = tunnelPeer.LastHandshake
			peer.State = PeerStateConnected
			if tunnelPeer.TransportLastError == "" {
				peer.DataState = PeerDataStateAlive
			}
			peer.LastSeen = tunnelPeer.LastHandshake
		}
	}
}

func (e *engine) cloneStatusLocked() *EngineStatus {
	out := e.status
	out.VirtualIP = append(net.IP(nil), e.status.VirtualIP...)
	out.NetworkCIDR = cloneIPNet(e.status.NetworkCIDR)
	out.Uptime = uptimeSince(out.StartedAt)
	return &out
}

func (e *engine) persistState() {
	e.mu.RLock()
	started := e.started
	statePath := e.statePath
	e.mu.RUnlock()
	if !started || strings.TrimSpace(statePath) == "" {
		return
	}
	status, peers := e.snapshot()
	if err := WriteRuntimeState(e.statePath, newRuntimeStateSnapshot(status, peers)); err != nil {
		e.log.Warn("failed to persist runtime state", logger.Error(err), logger.String("path", e.statePath))
	}
}

func (e *engine) snapshot() (*EngineStatus, []*PeerStatus) {
	e.mu.Lock()
	e.updateStatusCountersLocked()
	status := e.cloneStatusLocked()
	peers := make([]*PeerStatus, 0, len(e.peers))
	for _, peer := range e.peers {
		peers = append(peers, clonePeerStatus(peer))
	}
	e.mu.Unlock()

	sort.Slice(peers, func(i, j int) bool {
		return peers[i].NodeID < peers[j].NodeID
	})
	return status, peers
}

func (e *engine) startStateLoop() {
	done := e.runDone()
	if done == nil {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(defaultStateSyncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				e.persistState()
			}
		}
	}()
}

func (e *engine) cleanupResources() {
	e.mu.Lock()
	runCancel := e.runCancel
	sessions := []*peerSession(nil)
	if e.peerMgr != nil {
		for _, s := range e.peerMgr.sessions {
			sessions = append(sessions, s)
		}
		e.peerMgr.sessions = map[string]*peerSession{}
	}

	tun := e.tun
	coord := e.coord
	pingConn := e.pingConn
	inbandConn := e.inbandConn
	netif := e.netif

	e.tun = nil
	e.coord = nil
	e.pingConn = nil
	e.inbandConn = nil
	e.netif = nil
	e.nat = nil
	e.observationStore = nil
	e.runCtx = nil
	e.runCancel = nil
	e.mu.Unlock()

	if runCancel != nil {
		runCancel()
	}
	for _, s := range sessions {
		e.closePeerSession(s)
	}
	if tun != nil {
		e.logCleanupError("stop tunnel", tun.Stop())
	}
	if coord != nil {
		e.logCleanupError("close coordinator", coord.Close())
	}
	if pingConn != nil {
		e.logCleanupError("close ping responder", pingConn.Close())
	}
	if inbandConn != nil {
		e.logCleanupError("close in-band peer control", inbandConn.Close())
	}
	if netif != nil {
		e.logCleanupError("close network interface", netif.Close())
	}
}

func (e *engine) logCleanupError(action string, err error, fields ...logger.Field) {
	if err == nil {
		return
	}
	fields = append(fields, logger.Error(err))
	e.log.Debug(action+" failed", fields...)
}

func (e *engine) removeObservationState() error {
	path := e.observationStorePath()
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return removePathWithRetry(path)
}

func (e *engine) currentNodeID() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status.NodeID
}

func (e *engine) registrationMetadata() map[string]string {
	metadata := map[string]string{
		"backend":   e.cfg.NetIf.Backend,
		"node_name": e.cfg.Node.Name,
	}
	if endpoints := advertisedRouteEndpoints(e.cfg.Node.AdvertiseRoutes); len(endpoints) > 0 {
		metadata[coordclient.MetadataEndpointsKey] = strings.Join(endpoints, ",")
	}
	return metadata
}

func (e *engine) runContext() (context.Context, bool) {
	if e == nil {
		return nil, false
	}
	e.mu.RLock()
	ctx := e.runCtx
	e.mu.RUnlock()
	return ctx, ctx != nil
}

func toPeerStatus(peer *coordclient.PeerInfo) *PeerStatus {
	status := &PeerStatus{
		NodeID:           peer.NodeID,
		Name:             peer.Name,
		PublicKey:        peer.PublicKey,
		VirtualIP:        net.ParseIP(peer.VirtualIP),
		AdvertisedRoutes: parseAdvertisedRouteEndpoints(peer.Endpoints),
		LastSeen:         unixOrZero(peer.LastSeen),
		State:            PeerStateDisconnected,
		ControlState:     PeerControlStateDisconnected,
		DataState:        PeerDataStateStale,
		ConnectionType:   ConnectionTypeDirect,
	}
	if peer.Online {
		status.State = PeerStateConnecting
		status.ControlState = PeerControlStateConnected
		status.DataState = PeerDataStateConnecting
	}
	for _, raw := range peer.Endpoints {
		if strings.HasPrefix(strings.TrimSpace(raw), "route:") {
			continue
		}
		if endpoint, err := net.ResolveUDPAddr("udp", raw); err == nil {
			status.Endpoint = endpoint
			break
		}
	}
	return status
}

func loadOrGeneratePrivateKey(encoded string) (tunnel.PrivateKey, error) {
	if strings.TrimSpace(encoded) == "" {
		return tunnel.GeneratePrivateKey()
	}
	return tunnel.ParsePrivateKey(encoded)
}

func parseVirtualNetwork(virtualIP, networkCIDR string) (net.IP, *net.IPNet, error) {
	ip := net.ParseIP(strings.TrimSpace(virtualIP))
	if ip == nil {
		return nil, nil, fmt.Errorf("client engine: invalid virtual ip %q", virtualIP)
	}

	_, network, err := net.ParseCIDR(strings.TrimSpace(networkCIDR))
	if err != nil {
		return nil, nil, fmt.Errorf("client engine: invalid network cidr: %w", err)
	}
	return ip, network, nil
}

func clonePeerStatus(peer *PeerStatus) *PeerStatus {
	if peer == nil {
		return nil
	}

	out := *peer
	out.VirtualIP = append(net.IP(nil), peer.VirtualIP...)
	out.Endpoint = netutil.CloneUDPAddr(peer.Endpoint)
	out.AdvertisedRoutes = cloneIPNets(peer.AdvertisedRoutes)
	out.StandbyPathIDs = append([]string(nil), peer.StandbyPathIDs...)
	out.LastPathDependencies = append([]string(nil), peer.LastPathDependencies...)
	out.LastPathDetails = cloneStringMap(peer.LastPathDetails)
	return &out
}

func advertisedRouteEndpoints(routes []string) []string {
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		_, prefix, err := net.ParseCIDR(strings.TrimSpace(route))
		if err != nil || prefix == nil {
			continue
		}
		out = append(out, "route:"+prefix.String())
	}
	return out
}

func parseAdvertisedRouteEndpoints(endpoints []string) []net.IPNet {
	out := make([]net.IPNet, 0, len(endpoints))
	seen := map[string]struct{}{}
	for _, endpoint := range endpoints {
		value := strings.TrimSpace(endpoint)
		if !strings.HasPrefix(value, "route:") {
			continue
		}
		_, prefix, err := net.ParseCIDR(strings.TrimSpace(strings.TrimPrefix(value, "route:")))
		if err != nil || prefix == nil {
			continue
		}
		key := prefix.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, *cloneIPNet(prefix))
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneIPNet(prefix *net.IPNet) *net.IPNet {
	if prefix == nil {
		return nil
	}
	return &net.IPNet{
		IP:   append(net.IP(nil), prefix.IP...),
		Mask: append(net.IPMask(nil), prefix.Mask...),
	}
}

func toNATTURNServers(servers []config.TURNServerConfig) []nat.TURNServer {
	out := make([]nat.TURNServer, 0, len(servers))
	for _, server := range servers {
		out = append(out, nat.TURNServer{
			URL:      server.URL,
			Username: server.Username,
			Password: server.Password,
		})
	}
	return out
}

func heartbeatInterval(cfg config.Config) time.Duration {
	if cfg.Coordinator.Timeout > 0 && cfg.Coordinator.Timeout < defaultHeartbeatInterval {
		return cfg.Coordinator.Timeout
	}
	return defaultHeartbeatInterval
}

func uptimeSince(startedAt time.Time) time.Duration {
	if startedAt.IsZero() {
		return 0
	}
	return time.Since(startedAt).Round(time.Second)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func unixOrZero(ts int64) time.Time {
	if ts <= 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

func peerEventFromCoordinator(event coordclient.PeerEvent) PeerEvent {
	switch event {
	case coordclient.PeerEventOnline:
		return PeerEventOnline
	case coordclient.PeerEventOffline:
		return PeerEventOffline
	case coordclient.PeerEventDeleted:
		return PeerEventDeleted
	case coordclient.PeerEventUpsert:
		return PeerEventUpsert
	default:
		return PeerEventUnknown
	}
}
