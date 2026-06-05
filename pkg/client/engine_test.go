package client

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	"winkyou/pkg/config"
	coordclient "winkyou/pkg/coordinator/client"
	"winkyou/pkg/coordinator/server"
	"winkyou/pkg/logger"
	"winkyou/pkg/solver"
	"winkyou/pkg/tunnel"

	"google.golang.org/grpc"
)

func TestEngineStartPersistsRuntimeStateAndStopRemovesIt(t *testing.T) {
	grpcServer, listener := startTestCoordinator(t)
	defer grpcServer.Stop()
	defer func() {
		_ = listener.Close()
	}()

	cfg := config.Default()
	cfg.Node.Name = "alpha"
	cfg.Coordinator.URL = "grpc://" + listener.Addr().String()
	cfg.Coordinator.Timeout = 2 * time.Second
	cfg.NAT.STUNServers = nil

	statePath := filepath.Join(t.TempDir(), "wink.yaml")
	engine, err := NewEngine(&cfg, logger.Nop(), statePath)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	runtimeState, err := waitForRuntimeState(statePath, func(state *RuntimeState) bool {
		return state.Status.State == EngineStateConnected.String()
	})
	if err != nil {
		t.Fatalf("waitForRuntimeState() error = %v", err)
	}

	if runtimeState.Status.NodeName != "alpha" {
		t.Fatalf("runtime state node_name = %q, want alpha", runtimeState.Status.NodeName)
	}
	if runtimeState.Status.VirtualIP == "" {
		t.Fatal("runtime state virtual_ip is empty")
	}
	if runtimeState.Status.NetworkCIDR != "10.77.0.0/24" {
		t.Fatalf("runtime state network_cidr = %q, want 10.77.0.0/24", runtimeState.Status.NetworkCIDR)
	}

	if err := engine.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if _, err := LoadRuntimeState(statePath); err == nil {
		t.Fatal("runtime state file should be removed after Stop()")
	}
}

func TestRuntimeStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	now := time.Unix(1_700_000_000, 0)

	state := &RuntimeState{
		Version:   "dev",
		PID:       42,
		StartedAt: now,
		UpdatedAt: now.Add(5 * time.Second),
		Status: RuntimeEngineStatus{
			State:       EngineStateConnected.String(),
			NodeID:      "node-1",
			NodeName:    "alpha",
			VirtualIP:   "10.0.0.1",
			NetworkCIDR: "10.0.0.0/24",
			Uptime:      "5s",
		},
		Peers: []RuntimePeerStatus{{
			NodeID:                 "node-2",
			Name:                   "beta",
			State:                  PeerStateConnecting.String(),
			ControlState:           PeerControlStateConnected.String(),
			DataState:              PeerDataStateBound.String(),
			LastHandshake:          now.Add(3 * time.Second),
			LastPathID:             "relayonly/turn_relay",
			LastPathStrategy:       "relay_only",
			LastPathEndpoint:       "203.0.113.10:50000",
			LastPathConnType:       ConnectionTypeRelay.String(),
			LastPathUpdatedAt:      now.Add(4 * time.Second),
			MultipathEnabled:       true,
			PrimaryPathID:          "relay/path",
			ProtectedDirectPathID:  "direct/path",
			StandbyPathIDs:         []string{"direct/path"},
			ActivePathID:           "relay/path",
			LastFailoverAt:         now.Add(6 * time.Second),
			LastInbandHeartbeatAt:  now.Add(7 * time.Second),
			LastInbandPathHealthAt: now.Add(8 * time.Second),
		}},
	}

	if err := WriteRuntimeState(path, state); err != nil {
		t.Fatalf("WriteRuntimeState() error = %v", err)
	}

	loaded, err := LoadRuntimeState(path)
	if err != nil {
		t.Fatalf("LoadRuntimeState() error = %v", err)
	}
	if loaded.PID != 42 {
		t.Fatalf("loaded PID = %d, want 42", loaded.PID)
	}
	if len(loaded.Peers) != 1 || loaded.Peers[0].NodeID != "node-2" {
		t.Fatalf("loaded peers = %#v", loaded.Peers)
	}
	wantHandshake := now.Add(3 * time.Second)
	if !loaded.Peers[0].LastHandshake.Equal(wantHandshake) {
		t.Fatalf("loaded last handshake = %v, want instant %v", loaded.Peers[0].LastHandshake, wantHandshake)
	}
	if loaded.Peers[0].ControlState != PeerControlStateConnected.String() || loaded.Peers[0].DataState != PeerDataStateBound.String() {
		t.Fatalf("loaded peer states = control=%q data=%q", loaded.Peers[0].ControlState, loaded.Peers[0].DataState)
	}
	if loaded.Peers[0].LastPathStrategy != "relay_only" || loaded.Peers[0].LastPathEndpoint != "203.0.113.10:50000" {
		t.Fatalf("loaded path cache = %#v", loaded.Peers[0])
	}
	if !loaded.Peers[0].MultipathEnabled || loaded.Peers[0].PrimaryPathID != "relay/path" || loaded.Peers[0].ProtectedDirectPathID != "direct/path" {
		t.Fatalf("loaded multipath fields = %#v", loaded.Peers[0])
	}
	if len(loaded.Peers[0].StandbyPathIDs) != 1 || loaded.Peers[0].StandbyPathIDs[0] != "direct/path" {
		t.Fatalf("loaded standby path ids = %#v, want [direct/path]", loaded.Peers[0].StandbyPathIDs)
	}
	if !loaded.Peers[0].LastInbandHeartbeatAt.Equal(now.Add(7*time.Second)) || !loaded.Peers[0].LastInbandPathHealthAt.Equal(now.Add(8*time.Second)) {
		t.Fatalf("loaded in-band timestamps = heartbeat=%v path_health=%v", loaded.Peers[0].LastInbandHeartbeatAt, loaded.Peers[0].LastInbandPathHealthAt)
	}
}

func TestRuntimeStatePathAcceptsExplicitRuntimeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wink.runtime.json")
	if got := RuntimeStatePath(path); got != path {
		t.Fatalf("RuntimeStatePath(%q) = %q, want exact path", path, got)
	}
}

func TestUpdateStatusCountersSyncsTunnelPeerState(t *testing.T) {
	pub := mustTestPublicKey(t)
	eng := &engine{
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:    "node-2",
				PublicKey: pub.String(),
				State:     PeerStateConnecting,
			},
		},
		tun: fakeTunnelForEngineTest{peers: []*tunnel.PeerStatus{{
			PublicKey:             pub,
			Endpoint:              &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 51820},
			LastHandshake:         time.Unix(1_700_000_005, 0),
			TxBytes:               64,
			RxBytes:               128,
			TransportTxPackets:    3,
			TransportTxBytes:      96,
			TransportRxPackets:    4,
			TransportRxBytes:      144,
			TransportLastError:    "write: broken pipe",
			MultipathEnabled:      true,
			PrimaryPathID:         "relay/path",
			ProtectedDirectPathID: "direct/path",
			StandbyPathIDs:        []string{"direct/path"},
			ActivePathID:          "direct/path",
			LastFailoverAt:        time.Unix(1_700_000_006, 0),
		}}},
	}

	eng.updateStatusCountersLocked()

	peer := eng.peers["node-2"]
	if peer.TxBytes != 64 || peer.RxBytes != 128 {
		t.Fatalf("peer stats = tx=%d rx=%d, want 64/128", peer.TxBytes, peer.RxBytes)
	}
	if peer.Endpoint == nil || peer.Endpoint.String() != "203.0.113.10:51820" {
		t.Fatalf("peer endpoint = %+v, want 203.0.113.10:51820", peer.Endpoint)
	}
	if peer.LastHandshake.Unix() != 1_700_000_005 {
		t.Fatalf("peer last handshake = %v, want unix 1700000005", peer.LastHandshake)
	}
	if peer.State != PeerStateConnected {
		t.Fatalf("peer state = %s, want connected after handshake", peer.State)
	}
	if peer.DataState != PeerDataStateFailed {
		t.Fatalf("peer data state = %s, want failed while transport error is present", peer.DataState)
	}
	if peer.TransportTxPackets != 3 || peer.TransportTxBytes != 96 {
		t.Fatalf("peer transport tx = packets=%d bytes=%d, want 3/96", peer.TransportTxPackets, peer.TransportTxBytes)
	}
	if peer.TransportRxPackets != 4 || peer.TransportRxBytes != 144 {
		t.Fatalf("peer transport rx = packets=%d bytes=%d, want 4/144", peer.TransportRxPackets, peer.TransportRxBytes)
	}
	if peer.TransportLastError != "write: broken pipe" {
		t.Fatalf("peer transport error = %q, want write: broken pipe", peer.TransportLastError)
	}
	if !peer.MultipathEnabled || peer.PrimaryPathID != "relay/path" || peer.ProtectedDirectPathID != "direct/path" || peer.ActivePathID != "direct/path" {
		t.Fatalf("peer multipath fields = %#v", peer)
	}
	if len(peer.StandbyPathIDs) != 1 || peer.StandbyPathIDs[0] != "direct/path" {
		t.Fatalf("peer standby path ids = %#v, want [direct/path]", peer.StandbyPathIDs)
	}
}

func TestPeerOfflinePreservesConnectedDataPath(t *testing.T) {
	pub := mustTestPublicKey(t)
	now := time.Unix(1_700_000_010, 0)
	removeCalls := 0
	session := &peerSession{bound: true}
	endpoint := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 51820}
	eng := &engine{
		status: EngineStatus{NodeID: "node-1"},
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:             "node-2",
				Name:               "beta",
				PublicKey:          pub.String(),
				VirtualIP:          net.ParseIP("10.77.0.2"),
				State:              PeerStateConnected,
				Endpoint:           endpoint,
				LastHandshake:      now,
				TransportTxPackets: 3,
				TransportRxPackets: 4,
			},
		},
		peerMgr: &peerManager{sessions: map[string]*peerSession{"node-2": session}},
		tun: fakeTunnelForEngineTest{
			removeCalls: &removeCalls,
			peers: []*tunnel.PeerStatus{{
				PublicKey:          pub,
				Endpoint:           endpoint,
				LastHandshake:      now,
				TransportTxPackets: 3,
				TransportRxPackets: 4,
			}},
		},
	}

	eng.handlePeerUpdate(&coordclient.PeerInfo{
		NodeID:    "node-2",
		Name:      "beta",
		PublicKey: pub.String(),
		VirtualIP: "10.77.0.2",
		Online:    false,
		LastSeen:  now.Add(time.Second).Unix(),
	}, coordclient.PeerEventOffline)

	peer := eng.peers["node-2"]
	if peer == nil {
		t.Fatal("peer was removed")
	}
	if peer.State != PeerStateConnected {
		t.Fatalf("peer state = %s, want connected while data path is alive", peer.State)
	}
	if peer.ControlState != PeerControlStateDisconnected {
		t.Fatalf("peer control state = %s, want disconnected after offline update", peer.ControlState)
	}
	if peer.DataState != PeerDataStateAlive {
		t.Fatalf("peer data state = %s, want alive while data path is retained", peer.DataState)
	}
	if peer.Endpoint == nil || peer.Endpoint.String() != endpoint.String() {
		t.Fatalf("peer endpoint = %v, want retained %s", peer.Endpoint, endpoint)
	}
	if got := eng.peerMgr.sessions["node-2"]; got != session {
		t.Fatalf("peer session = %p, want retained %p", got, session)
	}
	if removeCalls != 0 {
		t.Fatalf("RemovePeer calls = %d, want 0", removeCalls)
	}
}

func TestPeerOfflineWithInbandHealthKeepsDataPath(t *testing.T) {
	pub := mustTestPublicKey(t)
	now := time.Now().UTC()
	removeCalls := 0
	session := &peerSession{bound: true}
	eng := &engine{
		status: EngineStatus{NodeID: "node-1"},
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:                 "node-2",
				Name:                   "beta",
				PublicKey:              pub.String(),
				VirtualIP:              net.ParseIP("10.77.0.2"),
				State:                  PeerStateConnected,
				ControlState:           PeerControlStateConnected,
				DataState:              PeerDataStateAlive,
				LastInbandHeartbeatAt:  now,
				LastInbandPathHealthAt: now,
			},
		},
		peerMgr: &peerManager{sessions: map[string]*peerSession{"node-2": session}},
		tun:     fakeTunnelForEngineTest{removeCalls: &removeCalls},
	}

	eng.handlePeerUpdate(&coordclient.PeerInfo{
		NodeID:    "node-2",
		Name:      "beta",
		PublicKey: pub.String(),
		VirtualIP: "10.77.0.2",
		Online:    false,
		LastSeen:  now.Unix(),
	}, coordclient.PeerEventOffline)

	peer := eng.peers["node-2"]
	if peer == nil {
		t.Fatal("peer was removed")
	}
	if peer.ControlState != PeerControlStateDegraded {
		t.Fatalf("peer control state = %s, want degraded while in-band heartbeat is alive", peer.ControlState)
	}
	if peer.DataState != PeerDataStateAlive {
		t.Fatalf("peer data state = %s, want alive while in-band path_health is alive", peer.DataState)
	}
	if peer.State != PeerStateConnected {
		t.Fatalf("peer state = %s, want connected while data path is retained", peer.State)
	}
	if got := eng.peerMgr.sessions["node-2"]; got != session {
		t.Fatalf("peer session = %p, want retained %p", got, session)
	}
	if removeCalls != 0 {
		t.Fatalf("RemovePeer calls = %d, want 0", removeCalls)
	}
}

func TestPeerOfflineWithOnlyInbandHeartbeatDoesNotCleanup(t *testing.T) {
	pub := mustTestPublicKey(t)
	now := time.Now().UTC()
	removeCalls := 0
	session := &peerSession{bound: true}
	eng := &engine{
		status: EngineStatus{NodeID: "node-1"},
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:                "node-2",
				Name:                  "beta",
				PublicKey:             pub.String(),
				VirtualIP:             net.ParseIP("10.77.0.2"),
				State:                 PeerStateConnected,
				ControlState:          PeerControlStateConnected,
				DataState:             PeerDataStateAlive,
				LastInbandHeartbeatAt: now,
			},
		},
		peerMgr: &peerManager{sessions: map[string]*peerSession{"node-2": session}},
		tun:     fakeTunnelForEngineTest{removeCalls: &removeCalls},
	}

	eng.handlePeerUpdate(&coordclient.PeerInfo{
		NodeID:    "node-2",
		Name:      "beta",
		PublicKey: pub.String(),
		VirtualIP: "10.77.0.2",
		Online:    false,
		LastSeen:  now.Unix(),
	}, coordclient.PeerEventOffline)

	peer := eng.peers["node-2"]
	if peer == nil {
		t.Fatal("peer was removed")
	}
	if peer.ControlState != PeerControlStateDegraded {
		t.Fatalf("peer control state = %s, want degraded while in-band heartbeat is alive", peer.ControlState)
	}
	if peer.DataState != PeerDataStateStale {
		t.Fatalf("peer data state = %s, want stale without path_health or tunnel evidence", peer.DataState)
	}
	if got := eng.peerMgr.sessions["node-2"]; got != session {
		t.Fatalf("peer session = %p, want retained %p", got, session)
	}
	if removeCalls != 0 {
		t.Fatalf("RemovePeer calls = %d, want 0", removeCalls)
	}
}

func TestPeerOfflineWithStaleInbandHealthCleansDataPath(t *testing.T) {
	pub := mustTestPublicKey(t)
	now := time.Now().UTC()
	staleAt := now.Add(-inbandHealthWindow - time.Second)
	removeCalls := 0
	eng := &engine{
		status: EngineStatus{NodeID: "node-1"},
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:                 "node-2",
				Name:                   "beta",
				PublicKey:              pub.String(),
				VirtualIP:              net.ParseIP("10.77.0.2"),
				State:                  PeerStateConnected,
				ControlState:           PeerControlStateConnected,
				DataState:              PeerDataStateAlive,
				LastInbandHeartbeatAt:  staleAt,
				LastInbandPathHealthAt: staleAt,
			},
		},
		peerMgr: &peerManager{sessions: map[string]*peerSession{"node-2": {}}},
		tun:     fakeTunnelForEngineTest{removeCalls: &removeCalls},
	}

	eng.handlePeerUpdate(&coordclient.PeerInfo{
		NodeID:    "node-2",
		Name:      "beta",
		PublicKey: pub.String(),
		VirtualIP: "10.77.0.2",
		Online:    false,
		LastSeen:  now.Unix(),
	}, coordclient.PeerEventOffline)

	peer := eng.peers["node-2"]
	if peer == nil {
		t.Fatal("peer was removed")
	}
	if peer.ControlState != PeerControlStateDisconnected {
		t.Fatalf("peer control state = %s, want disconnected after stale in-band heartbeat", peer.ControlState)
	}
	if peer.DataState != PeerDataStateFailed {
		t.Fatalf("peer data state = %s, want failed after cleanup", peer.DataState)
	}
	if _, ok := eng.peerMgr.sessions["node-2"]; ok {
		t.Fatal("peer session should be removed after stale in-band health")
	}
	if removeCalls != 1 {
		t.Fatalf("RemovePeer calls = %d, want 1", removeCalls)
	}
}

func TestPeerOfflineCleansStaleDataPath(t *testing.T) {
	pub := mustTestPublicKey(t)
	removeCalls := 0
	eng := &engine{
		status: EngineStatus{NodeID: "node-1"},
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:    "node-2",
				Name:      "beta",
				PublicKey: pub.String(),
				VirtualIP: net.ParseIP("10.77.0.2"),
				State:     PeerStateConnecting,
				Endpoint:  &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 51820},
			},
		},
		peerMgr: &peerManager{sessions: map[string]*peerSession{"node-2": {}}},
		tun:     fakeTunnelForEngineTest{removeCalls: &removeCalls},
	}

	eng.handlePeerUpdate(&coordclient.PeerInfo{
		NodeID:    "node-2",
		Name:      "beta",
		PublicKey: pub.String(),
		VirtualIP: "10.77.0.2",
		Online:    false,
		LastSeen:  time.Unix(1_700_000_020, 0).Unix(),
	}, coordclient.PeerEventOffline)

	peer := eng.peers["node-2"]
	if peer == nil {
		t.Fatal("peer was removed")
	}
	if peer.State != PeerStateDisconnected {
		t.Fatalf("peer state = %s, want disconnected for stale data path", peer.State)
	}
	if peer.ControlState != PeerControlStateDisconnected {
		t.Fatalf("peer control state = %s, want disconnected", peer.ControlState)
	}
	if peer.DataState != PeerDataStateFailed {
		t.Fatalf("peer data state = %s, want failed after cleanup", peer.DataState)
	}
	if peer.Endpoint != nil {
		t.Fatalf("peer endpoint = %v, want cleared", peer.Endpoint)
	}
	if _, ok := eng.peerMgr.sessions["node-2"]; ok {
		t.Fatal("peer session should be removed for stale data path")
	}
	if removeCalls != 1 {
		t.Fatalf("RemovePeer calls = %d, want 1", removeCalls)
	}
}

func TestPeerSessionBoundRecordsPathCache(t *testing.T) {
	eng := &engine{
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:    "node-2",
				Name:      "beta",
				PublicKey: mustTestPublicKey(t).String(),
				State:     PeerStateConnecting,
			},
		},
	}
	session := &peerSession{}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 50000}

	eng.handlePeerSessionBound("node-2", session, solver.Result{
		Summary: solver.PathSummary{
			PathID:         "relayonly/turn_relay",
			ConnectionType: "relay",
			RemoteAddr:     remoteAddr,
			Details: map[string]string{
				"strategy":         "relay_only",
				"ice_state":        "connected",
				"local_candidate":  "relay:198.51.100.10:50001",
				"remote_candidate": "relay:203.0.113.10:50000",
			},
		},
	})

	peer := eng.peers["node-2"]
	if peer == nil {
		t.Fatal("peer was removed")
	}
	if peer.DataState != PeerDataStateBound {
		t.Fatalf("peer data state = %s, want bound", peer.DataState)
	}
	if peer.LastPathID != "relayonly/turn_relay" || peer.LastPathStrategy != "relay_only" {
		t.Fatalf("peer path cache = id=%q strategy=%q", peer.LastPathID, peer.LastPathStrategy)
	}
	if peer.LastPathEndpoint != remoteAddr.String() || peer.LastPathConnType != "relay" {
		t.Fatalf("peer path endpoint/type = %q/%q", peer.LastPathEndpoint, peer.LastPathConnType)
	}
	if peer.LastPathUpdatedAt.IsZero() {
		t.Fatal("peer last path updated time should be set")
	}
	if peer.ICEState != "connected" || peer.LocalCandidate == "" || peer.RemoteCandidate == "" {
		t.Fatalf("peer ICE diagnostics were not recorded: %#v", peer)
	}
}

func TestBindingPeerRelayBootstrapKeepaliveUsesInitiatorOnly(t *testing.T) {
	pub := mustTestPublicKey(t)
	basePeer := &PeerStatus{
		NodeID:    "node-2",
		PublicKey: pub.String(),
		VirtualIP: net.ParseIP("10.77.0.2"),
		Endpoint:  &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 51820},
	}

	t.Run("initiator retains keepalive", func(t *testing.T) {
		eng := &engine{
			cfg: config.Config{
				NAT: config.NATConfig{ForceRelay: true},
			},
			peers: map[string]*PeerStatus{"node-2": clonePeerStatus(basePeer)},
			peerMgr: &peerManager{sessions: map[string]*peerSession{
				"node-2": {initiator: true},
			}},
		}

		bindingPeer, err := eng.BindingPeer(context.Background(), "node-2")
		if err != nil {
			t.Fatalf("BindingPeer() error = %v", err)
		}
		if bindingPeer.Keepalive != 10*time.Second {
			t.Fatalf("BindingPeer().Keepalive = %v, want 10s for initiator", bindingPeer.Keepalive)
		}
	})

	t.Run("controlled disables bootstrap keepalive", func(t *testing.T) {
		eng := &engine{
			cfg: config.Config{
				NAT: config.NATConfig{ForceRelay: true},
			},
			peers: map[string]*PeerStatus{"node-2": clonePeerStatus(basePeer)},
			peerMgr: &peerManager{sessions: map[string]*peerSession{
				"node-2": {initiator: false},
			}},
		}

		bindingPeer, err := eng.BindingPeer(context.Background(), "node-2")
		if err != nil {
			t.Fatalf("BindingPeer() error = %v", err)
		}
		if bindingPeer.Keepalive != 0 {
			t.Fatalf("BindingPeer().Keepalive = %v, want 0 for controlled relay bootstrap", bindingPeer.Keepalive)
		}
	})
}

func TestSchedulePeerRetryUsesCapturedRunContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &peerSession{initiator: true}
	eng := &engine{
		cfg: config.Config{
			NAT: config.NATConfig{
				RetryInterval:    5 * time.Millisecond,
				RetryMaxInterval: 5 * time.Millisecond,
			},
		},
		runCtx: ctx,
		peerMgr: &peerManager{sessions: map[string]*peerSession{
			"node-2": session,
		}},
	}

	eng.schedulePeerRetry("node-2", session)

	eng.mu.Lock()
	eng.runCtx = nil
	eng.mu.Unlock()
	cancel()

	time.Sleep(25 * time.Millisecond)
}

func TestSchedulePeerRetryAllowsControlledSide(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &peerSession{initiator: false}
	eng := &engine{
		cfg: config.Config{
			NAT: config.NATConfig{
				RetryInterval:    time.Minute,
				RetryMaxInterval: time.Minute,
			},
		},
		runCtx: ctx,
		peerMgr: &peerManager{sessions: map[string]*peerSession{
			"node-1": session,
		}},
	}

	eng.schedulePeerRetry("node-1", session)

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if !session.retryPending {
		t.Fatal("non-initiator peer session should schedule retry while data path is not alive")
	}
	if session.retryDelay != time.Minute {
		t.Fatalf("retry delay = %v, want %v", session.retryDelay, time.Minute)
	}
}

func TestStartPeerConnectAllowsControlledSide(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Default()
	cfg.NAT.RetryInterval = time.Minute
	cfg.NAT.RetryMaxInterval = time.Minute

	eng := &engine{
		cfg:    cfg,
		log:    logger.Nop(),
		runCtx: ctx,
		status: EngineStatus{NodeID: "node-2"},
		peers: map[string]*PeerStatus{
			"node-1": {
				NodeID:    "node-1",
				PublicKey: mustTestPublicKey(t).String(),
				VirtualIP: net.ParseIP("10.77.0.1"),
				State:     PeerStateConnecting,
			},
		},
		peerMgr: &peerManager{sessions: map[string]*peerSession{}},
	}

	eng.startPeerConnect("node-1")

	session := eng.peerMgr.sessions["node-1"]
	if session == nil {
		t.Fatal("controlled-side peer session was not created")
	}
	if session.initiator {
		t.Fatal("test setup expected controlled-side session")
	}
	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if !session.retryPending {
		t.Fatal("controlled-side peer session should retry after start failure")
	}
}

type fakeTunnelForEngineTest struct {
	peers       []*tunnel.PeerStatus
	stats       *tunnel.TunnelStats
	events      chan tunnel.TunnelEvent
	removeCalls *int
}

func (f fakeTunnelForEngineTest) Start() error                     { return nil }
func (f fakeTunnelForEngineTest) Stop() error                      { return nil }
func (f fakeTunnelForEngineTest) AddPeer(*tunnel.PeerConfig) error { return nil }
func (f fakeTunnelForEngineTest) RemovePeer(tunnel.PublicKey) error {
	if f.removeCalls != nil {
		*f.removeCalls = *f.removeCalls + 1
	}
	return nil
}
func (f fakeTunnelForEngineTest) UpdatePeerEndpoint(tunnel.PublicKey, *net.UDPAddr) error {
	return nil
}
func (f fakeTunnelForEngineTest) GetPeers() []*tunnel.PeerStatus { return f.peers }
func (f fakeTunnelForEngineTest) GetStats() *tunnel.TunnelStats  { return f.stats }
func (f fakeTunnelForEngineTest) Events() <-chan tunnel.TunnelEvent {
	if f.events == nil {
		return make(chan tunnel.TunnelEvent)
	}
	return f.events
}

func waitForRuntimeState(path string, predicate func(state *RuntimeState) bool) (*RuntimeState, error) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state, err := LoadRuntimeState(path)
		if err == nil && predicate(state) {
			return state, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, context.DeadlineExceeded
}

func startTestCoordinator(t *testing.T) (*grpc.Server, net.Listener) {
	t.Helper()

	domain, err := server.New(&server.Config{
		ListenAddress: "127.0.0.1:0",
		NetworkCIDR:   "10.77.0.0/24",
		LeaseTTL:      5 * time.Second,
	})
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	grpcServer := grpc.NewServer()
	coordinatorv1.RegisterCoordinatorServer(grpcServer, server.NewGRPCService(domain))

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	return grpcServer, listener
}

func mustTestPublicKey(t *testing.T) tunnel.PublicKey {
	t.Helper()
	privateKey, err := tunnel.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}
	return privateKey.PublicKey()
}

func TestMain(m *testing.M) {
	_ = os.Setenv("WINKYOU_NETIF_ALLOW_MEMORY", "1")
	_ = os.Setenv("WINKYOU_TUNNEL_ALLOW_MEMORY", "1")
	code := m.Run()
	os.Exit(code)
}
