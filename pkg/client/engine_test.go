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
	"winkyou/pkg/coordinator/server"
	"winkyou/pkg/logger"
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
			NodeID:        "node-2",
			Name:          "beta",
			State:         PeerStateConnecting.String(),
			LastHandshake: now.Add(3 * time.Second),
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
	if loaded.Peers[0].LastHandshake != now.Add(3*time.Second) {
		t.Fatalf("loaded last handshake = %v, want %v", loaded.Peers[0].LastHandshake, now.Add(3*time.Second))
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
			PublicKey:          pub,
			Endpoint:           &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 51820},
			LastHandshake:      time.Unix(1_700_000_005, 0),
			TxBytes:            64,
			RxBytes:            128,
			TransportTxPackets: 3,
			TransportTxBytes:   96,
			TransportRxPackets: 4,
			TransportRxBytes:   144,
			TransportLastError: "write: broken pipe",
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
	if peer.TransportTxPackets != 3 || peer.TransportTxBytes != 96 {
		t.Fatalf("peer transport tx = packets=%d bytes=%d, want 3/96", peer.TransportTxPackets, peer.TransportTxBytes)
	}
	if peer.TransportRxPackets != 4 || peer.TransportRxBytes != 144 {
		t.Fatalf("peer transport rx = packets=%d bytes=%d, want 4/144", peer.TransportRxPackets, peer.TransportRxBytes)
	}
	if peer.TransportLastError != "write: broken pipe" {
		t.Fatalf("peer transport error = %q, want write: broken pipe", peer.TransportLastError)
	}
}

type fakeTunnelForEngineTest struct {
	peers  []*tunnel.PeerStatus
	stats  *tunnel.TunnelStats
	events chan tunnel.TunnelEvent
}

func (f fakeTunnelForEngineTest) Start() error                      { return nil }
func (f fakeTunnelForEngineTest) Stop() error                       { return nil }
func (f fakeTunnelForEngineTest) AddPeer(*tunnel.PeerConfig) error  { return nil }
func (f fakeTunnelForEngineTest) RemovePeer(tunnel.PublicKey) error { return nil }
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
