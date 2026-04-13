package integration_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	"winkyou/pkg/client"
	"winkyou/pkg/config"
	"winkyou/pkg/coordinator/server"
	"winkyou/pkg/logger"

	"google.golang.org/grpc"
)

func TestEngineRuntimeStateLifecycleAgainstCoordinator(t *testing.T) {
	harness := startCoordinatorHarness(t)

	statePath := filepath.Join(t.TempDir(), "alpha.yaml")
	engine := newTestEngine(t, harness.addr(), "alpha", statePath, func(cfg *config.Config) {
		cfg.NAT.STUNServers = nil
	})

	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = engine.Stop()
	})

	runtimeState := waitForRuntimeState(t, statePath, func(state *client.RuntimeState) bool {
		return state.Status.State == "connected" &&
			state.Status.NodeID != "" &&
			state.Status.VirtualIP != "" &&
			state.Status.NetworkCIDR == "10.88.0.0/24"
	})

	if runtimeState.Status.NodeName != "alpha" {
		t.Fatalf("runtime state node_name = %q, want alpha", runtimeState.Status.NodeName)
	}
	if runtimeState.Status.CoordinatorURL != "grpc://"+harness.addr() {
		t.Fatalf("runtime state coordinator_url = %q, want %q", runtimeState.Status.CoordinatorURL, "grpc://"+harness.addr())
	}

	if err := engine.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	waitForCondition(t, 2*time.Second, "runtime state file removed", func() bool {
		_, err := client.LoadRuntimeState(statePath)
		return errors.Is(err, client.ErrRuntimeStateNotFound)
	})
}

func TestTwoEnginesDiscoverEachOtherViaCoordinator(t *testing.T) {
	harness := startCoordinatorHarness(t)

	alpha := newTestEngine(t, harness.addr(), "alpha", filepath.Join(t.TempDir(), "alpha.yaml"), func(cfg *config.Config) {
		cfg.NAT.STUNServers = nil
	})
	beta := newTestEngine(t, harness.addr(), "beta", filepath.Join(t.TempDir(), "beta.yaml"), func(cfg *config.Config) {
		cfg.NAT.STUNServers = nil
	})

	if err := alpha.Start(context.Background()); err != nil {
		t.Fatalf("alpha Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = alpha.Stop()
	})

	if err := beta.Start(context.Background()); err != nil {
		t.Fatalf("beta Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = beta.Stop()
	})

	waitForCondition(t, 3*time.Second, "both engines connected", func() bool {
		return alpha.Status().State == client.EngineStateConnected &&
			beta.Status().State == client.EngineStateConnected
	})

	waitForCondition(t, 3*time.Second, "alpha discovers beta", func() bool {
		return hasPeer(alpha.GetPeers(), "beta")
	})
	waitForCondition(t, 3*time.Second, "beta discovers alpha", func() bool {
		return hasPeer(beta.GetPeers(), "alpha")
	})

	waitForCondition(t, 5*time.Second, "state flow to connecting/connected", func() bool {
		return hasPeerState(alpha.GetPeers(), "beta", client.PeerStateConnecting, client.PeerStateConnected) &&
			hasPeerState(beta.GetPeers(), "alpha", client.PeerStateConnecting, client.PeerStateConnected)
	})

	if len(alpha.GetPeers()) != 1 {
		t.Fatalf("len(alpha peers) = %d, want 1", len(alpha.GetPeers()))
	}
	if len(beta.GetPeers()) != 1 {
		t.Fatalf("len(beta peers) = %d, want 1", len(beta.GetPeers()))
	}
}

func TestEngineStartsWithoutSTUNAndKeepsUnknownNATType(t *testing.T) {
	harness := startCoordinatorHarness(t)

	statePath := filepath.Join(t.TempDir(), "gamma.yaml")
	engine := newTestEngine(t, harness.addr(), "gamma", statePath, func(cfg *config.Config) {
		cfg.NAT.STUNServers = []string{}
	})

	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Start() with empty STUN list error = %v", err)
	}
	t.Cleanup(func() {
		_ = engine.Stop()
	})

	waitForCondition(t, 2*time.Second, "engine connected with unknown NAT type", func() bool {
		status := engine.Status()
		return status.State == client.EngineStateConnected && status.NATType == "unknown"
	})

	runtimeState := waitForRuntimeState(t, statePath, func(state *client.RuntimeState) bool {
		return state.Status.State == "connected" && state.Status.NATType == "unknown"
	})

	if runtimeState.Status.NATType != "unknown" {
		t.Fatalf("runtime state nat_type = %q, want unknown", runtimeState.Status.NATType)
	}
}

type coordinatorHarness struct {
	domain     *server.Server
	listener   net.Listener
	grpcServer *grpc.Server
}

func startCoordinatorHarness(t *testing.T) *coordinatorHarness {
	t.Helper()

	domain, err := server.New(&server.Config{
		ListenAddress: "127.0.0.1:0",
		NetworkCIDR:   "10.88.0.0/24",
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

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = grpcServer.Serve(listener)
	}()

	harness := &coordinatorHarness{
		domain:     domain,
		listener:   listener,
		grpcServer: grpcServer,
	}

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
		<-serveDone
	})

	return harness
}

func (h *coordinatorHarness) addr() string {
	return h.listener.Addr().String()
}

func newTestEngine(t *testing.T, coordinatorAddr, nodeName, statePath string, configure func(cfg *config.Config)) client.Engine {
	t.Helper()

	cfg := config.Default()
	cfg.Node.Name = nodeName
	cfg.Coordinator.URL = "grpc://" + coordinatorAddr
	cfg.Coordinator.Timeout = 100 * time.Millisecond
	cfg.NetIf.Backend = "auto"
	cfg.WireGuard.ListenPort = 0

	if configure != nil {
		configure(&cfg)
	}

	engine, err := client.NewEngine(&cfg, logger.Nop(), statePath)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func waitForRuntimeState(t *testing.T, statePath string, predicate func(state *client.RuntimeState) bool) *client.RuntimeState {
	t.Helper()

	var last *client.RuntimeState
	waitForCondition(t, 3*time.Second, "runtime state condition", func() bool {
		state, err := client.LoadRuntimeState(statePath)
		if err != nil {
			return false
		}
		last = state
		return predicate(state)
	})
	return last
}

func waitForCondition(t *testing.T, timeout time.Duration, description string, predicate func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func hasPeerState(peers []*client.PeerStatus, name string, states ...client.PeerState) bool {
	for _, peer := range peers {
		if peer == nil || peer.Name != name {
			continue
		}
		for _, st := range states {
			if peer.State == st {
				return true
			}
		}
	}
	return false
}

func hasPeer(peers []*client.PeerStatus, name string) bool {
	for _, peer := range peers {
		if peer != nil && peer.Name == name {
			return true
		}
	}
	return false
}
