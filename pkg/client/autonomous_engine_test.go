package client

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/bootstrap/selfhosted"
	"winkyou/pkg/config"
	"winkyou/pkg/logger"
	"winkyou/pkg/mesh"
	"winkyou/pkg/meshruntime"
)

func TestAutonomousEngineStartsWithoutCoordinatorOrWireGuard(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	engine, err := NewEngine(&cfg, logger.Nop(), stateKey)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if _, ok := engine.(*autonomousEngine); !ok {
		t.Fatalf("NewEngine() type = %T, want autonomous engine", engine)
	}
	if err := engine.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	status := engine.Status()
	if status.Mode != "autonomous_mesh" || status.Backend != "userspace-mesh" {
		t.Fatalf("status mode/backend = %q/%q", status.Mode, status.Backend)
	}
	if status.CoordinatorURL != "" || status.InfrastructureCoordinatorStarted {
		t.Fatalf("autonomous engine started infrastructure coordinator: %+v", status)
	}
	if status.VirtualIP.String() != "fd7a:115c:a1e0::a" || status.NetworkCIDR.String() != "fd7a:115c:a1e0::a/128" {
		t.Fatalf("virtual network = %v %v", status.VirtualIP, status.NetworkCIDR)
	}
	if status.ControlListen == "" || strings.HasSuffix(status.ControlListen, ":0") {
		t.Fatalf("control listen = %q, want bound ephemeral address", status.ControlListen)
	}

	state, err := LoadRuntimeState(stateKey)
	if err != nil {
		t.Fatalf("LoadRuntimeState() error = %v", err)
	}
	if state.SchemaVersion != 1 || state.InstanceID == "" || state.ProcessStartID == "" || state.ShutdownToken == "" {
		t.Fatalf("runtime lifecycle identity = %+v", state)
	}
	if state.ControlEndpoint != status.ControlListen || state.Status.Mode != "autonomous_mesh" {
		t.Fatalf("runtime state control/mode = %q/%q", state.ControlEndpoint, state.Status.Mode)
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+state.ControlEndpoint+"/v1/shutdown", nil)
	if err != nil {
		t.Fatalf("new shutdown request: %v", err)
	}
	req.Header.Set(meshruntime.ShutdownTokenHeader, state.ShutdownToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("shutdown request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("shutdown status = %s", resp.Status)
	}
	done := engine.(DoneEngine).Done()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("autonomous runtime did not close after authenticated shutdown")
	}
	if err := engine.Stop(); err != nil {
		t.Fatalf("Stop() after runtime shutdown error = %v", err)
	}
	if _, err := LoadRuntimeState(stateKey); !errors.Is(err, ErrRuntimeStateNotFound) {
		t.Fatalf("runtime state after Stop error = %v, want not found", err)
	}
}

func TestAutonomousEngineMapsGraphRoutesWithoutCallingTransitRelay(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	engineValue, err := newAutonomousEngine(cfg, logger.Nop(), "")
	if err != nil {
		t.Fatalf("newAutonomousEngine() error = %v", err)
	}
	engine := engineValue.(*autonomousEngine)
	status := meshruntime.Status{
		NodeID: "A",
		Members: []meshruntime.MemberStatus{
			{NodeID: "B", VirtualIP: "fd7a:115c:a1e0::b"},
			{NodeID: "C", VirtualIP: "fd7a:115c:a1e0::c"},
		},
		Routes: []meshruntime.RouteStatus{
			{Destination: "B", NextHop: "B", HopCount: 1, Path: []string{"A", "B"}, RTTMillis: 5},
			{Destination: "C", NextHop: "B", HopCount: 2, Path: []string{"A", "B", "C"}, RTTMillis: 12},
		},
		Neighbors: []string{"B"},
		MaintainedPeers: []meshruntime.MaintainedPeerStatus{
			{PeerID: "B", NeighborKind: mesh.NeighborKindPacket, ProtectedDirect: true, Reachable: true, RoutePath: []string{"A", "B"}, RouteHopCount: 1},
		},
		SelfBootstrap: []selfhosted.PeerStatus{{PeerID: "C", State: selfhosted.StateScheduled}},
	}

	peers := engine.peerStatuses(status)
	if len(peers) != 2 || peers[0].NodeID != "B" || peers[1].NodeID != "C" {
		t.Fatalf("peers = %+v", peers)
	}
	if !peers[0].ProtectedDirect || peers[0].ConnectionType != ConnectionTypeDirect || peers[0].NeighborKind != string(mesh.NeighborKindPacket) {
		t.Fatalf("B direct mapping = %+v", peers[0])
	}
	if peers[1].ConnectionType != ConnectionTypeMeshRoute || peers[1].ConnectionType.String() != "mesh_route" {
		t.Fatalf("C transit mapping = %+v", peers[1])
	}
	if strings.Join(peers[1].RoutePath, ",") != "A,B,C" || peers[1].RouteNextHop != "B" || peers[1].RouteHopCount != 2 {
		t.Fatalf("C route mapping = %+v", peers[1])
	}
	if peers[1].SelfBootstrapState != string(selfhosted.StateScheduled) {
		t.Fatalf("C self-bootstrap state = %q", peers[1].SelfBootstrapState)
	}
}

func TestAutonomousEngineStartFailsWhenInitialStateWriteFails(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	engineValue, err := newAutonomousEngine(cfg, logger.Nop(), stateKey)
	if err != nil {
		t.Fatalf("newAutonomousEngine() error = %v", err)
	}
	engine := engineValue.(*autonomousEngine)
	engine.writeState = func(string, *RuntimeState) error { return errors.New("injected state write failure") }

	err = engine.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "persist initial runtime state") {
		t.Fatalf("Start() error = %v, want initial persistence failure", err)
	}
	if status := engine.Status(); status.State != EngineStateStopped {
		t.Fatalf("status after failed Start = %s, want stopped", status.State)
	}
	if _, err := LoadRuntimeState(stateKey); !errors.Is(err, ErrRuntimeStateNotFound) {
		t.Fatalf("runtime state after failed Start error = %v, want not found", err)
	}
}

func TestAutonomousEngineStopWaitsForInitialStateWriteAndDoesNotResurrectState(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	engineValue, err := newAutonomousEngine(cfg, logger.Nop(), stateKey)
	if err != nil {
		t.Fatalf("newAutonomousEngine() error = %v", err)
	}
	engine := engineValue.(*autonomousEngine)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var releaseOnce sync.Once
	releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWrite)
	engine.writeState = func(path string, state *RuntimeState) error {
		once.Do(func() {
			close(entered)
			<-release
		})
		return WriteRuntimeState(path, state)
	}

	startDone := make(chan error, 1)
	go func() { startDone <- engine.Start(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("initial state write did not start")
	}
	stopDone := make(chan error, 1)
	go func() { stopDone <- engine.Stop() }()
	select {
	case err := <-stopDone:
		t.Fatalf("Stop() returned before initial state write completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseWrite()
	if err := <-startDone; err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if _, err := LoadRuntimeState(stateKey); !errors.Is(err, ErrRuntimeStateNotFound) {
		t.Fatalf("runtime state after Stop error = %v, want not found", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := LoadRuntimeState(stateKey); !errors.Is(err, ErrRuntimeStateNotFound) {
		t.Fatalf("runtime state resurrected after Stop: %v", err)
	}
}

func autonomousEngineTestConfig(nodeID, virtualIP string) config.Config {
	cfg := config.Default()
	cfg.Coordinator.URL = ""
	cfg.AutonomousMesh = config.AutonomousMeshConfig{
		Enabled: true, NodeID: nodeID, VirtualIP: virtualIP,
		Listen: "off", ControlListen: "127.0.0.1:0",
		RecoveryDebounce: 250 * time.Millisecond,
	}
	return cfg
}

func TestAutonomousEngineRuntimeConfigPropagatesRecoveryDebounce(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	cfg.AutonomousMesh.RecoveryDebounce = 500 * time.Millisecond

	engine := autonomousEngine{cfg: cfg}
	if got := engine.runtimeConfig().RecoveryDebounce; got != 500*time.Millisecond {
		t.Fatalf("runtime recovery debounce = %s, want 500ms", got)
	}
}

func TestAutonomousEngineRuntimeConfigPropagatesPunchInterface(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	cfg.NAT.PunchInterface = "Ethernet-underlay"

	engine := autonomousEngine{cfg: cfg}
	if got := engine.runtimeConfig().PunchInterface; got != "Ethernet-underlay" {
		t.Fatalf("runtime punch interface = %q, want Ethernet-underlay", got)
	}
}

func TestAutonomousEngineVirtualAliasOwnershipScopeIsStable(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	cfg.AutonomousMesh.VirtualTCPForwards = []config.AutonomousMeshVirtualTCPForward{{
		Listen: "[fd7a:115c:a1e0::b]:22", RemoteID: "B",
	}}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "wink.yaml")
	firstValue, err := newAutonomousEngine(cfg, logger.Nop(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := newAutonomousEngine(cfg, logger.Nop(), filepath.Join(dir, "wink.runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := firstValue.(*autonomousEngine)
	second := secondValue.(*autonomousEngine)
	firstOwnership, err := first.virtualAliasOwnership()
	if err != nil {
		t.Fatal(err)
	}
	secondOwnership, err := second.virtualAliasOwnership()
	if err != nil {
		t.Fatal(err)
	}
	if firstOwnership == nil || secondOwnership == nil {
		t.Fatalf("virtual alias ownership = %+v / %+v", firstOwnership, secondOwnership)
	}
	if firstOwnership.Scope != secondOwnership.Scope {
		t.Fatalf("equivalent runtime-state paths produced different scopes: %q / %q", firstOwnership.Scope, secondOwnership.Scope)
	}
	if firstOwnership.InstanceID == secondOwnership.InstanceID {
		t.Fatalf("process generations reused instance ID %q", firstOwnership.InstanceID)
	}
	if firstOwnership.PID != os.Getpid() || firstOwnership.ProcessStartID != first.processStartID {
		t.Fatalf("ownership process identity = %+v, want pid %d start %q", firstOwnership, os.Getpid(), first.processStartID)
	}

	differentPathValue, err := newAutonomousEngine(cfg, logger.Nop(), filepath.Join(dir, "other.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	differentPath, err := differentPathValue.(*autonomousEngine).virtualAliasOwnership()
	if err != nil {
		t.Fatal(err)
	}
	if differentPath.Scope == firstOwnership.Scope {
		t.Fatal("different runtime-state path reused ownership scope")
	}
	differentNodeCfg := cfg
	differentNodeCfg.AutonomousMesh.NodeID = "Z"
	differentNodeValue, err := newAutonomousEngine(differentNodeCfg, logger.Nop(), configPath)
	if err != nil {
		t.Fatal(err)
	}
	differentNode, err := differentNodeValue.(*autonomousEngine).virtualAliasOwnership()
	if err != nil {
		t.Fatal(err)
	}
	if differentNode.Scope == firstOwnership.Scope {
		t.Fatal("different node ID reused ownership scope")
	}
}

func TestAutonomousEngineVirtualAliasOwnershipRequiresStateAndForwards(t *testing.T) {
	cfg := autonomousEngineTestConfig("A", "fd7a:115c:a1e0::a")
	cfg.AutonomousMesh.VirtualTCPForwards = []config.AutonomousMeshVirtualTCPForward{{
		Listen: "[fd7a:115c:a1e0::b]:22", RemoteID: "B",
	}}
	withoutStateValue, err := newAutonomousEngine(cfg, logger.Nop(), "")
	if err != nil {
		t.Fatal(err)
	}
	if ownership, err := withoutStateValue.(*autonomousEngine).virtualAliasOwnership(); err != nil || ownership != nil {
		t.Fatalf("ownership without state = %+v error=%v, want nil", ownership, err)
	}
	cfg.AutonomousMesh.VirtualTCPForwards = nil
	withoutForwardValue, err := newAutonomousEngine(cfg, logger.Nop(), filepath.Join(t.TempDir(), "wink.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if ownership, err := withoutForwardValue.(*autonomousEngine).virtualAliasOwnership(); err != nil || ownership != nil {
		t.Fatalf("ownership without virtual forwards = %+v error=%v, want nil", ownership, err)
	}
}
