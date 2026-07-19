package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/recoverycard"
	"winkyou/pkg/solver"
)

func TestMeshRuntimeSelfBootstrapRestoresEdgeAfterPeerProcessRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	portA := selfBootstrapTestReserveUDPPort(t, nil)
	portB := selfBootstrapTestReserveUDPPort(t, map[int]bool{portA: true})
	directory := t.TempDir()
	cardA := filepath.Join(directory, "A-recovery.json")
	cardB := filepath.Join(directory, "B-recovery.json")
	selfBootstrapTestSaveCard(t, cardA, "A", map[string]selfBootstrapTestPairHint{
		"B": {LocalPort: portA, RemotePort: portB},
	})
	selfBootstrapTestSaveCard(t, cardB, "B", map[string]selfBootstrapTestPairHint{
		"A": {LocalPort: portB, RemotePort: portA},
	})

	runtimeA := selfBootstrapTestNewRuntime(t, "A", cardA, []string{"B"})
	defer runtimeA.Close()
	runtimeB := selfBootstrapTestNewRuntime(t, "B", cardB, []string{"A"})
	if err := runtimeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runtimeB.Start(ctx); err != nil {
		t.Fatal(err)
	}

	selfBootstrapTestWaitDirect(t, ctx, runtimeA, runtimeB)
	firstBStartedAt := runtimeB.startedAt
	selfBootstrapTestAssertNoBootstrapConnector(t, runtimeA, runtimeB)
	selfBootstrapTestAssertPacketNeighbor(t, runtimeA, "B")
	selfBootstrapTestAssertPacketNeighbor(t, runtimeB, "A")
	selfBootstrapTestAssertSuccessfulStatus(t, runtimeA, "B")
	selfBootstrapTestAssertSuccessfulStatus(t, runtimeB, "A")

	if err := runtimeB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		return !runtimeA.node.HasNeighbor("B")
	}); err != nil {
		t.Fatalf("A did not withdraw the stopped B process: %v", err)
	}

	// Construct a completely new runtime with the same on-disk card. It has no
	// InitialPeers, mesh listener, coordinator, or relay to help it rejoin.
	restartedB := selfBootstrapTestNewRuntime(t, "B", cardB, []string{"A"})
	defer restartedB.Close()
	if err := restartedB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !restartedB.startedAt.After(firstBStartedAt) {
		t.Fatalf("replacement B started_at = %s, want after %s", restartedB.startedAt, firstBStartedAt)
	}

	selfBootstrapTestWaitDirect(t, ctx, runtimeA, restartedB)
	selfBootstrapTestAssertNoBootstrapConnector(t, runtimeA, restartedB)
	selfBootstrapTestAssertPacketNeighbor(t, runtimeA, "B")
	selfBootstrapTestAssertPacketNeighbor(t, restartedB, "A")
	selfBootstrapTestAssertSuccessfulStatus(t, runtimeA, "B")
	selfBootstrapTestAssertSuccessfulStatus(t, restartedB, "A")

	storeB, err := recoverycard.NewStore(cardB, "B")
	if err != nil {
		t.Fatal(err)
	}
	var (
		peerA       recoverycard.Peer
		lastLoadErr error
	)
	if err := runtimeTestWait(ctx, func() bool {
		persistedB, loadErr := storeB.Load()
		if loadErr != nil {
			lastLoadErr = loadErr
			return false
		}
		var found bool
		peerA, found = selfBootstrapTestLookupPeer(persistedB, "A")
		return found && peerA.LastSuccessAt.After(firstBStartedAt)
	}); err != nil {
		t.Fatalf("wait for B restart recovery-card update: %v (last load error: %v)", err, lastLoadErr)
	}
	if peerA.LastSuccessfulLocalBindPort != uint16(portB) ||
		peerA.Endpoints[0].AddrPort != net.JoinHostPort("127.0.0.1", strconv.Itoa(portA)) {
		t.Fatalf("B restart did not refresh its successful A path: %+v", peerA)
	}
}

func TestMeshRuntimeSelfBootstrapRestoresThreeNodeTriangleAfterFullRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// These IDs have pair-window offsets clustered within 210ms for the 2s
	// cycle below. Starting in their common active interval lets cold bootstrap
	// quickly build a spanning tree; routed recovery then uses the third ordinary
	// peer to coordinate the final direct edge.
	nodeIDs := []string{"A", "B0", "C0"}
	ports := make(map[string]int)
	reserved := make(map[int]bool)
	for _, pair := range []string{"A-B0", "B0-A", "A-C0", "C0-A", "B0-C0", "C0-B0"} {
		ports[pair] = selfBootstrapTestReserveUDPPort(t, reserved)
		reserved[ports[pair]] = true
	}
	ports["stale-B0-C0"] = selfBootstrapTestReserveFarUDPPort(t, ports["B0-C0"], reserved)
	reserved[ports["stale-B0-C0"]] = true
	ports["stale-C0-B0"] = selfBootstrapTestReserveFarUDPPort(t, ports["C0-B0"], reserved)
	reserved[ports["stale-C0-B0"]] = true

	directory := t.TempDir()
	cardPaths := map[string]string{
		"A":  filepath.Join(directory, "A-recovery.json"),
		"B0": filepath.Join(directory, "B0-recovery.json"),
		"C0": filepath.Join(directory, "C0-recovery.json"),
	}
	selfBootstrapTestSaveCard(t, cardPaths["A"], "A", map[string]selfBootstrapTestPairHint{
		"B0": {LocalPort: ports["A-B0"], RemotePort: ports["B0-A"]},
		"C0": {LocalPort: ports["A-C0"], RemotePort: ports["C0-A"]},
	})
	selfBootstrapTestSaveCard(t, cardPaths["B0"], "B0", map[string]selfBootstrapTestPairHint{
		"A":  {LocalPort: ports["B0-A"], RemotePort: ports["A-B0"]},
		"C0": {LocalPort: ports["B0-C0"], RemotePort: ports["stale-C0-B0"]},
	})
	selfBootstrapTestSaveCard(t, cardPaths["C0"], "C0", map[string]selfBootstrapTestPairHint{
		"A":  {LocalPort: ports["C0-A"], RemotePort: ports["A-C0"]},
		"B0": {LocalPort: ports["C0-B0"], RemotePort: ports["stale-B0-C0"]},
	})

	type generation struct {
		runtimes map[string]*meshRuntime
		brokers  []*runtimeTestBroker
	}
	startGeneration := func() generation {
		brokers := map[string]*runtimeTestBroker{
			"A-B0":  selfBootstrapTestNewDistinctBroker(t, reserved, "A", "B0"),
			"A-C0":  selfBootstrapTestNewDistinctBroker(t, reserved, "A", "C0"),
			"B0-C0": selfBootstrapTestNewDistinctBroker(t, reserved, "B0", "C0"),
		}
		for _, broker := range brokers {
			current := broker
			t.Cleanup(current.Close)
		}
		factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
			left, right := spec.LocalNodeID, spec.RemoteNodeID
			if right < left {
				left, right = right, left
			}
			broker := brokers[left+"-"+right]
			if broker == nil {
				return nil, fmt.Errorf("no self-bootstrap test broker for %s-%s", left, right)
			}
			return &runtimeTestStrategy{spec: spec, broker: broker, remoteReady: make(chan struct{}, 1)}, nil
		}
		runtimes := make(map[string]*meshRuntime, len(nodeIDs))
		for _, nodeID := range nodeIDs {
			peers := make([]string, 0, len(nodeIDs)-1)
			for _, candidate := range nodeIDs {
				if candidate != nodeID {
					peers = append(peers, candidate)
				}
			}
			runtimes[nodeID] = selfBootstrapTestNewRuntimeWithRecovery(
				t, nodeID, cardPaths[nodeID], peers, 50*time.Millisecond, factory,
			)
			current := runtimes[nodeID]
			t.Cleanup(func() { _ = current.Close() })
		}
		selfBootstrapTestWaitForCommonTriangleWindow(t, ctx, nodeIDs)
		for _, nodeID := range nodeIDs {
			if err := runtimes[nodeID].Start(ctx); err != nil {
				t.Fatalf("start %s: %v", nodeID, err)
			}
		}
		return generation{
			runtimes: runtimes,
			brokers:  []*runtimeTestBroker{brokers["A-B0"], brokers["A-C0"], brokers["B0-C0"]},
		}
	}
	closeGeneration := func(current generation) {
		for _, nodeID := range nodeIDs {
			if err := current.runtimes[nodeID].Close(); err != nil {
				t.Errorf("close %s: %v", nodeID, err)
			}
		}
		for _, broker := range current.brokers {
			broker.Close()
		}
	}
	assertTriangle := func(runtimes map[string]*meshRuntime) {
		if err := runtimeTestWait(ctx, func() bool {
			for _, localID := range nodeIDs {
				for _, remoteID := range nodeIDs {
					if localID == remoteID {
						continue
					}
					if !selfBootstrapTestIsDirect(runtimes[localID], remoteID) {
						return false
					}
				}
			}
			return true
		}); err != nil {
			for _, nodeID := range nodeIDs {
				runtime := runtimes[nodeID]
				neighborDetails := make(map[string]mesh.NeighborInfo)
				for _, peerID := range runtime.node.Neighbors() {
					neighborDetails[peerID], _ = runtime.node.Neighbor(peerID)
				}
				t.Logf("%s neighbors=%v routes=%v self-bootstrap=%+v maintained=%+v",
					nodeID, neighborDetails, runtime.node.Routes(),
					runtime.status().SelfBootstrap, runtime.recovery.Snapshot())
			}
			t.Fatalf("three-node direct triangle did not converge: %v", err)
		}
		if err := runtimeTestWait(ctx, func() bool {
			for _, localID := range nodeIDs {
				for _, status := range runtimes[localID].shortcutSnapshot() {
					if status.Phase == shortcut.PhaseStable && status.CoordinatorID != "" &&
						status.CoordinatorID != status.InitiatorID && status.CoordinatorID != status.TargetID &&
						slices.Contains(nodeIDs, status.CoordinatorID) {
						return true
					}
				}
			}
			return false
		}); err != nil {
			t.Fatalf("ordinary-peer recovery did not reach stable after completing the triangle: %v", err)
		}
		selfBootstrapEdges := make(map[string]bool)
		peerCoordinatedRecovery := false
		for _, localID := range nodeIDs {
			selfBootstrapTestAssertNoBootstrapConnector(t, runtimes[localID])
			if len(runtimes[localID].node.Neighbors()) != 2 {
				t.Fatalf("%s neighbors = %v, want both direct peers", localID, runtimes[localID].node.Neighbors())
			}
			for _, status := range runtimes[localID].status().SelfBootstrap {
				if !status.LastSuccessAt.IsZero() {
					left, right := localID, status.PeerID
					if right < left {
						left, right = right, left
					}
					selfBootstrapEdges[left+"-"+right] = true
				}
			}
			for _, status := range runtimes[localID].shortcutSnapshot() {
				if status.Phase != shortcut.PhaseStable || status.CoordinatorID == "" ||
					status.CoordinatorID == status.InitiatorID || status.CoordinatorID == status.TargetID {
					continue
				}
				if slices.Contains(nodeIDs, status.CoordinatorID) {
					peerCoordinatedRecovery = true
				}
			}
		}
		if len(selfBootstrapEdges) < 2 {
			t.Fatalf("self-bootstrap created only %d undirected edges, want a coordinator-less spanning tree", len(selfBootstrapEdges))
		}
		if !peerCoordinatedRecovery {
			for _, nodeID := range nodeIDs {
				t.Logf("%s shortcuts=%+v self-bootstrap=%+v", nodeID,
					runtimes[nodeID].shortcutSnapshot(), runtimes[nodeID].status().SelfBootstrap)
			}
			t.Fatal("ordinary-peer coordinated recovery did not fill the remaining triangle edge")
		}
	}

	first := startGeneration()
	assertTriangle(first.runtimes)
	firstStartedAt := make(map[string]time.Time, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		firstStartedAt[nodeID] = first.runtimes[nodeID].startedAt
	}
	closeGeneration(first)

	second := startGeneration()
	defer closeGeneration(second)
	for _, nodeID := range nodeIDs {
		if !second.runtimes[nodeID].startedAt.After(firstStartedAt[nodeID]) {
			t.Fatalf("replacement %s did not start after its first process", nodeID)
		}
	}
	assertTriangle(second.runtimes)
}

type selfBootstrapTestPairHint struct {
	LocalPort  int
	RemotePort int
}

func selfBootstrapTestNewRuntime(t *testing.T, nodeID, cardPath string, peers []string) *meshRuntime {
	t.Helper()
	return selfBootstrapTestNewRuntimeWithRecovery(t, nodeID, cardPath, peers, 30*time.Second, nil)
}

func selfBootstrapTestNewRuntimeWithRecovery(
	t *testing.T,
	nodeID, cardPath string,
	peers []string,
	recoveryDebounce time.Duration,
	strategyFactory shortcut.StrategyFactory,
) *meshRuntime {
	t.Helper()
	config := runtimeConfig{
		NodeID: nodeID, MeshListen: "off", ControlListen: "off",
		MaintainedPeers: peers, RecoveryCardPath: cardPath,
		Lease: 2 * time.Second, RefreshInterval: 40 * time.Millisecond,
		KeepAliveInterval: 20 * time.Millisecond, PeerTimeout: 250 * time.Millisecond,
		Probation: 250 * time.Millisecond, RecoveryDebounce: recoveryDebounce,
		SelfBootstrapWindow: 1800 * time.Millisecond, SelfBootstrapCycle: 2 * time.Second,
		SelfBootstrapHelloTimeout:   200 * time.Millisecond,
		selfBootstrapAllowNonPublic: true, selfBootstrapPunchGrace: 20 * time.Millisecond,
		selfBootstrapHelloInterval: 10 * time.Millisecond, selfBootstrapHelloSettle: 40 * time.Millisecond,
		selfBootstrapRoundDelay: 10 * time.Millisecond,
	}
	if strategyFactory != nil {
		config.strategyName = runtimeTestStrategyName
		config.strategyFactory = strategyFactory
	}
	runtime, err := newMeshRuntime(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func selfBootstrapTestSaveCard(
	t *testing.T,
	path, nodeID string,
	hints map[string]selfBootstrapTestPairHint,
) {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	card := recoverycard.Card{
		Version: recoverycard.CurrentVersion, NodeID: nodeID,
		UpdatedAt: now.Add(time.Second), LastSuccessAt: now,
		LocalNAT: selfBootstrapTestPreservingNAT(now),
	}
	peerIDs := make([]string, 0, len(hints))
	for peerID := range hints {
		peerIDs = append(peerIDs, peerID)
	}
	slices.Sort(peerIDs)
	seenPorts := make(map[int]bool)
	for _, peerID := range peerIDs {
		hint := hints[peerID]
		if !seenPorts[hint.LocalPort] {
			card.LocalBindPorts = append(card.LocalBindPorts, uint16(hint.LocalPort))
			seenPorts[hint.LocalPort] = true
		}
		card.Peers = append(card.Peers, recoverycard.Peer{
			NodeID: peerID, LastSuccessfulLocalBindPort: uint16(hint.LocalPort), LastSuccessAt: now,
			Endpoints: []recoverycard.Endpoint{{
				AddrPort:   net.JoinHostPort("127.0.0.1", strconv.Itoa(hint.RemotePort)),
				ObservedAt: now, Source: "previous_direct",
				NAT: selfBootstrapTestPreservingNAT(now), LastSuccessAt: now,
			}},
		})
	}
	slices.Sort(card.LocalBindPorts)
	store, err := recoverycard.NewStore(path, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(card); err != nil {
		t.Fatal(err)
	}
}

func selfBootstrapTestPreservingNAT(at time.Time) recoverycard.NATModel {
	return recoverycard.NATModel{
		Pattern: recoverycard.PortPatternPreserving, Confidence: 1, ObservedAt: at,
	}
}

func selfBootstrapTestReserveUDPPort(t *testing.T, excluded map[int]bool) int {
	t.Helper()
	for {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := conn.LocalAddr().(*net.UDPAddr).Port
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if !excluded[port] {
			return port
		}
	}
}

func selfBootstrapTestReserveFarUDPPort(t *testing.T, from int, excluded map[int]bool) int {
	t.Helper()
	for delta := 10000; delta < 30000; delta++ {
		port := 1024 + (from-1024+delta)%(65535-1024+1)
		if excluded[port] || port >= from-64 && port <= from+64 {
			continue
		}
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			continue
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		return port
	}
	t.Fatal("could not reserve a far stale UDP endpoint")
	return 0
}

func selfBootstrapTestNewDistinctBroker(
	t *testing.T,
	excluded map[int]bool,
	leftID, rightID string,
) *runtimeTestBroker {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		broker := newRuntimeTestBroker(t, leftID, rightID)
		collision := false
		for _, conn := range broker.conns {
			if excluded[conn.LocalAddr().(*net.UDPAddr).Port] {
				collision = true
				break
			}
		}
		if !collision {
			return broker
		}
		broker.Close()
	}
	t.Fatalf("could not reserve a %s-%s recovery broker away from fixed bootstrap ports", leftID, rightID)
	return nil
}

func selfBootstrapTestWaitDirect(t *testing.T, ctx context.Context, left, right *meshRuntime) {
	t.Helper()
	if err := runtimeTestWait(ctx, func() bool {
		return selfBootstrapTestIsDirect(left, right.cfg.NodeID) &&
			selfBootstrapTestIsDirect(right, left.cfg.NodeID)
	}); err != nil {
		t.Fatalf("wait for self-bootstrap direct %s-%s: %v", left.cfg.NodeID, right.cfg.NodeID, err)
	}
}

func selfBootstrapTestIsDirect(runtime *meshRuntime, peerID string) bool {
	neighbor, neighborOK := runtime.node.Neighbor(peerID)
	route, routeOK := runtime.node.Route(peerID)
	return neighborOK && neighbor.Kind == mesh.NeighborKindPacket && neighbor.DataCapable &&
		routeOK && slices.Equal(route.Path, []string{runtime.cfg.NodeID, peerID})
}

func selfBootstrapTestAssertPacketNeighbor(t *testing.T, runtime *meshRuntime, peerID string) {
	t.Helper()
	if !selfBootstrapTestIsDirect(runtime, peerID) {
		neighbor, _ := runtime.node.Neighbor(peerID)
		route, _ := runtime.node.Route(peerID)
		t.Fatalf("%s-%s is not a data-capable packet edge: neighbor=%+v route=%+v", runtime.cfg.NodeID, peerID, neighbor, route)
	}
}

func selfBootstrapTestAssertNoBootstrapConnector(t *testing.T, runtimes ...*meshRuntime) {
	t.Helper()
	for _, runtime := range runtimes {
		status := runtime.status()
		if len(status.DesiredPeers) != 0 || status.MeshListen != "" || status.InfrastructureUp {
			t.Fatalf("%s used bootstrap infrastructure: desired=%v listen=%q infrastructure=%t",
				runtime.cfg.NodeID, status.DesiredPeers, status.MeshListen, status.InfrastructureUp)
		}
	}
}

func selfBootstrapTestAssertSuccessfulStatus(t *testing.T, runtime *meshRuntime, peerID string) {
	t.Helper()
	statuses := runtime.status().SelfBootstrap
	for _, status := range statuses {
		if status.PeerID == peerID {
			if status.Attempts == 0 || status.LastSuccessAt.IsZero() {
				t.Fatalf("%s self-bootstrap status for %s has no successful attempt: %+v", runtime.cfg.NodeID, peerID, status)
			}
			return
		}
	}
	t.Fatalf("%s has no self-bootstrap status for %s: %+v", runtime.cfg.NodeID, peerID, statuses)
}

func selfBootstrapTestLookupPeer(card recoverycard.Card, peerID string) (recoverycard.Peer, bool) {
	for _, peer := range card.Peers {
		if peer.NodeID == peerID {
			return peer, true
		}
	}
	return recoverycard.Peer{}, false
}

func selfBootstrapTestWaitForCommonTriangleWindow(t *testing.T, ctx context.Context, nodeIDs []string) {
	t.Helper()
	const (
		cycle            = 2 * time.Second
		window           = 1800 * time.Millisecond
		minimumRemaining = 1220 * time.Millisecond
		startMargin      = 40 * time.Millisecond
	)
	for {
		now := time.Now()
		allReady := true
		for i := 0; i < len(nodeIDs); i++ {
			for j := i + 1; j < len(nodeIDs); j++ {
				offset := selfBootstrapTestPairOffset(nodeIDs[i], nodeIDs[j], cycle)
				phase := time.Duration(now.UnixNano()%cycle.Nanoseconds()) - offset
				if phase < 0 {
					phase += cycle
				}
				remaining := window - phase
				if phase < startMargin || remaining <= minimumRemaining+startMargin {
					allReady = false
				}
			}
		}
		if allReady {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for common self-bootstrap triangle window: %v", ctx.Err())
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func selfBootstrapTestPairOffset(left, right string, cycle time.Duration) time.Duration {
	if right < left {
		left, right = right, left
	}
	mac := hmac.New(sha256.New, nil)
	_, _ = mac.Write([]byte("wink-selfbootstrap-pair-v1\x00"))
	_, _ = mac.Write([]byte(left))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(right))
	return time.Duration(binary.BigEndian.Uint64(mac.Sum(nil)[:8]) % uint64(cycle.Nanoseconds()))
}
