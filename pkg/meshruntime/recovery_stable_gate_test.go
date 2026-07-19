package meshruntime

import (
	"context"
	"fmt"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/solver"
)

// TestRecoverySupervisorKeepsBootstrapUntilAlternateFirstHopStable covers the
// rolling-upgrade race in which B learns an alternate B-A-C route as soon as a
// manually initiated A-B shortcut installs its packet neighbor. Installed and
// probationary are not sufficient teardown barriers: B must retain the B-C
// bootstrap stream until the exact B-A neighbor generation reaches Stable.
func TestRecoverySupervisorKeepsBootstrapUntilAlternateFirstHopStable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	brokers := newRecoveryTestBrokerSet()
	defer brokers.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		if !runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "A", "B") &&
			!runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "B", "C") {
			return nil, fmt.Errorf("unexpected stable-gate pair %s-%s", spec.LocalNodeID, spec.RemoteNodeID)
		}
		broker, err := brokers.forAttempt(spec.AttemptID, spec.InitiatorID, spec.TargetID)
		if err != nil {
			return nil, err
		}
		return &runtimeTestStrategy{spec: spec, broker: broker, remoteReady: make(chan struct{}, 1)}, nil
	}

	const (
		probation = 1500 * time.Millisecond
		debounce  = 40 * time.Millisecond
	)
	config := func(nodeID string) runtimeConfig {
		return runtimeConfig{
			NodeID: nodeID, MeshListen: "127.0.0.1:0", ControlListen: "off",
			Lease: time.Second, RefreshInterval: 25 * time.Millisecond,
			DialRetry: 20 * time.Millisecond, HandshakeTimeout: time.Second,
			SolveTimeout: time.Second, AttemptTimeout: 5 * time.Second,
			Probation: probation, KeepAliveInterval: 10 * time.Millisecond,
			PeerTimeout: 80 * time.Millisecond, RecoveryDebounce: debounce,
			RecoveryMinBackoff: 30 * time.Millisecond, RecoveryMaxBackoff: 200 * time.Millisecond,
			RecoveryStableReset: probation, TCPFrameTimeout: 16 * time.Second,
			strategyName: runtimeTestStrategyName, strategyFactory: factory,
		}
	}

	runtimeC := recoveryTestStartRuntime(t, ctx, config("C"))
	defer runtimeC.Close()

	configA := config("A")
	configA.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	runtimeA := recoveryTestStartRuntime(t, ctx, configA)
	defer runtimeA.Close()

	configB := config("B")
	configB.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	configB.MaintainedPeers = []string{"C"}
	runtimeB := recoveryTestStartRuntime(t, ctx, configB)
	defer runtimeB.Close()

	var initialBC, initialCB mesh.NeighborInfo
	if err := runtimeTestWait(ctx, func() bool {
		var okBC, okCB bool
		initialBC, okBC = runtimeB.node.Neighbor("C")
		initialCB, okCB = runtimeC.node.Neighbor("B")
		return okBC && okCB && initialBC.Kind == mesh.NeighborKindStream && initialCB.Kind == mesh.NeighborKindStream
	}); err != nil {
		t.Fatalf("wait initial B-C bootstrap stream: %v; B=%+v C=%+v", err, runtimeB.node.Neighbors(), runtimeC.node.Neighbors())
	}
	recoveryTestWaitRoute(t, ctx, runtimeA, "B", []string{"A", "C", "B"})
	recoveryTestWaitRoute(t, ctx, runtimeB, "A", []string{"B", "C", "A"})

	// This models the field migration: A manually asks C to coordinate A-B;
	// B did not initiate this shortcut, but its recovery loop observes the new
	// packet first hop and must still enforce B's local stability barrier.
	handle, err := runtimeA.shortcuts.Start(ctx, "B", "C")
	if err != nil {
		t.Fatalf("start manual A-B shortcut through C: %v", err)
	}
	if _, err := handle.WaitFor(ctx, shortcut.PhaseProbation); err != nil {
		t.Fatalf("wait manual A-B probation: %v", err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		status, ok := runtimeB.shortcuts.Status(handle.ID())
		neighbor, attached := runtimeB.node.Neighbor("A")
		return ok && status.Phase == shortcut.PhaseProbation && attached && neighbor.Kind == mesh.NeighborKindPacket
	}); err != nil {
		t.Fatalf("wait B to observe probationary A first hop: %v; shortcuts=%+v", err, runtimeB.shortcutSnapshot())
	}

	probationaryBA, ok := runtimeB.node.Neighbor("A")
	if !ok {
		t.Fatal("B lost its probationary A neighbor")
	}
	if runtimeB.shortcuts.IsStableDirectNeighbor("A", probationaryBA.Handle) {
		t.Fatal("B classified its probationary A neighbor as stable")
	}

	// Stay well beyond RecoveryDebounce while remaining far inside Probation.
	// The pre-fix recovery loop tears B-C down during this interval.
	holdUntil := time.Now().Add(5 * debounce)
	for time.Now().Before(holdUntil) {
		status, exists := runtimeB.shortcuts.Status(handle.ID())
		if !exists || status.Phase != shortcut.PhaseProbation {
			t.Fatalf("B A-B shortcut left probation before hold assertion: %+v, exists=%t", status, exists)
		}
		currentBC, attached := runtimeB.node.Neighbor("C")
		if !attached || currentBC.Kind != mesh.NeighborKindStream || currentBC.Handle != initialBC.Handle {
			t.Fatalf("B-C bootstrap changed before A-B became stable: initial=%+v current=%+v attached=%t", initialBC, currentBC, attached)
		}
		currentCB, attached := runtimeC.node.Neighbor("B")
		if !attached || currentCB.Kind != mesh.NeighborKindStream || currentCB.Handle != initialCB.Handle {
			t.Fatalf("C-B bootstrap changed before A-B became stable: initial=%+v current=%+v attached=%t", initialCB, currentCB, attached)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if attempts := recoveryTestInitiatorAttempts(runtimeB, "B", "C"); len(attempts) != 0 {
		t.Fatalf("B started B-C recovery while alternate first hop was probationary: %v", attempts)
	}

	if _, err := handle.WaitFor(ctx, shortcut.PhaseStable); err != nil {
		t.Fatalf("wait manual A-B stable: %v", err)
	}
	if err := runtimeTestWaitShortcut(ctx, handle.ID(), runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("wait A-B stable consensus: %v", err)
	}
	stableBA, ok := runtimeB.node.Neighbor("A")
	if !ok || !runtimeB.shortcuts.IsStableDirectNeighbor("A", stableBA.Handle) {
		t.Fatalf("B did not trust the stable A neighbor: neighbor=%+v attached=%t", stableBA, ok)
	}

	// The Stable event wakes recovery. B may now release the old B-C stream and
	// rebuild B-C through the proven B-A-C alternate route.
	attemptBC := recoveryTestWaitStablePair(t, ctx, runtimeB, "B", "C", "")
	if err := runtimeTestWaitShortcut(ctx, attemptBC, runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("wait B-C stable consensus after gated release: %v", err)
	}
	currentBC, okBC := runtimeB.node.Neighbor("C")
	currentCB, okCB := runtimeC.node.Neighbor("B")
	if !okBC || !okCB || currentBC.Kind != mesh.NeighborKindPacket || currentCB.Kind != mesh.NeighborKindPacket {
		t.Fatalf("rebuilt B-C edge is not packet-direct: B=%+v/%t C=%+v/%t", currentBC, okBC, currentCB, okCB)
	}
	if currentBC.Handle == initialBC.Handle || currentCB.Handle == initialCB.Handle {
		t.Fatalf("rebuilt B-C edge retained a bootstrap handle: B same=%t C same=%t", currentBC.Handle == initialBC.Handle, currentCB.Handle == initialCB.Handle)
	}
}

// TestRecoverySupervisorKeepsBootstrapUntilEveryAlternateEdgeStable covers the
// C-second rolling-upgrade race. B-A is already a stable packet edge while B-C
// is still the bootstrap stream that B maintains. A then asks B to coordinate
// A-C. The resulting B-A-C alternate route must not authorize teardown of B-C
// merely because its first hop is stable: the remote A-C edge must reach the
// three-party Stable consensus too.
func TestRecoverySupervisorKeepsBootstrapUntilEveryAlternateEdgeStable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	brokers := newRecoveryTestBrokerSet()
	defer brokers.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		if !runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "A", "B") &&
			!runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "A", "C") &&
			!runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "B", "C") {
			return nil, fmt.Errorf("unexpected all-edge stable-gate pair %s-%s", spec.LocalNodeID, spec.RemoteNodeID)
		}
		broker, err := brokers.forAttempt(spec.AttemptID, spec.InitiatorID, spec.TargetID)
		if err != nil {
			return nil, err
		}
		return &runtimeTestStrategy{spec: spec, broker: broker, remoteReady: make(chan struct{}, 1)}, nil
	}

	const (
		probation = 1500 * time.Millisecond
		debounce  = 40 * time.Millisecond
	)
	config := func(nodeID string) runtimeConfig {
		return runtimeConfig{
			NodeID: nodeID, MeshListen: "127.0.0.1:0", ControlListen: "off",
			Lease: time.Second, RefreshInterval: 25 * time.Millisecond,
			DialRetry: 20 * time.Millisecond, HandshakeTimeout: time.Second,
			SolveTimeout: time.Second, AttemptTimeout: 5 * time.Second,
			Probation: probation, KeepAliveInterval: 10 * time.Millisecond,
			PeerTimeout: time.Second, RecoveryDebounce: debounce,
			RecoveryMinBackoff: 30 * time.Millisecond, RecoveryMaxBackoff: 200 * time.Millisecond,
			RecoveryStableReset: probation, TCPFrameTimeout: 20 * time.Second,
			strategyName: runtimeTestStrategyName, strategyFactory: factory,
		}
	}

	runtimeC := recoveryTestStartRuntime(t, ctx, config("C"))
	defer runtimeC.Close()

	configA := config("A")
	configA.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	runtimeA := recoveryTestStartRuntime(t, ctx, configA)
	defer runtimeA.Close()

	// Keep the runtime's automatic supervisor out of the fixture until A-C is
	// in probation. Starting an equivalent supervisor at that exact boundary
	// makes the regression deterministic instead of racing its setup debounce.
	configB := config("B")
	configB.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	runtimeB := recoveryTestStartRuntime(t, ctx, configB)
	defer runtimeB.Close()

	var initialBC, initialCB mesh.NeighborInfo
	if err := runtimeTestWait(ctx, func() bool {
		var okBC, okCB bool
		initialBC, okBC = runtimeB.node.Neighbor("C")
		initialCB, okCB = runtimeC.node.Neighbor("B")
		return okBC && okCB && initialBC.Kind == mesh.NeighborKindStream && initialCB.Kind == mesh.NeighborKindStream
	}); err != nil {
		t.Fatalf("wait initial B-C bootstrap stream: %v; B=%+v C=%+v", err, runtimeB.node.Neighbors(), runtimeC.node.Neighbors())
	}
	recoveryTestWaitRoute(t, ctx, runtimeA, "B", []string{"A", "C", "B"})
	recoveryTestWaitRoute(t, ctx, runtimeB, "A", []string{"B", "C", "A"})

	// First establish the already-proven B-A first hop through C.
	handleAB, err := runtimeA.shortcuts.Start(ctx, "B", "C")
	if err != nil {
		t.Fatalf("start manual A-B shortcut through C: %v", err)
	}
	if _, err := handleAB.WaitFor(ctx, shortcut.PhaseStable); err != nil {
		t.Fatalf("wait manual A-B stable: %v", err)
	}
	if err := runtimeTestWaitShortcut(ctx, handleAB.ID(), runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("wait A-B stable consensus: %v", err)
	}
	stableBA, ok := runtimeB.node.Neighbor("A")
	if !ok || stableBA.Kind != mesh.NeighborKindPacket ||
		!runtimeB.shortcuts.IsStableDirectNeighbor("A", stableBA.Handle) {
		t.Fatalf("B-A first hop is not stable packet-direct: neighbor=%+v attached=%t", stableBA, ok)
	}
	if !runtimeA.connectors.Remove("C") {
		t.Fatal("A-C bootstrap connector was not present")
	}
	if err := runtimeTestWait(ctx, func() bool {
		return !runtimeA.node.HasNeighbor("C") && !runtimeC.node.HasNeighbor("A")
	}); err != nil {
		t.Fatalf("wait A-C bootstrap session to close: %v", err)
	}
	recoveryTestWaitRoute(t, ctx, runtimeA, "C", []string{"A", "B", "C"})
	recoveryTestWaitRoute(t, ctx, runtimeC, "A", []string{"C", "B", "A"})

	// A-C is deliberately initiated through B while B-C is still the only
	// bootstrap edge. The packet sessions may be installed during probation,
	// but neither endpoint may advertise A-C into B's routed graph yet.
	handleAC, err := runtimeA.shortcuts.Start(ctx, "C", "B")
	if err != nil {
		t.Fatalf("start manual A-C shortcut through B: %v", err)
	}
	if _, err := handleAC.WaitFor(ctx, shortcut.PhaseProbation); err != nil {
		t.Fatalf("wait manual A-C probation: %v", err)
	}
	if err := runtimeTestWait(ctx, func() bool {
		status, statusOK := runtimeB.shortcuts.Status(handleAC.ID())
		neighbor, attached := runtimeA.node.Neighbor("C")
		return statusOK && status.Phase == shortcut.PhaseProbation && attached && neighbor.Kind == mesh.NeighborKindPacket
	}); err != nil {
		t.Fatalf("wait B to observe probationary A-C pair: %v; shortcuts=%+v", err, runtimeB.shortcutSnapshot())
	}
	if alternate, ok := runtimeB.node.AlternateRoute("C"); ok {
		t.Fatalf("probationary A-C leaked into B's alternate graph: %+v", alternate)
	}

	recoveryConfigB := config("B")
	recoveryConfigB.MaintainedPeers = []string{"C"}
	recoveryB := newRecoverySupervisor(recoveryConfigB, runtimeB.node, runtimeB.shortcuts, nil)
	if recoveryB == nil {
		t.Fatal("B maintained-edge supervisor was not constructed")
	}
	defer recoveryB.Close()
	if err := recoveryB.Start(ctx); err != nil {
		t.Fatalf("start B maintained-edge supervisor: %v", err)
	}

	// Stay beyond several debounce windows while remaining well inside A-C's
	// probation. The pre-fix first-hop-only gate releases B-C immediately.
	holdUntil := time.Now().Add(5 * debounce)
	for time.Now().Before(holdUntil) {
		status, exists := runtimeB.shortcuts.Status(handleAC.ID())
		if !exists || status.Phase != shortcut.PhaseProbation {
			t.Fatalf("B A-C shortcut left probation before hold assertion: %+v, exists=%t", status, exists)
		}
		currentBC, attached := runtimeB.node.Neighbor("C")
		if !attached || currentBC.Kind != mesh.NeighborKindStream || currentBC.Handle != initialBC.Handle {
			t.Fatalf("B-C bootstrap changed before A-C became stable: initial=%+v current=%+v attached=%t", initialBC, currentBC, attached)
		}
		currentCB, attached := runtimeC.node.Neighbor("B")
		if !attached || currentCB.Kind != mesh.NeighborKindStream || currentCB.Handle != initialCB.Handle {
			t.Fatalf("C-B bootstrap changed before A-C became stable: initial=%+v current=%+v attached=%t", initialCB, currentCB, attached)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if attempts := recoveryTestInitiatorAttempts(runtimeB, "B", "C"); len(attempts) != 0 {
		t.Fatalf("B started B-C recovery while alternate A-C edge was probationary: %v", attempts)
	}

	if _, err := handleAC.WaitFor(ctx, shortcut.PhaseStable); err != nil {
		t.Fatalf("wait manual A-C stable: %v", err)
	}
	if err := runtimeTestWaitShortcut(ctx, handleAC.ID(), runtimeA, runtimeB, runtimeC); err != nil {
		for _, runtime := range []*meshRuntime{runtimeA, runtimeB, runtimeC} {
			status, exists := runtime.shortcuts.Status(handleAC.ID())
			neighbors := make(map[string]mesh.NeighborInfo)
			for _, peerID := range runtime.node.Neighbors() {
				if neighbor, ok := runtime.node.Neighbor(peerID); ok {
					neighbors[peerID] = neighbor
				}
			}
			t.Logf("%s A-C status=%+v exists=%t neighbors=%+v routes=%+v",
				runtime.cfg.NodeID, status, exists, neighbors, runtime.node.Routes())
		}
		t.Fatalf("wait A-C stable consensus: %v", err)
	}
	statusB, ok := runtimeB.shortcuts.Status(handleAC.ID())
	if !ok || statusB.Phase != shortcut.PhaseStable {
		t.Fatalf("B did not observe three-party A-C Stable consensus: status=%+v exists=%t", statusB, ok)
	}
	// In the real runtime this exact terminal callback wakes recovery. The
	// fixture owns the supervisor separately so setup could not race teardown.
	recoveryB.ObserveShortcut(statusB)

	// Only now may B release the old stream and rebuild B-C through B-A-C.
	attemptBC := recoveryTestWaitStablePair(t, ctx, runtimeB, "B", "C", "")
	if err := runtimeTestWaitShortcut(ctx, attemptBC, runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("wait B-C stable consensus after all-edge gate: %v", err)
	}
	currentBC, okBC := runtimeB.node.Neighbor("C")
	currentCB, okCB := runtimeC.node.Neighbor("B")
	if !okBC || !okCB || currentBC.Kind != mesh.NeighborKindPacket || currentCB.Kind != mesh.NeighborKindPacket {
		t.Fatalf("rebuilt B-C edge is not packet-direct: B=%+v/%t C=%+v/%t", currentBC, okBC, currentCB, okCB)
	}
	if currentBC.Handle == initialBC.Handle || currentCB.Handle == initialCB.Handle {
		t.Fatalf("rebuilt B-C edge retained a bootstrap handle: B same=%t C same=%t", currentBC.Handle == initialBC.Handle, currentCB.Handle == initialCB.Handle)
	}
}

func TestRecoverySupervisorTrustsOnlyExactSelfBootstrapNeighborGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	config := func(nodeID string) runtimeConfig {
		return runtimeConfig{
			NodeID: nodeID, MeshListen: "off", ControlListen: "off",
			Lease: time.Second, RefreshInterval: 25 * time.Millisecond,
			KeepAliveInterval: 10 * time.Millisecond, PeerTimeout: 500 * time.Millisecond,
			RecoveryDebounce: 10 * time.Millisecond, RecoveryMinBackoff: 20 * time.Millisecond,
			RecoveryMaxBackoff: 100 * time.Millisecond, RecoveryStableReset: 100 * time.Millisecond,
			AttemptTimeout: time.Second, TCPFrameTimeout: 16 * time.Second,
		}
	}

	runtimeA := recoveryTestStartRuntime(t, ctx, config("A"))
	defer runtimeA.Close()
	configB := config("B")
	configB.MaintainedPeers = []string{"A"} // B is standby owner and cannot start a repair.
	runtimeB := recoveryTestStartRuntime(t, ctx, configB)
	defer runtimeB.Close()

	attachPair := func(broker *runtimeTestBroker) mesh.NeighborInfo {
		t.Helper()
		left, err := broker.take("A")
		if err != nil {
			t.Fatal(err)
		}
		right, err := broker.take("B")
		if err != nil {
			_ = left.Close()
			t.Fatal(err)
		}
		packetConfig := mesh.PacketNeighborConfig{
			KeepAliveInterval: 10 * time.Millisecond, PeerTimeout: 500 * time.Millisecond,
		}
		if _, err := runtimeA.node.AttachPacketTransportWithHandle("B", left, packetConfig); err != nil {
			_ = right.Close()
			t.Fatal(err)
		}
		handle, err := runtimeB.node.AttachPacketTransportWithHandle("A", right, packetConfig)
		if err != nil {
			_ = runtimeA.node.RemoveNeighbor("B")
			t.Fatal(err)
		}
		return mesh.NeighborInfo{PeerID: "A", Kind: mesh.NeighborKindPacket, DataCapable: true, Handle: handle}
	}

	firstBroker := newRuntimeTestBroker(t, "A", "B")
	defer firstBroker.Close()
	first := attachPair(firstBroker)
	runtimeB.recovery.ObserveStablePacket("A", first.Handle)
	if err := runtimeTestWait(ctx, func() bool {
		views := runtimeB.recovery.Snapshot()
		return len(views) == 1 && views[0].State == recoveryStateHealthy && views[0].ProtectedDirect
	}); err != nil {
		t.Fatalf("trusted self-bootstrap generation did not become healthy: %v; status=%+v", err, runtimeB.recovery.Snapshot())
	}

	secondBroker := newRuntimeTestBroker(t, "A", "B")
	defer secondBroker.Close()
	if err := runtimeA.node.RemoveNeighbor("B"); err != nil {
		t.Fatal(err)
	}
	if err := runtimeB.node.RemoveNeighbor("A"); err != nil {
		t.Fatal(err)
	}
	second := attachPair(secondBroker)
	if first.Handle == second.Handle {
		t.Fatal("replacement packet neighbor reused the old opaque handle")
	}
	if err := runtimeTestWait(ctx, func() bool {
		views := runtimeB.recovery.Snapshot()
		return len(views) == 1 && views[0].State == recoveryStateUnknownDirect && !views[0].ProtectedDirect
	}); err != nil {
		t.Fatalf("replacement inherited trust from old generation: %v; status=%+v", err, runtimeB.recovery.Snapshot())
	}

	runtimeB.recovery.ObserveStablePacket("A", second.Handle)
	if err := runtimeTestWait(ctx, func() bool {
		views := runtimeB.recovery.Snapshot()
		return len(views) == 1 && views[0].State == recoveryStateHealthy && views[0].ProtectedDirect
	}); err != nil {
		t.Fatalf("replacement did not become healthy after explicit trust: %v; status=%+v", err, runtimeB.recovery.Snapshot())
	}
}
