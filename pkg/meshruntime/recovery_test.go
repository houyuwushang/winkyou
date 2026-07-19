package meshruntime

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/solver"
)

func TestRecoverySupervisorWaitsWithoutRouteAndElectsOneOwner(t *testing.T) {
	newFixture := func(nodeID, peerID string) (*mesh.Node, *shortcut.Manager, *recoverySupervisor) {
		t.Helper()
		node, err := mesh.NewNode(mesh.NodeConfig{NodeID: nodeID})
		if err != nil {
			t.Fatal(err)
		}
		manager, err := shortcut.NewManager(shortcut.Config{
			Node: node, StrategyName: runtimeTestStrategyName,
			StrategyFactory: func(shortcut.AttemptSpec) (solver.Strategy, error) {
				return nil, fmt.Errorf("strategy must not start without a route")
			},
			Probation: 40 * time.Millisecond, SolveTimeout: time.Second, AttemptTimeout: time.Second,
			PacketNeighbor: mesh.PacketNeighborConfig{
				KeepAliveInterval: 5 * time.Millisecond, PeerTimeout: 20 * time.Millisecond,
			},
		})
		if err != nil {
			_ = node.Close()
			t.Fatal(err)
		}
		config := runtimeConfig{
			NodeID: nodeID, MaintainedPeers: []string{peerID}, RecoveryDebounce: time.Millisecond,
			RecoveryMinBackoff: 10 * time.Millisecond, RecoveryMaxBackoff: 100 * time.Millisecond,
			RecoveryStableReset: 20 * time.Millisecond, AttemptTimeout: time.Second,
		}
		supervisor := newRecoverySupervisor(config, node, manager, nil)
		return node, manager, supervisor
	}

	nodeA, managerA, owner := newFixture("A", "B")
	defer nodeA.Close()
	defer managerA.Close()
	owner.reconcile(time.Now().UTC())
	ownerView := owner.Snapshot()
	if len(ownerView) != 1 || ownerView[0].OwnerID != "A" || ownerView[0].State != recoveryStateWaitingRoute ||
		ownerView[0].AttemptID != "" || ownerView[0].Failures != 0 {
		t.Fatalf("owner without route = %+v", ownerView)
	}

	nodeB, managerB, standby := newFixture("B", "A")
	defer nodeB.Close()
	defer managerB.Close()
	standby.reconcile(time.Now().UTC())
	standbyView := standby.Snapshot()
	if len(standbyView) != 1 || standbyView[0].OwnerID != "A" || standbyView[0].State != recoveryStateStandby ||
		standbyView[0].AttemptID != "" {
		t.Fatalf("non-owner without route = %+v", standbyView)
	}

	previous := time.Duration(0)
	for failures := 1; failures <= 8; failures++ {
		delay := owner.retryDelay("B", failures)
		if delay < owner.minBackoff/2 || delay > owner.maxBackoff {
			t.Fatalf("retry %d delay %s outside bounds", failures, delay)
		}
		if failures > 1 && delay < previous/2 {
			t.Fatalf("retry delay regressed too far: previous=%s current=%s", previous, delay)
		}
		previous = delay
	}
}

func TestRecoveryStartAttemptBoundsControlStreamSend(t *testing.T) {
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	attachBlockedStream := func(peerID string) net.Conn {
		t.Helper()
		local, remote := net.Pipe()
		if err := node.AttachStream(peerID, local); err != nil {
			_ = remote.Close()
			t.Fatalf("attach blocked stream %s: %v", peerID, err)
		}
		return remote
	}
	peerB := attachBlockedStream("B")
	defer peerB.Close()
	peerC := attachBlockedStream("C")
	defer peerC.Close()

	manager, err := shortcut.NewManager(shortcut.Config{
		Node: node, StrategyName: runtimeTestStrategyName,
		StrategyFactory: func(shortcut.AttemptSpec) (solver.Strategy, error) {
			return nil, fmt.Errorf("strategy must not run before PREPARE is delivered")
		},
		Probation: time.Second, SolveTimeout: time.Second, AttemptTimeout: time.Second,
		PacketNeighbor: mesh.PacketNeighborConfig{
			KeepAliveInterval: 20 * time.Millisecond, PeerTimeout: 100 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	supervisor := newRecoverySupervisor(runtimeConfig{
		NodeID: "A", MaintainedPeers: []string{"C"}, HandshakeTimeout: 30 * time.Millisecond,
		AttemptTimeout: time.Second,
	}, node, manager, nil)
	supervisor.ctx = context.Background()

	started := time.Now()
	err = supervisor.startAttempt("C", mesh.Route{
		Destination: "C", NextHop: "B", HopCount: 2, Path: []string{"A", "B", "C"},
	}, started.UTC())
	if err == nil {
		t.Fatal("startAttempt unexpectedly sent PREPARE over an unread control stream")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("bounded recovery start took %s, want less than 500ms; error=%v", elapsed, err)
	}
}

func TestRecoverySupervisorRepunchesAndPreservesRoutedTCPFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	target := runtimeTestStartTCPEcho(t)
	defer target.Close()
	brokers := newRecoveryTestBrokerSet()
	defer brokers.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		broker, err := brokers.forAttempt(spec.AttemptID, spec.InitiatorID, spec.TargetID)
		if err != nil {
			return nil, err
		}
		return &runtimeTestStrategy{spec: spec, broker: broker, remoteReady: make(chan struct{}, 1)}, nil
	}
	config := func(nodeID string) runtimeConfig {
		return runtimeConfig{
			NodeID: nodeID, MeshListen: "127.0.0.1:0", ControlListen: "off",
			Lease: time.Second, RefreshInterval: 25 * time.Millisecond,
			DialRetry: 20 * time.Millisecond, HandshakeTimeout: time.Second,
			SolveTimeout: time.Second, AttemptTimeout: 3 * time.Second,
			Probation: 180 * time.Millisecond, KeepAliveInterval: 20 * time.Millisecond,
			PeerTimeout: 120 * time.Millisecond, RecoveryDebounce: 350 * time.Millisecond,
			RecoveryMinBackoff: 30 * time.Millisecond, RecoveryMaxBackoff: 200 * time.Millisecond,
			RecoveryStableReset: 180 * time.Millisecond, TCPFrameTimeout: 16 * time.Second,
			strategyName: runtimeTestStrategyName, strategyFactory: factory,
		}
	}

	configC := config("C")
	configC.MaintainedPeers = []string{"A"}
	runtimeC := recoveryTestStartRuntime(t, ctx, configC)
	defer runtimeC.Close()

	configA := config("A")
	configA.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	configA.MaintainedPeers = []string{"B", "C"}
	configA.TCPForwards = []string{"127.0.0.1:0=B"}
	runtimeA := recoveryTestStartRuntime(t, ctx, configA)
	defer runtimeA.Close()

	configB := config("B")
	configB.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	configB.MaintainedPeers = []string{"A"}
	configB.TCPTarget = target.Addr().String()
	runtimeB := recoveryTestStartRuntime(t, ctx, configB)
	defer runtimeB.Close()

	firstAB := recoveryTestWaitStablePair(t, ctx, runtimeA, "A", "B", "")
	if err := runtimeTestWaitShortcut(ctx, firstAB, runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("wait initial A-B global consensus: %v", err)
	}
	if directEdgeOwner("A", "B") != "A" {
		t.Fatal("unexpected deterministic A-B owner")
	}
	if attempts := recoveryTestInitiatorAttempts(runtimeB, "A", "B"); len(attempts) != 0 {
		t.Fatalf("non-owner B initiated A-B attempts: %v", attempts)
	}

	// Once A-B is stable, A can automatically replace its A-C bootstrap
	// stream through B. The seed stays configured but must not redial while an
	// alternate graph route exists, so a later process restart still has a
	// last-resort address without competing with packet-edge installation.
	attemptAC := recoveryTestWaitStablePair(t, ctx, runtimeA, "A", "C", "")
	if err := runtimeTestWaitShortcut(ctx, attemptAC, runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("wait A-C global consensus: %v", err)
	}
	if desired := runtimeA.connectors.Snapshot(); desired["C"] == "" {
		t.Fatalf("A-C bootstrap seed was discarded during promotion: %v", desired)
	}

	// Replace the last remaining bootstrap stream in a safe order. Once all
	// three sides are packet neighbors, the alternate graph can carry the same
	// TCP flow while A-B is being reconstructed.
	if !runtimeB.connectors.Remove("C") {
		t.Fatal("B-C bootstrap connector was not present")
	}
	if err := runtimeTestWait(ctx, func() bool {
		return !runtimeB.node.HasNeighbor("C") && !runtimeC.node.HasNeighbor("B")
	}); err != nil {
		t.Fatalf("wait both B-C bootstrap sessions to close: %v", err)
	}
	recoveryTestWaitRoute(t, ctx, runtimeB, "C", []string{"B", "A", "C"})
	recoveryTestWaitRoute(t, ctx, runtimeC, "B", []string{"C", "A", "B"})
	attemptBC := recoveryTestStartShortcut(t, ctx, runtimeB, "C", "A")
	if err := runtimeTestWaitShortcut(ctx, attemptBC, runtimeA, runtimeB, runtimeC); err != nil {
		t.Fatalf("wait B-C global consensus: %v", err)
	}
	recoveryTestWaitPacketTriangle(t, ctx, runtimeA, runtimeB, runtimeC)
	// Let promotion-related topology wakes drain before injecting the one-way
	// fault, so its debounce window is measured from the fault itself.
	time.Sleep(400 * time.Millisecond)

	forwards := runtimeA.tcpForwardSnapshot()
	if len(forwards) != 1 {
		t.Fatalf("A forwards = %+v, want one", forwards)
	}
	conn, err := net.DialTimeout("tcp", forwards[0].Listen, 2*time.Second)
	if err != nil {
		t.Fatalf("dial persistent routed TCP flow: %v", err)
	}
	defer conn.Close()
	recoveryTestConnRoundTrip(t, conn, []byte("before automatic repair"))

	faultBroker := brokers.existing(firstAB)
	if faultBroker == nil || !faultBroker.setDropWrites("B", true) {
		t.Fatalf("A-B transport for attempt %s is unavailable", firstAB)
	}
	// Drop only B-to-A writes. A keeps B's old adjacency alive with direct
	// retransmissions until A times out and moves the already-pending frame to
	// A-C-B. B then needs its own full timeout before ACKs stop preferring the
	// stale direct edge. This exercises the two detection windows covered by the
	// runtime frame-timeout floor.
	forwardedBeforeFallback := runtimeC.counters.dataForwarded.Load()
	payload := []byte("same in-flight TCP frame over one-way A-C-B fallback")
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write frame before one-way failure detection: %v", err)
	}
	recoveryTestWaitRoute(t, ctx, runtimeA, "B", []string{"A", "C", "B"})
	if err := runtimeTestWait(ctx, func() bool {
		return runtimeC.counters.dataForwarded.Load() > forwardedBeforeFallback
	}); err != nil {
		t.Fatalf("C did not forward fallback TCP frames: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read frame after asymmetric detection windows: %v", err)
	}
	if !slices.Equal(response, payload) {
		t.Fatalf("asymmetric fallback response = %q, want %q", response, payload)
	}

	secondAB := recoveryTestWaitStablePair(t, ctx, runtimeA, "A", "B", firstAB)
	if secondAB == firstAB {
		t.Fatalf("repair reused attempt %s", firstAB)
	}
	recoveryTestWaitPacketTriangle(t, ctx, runtimeA, runtimeB, runtimeC)
	forwardedBeforeDirect := runtimeC.counters.dataForwarded.Load()
	recoveryTestConnRoundTrip(t, conn, []byte("same TCP flow after repunch"))
	time.Sleep(60 * time.Millisecond)
	if got := runtimeC.counters.dataForwarded.Load(); got != forwardedBeforeDirect {
		t.Fatalf("C forwarded post-repair direct TCP frames: before=%d after=%d", forwardedBeforeDirect, got)
	}

	attempts := recoveryTestInitiatorAttempts(runtimeA, "A", "B")
	if len(attempts) != 2 {
		t.Fatalf("A-B initiator attempts = %v, want initial plus exactly one repair", attempts)
	}
	if err := runtimeTestWait(ctx, func() bool {
		views := runtimeA.recovery.Snapshot()
		for _, view := range views {
			if view.PeerID == "B" {
				return view.State == recoveryStateHealthy && view.ProtectedDirect && view.AttemptID == ""
			}
		}
		return false
	}); err != nil {
		t.Fatalf("A recovery status did not become healthy: %v; status=%+v", err, runtimeA.recovery.Snapshot())
	}
}

func TestRecoverySupervisorRestoresEdgeAfterPeerRuntimeRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	brokers := newRecoveryTestBrokerSet()
	defer brokers.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		if !runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "A", "B") {
			return nil, fmt.Errorf("unexpected recovery pair %s-%s", spec.LocalNodeID, spec.RemoteNodeID)
		}
		broker, err := brokers.forAttempt(spec.AttemptID, spec.InitiatorID, spec.TargetID)
		if err != nil {
			return nil, err
		}
		return &runtimeTestStrategy{spec: spec, broker: broker, remoteReady: make(chan struct{}, 1)}, nil
	}
	config := func(nodeID string) runtimeConfig {
		return runtimeConfig{
			NodeID: nodeID, MeshListen: "127.0.0.1:0", ControlListen: "off",
			Lease: 350 * time.Millisecond, RefreshInterval: 30 * time.Millisecond,
			DialRetry: 20 * time.Millisecond, HandshakeTimeout: time.Second,
			SolveTimeout: time.Second, AttemptTimeout: 3 * time.Second,
			Probation: 180 * time.Millisecond, KeepAliveInterval: 20 * time.Millisecond,
			PeerTimeout: 120 * time.Millisecond, RecoveryDebounce: 40 * time.Millisecond,
			RecoveryMinBackoff: 30 * time.Millisecond, RecoveryMaxBackoff: 200 * time.Millisecond,
			RecoveryStableReset: 180 * time.Millisecond, TCPFrameTimeout: 16 * time.Second,
			strategyName: runtimeTestStrategyName, strategyFactory: factory,
		}
	}

	runtimeC := recoveryTestStartRuntime(t, ctx, config("C"))
	defer runtimeC.Close()
	configA := config("A")
	configA.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	configA.MaintainedPeers = []string{"B"}
	runtimeA := recoveryTestStartRuntime(t, ctx, configA)
	defer runtimeA.Close()
	configB := config("B")
	configB.InitialPeers = []string{"C=" + runtimeC.MeshAddr()}
	configB.MaintainedPeers = []string{"A"}
	runtimeB1 := recoveryTestStartRuntime(t, ctx, configB)

	first := recoveryTestWaitStablePair(t, ctx, runtimeA, "A", "B", "")
	if err := runtimeTestWaitShortcut(ctx, first, runtimeA, runtimeB1, runtimeC); err != nil {
		_ = runtimeB1.Close()
		t.Fatalf("wait first A-B consensus: %v", err)
	}
	firstStartedAt := runtimeB1.startedAt
	if err := runtimeB1.Close(); err != nil {
		t.Fatalf("stop first B runtime: %v", err)
	}

	runtimeB2 := recoveryTestStartRuntime(t, ctx, configB)
	defer runtimeB2.Close()
	if !runtimeB2.startedAt.After(firstStartedAt) {
		t.Fatalf("replacement B start %s is not after %s", runtimeB2.startedAt, firstStartedAt)
	}
	second := recoveryTestWaitStablePair(t, ctx, runtimeA, "A", "B", first)
	if err := runtimeTestWaitShortcut(ctx, second, runtimeA, runtimeB2, runtimeC); err != nil {
		t.Fatalf("wait restarted B A-B consensus: %v", err)
	}
	if second == first {
		t.Fatalf("restarted B reused old attempt %s", first)
	}
	infoA, okA := runtimeA.node.Neighbor("B")
	infoB, okB := runtimeB2.node.Neighbor("A")
	if !okA || !okB || infoA.Kind != mesh.NeighborKindPacket || infoB.Kind != mesh.NeighborKindPacket {
		t.Fatalf("restarted edge kinds: A=%+v/%t B=%+v/%t", infoA, okA, infoB, okB)
	}
	if attempts := recoveryTestInitiatorAttempts(runtimeA, "A", "B"); len(attempts) < 2 || len(attempts) > 4 {
		t.Fatalf("restart A-B attempts = %v, want one initial and bounded automatic retries", attempts)
	}
}

func TestRecoverySupervisorChangesCoordinatorAfterRouteFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	brokers := newRecoveryTestBrokerSet()
	defer brokers.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		if !runtimeTestSamePair(spec.LocalNodeID, spec.RemoteNodeID, "A", "D") {
			return nil, fmt.Errorf("unexpected coordinator-switch pair %s-%s", spec.LocalNodeID, spec.RemoteNodeID)
		}
		if spec.CoordinatorID == "B" {
			return &recoveryBlockingStrategy{spec: spec, remoteReady: make(chan struct{}, 1)}, nil
		}
		if spec.CoordinatorID != "C" {
			return nil, fmt.Errorf("unexpected coordinator %s", spec.CoordinatorID)
		}
		broker, err := brokers.forAttempt(spec.AttemptID, spec.InitiatorID, spec.TargetID)
		if err != nil {
			return nil, err
		}
		return &runtimeTestStrategy{spec: spec, broker: broker, remoteReady: make(chan struct{}, 1)}, nil
	}
	config := func(nodeID string) runtimeConfig {
		return runtimeConfig{
			NodeID: nodeID, MeshListen: "127.0.0.1:0", ControlListen: "off",
			Lease: time.Second, RefreshInterval: 25 * time.Millisecond,
			DialRetry: 20 * time.Millisecond, HandshakeTimeout: time.Second,
			SolveTimeout: 300 * time.Millisecond, AttemptTimeout: 700 * time.Millisecond,
			Probation: 120 * time.Millisecond, KeepAliveInterval: 10 * time.Millisecond,
			PeerTimeout: 80 * time.Millisecond, RecoveryDebounce: 20 * time.Millisecond,
			RecoveryMinBackoff: 20 * time.Millisecond, RecoveryMaxBackoff: 80 * time.Millisecond,
			RecoveryStableReset: 120 * time.Millisecond, TCPFrameTimeout: 16 * time.Second,
			strategyName: runtimeTestStrategyName, strategyFactory: factory,
		}
	}

	runtimeB := recoveryTestStartRuntime(t, ctx, config("B"))
	bClosed := false
	defer func() {
		if !bClosed {
			_ = runtimeB.Close()
		}
	}()
	runtimeC := recoveryTestStartRuntime(t, ctx, config("C"))
	defer runtimeC.Close()
	configA := config("A")
	configA.InitialPeers = []string{"B=" + runtimeB.MeshAddr()}
	configA.MaintainedPeers = []string{"D"}
	runtimeA := recoveryTestStartRuntime(t, ctx, configA)
	defer runtimeA.Close()
	configD := config("D")
	configD.InitialPeers = []string{"B=" + runtimeB.MeshAddr()}
	configD.MaintainedPeers = []string{"A"}
	runtimeD := recoveryTestStartRuntime(t, ctx, configD)
	defer runtimeD.Close()

	var firstAttempt string
	if err := runtimeTestWait(ctx, func() bool {
		views := runtimeA.recovery.Snapshot()
		return len(views) == 1 && views[0].State == recoveryStateAttempting &&
			views[0].CoordinatorID == "B" && func() bool {
			firstAttempt = views[0].AttemptID
			return firstAttempt != ""
		}()
	}); err != nil {
		t.Fatalf("wait first repair through B: %v; status=%+v", err, runtimeA.recovery.Snapshot())
	}
	recoveryTestAttachStreamPair(t, runtimeA.node, runtimeC.node)
	recoveryTestAttachStreamPair(t, runtimeD.node, runtimeC.node)
	if err := runtimeTestWait(ctx, func() bool {
		return runtimeA.node.HasNeighbor("C") && runtimeD.node.HasNeighbor("C") &&
			runtimeC.node.HasNeighbor("A") && runtimeC.node.HasNeighbor("D")
	}); err != nil {
		t.Fatalf("wait alternate A-C-D path: %v", err)
	}
	recoveryTestWaitRoute(t, ctx, runtimeA, "C", []string{"A", "C"})
	recoveryTestWaitRoute(t, ctx, runtimeD, "C", []string{"D", "C"})
	recoveryTestWaitRoute(t, ctx, runtimeC, "A", []string{"C", "A"})
	recoveryTestWaitRoute(t, ctx, runtimeC, "D", []string{"C", "D"})
	if err := runtimeB.Close(); err != nil {
		t.Fatalf("stop first coordinator B: %v", err)
	}
	bClosed = true
	recoveryTestWaitRoute(t, ctx, runtimeA, "D", []string{"A", "C", "D"})

	secondAttempt := recoveryTestWaitStablePair(t, ctx, runtimeA, "A", "D", firstAttempt)
	if err := runtimeTestWaitShortcut(ctx, secondAttempt, runtimeA, runtimeC, runtimeD); err != nil {
		t.Fatalf("wait replacement attempt through C: %v", err)
	}
	status, ok := runtimeA.shortcuts.Status(secondAttempt)
	if !ok || status.CoordinatorID != "C" || status.Phase != shortcut.PhaseStable {
		t.Fatalf("replacement coordinator status = %+v, ok=%t", status, ok)
	}
	if attempts := recoveryTestInitiatorAttempts(runtimeA, "A", "D"); len(attempts) < 2 || len(attempts) > 3 {
		t.Fatalf("coordinator-switch attempts = %v, want failed B and bounded retry through C", attempts)
	}
}

func recoveryTestStartRuntime(t *testing.T, ctx context.Context, config runtimeConfig) *meshRuntime {
	t.Helper()
	runtime, err := newMeshRuntime(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(ctx); err != nil {
		_ = runtime.Close()
		t.Fatal(err)
	}
	return runtime
}

func recoveryTestAttachStreamPair(t *testing.T, left, right *mesh.Node) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	leftConn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var rightConn net.Conn
	select {
	case rightConn = <-accepted:
	case err := <-acceptErr:
		_ = leftConn.Close()
		_ = listener.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = leftConn.Close()
		_ = listener.Close()
		t.Fatal("accept test stream pair timed out")
	}
	_ = listener.Close()
	if err := left.AttachStream(right.NodeID(), leftConn); err != nil {
		_ = rightConn.Close()
		t.Fatalf("attach %s-%s left stream: %v", left.NodeID(), right.NodeID(), err)
	}
	if err := right.AttachStream(left.NodeID(), rightConn); err != nil {
		_ = left.RemoveNeighbor(right.NodeID())
		t.Fatalf("attach %s-%s right stream: %v", left.NodeID(), right.NodeID(), err)
	}
}

func recoveryTestStartShortcut(t *testing.T, ctx context.Context, runtime *meshRuntime, targetID, coordinatorID string) string {
	t.Helper()
	handle, err := runtime.shortcuts.Start(ctx, targetID, coordinatorID)
	if err != nil {
		t.Fatalf("start %s-%s through %s: %v", runtime.cfg.NodeID, targetID, coordinatorID, err)
	}
	if _, err := handle.WaitFor(ctx, shortcut.PhaseStable); err != nil {
		t.Fatalf("wait %s stable: %v", handle.ID(), err)
	}
	return handle.ID()
}

func recoveryTestWaitStablePair(t *testing.T, ctx context.Context, runtime *meshRuntime, initiator, target, exclude string) string {
	t.Helper()
	var attemptID string
	if err := runtimeTestWait(ctx, func() bool {
		for _, status := range runtime.shortcutSnapshot() {
			if status.AttemptID != exclude && status.InitiatorID == initiator && status.TargetID == target &&
				status.LocalRole == "initiator" && status.Phase == shortcut.PhaseStable {
				attemptID = status.AttemptID
				return true
			}
		}
		return false
	}); err != nil {
		t.Fatalf("wait stable %s-%s shortcut: %v; statuses=%+v", initiator, target, err, runtime.shortcutSnapshot())
	}
	return attemptID
}

func recoveryTestInitiatorAttempts(runtime *meshRuntime, initiator, target string) []string {
	result := make([]string, 0)
	for _, status := range runtime.shortcutSnapshot() {
		if status.InitiatorID == initiator && status.TargetID == target && status.LocalRole == "initiator" {
			result = append(result, status.AttemptID)
		}
	}
	slices.Sort(result)
	return result
}

func recoveryTestWaitRoute(t *testing.T, ctx context.Context, runtime *meshRuntime, target string, path []string) {
	t.Helper()
	if err := runtimeTestWait(ctx, func() bool {
		route, ok := runtime.node.Route(target)
		return ok && slices.Equal(route.Path, path)
	}); err != nil {
		t.Fatalf("wait route %v on %s: %v", path, runtime.cfg.NodeID, err)
	}
}

func recoveryTestWaitPacketTriangle(t *testing.T, ctx context.Context, runtimes ...*meshRuntime) {
	t.Helper()
	if err := runtimeTestWait(ctx, func() bool {
		for _, runtime := range runtimes {
			if len(runtime.node.Neighbors()) != 2 {
				return false
			}
			for _, peerID := range runtime.node.Neighbors() {
				info, ok := runtime.node.Neighbor(peerID)
				if !ok || info.Kind != mesh.NeighborKindPacket {
					return false
				}
			}
		}
		return true
	}); err != nil {
		for _, runtime := range runtimes {
			t.Logf("%s neighbors=%v routes=%+v", runtime.cfg.NodeID, runtime.node.Neighbors(), runtime.node.Routes())
		}
		t.Fatalf("wait protected-direct triangle: %v", err)
	}
}

func recoveryTestConnRoundTrip(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write persistent flow: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read persistent flow: %v", err)
	}
	if !slices.Equal(response, payload) {
		t.Fatalf("persistent flow response = %q, want %q", response, payload)
	}
}

type recoveryTestBrokerSet struct {
	mu      sync.Mutex
	brokers map[string]*runtimeTestBroker
}

type recoveryBlockingStrategy struct {
	spec        shortcut.AttemptSpec
	remoteReady chan struct{}
}

func (s *recoveryBlockingStrategy) Name() string { return runtimeTestStrategyName }

func (s *recoveryBlockingStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "recovery-test/block", Strategy: runtimeTestStrategyName}}, nil
}

func (s *recoveryBlockingStrategy) Execute(ctx context.Context, session solver.SessionIO, _ solver.Plan) (solver.Result, error) {
	if err := session.Send(ctx, solver.Message{
		Kind: solver.MessageKindStrategy, Namespace: runtimeTestStrategyName, Type: "ready",
		Payload: []byte(s.spec.LocalNodeID), ReceivedAt: time.Now().UTC(),
	}); err != nil {
		return solver.Result{}, err
	}
	select {
	case <-ctx.Done():
		return solver.Result{}, ctx.Err()
	case <-s.remoteReady:
	}
	<-ctx.Done()
	return solver.Result{}, ctx.Err()
}

func (s *recoveryBlockingStrategy) HandleMessage(_ context.Context, _ solver.SessionIO, message solver.Message) error {
	if message.Namespace == runtimeTestStrategyName && message.Type == "ready" {
		select {
		case s.remoteReady <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *recoveryBlockingStrategy) Close() error { return nil }

var _ solver.Strategy = (*recoveryBlockingStrategy)(nil)
var _ solver.MessageHandler = (*recoveryBlockingStrategy)(nil)

func newRecoveryTestBrokerSet() *recoveryTestBrokerSet {
	return &recoveryTestBrokerSet{brokers: make(map[string]*runtimeTestBroker)}
}

func (s *recoveryTestBrokerSet) forAttempt(attemptID, leftID, rightID string) (*runtimeTestBroker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if broker := s.brokers[attemptID]; broker != nil {
		return broker, nil
	}
	left, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	right, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = left.Close()
		return nil, err
	}
	broker := &runtimeTestBroker{
		conns: map[string]*net.UDPConn{leftID: left, rightID: right},
		peers: map[string]*net.UDPAddr{
			leftID:  runtimeTestCopyUDP(right.LocalAddr().(*net.UDPAddr)),
			rightID: runtimeTestCopyUDP(left.LocalAddr().(*net.UDPAddr)),
		},
		taken: make(map[string]bool), transports: make(map[string]*runtimeTestPacketTransport),
	}
	s.brokers[attemptID] = broker
	return broker, nil
}

func (s *recoveryTestBrokerSet) existing(attemptID string) *runtimeTestBroker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.brokers[attemptID]
}

func (s *recoveryTestBrokerSet) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, broker := range s.brokers {
		broker.Close()
	}
}
