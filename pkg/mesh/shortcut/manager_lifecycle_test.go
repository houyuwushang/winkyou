package shortcut

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/solver"
)

func TestAttemptWatchdogCoversEveryLocalRole(t *testing.T) {
	const attemptTimeout = 60 * time.Millisecond
	packetConfig := mesh.PacketNeighborConfig{
		KeepAliveInterval: 5 * time.Millisecond,
		PeerTimeout:       20 * time.Millisecond,
		ReadPollInterval:  5 * time.Millisecond,
		WriteTimeout:      20 * time.Millisecond,
	}
	managerConfig := func(node *mesh.Node, withFactory bool) Config {
		config := Config{
			Node:           node,
			StrategyName:   fakeEdgeStrategyName,
			Probation:      30 * time.Millisecond,
			SolveTimeout:   time.Second,
			AttemptTimeout: attemptTimeout,
			PacketNeighbor: packetConfig,
		}
		if withFactory {
			broker := newFakeEdgeBroker()
			config.StrategyFactory = func(spec AttemptSpec) (solver.Strategy, error) {
				return newFakeEdgeStrategy(spec, broker), nil
			}
		}
		return config
	}
	wireFor := func(attemptID string) wireMessage {
		return wireMessage{
			AttemptID: attemptID, InitiatorID: "A", TargetID: "C", CoordinatorID: "B",
			Strategy: fakeEdgeStrategyName, ProbationMillis: 30, SentAt: time.Now().UTC(),
		}
	}

	t.Run("initiator", func(t *testing.T) {
		nodeA := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
		nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B"})
		nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C"})
		attachTestDualPair(t, nodeA, "B", nodeB, "A")
		attachTestDualPair(t, nodeA, "C", nodeC, "A")
		manager := newTestManager(t, managerConfig(nodeA, true))

		handle, err := manager.Start(context.Background(), "C", "B")
		if err != nil {
			t.Fatal(err)
		}
		assertAttemptTimesOut(t, manager, handle.ID(), attemptTimeout)
	})

	t.Run("coordinator", func(t *testing.T) {
		nodeA := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
		nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B"})
		nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C"})
		attachTestDualPair(t, nodeB, "A", nodeA, "B")
		attachTestDualPair(t, nodeB, "C", nodeC, "B")
		manager := newTestManager(t, managerConfig(nodeB, false))
		wire := wireFor("coordinator-timeout")

		if err := manager.handlePrepareRequest(context.Background(), "A", wire); err != nil {
			t.Fatal(err)
		}
		assertAttemptTimesOut(t, manager, wire.AttemptID, attemptTimeout)
	})

	t.Run("target", func(t *testing.T) {
		nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B"})
		nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C"})
		attachTestDualPair(t, nodeC, "B", nodeB, "C")
		manager := newTestManager(t, managerConfig(nodeC, true))
		wire := wireFor("target-timeout")

		if err := manager.handlePrepare(context.Background(), "B", wire); err != nil {
			t.Fatal(err)
		}
		assertAttemptTimesOut(t, manager, wire.AttemptID, attemptTimeout)
	})
}

func TestAttemptTimeoutCancelsPlanningStrategy(t *testing.T) {
	nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B"})
	nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C"})
	attachTestDualPair(t, nodeC, "B", nodeB, "C")
	strategy := &blockingPlanStrategy{started: make(chan struct{})}
	manager := newTestManager(t, Config{
		Node: nodeC, StrategyName: blockingPlanStrategyName,
		Probation: 30 * time.Millisecond, SolveTimeout: time.Second, AttemptTimeout: 60 * time.Millisecond,
		PacketNeighbor: mesh.PacketNeighborConfig{
			KeepAliveInterval: 5 * time.Millisecond, PeerTimeout: 20 * time.Millisecond,
			ReadPollInterval: 5 * time.Millisecond, WriteTimeout: 20 * time.Millisecond,
		},
		StrategyFactory: func(AttemptSpec) (solver.Strategy, error) { return strategy, nil },
	})
	wire := wireMessage{
		AttemptID: "planning-timeout", InitiatorID: "A", TargetID: "C", CoordinatorID: "B",
		Strategy: blockingPlanStrategyName, ProbationMillis: 30, SentAt: time.Now().UTC(),
	}
	done := make(chan error, 1)
	go func() {
		done <- manager.handlePrepare(context.Background(), "B", wire)
	}()

	select {
	case <-strategy.started:
	case <-time.After(time.Second):
		t.Fatal("strategy Plan did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handlePrepare error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("attempt timeout did not cancel strategy Plan")
	}
	assertAttemptTimesOut(t, manager, wire.AttemptID, 60*time.Millisecond)
}

func TestCancelTerminalAttemptIsIdempotentAndKeepsDirectEdge(t *testing.T) {
	for _, phase := range []Phase{PhaseStable, PhaseFailed} {
		t.Run(string(phase), func(t *testing.T) {
			node := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
			manager := newTestManager(t, Config{Node: node, StrategyName: "test"})
			left, right := newShortcutMemoryPacketPair()
			t.Cleanup(func() { _ = right.Close() })
			handle, err := node.AttachPacketTransportWithHandle("B", left, longLivedPacketNeighborConfig())
			if err != nil {
				t.Fatal(err)
			}
			attemptID := "terminal-" + string(phase)
			manager.mu.Lock()
			manager.attempts[attemptID] = &attemptState{
				status: Status{
					AttemptID: attemptID, InitiatorID: "A", TargetID: "B", CoordinatorID: "C",
					LocalRole: "initiator", Phase: phase, DirectPeerID: "B",
				},
				directAttached: true,
				neighborHandle: handle,
				changed:        make(chan struct{}),
			}
			manager.mu.Unlock()

			for range 2 {
				if err := manager.Cancel(attemptID, errors.New("operator cancel")); err != nil {
					t.Fatal(err)
				}
			}
			status, ok := manager.Status(attemptID)
			if !ok || status.Phase != phase {
				t.Fatalf("terminal attempt changed to %+v", status)
			}
			assertNeighborHandle(t, node, "B", handle)
		})
	}
}

func TestAttemptWatchdogStopsAtStable(t *testing.T) {
	const attemptTimeout = 80 * time.Millisecond
	node := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
	manager := newTestManager(t, Config{Node: node, StrategyName: "test", AttemptTimeout: attemptTimeout})
	left, right := newShortcutMemoryPacketPair()
	t.Cleanup(func() { _ = right.Close() })
	handle, err := node.AttachPacketTransportWithHandle("B", left, longLivedPacketNeighborConfig())
	if err != nil {
		t.Fatal(err)
	}
	const attemptID = "stable-before-deadline"
	now := time.Now().UTC()
	manager.mu.Lock()
	manager.attempts[attemptID] = &attemptState{
		status: Status{
			AttemptID: attemptID, InitiatorID: "A", TargetID: "B", CoordinatorID: "C",
			LocalRole: "initiator", Phase: PhaseInstalled, DirectPeerID: "B", StartedAt: now, UpdatedAt: now,
		},
		directAttached: true,
		neighborHandle: handle,
		changed:        make(chan struct{}),
	}
	manager.mu.Unlock()
	if !manager.startAttemptWatchdog(attemptID) {
		t.Fatal("watchdog did not start")
	}
	manager.mu.Lock()
	state := manager.attempts[attemptID]
	state.status.Phase = PhaseStable
	state.status.UpdatedAt = time.Now().UTC()
	manager.notifyLocked(state)
	manager.mu.Unlock()

	time.Sleep(2 * attemptTimeout)
	status, ok := manager.Status(attemptID)
	if !ok || status.Phase != PhaseStable {
		t.Fatalf("stable attempt changed after watchdog deadline: %+v", status)
	}
	assertNeighborHandle(t, node, "B", handle)
}

func TestStartEnforcesLocalPairSingleFlight(t *testing.T) {
	nodeA := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
	nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B"})
	nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C"})
	attachTestDualPair(t, nodeA, "B", nodeB, "A")
	attachTestDualPair(t, nodeA, "C", nodeC, "A")
	manager := newTestManager(t, Config{
		Node: nodeA, StrategyName: "test", AttemptTimeout: 2 * time.Second,
		StrategyFactory: func(AttemptSpec) (solver.Strategy, error) {
			return nil, errors.New("factory should not run before PREPARE")
		},
	})

	first, err := manager.Start(context.Background(), "C", "B")
	if err != nil {
		t.Fatal(err)
	}
	_, err = manager.Start(context.Background(), "C", "B")
	if !errors.Is(err, ErrPairBusy) || !strings.Contains(err.Error(), first.ID()) {
		t.Fatalf("second Start error = %v, want ErrPairBusy containing %s", err, first.ID())
	}
	if err := manager.Cancel(first.ID(), errors.New("retry")); err != nil {
		t.Fatal(err)
	}

	second, err := manager.Start(context.Background(), "C", "B")
	if err != nil {
		t.Fatalf("Start after failed attempt: %v", err)
	}
	manager.mu.Lock()
	state := manager.attempts[second.ID()]
	state.status.Phase = PhaseStable
	state.status.UpdatedAt = time.Now().UTC()
	manager.notifyLocked(state)
	manager.mu.Unlock()

	_, err = manager.Start(context.Background(), "C", "B")
	if !errors.Is(err, ErrPairBusy) || !strings.Contains(err.Error(), second.ID()) {
		t.Fatalf("Start beside stable attempt error = %v, want ErrPairBusy containing %s", err, second.ID())
	}
	manager.failLocal(second.ID(), errors.New("stable edge closed"), false)
	const reversedID = "existing-reversed"
	manager.mu.Lock()
	manager.attempts[reversedID] = &attemptState{
		status: Status{
			AttemptID: reversedID, InitiatorID: "C", TargetID: "A", CoordinatorID: "B",
			LocalRole: "target", Phase: PhaseReady, DirectPeerID: "C",
		},
		changed: make(chan struct{}),
	}
	manager.mu.Unlock()
	_, err = manager.Start(context.Background(), "C", "B")
	if !errors.Is(err, ErrPairBusy) || !strings.Contains(err.Error(), reversedID) {
		t.Fatalf("Start beside reversed attempt error = %v, want ErrPairBusy containing %s", err, reversedID)
	}
}

func TestStaleAttemptHandleCannotRemoveReplacementNeighbor(t *testing.T) {
	testCases := []struct {
		name    string
		cleanup func(*Manager, string) error
	}{
		{
			name: "failure cleanup",
			cleanup: func(manager *Manager, attemptID string) error {
				manager.failLocal(attemptID, errors.New("old attempt failed"), false)
				return nil
			},
		},
		{
			name: "manager Close",
			cleanup: func(manager *Manager, _ string) error {
				return manager.Close()
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			node := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
			manager := newTestManager(t, Config{Node: node, StrategyName: "test"})
			oldLeft, oldRight := newShortcutMemoryPacketPair()
			t.Cleanup(func() { _ = oldRight.Close() })
			oldHandle, err := node.AttachPacketTransportWithHandle("B", oldLeft, longLivedPacketNeighborConfig())
			if err != nil {
				t.Fatal(err)
			}
			attemptID := "stale-handle"
			manager.mu.Lock()
			manager.attempts[attemptID] = &attemptState{
				status: Status{
					AttemptID: attemptID, InitiatorID: "A", TargetID: "B", CoordinatorID: "C",
					LocalRole: "initiator", Phase: PhaseInstalled, DirectPeerID: "B",
				},
				directAttached: true,
				neighborHandle: oldHandle,
				changed:        make(chan struct{}),
			}
			manager.mu.Unlock()

			if err := node.RemoveNeighborHandle(oldHandle); err != nil {
				t.Fatal(err)
			}
			newLeft, newRight := newShortcutMemoryPacketPair()
			t.Cleanup(func() { _ = newRight.Close() })
			newHandle, err := node.AttachPacketTransportWithHandle("B", newLeft, longLivedPacketNeighborConfig())
			if err != nil {
				t.Fatal(err)
			}

			if err := testCase.cleanup(manager, attemptID); err != nil {
				t.Fatal(err)
			}
			assertNeighborHandle(t, node, "B", newHandle)
		})
	}
}

func TestDelayedOldNeighborOnCloseCannotAffectReplacement(t *testing.T) {
	node := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
	manager := newTestManager(t, Config{Node: node, StrategyName: "test"})
	const attemptID = "delayed-old-on-close"
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	oldConfig := longLivedPacketNeighborConfig()
	oldConfig.OnClose = func(peerID string, cause error) {
		close(callbackStarted)
		<-releaseCallback
		manager.handleDirectNeighborClose(attemptID, peerID, cause)
	}
	oldLeft, oldRight := newShortcutMemoryPacketPair()
	t.Cleanup(func() { _ = oldRight.Close() })
	oldHandle, err := node.AttachPacketTransportWithHandle("B", oldLeft, oldConfig)
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.attempts[attemptID] = &attemptState{
		status: Status{
			AttemptID: attemptID, InitiatorID: "A", TargetID: "B",
			LocalRole: "initiator", Phase: PhaseStable, DirectPeerID: "B",
		},
		directAttached: true,
		neighborHandle: oldHandle,
		changed:        make(chan struct{}),
	}
	manager.mu.Unlock()

	removeDone := make(chan error, 1)
	go func() { removeDone <- node.RemoveNeighborHandle(oldHandle) }()
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("old neighbor OnClose did not start")
	}
	newLeft, newRight := newShortcutMemoryPacketPair()
	t.Cleanup(func() { _ = newRight.Close() })
	newHandle, err := node.AttachPacketTransportWithHandle("B", newLeft, longLivedPacketNeighborConfig())
	if err != nil {
		close(releaseCallback)
		t.Fatal(err)
	}
	close(releaseCallback)
	select {
	case err := <-removeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("old neighbor cleanup did not finish")
	}
	assertNeighborHandle(t, node, "B", newHandle)
	status, ok := manager.Status(attemptID)
	if !ok || status.Phase != PhaseFailed {
		t.Fatalf("old attempt status = %+v, want failed", status)
	}
}

func assertAttemptTimesOut(t *testing.T, manager *Manager, attemptID string, attemptTimeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	status, err := manager.WaitFor(ctx, attemptID, PhaseStable)
	if !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("WaitFor(%s) error = %v, status = %+v", attemptID, err, status)
	}
	if status.Phase != PhaseFailed || !strings.Contains(status.Failure, "lifecycle timed out") ||
		!strings.Contains(status.Failure, attemptTimeout.String()) {
		t.Fatalf("timeout status = %+v", status)
	}
}

func assertNeighborHandle(t *testing.T, node *mesh.Node, peerID string, want mesh.NeighborHandle) {
	t.Helper()
	info, ok := node.Neighbor(peerID)
	if !ok {
		t.Fatalf("neighbor %s was removed", peerID)
	}
	if info.Handle != want {
		t.Fatalf("neighbor %s handle was replaced unexpectedly", peerID)
	}
}

func longLivedPacketNeighborConfig() mesh.PacketNeighborConfig {
	return mesh.PacketNeighborConfig{
		KeepAliveInterval: time.Second,
		PeerTimeout:       10 * time.Second,
		ReadPollInterval:  time.Second,
		WriteTimeout:      time.Second,
	}
}

const blockingPlanStrategyName = "blocking_plan"

type blockingPlanStrategy struct {
	started chan struct{}
}

func (s *blockingPlanStrategy) Name() string { return blockingPlanStrategyName }

func (s *blockingPlanStrategy) Plan(ctx context.Context, _ solver.SolveInput) ([]solver.Plan, error) {
	close(s.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *blockingPlanStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	return solver.Result{}, errors.New("blocking plan strategy must not execute")
}

func (s *blockingPlanStrategy) Close() error { return nil }

func TestDefaultAttemptLifecycleTimeoutCoversSolveAndCommitWindows(t *testing.T) {
	solveTimeout := 2 * time.Minute
	probation := 35 * time.Second
	peerTimeout := 30 * time.Second
	want := 2*solveTimeout + probation + 2*peerTimeout + defaultAttemptTimeoutSlack
	if got := defaultAttemptLifecycleTimeout(solveTimeout, probation, peerTimeout); got != want {
		t.Fatalf("default attempt timeout = %s, want %s", got, want)
	}
}

func TestDefaultAttemptLifecycleTimeoutSaturatesAtMaxDuration(t *testing.T) {
	if got := defaultAttemptLifecycleTimeout(maxTimeDuration, maxTimeDuration, maxTimeDuration); got != maxTimeDuration {
		t.Fatalf("maximum default attempt timeout = %s, want %s", got, maxTimeDuration)
	}
	if got := saturatingPositiveDurationSum(maxTimeDuration, time.Second); got != maxTimeDuration {
		t.Fatalf("maximum duration plus slack = %s, want saturation", got)
	}
	if got := saturatingPositiveDurationMultiply(maxTimeDuration, 2); got != maxTimeDuration {
		t.Fatalf("maximum duration doubled = %s, want saturation", got)
	}
}
