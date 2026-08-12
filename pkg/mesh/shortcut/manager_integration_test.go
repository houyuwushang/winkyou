package shortcut

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/dataplane/routed"
	"winkyou/pkg/mesh"
	"winkyou/pkg/peercontrol"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
)

func TestShortcutKeepsDirectEdgeUnroutedAndFallsBackDuringProbation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var dataForwardedByB atomic.Int32
	var controlSignalsAtB atomic.Int32
	nodeA := newTestNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeB := newTestNode(t, mesh.NodeConfig{
		NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind == mesh.EventForwarded && event.Frame.Type == mesh.DataTypePacket {
				dataForwardedByB.Add(1)
			}
		},
		OnEvent: func(event mesh.Event) {
			if event.Kind == mesh.EventForwarded && event.Message.Type == peercontrol.TypeSessionSignal {
				controlSignalsAtB.Add(1)
			}
		},
	})
	nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	attachTestDualPair(t, nodeA, "B", nodeB, "A")
	attachTestDualPair(t, nodeB, "C", nodeC, "B")
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	waitReciprocalRoute(t, ctx, nodeA, nodeC, []string{"A", "B", "C"}, []string{"C", "B", "A"})

	endpointA := newTestEndpoint(t, nodeA)
	endpointC := newTestEndpoint(t, nodeC)
	packetA, err := endpointA.NewPacketTransport("C", "test/A-C")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetA.Close() })
	packetC, err := endpointC.NewPacketTransport("A", "test/C-A")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetC.Close() })

	packetRoundTrip(t, ctx, packetA, packetC, "before-shortcut")
	waitTestCondition(t, ctx, func() bool { return dataForwardedByB.Load() == 2 }, "baseline packet did not cross B twice")

	broker := newFakeEdgeBroker()
	factory := func(spec AttemptSpec) (solver.Strategy, error) {
		return newFakeEdgeStrategy(spec, broker), nil
	}
	managerConfig := func(node *mesh.Node, withFactory bool) Config {
		cfg := Config{
			Node: node, StrategyName: fakeEdgeStrategyName, Probation: 2 * time.Second,
			SolveTimeout: 2 * time.Second,
			PacketNeighbor: mesh.PacketNeighborConfig{
				KeepAliveInterval: 20 * time.Millisecond, PeerTimeout: 120 * time.Millisecond,
				ReadPollInterval: 20 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
			},
		}
		if withFactory {
			cfg.StrategyFactory = factory
		}
		return cfg
	}
	managerA := newTestManager(t, managerConfig(nodeA, true))
	_ = newTestManager(t, managerConfig(nodeB, false))
	_ = newTestManager(t, managerConfig(nodeC, true))

	handle, err := managerA.Start(ctx, "C", "B")
	if err != nil {
		t.Fatal(err)
	}
	status, err := handle.WaitFor(ctx, PhaseProbation)
	if err != nil {
		t.Fatal(err)
	}
	if status.PathSummary.PathID != "fake-protected-direct" || status.DirectPeerID != "C" {
		t.Fatalf("probation status = %+v", status)
	}
	waitTestCondition(t, ctx, func() bool {
		neighborA, okA := nodeA.Neighbor("C")
		neighborC, okC := nodeC.Neighbor("A")
		return okA && okC && !neighborA.Advertised && !neighborC.Advertised
	}, "probationary packet neighbors were not attached as deferred")
	waitReciprocalRoute(t, ctx, nodeA, nodeC, []string{"A", "B", "C"}, []string{"C", "B", "A"})
	if !nodeA.HasNeighbor("B") || !nodeB.HasNeighbor("A") || !nodeB.HasNeighbor("C") || !nodeC.HasNeighbor("B") {
		t.Fatal("transit A-B-C edge was removed during shortcut probation")
	}

	packetRoundTrip(t, ctx, packetA, packetC, "during-probation")
	waitTestCondition(t, ctx, func() bool { return dataForwardedByB.Load() >= 4 }, "probation traffic bypassed B")
	if got := dataForwardedByB.Load(); got != 4 {
		t.Fatalf("B forwarded %d packet frames during probation, want 4", got)
	}
	if controlSignalsAtB.Load() == 0 {
		t.Fatal("B did not carry shortcut/solver control signals")
	}

	if err := nodeA.RemoveNeighbor("C"); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.WaitFor(ctx, PhaseStable); !errors.Is(err, ErrAttemptFailed) {
		t.Fatalf("WaitFor(stable) after probation failure error = %v", err)
	}
	waitReciprocalRoute(t, ctx, nodeA, nodeC, []string{"A", "B", "C"}, []string{"C", "B", "A"})
	waitTestCondition(t, ctx, func() bool {
		return !nodeA.HasNeighbor("C") && !nodeC.HasNeighbor("A")
	}, "failed direct neighbor was not removed at both endpoints")
	packetRoundTrip(t, ctx, packetA, packetC, "fallback-via-B")
	waitTestCondition(t, ctx, func() bool { return dataForwardedByB.Load() >= 6 }, "fallback packet did not return to B")
}

func TestShortcutBecomesStableAfterProbation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodeA := newTestNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	attachTestDualPair(t, nodeA, "B", nodeB, "A")
	attachTestDualPair(t, nodeB, "C", nodeC, "B")
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	waitReciprocalRoute(t, ctx, nodeA, nodeC, []string{"A", "B", "C"}, []string{"C", "B", "A"})
	broker := newFakeEdgeBroker()
	factory := func(spec AttemptSpec) (solver.Strategy, error) { return newFakeEdgeStrategy(spec, broker), nil }
	base := Config{
		StrategyName: fakeEdgeStrategyName, Probation: 150 * time.Millisecond, SolveTimeout: time.Second,
		PacketNeighbor: mesh.PacketNeighborConfig{
			KeepAliveInterval: 10 * time.Millisecond, PeerTimeout: 100 * time.Millisecond,
			ReadPollInterval: 10 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
		},
	}
	base.Node, base.StrategyFactory = nodeA, factory
	managerA := newTestManager(t, base)
	base.Node, base.StrategyFactory = nodeB, nil
	managerB := newTestManager(t, base)
	base.Node, base.StrategyFactory = nodeC, factory
	managerC := newTestManager(t, base)
	handle, err := managerA.Start(ctx, "C", "B")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handle.WaitFor(ctx, PhaseStable); err != nil {
		t.Fatal(err)
	}
	waitTestCondition(t, ctx, func() bool {
		for _, manager := range []*Manager{managerA, managerB, managerC} {
			status, ok := manager.Status(handle.ID())
			if !ok || status.Phase != PhaseStable {
				return false
			}
		}
		return true
	}, "all shortcut managers did not reach stable")
}

func TestShortcutReportsInstalledOnlyAfterPacketNeighborReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodeA := newTestNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	attachTestDualPair(t, nodeA, "B", nodeB, "A")
	attachTestDualPair(t, nodeB, "C", nodeC, "B")
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	waitReciprocalRoute(t, ctx, nodeA, nodeC, []string{"A", "B", "C"}, []string{"C", "B", "A"})

	gate := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate) }) }
	t.Cleanup(release)
	broker := newFakeEdgeBroker()
	for nodeID, packetTransport := range broker.transports {
		broker.transports[nodeID] = &gatedShortcutPacketTransport{
			PacketTransport: packetTransport,
			gate:            gate,
		}
	}
	factory := func(spec AttemptSpec) (solver.Strategy, error) { return newFakeEdgeStrategy(spec, broker), nil }
	base := Config{
		StrategyName: fakeEdgeStrategyName,
		Probation:    150 * time.Millisecond,
		SolveTimeout: time.Second,
		PacketNeighbor: mesh.PacketNeighborConfig{
			KeepAliveInterval: 10 * time.Millisecond,
			PeerTimeout:       50 * time.Millisecond,
			ReadPollInterval:  10 * time.Millisecond,
			WriteTimeout:      500 * time.Millisecond,
		},
	}
	base.Node, base.StrategyFactory = nodeA, factory
	managerA := newTestManager(t, base)
	base.Node, base.StrategyFactory = nodeB, nil
	managerB := newTestManager(t, base)
	base.Node, base.StrategyFactory = nodeC, factory
	managerC := newTestManager(t, base)

	handle, err := managerA.Start(ctx, "C", "B")
	if err != nil {
		t.Fatal(err)
	}
	waitTestCondition(t, ctx, func() bool {
		_, readyAtA := nodeA.Neighbor("C")
		_, readyAtC := nodeC.Neighbor("A")
		return readyAtA && readyAtC
	}, "packet sessions were not attached")
	for nodeID, manager := range map[string]*Manager{"A": managerA, "C": managerC} {
		status, ok := manager.Status(handle.ID())
		if !ok || status.Phase != PhaseSolving {
			t.Fatalf("%s endpoint phase before packet readiness = %q, want %q", nodeID, status.Phase, PhaseSolving)
		}
	}
	if status, ok := managerB.Status(handle.ID()); !ok || phaseReached(status.Phase, PhaseProbation) {
		t.Fatalf("coordinator phase before packet readiness = %q, want before %q", status.Phase, PhaseProbation)
	}

	release()
	if _, err := handle.WaitFor(ctx, PhaseStable); err != nil {
		t.Fatal(err)
	}
}

func TestShortcutReconcilesDroppedPacketBarrierSignal(t *testing.T) {
	testCases := []struct {
		name       string
		signalType string
		dropAt     string
		probation  time.Duration
	}{
		{name: "first commit", signalType: typeCommit, dropAt: "B", probation: 150 * time.Millisecond},
		{name: "first stable after initial delivery window", signalType: typeStable, dropAt: "A", probation: 1500 * time.Millisecond},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			nodeA := newTestNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
			nodeB := newTestNode(t, mesh.NodeConfig{NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
			nodeC := newTestNode(t, mesh.NodeConfig{NodeID: "C", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})

			packetA, packetB := newShortcutMemoryPacketPair()
			dropper := &dropFirstShortcutSignalTransport{signalType: testCase.signalType}
			var transportA transport.PacketTransport = packetA
			var transportB transport.PacketTransport = packetB
			if testCase.dropAt == "A" {
				dropper.PacketTransport = transportA
				transportA = dropper
			} else {
				dropper.PacketTransport = transportB
				transportB = dropper
			}
			packetConfig := mesh.PacketNeighborConfig{
				KeepAliveInterval: 10 * time.Millisecond, PeerTimeout: 100 * time.Millisecond,
				ReadPollInterval: 10 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
			}
			if err := nodeA.AttachPacketTransport("B", transportA, packetConfig); err != nil {
				t.Fatal(err)
			}
			if err := nodeB.AttachPacketTransport("A", transportB, packetConfig); err != nil {
				t.Fatal(err)
			}
			attachTestDualPair(t, nodeB, "C", nodeC, "B")
			for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
				if err := node.Start(ctx); err != nil {
					t.Fatal(err)
				}
			}
			waitReciprocalRoute(t, ctx, nodeA, nodeC, []string{"A", "B", "C"}, []string{"C", "B", "A"})

			broker := newFakeEdgeBroker()
			factory := func(spec AttemptSpec) (solver.Strategy, error) { return newFakeEdgeStrategy(spec, broker), nil }
			base := Config{
				StrategyName: fakeEdgeStrategyName, Probation: testCase.probation, SolveTimeout: time.Second,
				PacketNeighbor: packetConfig,
			}
			base.Node, base.StrategyFactory = nodeA, factory
			managerA := newTestManager(t, base)
			base.Node, base.StrategyFactory = nodeB, nil
			managerB := newTestManager(t, base)
			base.Node, base.StrategyFactory = nodeC, factory
			managerC := newTestManager(t, base)

			handle, err := managerA.Start(ctx, "C", "B")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := handle.WaitFor(ctx, PhaseStable); err != nil {
				t.Fatal(err)
			}
			waitTestCondition(t, ctx, func() bool {
				for _, manager := range []*Manager{managerA, managerB, managerC} {
					status, ok := manager.Status(handle.ID())
					if !ok || status.Phase != PhaseStable {
						return false
					}
				}
				return true
			}, "shortcut managers did not reconcile after a dropped barrier signal")
			if got := dropper.dropped.Load(); got != 1 {
				t.Fatalf("dropped %s count = %d, want 1", testCase.signalType, got)
			}
			if got := dropper.matched.Load(); got < 2 {
				t.Fatalf("matched %s count = %d, want at least 2", testCase.signalType, got)
			}
		})
	}
}

func TestLateStableDoesNotReviveFailedAttempt(t *testing.T) {
	node := newTestNode(t, mesh.NodeConfig{NodeID: "B"})
	manager := newTestManager(t, Config{Node: node, StrategyName: "test"})
	wire := wireMessage{
		AttemptID: "failed-attempt", InitiatorID: "A", TargetID: "C", CoordinatorID: "B",
		Strategy: "test", ProbationMillis: 1000, SentAt: time.Now().UTC(),
	}
	manager.mu.Lock()
	manager.attempts[wire.AttemptID] = &attemptState{
		status: Status{
			AttemptID: wire.AttemptID, InitiatorID: wire.InitiatorID, TargetID: wire.TargetID,
			CoordinatorID: wire.CoordinatorID, LocalRole: "coordinator", Phase: PhaseFailed,
			Failure: "terminal failure",
		},
		stable: make(map[string]bool), changed: make(chan struct{}),
	}
	manager.mu.Unlock()
	if err := manager.handleStable(wire.InitiatorID, wire); err != nil {
		t.Fatal(err)
	}
	if err := manager.handleStable(wire.TargetID, wire); err != nil {
		t.Fatal(err)
	}
	status, ok := manager.Status(wire.AttemptID)
	if !ok || status.Phase != PhaseFailed || status.Failure != "terminal failure" {
		t.Fatalf("late STABLE changed failed attempt to %+v", status)
	}
}

func TestProbationCompletionCannotOverwriteConcurrentFailure(t *testing.T) {
	node := newTestNode(t, mesh.NodeConfig{NodeID: "A"})
	manager := newTestManager(t, Config{Node: node, StrategyName: "test"})
	const attempts = 200
	for index := range attempts {
		attemptID := fmt.Sprintf("probation-race-%03d", index)
		packet, peer := newShortcutMemoryPacketPair()
		handle, err := node.AttachPacketTransportWithHandle("B", packet, mesh.PacketNeighborConfig{
			KeepAliveInterval:  time.Second,
			PeerTimeout:        5 * time.Second,
			DeferAdvertisement: true,
		})
		if err != nil {
			_ = peer.Close()
			t.Fatal(err)
		}
		manager.mu.Lock()
		manager.attempts[attemptID] = &attemptState{
			status:         Status{AttemptID: attemptID, Phase: PhaseProbation, DirectPeerID: "B"},
			directAttached: true,
			neighborHandle: handle,
			changed:        make(chan struct{}),
		}
		manager.mu.Unlock()
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			manager.failLocal(attemptID, errors.New("concurrent failure"), false)
		}()
		go func() {
			defer wait.Done()
			<-start
			manager.completeProbation(attemptID)
		}()
		close(start)
		wait.Wait()
		_ = peer.Close()
		status, ok := manager.Status(attemptID)
		if !ok || status.Phase != PhaseFailed {
			t.Fatalf("attempt %s ended as %+v, want failed", attemptID, status)
		}
		if node.HasNeighbor("B") {
			t.Fatalf("attempt %s left a direct neighbor installed", attemptID)
		}
	}
}

type dropFirstShortcutSignalTransport struct {
	transport.PacketTransport
	signalType string
	matched    atomic.Int32
	dropped    atomic.Int32
}

func (t *dropFirstShortcutSignalTransport) WritePacket(ctx context.Context, packet []byte) error {
	if isShortcutControlSignal(packet, t.signalType) {
		t.matched.Add(1)
		if t.dropped.CompareAndSwap(0, 1) {
			return nil
		}
	}
	return t.PacketTransport.WritePacket(ctx, packet)
}

func isShortcutControlSignal(packet []byte, signalType string) bool {
	if len(packet) <= 10 || !bytes.Equal(packet[:4], []byte("WKPN")) || packet[5] != 1 {
		return false
	}
	payload := packet[10:]
	return bytes.Contains(payload, []byte(`"namespace":"`+Namespace+`"`)) &&
		bytes.Contains(payload, []byte(`"type":"`+signalType+`"`))
}

const fakeEdgeStrategyName = "fake_protected_direct"

type fakeEdgeStrategy struct {
	spec     AttemptSpec
	broker   *fakeEdgeBroker
	input    solver.SolveInput
	remoteCh chan struct{}
	closed   atomic.Bool
}

func newFakeEdgeStrategy(spec AttemptSpec, broker *fakeEdgeBroker) *fakeEdgeStrategy {
	return &fakeEdgeStrategy{spec: spec, broker: broker, remoteCh: make(chan struct{}, 1)}
}

func (s *fakeEdgeStrategy) Name() string { return fakeEdgeStrategyName }
func (s *fakeEdgeStrategy) Plan(_ context.Context, input solver.SolveInput) ([]solver.Plan, error) {
	s.input = input
	return []solver.Plan{{ID: "fake/direct", Strategy: fakeEdgeStrategyName}}, nil
}
func (s *fakeEdgeStrategy) Execute(ctx context.Context, session solver.SessionIO, _ solver.Plan) (solver.Result, error) {
	if err := session.Send(ctx, solver.Message{
		Kind: solver.MessageKindStrategy, Namespace: fakeEdgeStrategyName, Type: "endpoint",
		Payload: []byte(s.spec.LocalNodeID), ReceivedAt: time.Now(),
	}); err != nil {
		return solver.Result{}, err
	}
	select {
	case <-ctx.Done():
		return solver.Result{}, ctx.Err()
	case <-s.remoteCh:
	}
	packetTransport, err := s.broker.transportFor(s.spec.LocalNodeID)
	if err != nil {
		return solver.Result{}, err
	}
	return solver.Result{
		Transport: packetTransport,
		Summary: solver.PathSummary{
			PathID: "fake-protected-direct", ConnectionType: "direct",
			Role: solver.PathRoleProtectedDirect, Metrics: map[string]string{"solver": fakeEdgeStrategyName},
		},
	}, nil
}
func (s *fakeEdgeStrategy) HandleMessage(_ context.Context, _ solver.SessionIO, message solver.Message) error {
	if message.Namespace == fakeEdgeStrategyName && message.Type == "endpoint" {
		select {
		case s.remoteCh <- struct{}{}:
		default:
		}
	}
	return nil
}
func (s *fakeEdgeStrategy) Close() error {
	s.closed.Store(true)
	return nil
}

type fakeEdgeBroker struct {
	mu         sync.Mutex
	transports map[string]transport.PacketTransport
	taken      map[string]bool
}

func newFakeEdgeBroker() *fakeEdgeBroker {
	left, right := newShortcutMemoryPacketPair()
	return &fakeEdgeBroker{
		transports: map[string]transport.PacketTransport{"A": left, "C": right},
		taken:      make(map[string]bool),
	}
}

func (b *fakeEdgeBroker) transportFor(nodeID string) (transport.PacketTransport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	packetTransport := b.transports[nodeID]
	if packetTransport == nil || b.taken[nodeID] {
		return nil, errors.New("fake edge transport unavailable")
	}
	b.taken[nodeID] = true
	return packetTransport, nil
}

type shortcutMemoryPacketTransport struct {
	recv      chan []byte
	done      chan struct{}
	peer      *shortcutMemoryPacketTransport
	closeOnce sync.Once
}

type gatedShortcutPacketTransport struct {
	transport.PacketTransport
	gate <-chan struct{}
}

func (t *gatedShortcutPacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.gate:
		return t.PacketTransport.WritePacket(ctx, packet)
	}
}

func newShortcutMemoryPacketPair() (*shortcutMemoryPacketTransport, *shortcutMemoryPacketTransport) {
	left := &shortcutMemoryPacketTransport{recv: make(chan []byte, 256), done: make(chan struct{})}
	right := &shortcutMemoryPacketTransport{recv: make(chan []byte, 256), done: make(chan struct{})}
	left.peer, right.peer = right, left
	return left, right
}

func (m *shortcutMemoryPacketTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	select {
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	case <-m.done:
		return 0, transport.PacketMeta{}, net.ErrClosed
	case packet := <-m.recv:
		if len(dst) < len(packet) {
			return 0, transport.PacketMeta{}, errors.New("short buffer")
		}
		return copy(dst, packet), transport.PacketMeta{ReceivedAt: time.Now()}, nil
	}
}
func (m *shortcutMemoryPacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return net.ErrClosed
	case <-m.peer.done:
		return net.ErrClosed
	case m.peer.recv <- append([]byte(nil), packet...):
		return nil
	}
}
func (m *shortcutMemoryPacketTransport) LocalAddr() net.Addr  { return shortcutAddr("local") }
func (m *shortcutMemoryPacketTransport) RemoteAddr() net.Addr { return shortcutAddr("remote") }
func (m *shortcutMemoryPacketTransport) Close() error {
	m.closeOnce.Do(func() { close(m.done) })
	return nil
}

type shortcutAddr string

func (a shortcutAddr) Network() string { return "shortcut-memory" }
func (a shortcutAddr) String() string  { return string(a) }

func newTestNode(t *testing.T, config mesh.NodeConfig) *mesh.Node {
	t.Helper()
	node, err := mesh.NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func newTestEndpoint(t *testing.T, node *mesh.Node) *routed.Endpoint {
	t.Helper()
	endpoint, err := routed.NewEndpoint(node)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint
}

func newTestManager(t *testing.T, config Config) *Manager {
	t.Helper()
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func attachTestDualPair(t *testing.T, left *mesh.Node, leftPeer string, right *mesh.Node, rightPeer string) {
	t.Helper()
	leftControl, rightControl := testTCPPair(t)
	leftData, rightData := testTCPPair(t)
	if err := left.AttachStreams(leftPeer, leftControl, leftData); err != nil {
		t.Fatal(err)
	}
	if err := right.AttachStreams(rightPeer, rightControl, rightData); err != nil {
		t.Fatal(err)
	}
}

func testTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		result <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	left, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	right := <-result
	if right.err != nil {
		_ = left.Close()
		t.Fatal(right.err)
	}
	return left, right.conn
}

func packetRoundTrip(t *testing.T, ctx context.Context, left, right *routed.PacketTransport, payload string) {
	t.Helper()
	errorsCh := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, _, err := right.ReadPacket(ctx, buffer)
		if err == nil {
			err = right.WritePacket(ctx, append([]byte("reply:"), buffer[:n]...))
		}
		errorsCh <- err
	}()
	if err := left.WritePacket(ctx, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, _, err := left.ReadPacket(ctx, buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "reply:"+payload {
		t.Fatalf("reply = %q", buffer[:n])
	}
	if err := <-errorsCh; err != nil {
		t.Fatal(err)
	}
}

func waitReciprocalRoute(t *testing.T, ctx context.Context, left, right *mesh.Node, leftPath, rightPath []string) {
	t.Helper()
	waitTestCondition(t, ctx, func() bool {
		forward, forwardOK := left.Route(right.NodeID())
		reverse, reverseOK := right.Route(left.NodeID())
		return forwardOK && reverseOK && slices.Equal(forward.Path, leftPath) && slices.Equal(reverse.Path, rightPath)
	}, "reciprocal routes did not converge")
}

func waitTestCondition(t *testing.T, ctx context.Context, condition func() bool, message string) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: %v", message, ctx.Err())
		case <-ticker.C:
		}
	}
}

var _ solver.Strategy = (*fakeEdgeStrategy)(nil)
var _ solver.MessageHandler = (*fakeEdgeStrategy)(nil)
var _ transport.PacketTransport = (*shortcutMemoryPacketTransport)(nil)
