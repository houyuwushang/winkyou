package birthdaypunch

import (
	"context"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/dataplane/routed"
	"winkyou/pkg/mesh"
	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/nat"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/peercontrol"
	"winkyou/pkg/solver"
)

func TestStrategyRunsThroughPeerCoordinatorAndInstallsMeshShortcut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var dataForwardedByB atomic.Int32
	var solverSignalsForwardedByB atomic.Int32
	var punchCalls atomic.Int32
	var closeMu sync.Mutex
	var closeReasons []string
	nodeA := shortcutTestNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	nodeB := shortcutTestNode(t, mesh.NodeConfig{
		NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind == mesh.EventForwarded && event.Frame.Type == mesh.DataTypePacket {
				dataForwardedByB.Add(1)
			}
		},
		OnEvent: func(event mesh.Event) {
			if event.Kind == mesh.EventForwarded && event.Message.Type == peercontrol.TypeSessionSignal &&
				event.Message.SessionSignal != nil && event.Message.SessionSignal.Type == "solver_message" {
				solverSignalsForwardedByB.Add(1)
			}
		},
	})
	nodeC := shortcutTestNode(t, mesh.NodeConfig{NodeID: "C", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond})
	shortcutAttachDualPair(t, nodeA, "B", nodeB, "A")
	shortcutAttachDualPair(t, nodeB, "C", nodeC, "B")
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	shortcutWaitRoutes(t, ctx, nodeA, nodeC, []string{"A", "B", "C"}, []string{"C", "B", "A"})

	endpointA := shortcutEndpoint(t, nodeA)
	endpointC := shortcutEndpoint(t, nodeC)
	packetA, err := endpointA.NewPacketTransport("C", "birthday/A-C")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetA.Close() })
	packetC, err := endpointC.NewPacketTransport("A", "birthday/C-A")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetC.Close() })
	shortcutPacketEcho(t, ctx, packetA, packetC, "before-birthday")
	shortcutEventually(t, ctx, func() bool { return dataForwardedByB.Load() == 2 }, "baseline did not use B")

	pair := newInjectedPunchPair(t)
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		local := pair.localEndpoint(spec.LocalNodeID)
		return New(Config{
			StartLead: 5 * time.Millisecond, EndpointTimeout: time.Second, PunchTimeout: time.Second,
			localEndpointFunc: func(context.Context) (localEndpoint, error) {
				return local, nil
			},
			punchFunc: func(_ context.Context, cfg puncher.Config) (*puncher.Result, error) {
				punchCalls.Add(1)
				return pair.take(spec.LocalNodeID, cfg.Method)
			},
		}), nil
	}
	base := shortcut.Config{
		StrategyName: StrategyName, Probation: 900 * time.Millisecond, SolveTimeout: 3 * time.Second,
		PacketNeighbor: mesh.PacketNeighborConfig{
			KeepAliveInterval: 25 * time.Millisecond, PeerTimeout: 750 * time.Millisecond,
			ReadPollInterval: 25 * time.Millisecond, WriteTimeout: 250 * time.Millisecond,
			OnClose: func(peerID string, cause error) {
				closeMu.Lock()
				closeReasons = append(closeReasons, peerID+":"+errorString(cause))
				closeMu.Unlock()
			},
		},
	}
	base.Node, base.StrategyFactory = nodeA, factory
	managerA := shortcutManager(t, base)
	base.Node, base.StrategyFactory = nodeB, nil
	managerB := shortcutManager(t, base)
	base.Node, base.StrategyFactory = nodeC, factory
	managerC := shortcutManager(t, base)

	handle, err := managerA.Start(ctx, "C", "B")
	if err != nil {
		t.Fatal(err)
	}
	status, err := handle.WaitFor(ctx, shortcut.PhaseStable)
	if err != nil {
		closeMu.Lock()
		reasons := append([]string(nil), closeReasons...)
		closeMu.Unlock()
		t.Fatalf("%v; packet neighbor closes=%v", err, reasons)
	}
	if status.PathSummary.PathID != PlanID || !solver.IsProtectedDirectPath(status.PathSummary) {
		t.Fatalf("shortcut path summary = %+v", status.PathSummary)
	}
	shortcutWaitRoutes(t, ctx, nodeA, nodeC, []string{"A", "C"}, []string{"C", "A"})
	shortcutEventually(t, ctx, func() bool {
		for _, manager := range []*shortcut.Manager{managerA, managerB, managerC} {
			status, ok := manager.Status(handle.ID())
			if !ok || status.Phase != shortcut.PhaseStable {
				return false
			}
		}
		return true
	}, "all birthday shortcut participants did not become stable")
	if punchCalls.Load() != 2 {
		t.Fatalf("birthday punch function called %d times, want 2 endpoints", punchCalls.Load())
	}
	if solverSignalsForwardedByB.Load() < 3 {
		t.Fatalf("B forwarded %d wrapped birthday solver signals, want endpoint exchange plus start", solverSignalsForwardedByB.Load())
	}
	if !nodeA.HasNeighbor("B") || !nodeC.HasNeighbor("B") {
		t.Fatal("transit path was removed after direct shortcut became stable")
	}

	shortcutPacketEcho(t, ctx, packetA, packetC, "after-birthday")
	time.Sleep(30 * time.Millisecond)
	if got := dataForwardedByB.Load(); got != 2 {
		t.Fatalf("B forwarded %d data frames after direct shortcut, want baseline 2", got)
	}
}

func errorString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

type injectedPunchPair struct {
	mu    sync.Mutex
	conns map[string]*net.UDPConn
	peers map[string]*net.UDPAddr
	used  map[string]bool
}

func newInjectedPunchPair(t *testing.T) *injectedPunchPair {
	t.Helper()
	left, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	right, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	return &injectedPunchPair{
		conns: map[string]*net.UDPConn{"A": left, "C": right},
		peers: map[string]*net.UDPAddr{
			"A": cloneUDPAddr(right.LocalAddr().(*net.UDPAddr)),
			"C": cloneUDPAddr(left.LocalAddr().(*net.UDPAddr)),
		},
		used: make(map[string]bool),
	}
}

func (p *injectedPunchPair) localEndpoint(nodeID string) localEndpoint {
	p.mu.Lock()
	defer p.mu.Unlock()
	address := p.conns[nodeID].LocalAddr().(*net.UDPAddr)
	return localEndpoint{
		IP: net.IPv4(127, 0, 0, 1), ObservedPort: address.Port,
		Pattern: nat.PortAllocationPreserving,
	}
}

func (p *injectedPunchPair) take(nodeID, method string) (*puncher.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used[nodeID] {
		return nil, net.ErrClosed
	}
	p.used[nodeID] = true
	conn := p.conns[nodeID]
	return &puncher.Result{
		Conn: conn, LocalAddr: cloneUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
		RemoteAddr: cloneUDPAddr(p.peers[nodeID]), Method: method,
	}, nil
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func shortcutTestNode(t *testing.T, config mesh.NodeConfig) *mesh.Node {
	t.Helper()
	node, err := mesh.NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func shortcutEndpoint(t *testing.T, node *mesh.Node) *routed.Endpoint {
	t.Helper()
	endpoint, err := routed.NewEndpoint(node)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint
}

func shortcutManager(t *testing.T, config shortcut.Config) *shortcut.Manager {
	t.Helper()
	manager, err := shortcut.NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func shortcutAttachDualPair(t *testing.T, left *mesh.Node, leftPeer string, right *mesh.Node, rightPeer string) {
	t.Helper()
	leftControl, rightControl := shortcutTCPPair(t)
	leftData, rightData := shortcutTCPPair(t)
	if err := left.AttachStreams(leftPeer, leftControl, leftData); err != nil {
		t.Fatal(err)
	}
	if err := right.AttachStreams(rightPeer, rightControl, rightData); err != nil {
		t.Fatal(err)
	}
}

func shortcutTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	left, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	right := <-accepted
	if right.err != nil {
		_ = left.Close()
		t.Fatal(right.err)
	}
	return left, right.conn
}

func shortcutPacketEcho(t *testing.T, ctx context.Context, left, right *routed.PacketTransport, payload string) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, _, err := right.ReadPacket(ctx, buffer)
		if err == nil {
			err = right.WritePacket(ctx, append([]byte("reply:"), buffer[:n]...))
		}
		result <- err
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
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func shortcutWaitRoutes(t *testing.T, ctx context.Context, left, right *mesh.Node, leftPath, rightPath []string) {
	t.Helper()
	shortcutEventually(t, ctx, func() bool {
		forward, forwardOK := left.Route(right.NodeID())
		reverse, reverseOK := right.Route(left.NodeID())
		return forwardOK && reverseOK && slices.Equal(forward.Path, leftPath) && slices.Equal(reverse.Path, rightPath)
	}, "shortcut routes did not converge")
}

func shortcutEventually(t *testing.T, ctx context.Context, condition func() bool, message string) {
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
