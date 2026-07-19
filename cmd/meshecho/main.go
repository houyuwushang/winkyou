// Command meshecho runs the incremental autonomous-mesh proofs with three
// independent node runtimes and no infrastructure coordinator.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/dataplane/routed"
	"winkyou/pkg/mesh"
	"winkyou/pkg/mesh/shortcut"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/peercontrol"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
	"winkyou/pkg/transport/iceadapter"
)

type result struct {
	CoordinatorStarted bool     `json:"coordinator_started"`
	Mode               string   `json:"mode"`
	Transport          string   `json:"transport"`
	EchoID             string   `json:"echo_id,omitempty"`
	Payload            string   `json:"payload"`
	RequestPath        []string `json:"request_path,omitempty"`
	ReplyPath          []string `json:"reply_path,omitempty"`
	ForwardedByB       int32    `json:"forwarded_by_b,omitempty"`
	AutoDiscovered     bool     `json:"auto_discovered,omitempty"`
	LearnedRoute       []string `json:"learned_route,omitempty"`
	RouteWithdrawn     bool     `json:"route_withdrawn,omitempty"`
	MemberRetained     bool     `json:"member_retained_after_withdraw,omitempty"`
	OverlayReply       string   `json:"overlay_reply,omitempty"`
	TCPReply           string   `json:"tcp_reply,omitempty"`
	DataForwardedByB   int32    `json:"data_frames_forwarded_by_b,omitempty"`
	DataChannelSplit   bool     `json:"control_data_channels_separate,omitempty"`
	TCPHalfClose       bool     `json:"tcp_half_close_completed,omitempty"`
	PeerCoordinator    string   `json:"peer_coordinator,omitempty"`
	ShortcutSolver     string   `json:"shortcut_solver,omitempty"`
	InitialRoute       []string `json:"initial_route,omitempty"`
	DirectRoute        []string `json:"direct_route,omitempty"`
	ShortcutPhase      string   `json:"shortcut_phase,omitempty"`
	SolverSignalsByB   int32    `json:"solver_signals_forwarded_by_b,omitempty"`
	DirectBypassedB    bool     `json:"direct_data_bypassed_b,omitempty"`
	TransitRetained    bool     `json:"transit_path_retained,omitempty"`
	RejoinedNode       string   `json:"rejoined_node,omitempty"`
	BootstrapRoute     []string `json:"bootstrap_route,omitempty"`
	FirstCoordinator   string   `json:"first_coordinator,omitempty"`
	FirstDirectRoute   []string `json:"first_direct_route,omitempty"`
	ReplacementRoute   []string `json:"replacement_route,omitempty"`
	SecondCoordinator  string   `json:"second_coordinator,omitempty"`
	SecondDirectRoute  []string `json:"second_direct_route,omitempty"`
	TemporaryDetached  bool     `json:"temporary_underlay_detached,omitempty"`
	AllEdgesDirect     bool     `json:"all_edges_direct,omitempty"`
	DataBypassVerified bool     `json:"data_bypass_verified,omitempty"`
}

func main() {
	payload := flag.String("payload", "hello-mesh", "opaque control echo payload")
	mode := flag.String("mode", "static", "proof mode: static|dynamic|data|shortcut|rejoin")
	timeout := flag.Duration("timeout", 5*time.Second, "demo timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var got result
	var err error
	switch *mode {
	case "static":
		got, err = runStatic(ctx, []byte(*payload))
	case "dynamic":
		got, err = runDynamic(ctx, []byte(*payload))
	case "data":
		got, err = runData(ctx, []byte(*payload))
	case "shortcut":
		got, err = runShortcut(ctx, []byte(*payload))
	case "rejoin":
		got, err = runRejoin(ctx, []byte(*payload))
	default:
		err = fmt.Errorf("unknown mode %q (want static, dynamic, data, shortcut, or rejoin)", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshecho failed: %v\n", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(got); err != nil {
		fmt.Fprintf(os.Stderr, "meshecho output failed: %v\n", err)
		os.Exit(1)
	}
}

func runShortcut(ctx context.Context, payload []byte) (result, error) {
	var dataForwardedByB atomic.Int32
	var solverSignalsByB atomic.Int32
	nodeA, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "A", VirtualIP: "fd00::a", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
	})
	if err != nil {
		return result{}, err
	}
	defer nodeA.Close()
	nodeB, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "B", VirtualIP: "fd00::b", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind == mesh.EventForwarded && event.Frame.Type == mesh.DataTypePacket {
				dataForwardedByB.Add(1)
			}
		},
		OnEvent: func(event mesh.Event) {
			if event.Kind == mesh.EventForwarded && event.Message.Type == peercontrol.TypeSessionSignal &&
				event.Message.SessionSignal != nil &&
				event.Message.SessionSignal.Namespace == shortcut.Namespace &&
				event.Message.SessionSignal.Type == shortcut.SignalTypeSolverMessage {
				solverSignalsByB.Add(1)
			}
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeB.Close()
	nodeC, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "C", VirtualIP: "fd00::c", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
	})
	if err != nil {
		return result{}, err
	}
	defer nodeC.Close()
	if err := attachDualTCPPair(nodeA, "B", nodeB, "A"); err != nil {
		return result{}, fmt.Errorf("attach dual-stream A-B: %w", err)
	}
	if err := attachDualTCPPair(nodeB, "C", nodeC, "B"); err != nil {
		return result{}, fmt.Errorf("attach dual-stream B-C: %w", err)
	}
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			return result{}, fmt.Errorf("start mesh node: %w", err)
		}
	}
	var initialRoute mesh.Route
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		if forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "B", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "B", "A"}) {
			initialRoute = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for initial transit route: %w", err)
	}

	endpointA, err := routed.NewEndpoint(nodeA)
	if err != nil {
		return result{}, err
	}
	defer endpointA.Close()
	endpointC, err := routed.NewEndpoint(nodeC)
	if err != nil {
		return result{}, err
	}
	defer endpointC.Close()
	packetA, err := endpointA.NewPacketTransport("C", "shortcut/A-C")
	if err != nil {
		return result{}, err
	}
	defer packetA.Close()
	packetC, err := endpointC.NewPacketTransport("A", "shortcut/C-A")
	if err != nil {
		return result{}, err
	}
	defer packetC.Close()
	baselineReply, err := packetEcho(ctx, packetA, packetC, append([]byte("BEFORE:"), payload...))
	if err != nil {
		return result{}, fmt.Errorf("transit packet echo: %w", err)
	}
	if err := waitFor(ctx, func() bool { return dataForwardedByB.Load() == 2 }); err != nil {
		return result{}, fmt.Errorf("wait for baseline transit counters: %w", err)
	}

	broker, err := newDemoEdgeBroker("A", "C")
	if err != nil {
		return result{}, err
	}
	defer broker.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		return newDemoEdgeStrategy(spec, broker), nil
	}
	managerConfig := func(node *mesh.Node, withFactory bool) shortcut.Config {
		config := shortcut.Config{
			Node: node, StrategyName: demoEdgeStrategyName, Probation: 400 * time.Millisecond,
			SolveTimeout: 2 * time.Second,
			PacketNeighbor: mesh.PacketNeighborConfig{
				KeepAliveInterval: 25 * time.Millisecond, PeerTimeout: 250 * time.Millisecond,
				ReadPollInterval: 25 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
			},
		}
		if withFactory {
			config.StrategyFactory = factory
		}
		return config
	}
	managerA, err := shortcut.NewManager(managerConfig(nodeA, true))
	if err != nil {
		return result{}, err
	}
	defer managerA.Close()
	managerB, err := shortcut.NewManager(managerConfig(nodeB, false))
	if err != nil {
		return result{}, err
	}
	defer managerB.Close()
	managerC, err := shortcut.NewManager(managerConfig(nodeC, true))
	if err != nil {
		return result{}, err
	}
	defer managerC.Close()

	handle, err := managerA.Start(ctx, "C", "B")
	if err != nil {
		return result{}, err
	}
	shortcutStatus, err := handle.WaitFor(ctx, shortcut.PhaseStable)
	if err != nil {
		return result{}, err
	}
	var directRoute mesh.Route
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		if forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "A"}) {
			directRoute = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for direct route: %w", err)
	}
	if err := waitFor(ctx, func() bool {
		for _, manager := range []*shortcut.Manager{managerA, managerB, managerC} {
			status, ok := manager.Status(handle.ID())
			if !ok || status.Phase != shortcut.PhaseStable {
				return false
			}
		}
		return true
	}); err != nil {
		return result{}, fmt.Errorf("wait for shortcut stability: %w", err)
	}
	directReply, err := packetEcho(ctx, packetA, packetC, append([]byte("DIRECT:"), payload...))
	if err != nil {
		return result{}, fmt.Errorf("direct packet echo: %w", err)
	}
	time.Sleep(25 * time.Millisecond)
	directBypassedB := dataForwardedByB.Load() == 2
	transitRetained := nodeA.HasNeighbor("B") && nodeB.HasNeighbor("A") && nodeB.HasNeighbor("C") && nodeC.HasNeighbor("B")
	if !directBypassedB || !transitRetained || solverSignalsByB.Load() < 2 {
		return result{}, fmt.Errorf(
			"shortcut acceptance failed: bypass=%t transit=%t solver_signals=%d baseline_reply=%q",
			directBypassedB, transitRetained, solverSignalsByB.Load(), baselineReply,
		)
	}
	return result{
		CoordinatorStarted: false,
		Mode:               "shortcut",
		Transport:          "dual-tcp-transit+udp-shortcut",
		Payload:            string(payload),
		AutoDiscovered:     true,
		LearnedRoute:       append([]string(nil), initialRoute.Path...),
		OverlayReply:       string(directReply),
		DataForwardedByB:   dataForwardedByB.Load(),
		DataChannelSplit:   true,
		PeerCoordinator:    "B",
		ShortcutSolver:     demoEdgeStrategyName,
		InitialRoute:       append([]string(nil), initialRoute.Path...),
		DirectRoute:        append([]string(nil), directRoute.Path...),
		ShortcutPhase:      string(shortcutStatus.Phase),
		SolverSignalsByB:   solverSignalsByB.Load(),
		DirectBypassedB:    directBypassedB,
		TransitRetained:    transitRetained,
	}, nil
}

// runRejoin proves that an offline node can use a temporary underlay to join an
// existing two-node mesh, then replace that dependency without ever
// disconnecting the graph. The field topology is A=local, B=chen-win and
// C=inner-gw:
//
//	A--C + C~~B  ->  A--B (coordinated by C)  ->  remove C~~B
//	              ->  B--C (coordinated by A)
//
// The temporary C~~B stream models natpierce reachability. Both replacement
// edges are packet transports installed by the normal shortcut manager.
func runRejoin(ctx context.Context, payload []byte) (result, error) {
	var dataForwardedByA atomic.Int32
	var dataForwardedByC atomic.Int32
	var solverSignalsByA atomic.Int32
	var solverSignalsByC atomic.Int32

	shortcutSignalCounter := func(counter *atomic.Int32) func(mesh.Event) {
		return func(event mesh.Event) {
			if event.Kind == mesh.EventForwarded && event.Message.Type == peercontrol.TypeSessionSignal &&
				event.Message.SessionSignal != nil &&
				event.Message.SessionSignal.Namespace == shortcut.Namespace &&
				event.Message.SessionSignal.Type == shortcut.SignalTypeSolverMessage {
				counter.Add(1)
			}
		}
	}
	dataCounter := func(counter *atomic.Int32) func(mesh.DataEvent) {
		return func(event mesh.DataEvent) {
			if event.Kind == mesh.EventForwarded && event.Frame.Type == mesh.DataTypePacket {
				counter.Add(1)
			}
		}
	}

	nodeA, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "A", VirtualIP: "fd00::a", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
		OnEvent: shortcutSignalCounter(&solverSignalsByA), OnDataEvent: dataCounter(&dataForwardedByA),
	})
	if err != nil {
		return result{}, err
	}
	defer nodeA.Close()
	nodeB, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "B", VirtualIP: "fd00::b", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
	})
	if err != nil {
		return result{}, err
	}
	defer nodeB.Close()
	nodeC, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "C", VirtualIP: "fd00::c", Lease: 5 * time.Second, RefreshInterval: 50 * time.Millisecond,
		OnEvent: shortcutSignalCounter(&solverSignalsByC), OnDataEvent: dataCounter(&dataForwardedByC),
	})
	if err != nil {
		return result{}, err
	}
	defer nodeC.Close()

	// A-C is the already established public bridge. Start it before B exists so
	// the later B attachment exercises a real late join rather than static setup.
	if err := attachDualTCPPair(nodeA, "C", nodeC, "A"); err != nil {
		return result{}, fmt.Errorf("attach established A-C edge: %w", err)
	}
	for _, node := range []*mesh.Node{nodeA, nodeC} {
		if err := node.Start(ctx); err != nil {
			return result{}, fmt.Errorf("start established mesh node: %w", err)
		}
	}
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		return forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "A"})
	}); err != nil {
		return result{}, fmt.Errorf("wait for established A-C edge: %w", err)
	}

	if err := nodeB.Start(ctx); err != nil {
		return result{}, fmt.Errorf("start rejoining B: %w", err)
	}
	if err := attachDualTCPPair(nodeC, "B", nodeB, "C"); err != nil {
		return result{}, fmt.Errorf("attach temporary C-B bootstrap edge: %w", err)
	}
	var bootstrapRoute mesh.Route
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeA.Route("B")
		reverse, reverseOK := nodeB.Route("A")
		if forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "C", "B"}) &&
			slices.Equal(reverse.Path, []string{"B", "C", "A"}) {
			bootstrapRoute = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for B bootstrap membership: %w", err)
	}

	endpointA, err := routed.NewEndpoint(nodeA)
	if err != nil {
		return result{}, err
	}
	defer endpointA.Close()
	endpointB, err := routed.NewEndpoint(nodeB)
	if err != nil {
		return result{}, err
	}
	defer endpointB.Close()
	endpointC, err := routed.NewEndpoint(nodeC)
	if err != nil {
		return result{}, err
	}
	defer endpointC.Close()
	packetAB, err := endpointA.NewPacketTransport("B", "rejoin/A-B")
	if err != nil {
		return result{}, err
	}
	defer packetAB.Close()
	packetBA, err := endpointB.NewPacketTransport("A", "rejoin/B-A")
	if err != nil {
		return result{}, err
	}
	defer packetBA.Close()
	packetBC, err := endpointB.NewPacketTransport("C", "rejoin/B-C")
	if err != nil {
		return result{}, err
	}
	defer packetBC.Close()
	packetCB, err := endpointC.NewPacketTransport("B", "rejoin/C-B")
	if err != nil {
		return result{}, err
	}
	defer packetCB.Close()

	beforeBootstrapC := dataForwardedByC.Load()
	if _, err := packetEcho(ctx, packetAB, packetBA, append([]byte("BOOTSTRAP:"), payload...)); err != nil {
		return result{}, fmt.Errorf("bootstrap A-C-B packet echo: %w", err)
	}
	if err := waitFor(ctx, func() bool { return dataForwardedByC.Load() >= beforeBootstrapC+2 }); err != nil {
		return result{}, fmt.Errorf("wait for C bootstrap forwarding (before=%d now=%d): %w", beforeBootstrapC, dataForwardedByC.Load(), err)
	}
	afterBootstrapC := dataForwardedByC.Load()

	brokerAB, err := newDemoEdgeBroker("A", "B")
	if err != nil {
		return result{}, err
	}
	defer brokerAB.Close()
	brokerBC, err := newDemoEdgeBroker("B", "C")
	if err != nil {
		return result{}, err
	}
	defer brokerBC.Close()
	factory := func(spec shortcut.AttemptSpec) (solver.Strategy, error) {
		var broker *demoEdgeBroker
		switch {
		case sameNodePair(spec.LocalNodeID, spec.RemoteNodeID, "A", "B"):
			broker = brokerAB
		case sameNodePair(spec.LocalNodeID, spec.RemoteNodeID, "B", "C"):
			broker = brokerBC
		default:
			return nil, fmt.Errorf("no demo direct edge for %s-%s", spec.LocalNodeID, spec.RemoteNodeID)
		}
		return newDemoEdgeStrategy(spec, broker), nil
	}
	managerConfig := func(node *mesh.Node) shortcut.Config {
		return shortcut.Config{
			Node: node, StrategyName: demoEdgeStrategyName, StrategyFactory: factory,
			Probation: 400 * time.Millisecond, SolveTimeout: 2 * time.Second,
			PacketNeighbor: mesh.PacketNeighborConfig{
				KeepAliveInterval: 25 * time.Millisecond, PeerTimeout: 250 * time.Millisecond,
				ReadPollInterval: 25 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
			},
		}
	}
	managerA, err := shortcut.NewManager(managerConfig(nodeA))
	if err != nil {
		return result{}, err
	}
	defer managerA.Close()
	managerB, err := shortcut.NewManager(managerConfig(nodeB))
	if err != nil {
		return result{}, err
	}
	defer managerB.Close()
	managerC, err := shortcut.NewManager(managerConfig(nodeC))
	if err != nil {
		return result{}, err
	}
	defer managerC.Close()
	managers := []*shortcut.Manager{managerA, managerB, managerC}

	// C is a normal peer, not infrastructure: it coordinates A and B because it
	// is the only node currently adjacent to both.
	firstHandle, err := managerA.Start(ctx, "B", "C")
	if err != nil {
		return result{}, fmt.Errorf("start C-coordinated A-B shortcut: %w", err)
	}
	if _, err := firstHandle.WaitFor(ctx, shortcut.PhaseStable); err != nil {
		return result{}, fmt.Errorf("wait for C-coordinated A-B shortcut: %w", err)
	}
	if err := waitForShortcutEverywhere(ctx, managers, firstHandle.ID()); err != nil {
		return result{}, fmt.Errorf("wait for A-B shortcut consensus: %w", err)
	}
	var firstDirectRoute mesh.Route
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeA.Route("B")
		reverse, reverseOK := nodeB.Route("A")
		if forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "B"}) &&
			slices.Equal(reverse.Path, []string{"B", "A"}) {
			firstDirectRoute = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for direct A-B route: %w", err)
	}
	if _, err := packetEcho(ctx, packetAB, packetBA, append([]byte("DIRECT-A-B:"), payload...)); err != nil {
		return result{}, fmt.Errorf("direct A-B packet echo: %w", err)
	}
	time.Sleep(25 * time.Millisecond)
	firstBypassedC := dataForwardedByC.Load() == afterBootstrapC
	if !firstBypassedC || solverSignalsByC.Load() < 2 {
		return result{}, fmt.Errorf(
			"A-B shortcut acceptance failed: bypass_c=%t solver_signals_by_c=%d",
			firstBypassedC, solverSignalsByC.Load(),
		)
	}

	// Only after A-B is stable do we remove the temporary natpierce-shaped edge.
	// B remains connected to C through A, so this transition has no graph cut.
	if err := nodeB.RemoveNeighbor("C"); err != nil {
		return result{}, fmt.Errorf("detach temporary B-C edge: %w", err)
	}
	var replacementRoute mesh.Route
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeB.Route("C")
		reverse, reverseOK := nodeC.Route("B")
		if !nodeB.HasNeighbor("C") && !nodeC.HasNeighbor("B") && forwardOK && reverseOK &&
			slices.Equal(forward.Path, []string{"B", "A", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "A", "B"}) {
			replacementRoute = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for B-A-C replacement route: %w", err)
	}
	beforeReplacementA := dataForwardedByA.Load()
	if _, err := packetEcho(ctx, packetBC, packetCB, append([]byte("REPLACEMENT:"), payload...)); err != nil {
		return result{}, fmt.Errorf("replacement B-A-C packet echo: %w", err)
	}
	if err := waitFor(ctx, func() bool { return dataForwardedByA.Load() >= beforeReplacementA+2 }); err != nil {
		return result{}, fmt.Errorf("wait for A replacement forwarding (before=%d now=%d): %w", beforeReplacementA, dataForwardedByA.Load(), err)
	}
	afterReplacementA := dataForwardedByA.Load()

	// The newly created A-B edge now lets A coordinate a native B-C edge.
	secondHandle, err := managerB.Start(ctx, "C", "A")
	if err != nil {
		return result{}, fmt.Errorf("start A-coordinated B-C shortcut: %w", err)
	}
	if _, err := secondHandle.WaitFor(ctx, shortcut.PhaseStable); err != nil {
		return result{}, fmt.Errorf("wait for A-coordinated B-C shortcut: %w", err)
	}
	if err := waitForShortcutEverywhere(ctx, managers, secondHandle.ID()); err != nil {
		return result{}, fmt.Errorf("wait for B-C shortcut consensus: %w", err)
	}
	var secondDirectRoute mesh.Route
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeB.Route("C")
		reverse, reverseOK := nodeC.Route("B")
		if forwardOK && reverseOK && slices.Equal(forward.Path, []string{"B", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "B"}) {
			secondDirectRoute = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for direct B-C route: %w", err)
	}
	if _, err := packetEcho(ctx, packetBC, packetCB, append([]byte("DIRECT-B-C:"), payload...)); err != nil {
		return result{}, fmt.Errorf("direct B-C packet echo: %w", err)
	}
	time.Sleep(25 * time.Millisecond)
	secondBypassedA := dataForwardedByA.Load() == afterReplacementA
	allEdgesDirect := nodeA.HasNeighbor("B") && nodeB.HasNeighbor("A") &&
		nodeA.HasNeighbor("C") && nodeC.HasNeighbor("A") &&
		nodeB.HasNeighbor("C") && nodeC.HasNeighbor("B")
	if !secondBypassedA || solverSignalsByA.Load() < 2 || !allEdgesDirect {
		return result{}, fmt.Errorf(
			"B-C shortcut acceptance failed: bypass_a=%t solver_signals_by_a=%d all_direct=%t",
			secondBypassedA, solverSignalsByA.Load(), allEdgesDirect,
		)
	}

	return result{
		CoordinatorStarted: false,
		Mode:               "rejoin",
		Transport:          "existing-stream+temporary-stream+two-udp-shortcuts",
		Payload:            string(payload),
		AutoDiscovered:     true,
		RejoinedNode:       "B",
		BootstrapRoute:     append([]string(nil), bootstrapRoute.Path...),
		FirstCoordinator:   "C",
		FirstDirectRoute:   append([]string(nil), firstDirectRoute.Path...),
		ReplacementRoute:   append([]string(nil), replacementRoute.Path...),
		SecondCoordinator:  "A",
		SecondDirectRoute:  append([]string(nil), secondDirectRoute.Path...),
		TemporaryDetached:  true,
		AllEdgesDirect:     allEdgesDirect,
		DataBypassVerified: firstBypassedC && secondBypassedA,
	}, nil
}

func waitForShortcutEverywhere(ctx context.Context, managers []*shortcut.Manager, attemptID string) error {
	return waitFor(ctx, func() bool {
		for _, manager := range managers {
			status, ok := manager.Status(attemptID)
			if !ok || status.Phase != shortcut.PhaseStable {
				return false
			}
		}
		return true
	})
}

func sameNodePair(left, right, wantLeft, wantRight string) bool {
	return (left == wantLeft && right == wantRight) || (left == wantRight && right == wantLeft)
}

func runData(ctx context.Context, payload []byte) (result, error) {
	var forwardedByB atomic.Int32
	nodeA, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "A", VirtualIP: "fd00::a", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
	})
	if err != nil {
		return result{}, err
	}
	defer nodeA.Close()
	nodeB, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "B", VirtualIP: "fd00::b", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind == mesh.EventForwarded {
				forwardedByB.Add(1)
			}
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeB.Close()
	nodeC, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "C", VirtualIP: "fd00::c", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
	})
	if err != nil {
		return result{}, err
	}
	defer nodeC.Close()

	if err := attachDualTCPPair(nodeA, "B", nodeB, "A"); err != nil {
		return result{}, fmt.Errorf("attach dual-stream A-B: %w", err)
	}
	if err := attachDualTCPPair(nodeB, "C", nodeC, "B"); err != nil {
		return result{}, fmt.Errorf("attach dual-stream B-C: %w", err)
	}
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			return result{}, fmt.Errorf("start mesh node: %w", err)
		}
	}

	var learned mesh.Route
	if err := waitFor(ctx, func() bool {
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		if forwardOK && reverseOK &&
			slices.Equal(forward.Path, []string{"A", "B", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "B", "A"}) {
			learned = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for reciprocal A-C routes: %w", err)
	}

	endpointA, err := routed.NewEndpoint(nodeA)
	if err != nil {
		return result{}, err
	}
	defer endpointA.Close()
	endpointC, err := routed.NewEndpoint(nodeC)
	if err != nil {
		return result{}, err
	}
	defer endpointC.Close()
	packetA, err := endpointA.NewPacketTransport("C", "mesh/A-B-C")
	if err != nil {
		return result{}, err
	}
	defer packetA.Close()
	packetC, err := endpointC.NewPacketTransport("A", "mesh/C-B-A")
	if err != nil {
		return result{}, err
	}
	defer packetC.Close()

	packetRequest := append([]byte("PING:"), payload...)
	packetEcho := make(chan error, 1)
	go func() {
		buffer := make([]byte, mesh.MaxDataPayloadSize)
		n, _, readErr := packetC.ReadPacket(ctx, buffer)
		if readErr != nil {
			packetEcho <- readErr
			return
		}
		packetEcho <- packetC.WritePacket(ctx, append([]byte("PONG:"), buffer[:n]...))
	}()
	if err := packetA.WritePacket(ctx, packetRequest); err != nil {
		return result{}, fmt.Errorf("send overlay ping: %w", err)
	}
	packetBuffer := make([]byte, mesh.MaxDataPayloadSize)
	packetLength, _, err := packetA.ReadPacket(ctx, packetBuffer)
	if err != nil {
		return result{}, fmt.Errorf("read overlay pong: %w", err)
	}
	if err := <-packetEcho; err != nil {
		return result{}, fmt.Errorf("reply to overlay ping: %w", err)
	}
	overlayReply := append([]byte(nil), packetBuffer[:packetLength]...)
	wantOverlayReply := append([]byte("PONG:"), packetRequest...)
	if !bytes.Equal(overlayReply, wantOverlayReply) {
		return result{}, fmt.Errorf("overlay reply mismatch: got %q want %q", overlayReply, wantOverlayReply)
	}

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return result{}, fmt.Errorf("listen fixed TCP target: %w", err)
	}
	defer targetListener.Close()
	targetReceived := make(chan []byte, 1)
	targetErrors := make(chan error, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			targetErrors <- acceptErr
			return
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		received, readErr := io.ReadAll(conn)
		if readErr != nil {
			targetErrors <- readErr
			return
		}
		targetReceived <- append([]byte(nil), received...)
		if writeErr := writeBytes(conn, append([]byte("TCP-ECHO:"), received...)); writeErr != nil {
			targetErrors <- writeErr
			return
		}
		if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
			targetErrors <- closeWriter.CloseWrite()
			return
		}
		targetErrors <- fmt.Errorf("fixed target does not support TCP half-close")
	}()

	forwarderA, err := routed.NewTCPForwarder(endpointA, "")
	if err != nil {
		return result{}, err
	}
	defer forwarderA.Close()
	forwarderC, err := routed.NewTCPForwarder(endpointC, targetListener.Addr().String())
	if err != nil {
		return result{}, err
	}
	defer forwarderC.Close()
	localListener, err := forwarderA.StartListener(ctx, "127.0.0.1:0", "C")
	if err != nil {
		return result{}, err
	}
	defer localListener.Close()

	localConn, err := net.DialTimeout("tcp", localListener.Addr().String(), 2*time.Second)
	if err != nil {
		return result{}, fmt.Errorf("dial local TCP forwarder: %w", err)
	}
	tcpConn, ok := localConn.(*net.TCPConn)
	if !ok {
		_ = localConn.Close()
		return result{}, fmt.Errorf("local forward connection is not TCP")
	}
	defer tcpConn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tcpConn.SetDeadline(deadline)
	}
	tcpRequest := append([]byte("TCP:"), payload...)
	if err := writeBytes(tcpConn, tcpRequest); err != nil {
		return result{}, fmt.Errorf("write local TCP request: %w", err)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		return result{}, fmt.Errorf("half-close local TCP request: %w", err)
	}
	tcpReply, err := io.ReadAll(tcpConn)
	if err != nil {
		return result{}, fmt.Errorf("read local TCP reply: %w", err)
	}
	wantTCPReply := append([]byte("TCP-ECHO:"), tcpRequest...)
	if !bytes.Equal(tcpReply, wantTCPReply) {
		return result{}, fmt.Errorf("TCP reply mismatch: got %q want %q", tcpReply, wantTCPReply)
	}
	select {
	case received := <-targetReceived:
		if !bytes.Equal(received, tcpRequest) {
			return result{}, fmt.Errorf("fixed target received %q, want %q", received, tcpRequest)
		}
	case err := <-targetErrors:
		return result{}, fmt.Errorf("fixed target: %w", err)
	case <-ctx.Done():
		return result{}, ctx.Err()
	}
	select {
	case err := <-targetErrors:
		if err != nil {
			return result{}, fmt.Errorf("fixed target half-close: %w", err)
		}
	case <-ctx.Done():
		return result{}, ctx.Err()
	}

	if err := waitFor(ctx, func() bool { return forwardedByB.Load() >= 8 }); err != nil {
		return result{}, fmt.Errorf("wait for B data forwarding events: %w", err)
	}
	if err := nodeB.RemoveNeighbor("C"); err != nil {
		return result{}, fmt.Errorf("remove B-C edge: %w", err)
	}
	memberRetained := false
	if err := waitFor(ctx, func() bool {
		_, routeOK := nodeA.Route("C")
		_, memberRetained = nodeA.Member("C")
		if routeOK || !memberRetained {
			return false
		}
		return errors.Is(packetA.WritePacket(ctx, []byte("after-withdraw")), mesh.ErrNoRoute)
	}); err != nil {
		return result{}, fmt.Errorf("wait for data route withdrawal: %w", err)
	}

	return result{
		CoordinatorStarted: false,
		Mode:               "data",
		Transport:          "dual-real-loopback-tcp",
		Payload:            string(payload),
		AutoDiscovered:     true,
		LearnedRoute:       append([]string(nil), learned.Path...),
		RouteWithdrawn:     true,
		MemberRetained:     memberRetained,
		OverlayReply:       string(overlayReply),
		TCPReply:           string(tcpReply),
		DataForwardedByB:   forwardedByB.Load(),
		DataChannelSplit:   true,
		TCPHalfClose:       true,
	}, nil
}

func runStatic(ctx context.Context, payload []byte) (result, error) {
	const echoID = "slice1-static-routed-echo"
	replies := make(chan peercontrol.Message, 1)
	var forwardedByB atomic.Int32

	var nodeC *mesh.Router
	nodeA, err := mesh.NewRouter(mesh.Config{
		NodeID: "A",
		OnMessage: func(_ context.Context, msg peercontrol.Message) error {
			select {
			case replies <- msg:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeA.Close()
	nodeB, err := mesh.NewRouter(mesh.Config{
		NodeID: "B",
		OnEvent: func(event mesh.Event) {
			if event.Kind == mesh.EventForwarded {
				forwardedByB.Add(1)
			}
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeB.Close()
	nodeC, err = mesh.NewRouter(mesh.Config{
		NodeID: "C",
		OnMessage: func(messageCtx context.Context, msg peercontrol.Message) error {
			if msg.Type != peercontrol.TypeControlEchoRequest || msg.ControlEcho == nil {
				return fmt.Errorf("C received unexpected message %q", msg.Type)
			}
			reply := peercontrol.NewControlEchoReply(
				"C",
				msg.From,
				msg.ControlEcho.ID,
				msg.ControlEcho.Payload,
				msg.PathVector,
				8,
			)
			return nodeC.Send(messageCtx, reply)
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeC.Close()

	if err := attachTCPPair(nodeA, "B", nodeB, "A"); err != nil {
		return result{}, fmt.Errorf("attach A-B: %w", err)
	}
	if err := attachTCPPair(nodeB, "C", nodeC, "B"); err != nil {
		return result{}, fmt.Errorf("attach B-C: %w", err)
	}
	if err := nodeA.SetRoute("C", "B"); err != nil {
		return result{}, err
	}
	if err := nodeC.SetRoute("A", "B"); err != nil {
		return result{}, err
	}

	request := peercontrol.NewControlEchoRequest("A", "C", echoID, payload, 8)
	if err := nodeA.Send(ctx, request); err != nil {
		return result{}, err
	}
	select {
	case reply := <-replies:
		if reply.Type != peercontrol.TypeControlEchoReply || reply.ControlEcho == nil {
			return result{}, fmt.Errorf("A received unexpected message %q", reply.Type)
		}
		return result{
			CoordinatorStarted: false,
			Mode:               "static",
			Transport:          "real-loopback-tcp",
			EchoID:             reply.ControlEcho.ID,
			Payload:            string(reply.ControlEcho.Payload),
			RequestPath:        append([]string(nil), reply.ControlEcho.RequestPath...),
			ReplyPath:          append([]string(nil), reply.PathVector...),
			ForwardedByB:       forwardedByB.Load(),
		}, nil
	case <-ctx.Done():
		return result{}, ctx.Err()
	}
}

func runDynamic(ctx context.Context, payload []byte) (result, error) {
	const echoID = "slice2-autonomous-topology-echo"
	replies := make(chan peercontrol.Message, 1)
	var forwardedByB atomic.Int32

	var nodeC *mesh.Node
	nodeA, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "A", VirtualIP: "fd00::a", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnMessage: func(_ context.Context, msg peercontrol.Message) error {
			select {
			case replies <- msg:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeA.Close()
	nodeB, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: "B", VirtualIP: "fd00::b", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnEvent: func(event mesh.Event) {
			if event.Kind == mesh.EventForwarded &&
				(event.Message.Type == peercontrol.TypeControlEchoRequest || event.Message.Type == peercontrol.TypeControlEchoReply) {
				forwardedByB.Add(1)
			}
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeB.Close()
	nodeC, err = mesh.NewNode(mesh.NodeConfig{
		NodeID: "C", VirtualIP: "fd00::c", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnMessage: func(messageCtx context.Context, msg peercontrol.Message) error {
			if msg.Type != peercontrol.TypeControlEchoRequest || msg.ControlEcho == nil {
				return nil
			}
			reply := peercontrol.NewControlEchoReply(
				"C", msg.From, msg.ControlEcho.ID, msg.ControlEcho.Payload, msg.PathVector, 8,
			)
			return nodeC.Send(messageCtx, reply)
		},
	})
	if err != nil {
		return result{}, err
	}
	defer nodeC.Close()

	if err := attachTCPPair(nodeA, "B", nodeB, "A"); err != nil {
		return result{}, fmt.Errorf("attach A-B: %w", err)
	}
	if err := attachTCPPair(nodeB, "C", nodeC, "B"); err != nil {
		return result{}, fmt.Errorf("attach B-C: %w", err)
	}
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			return result{}, fmt.Errorf("start mesh node: %w", err)
		}
	}

	var learned mesh.Route
	if err := waitFor(ctx, func() bool {
		member, memberOK := nodeA.Member("C")
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		if memberOK && member.VirtualIP == "fd00::c" && forwardOK && reverseOK &&
			forward.NextHop == "B" && slices.Equal(reverse.Path, []string{"C", "B", "A"}) {
			learned = forward
			return true
		}
		return false
	}); err != nil {
		return result{}, fmt.Errorf("wait for autonomous A-C route: %w", err)
	}
	request := peercontrol.NewControlEchoRequest("A", "C", echoID, payload, 8)
	if err := nodeA.Send(ctx, request); err != nil {
		return result{}, err
	}

	var reply peercontrol.Message
	select {
	case reply = <-replies:
	case <-ctx.Done():
		return result{}, ctx.Err()
	}
	if reply.Type != peercontrol.TypeControlEchoReply || reply.ControlEcho == nil {
		return result{}, fmt.Errorf("A received unexpected message %q", reply.Type)
	}
	if err := nodeB.RemoveNeighbor("C"); err != nil {
		return result{}, fmt.Errorf("remove B-C edge: %w", err)
	}
	memberRetained := false
	if err := waitFor(ctx, func() bool {
		_, routeOK := nodeA.Route("C")
		_, memberRetained = nodeA.Member("C")
		if routeOK || !memberRetained {
			return false
		}
		probe := peercontrol.NewControlEchoRequest("A", "C", "after-close", nil, 8)
		return errors.Is(nodeA.Send(ctx, probe), mesh.ErrNoRoute)
	}); err != nil {
		return result{}, fmt.Errorf("wait for A-C route withdrawal: %w", err)
	}

	return result{
		CoordinatorStarted: false,
		Mode:               "dynamic",
		Transport:          "real-loopback-tcp",
		EchoID:             reply.ControlEcho.ID,
		Payload:            string(reply.ControlEcho.Payload),
		RequestPath:        append([]string(nil), reply.ControlEcho.RequestPath...),
		ReplyPath:          append([]string(nil), reply.PathVector...),
		ForwardedByB:       forwardedByB.Load(),
		AutoDiscovered:     true,
		LearnedRoute:       append([]string(nil), learned.Path...),
		RouteWithdrawn:     true,
		MemberRetained:     memberRetained,
	}, nil
}

func waitFor(ctx context.Context, condition func() bool) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

const demoEdgeStrategyName = "demo_protected_direct"

type demoEdgeStrategy struct {
	spec     shortcut.AttemptSpec
	broker   *demoEdgeBroker
	remoteCh chan struct{}
}

func newDemoEdgeStrategy(spec shortcut.AttemptSpec, broker *demoEdgeBroker) *demoEdgeStrategy {
	return &demoEdgeStrategy{spec: spec, broker: broker, remoteCh: make(chan struct{}, 1)}
}

func (s *demoEdgeStrategy) Name() string { return demoEdgeStrategyName }

func (s *demoEdgeStrategy) Plan(_ context.Context, _ solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "demo/direct", Strategy: demoEdgeStrategyName}}, nil
}

func (s *demoEdgeStrategy) Execute(ctx context.Context, session solver.SessionIO, _ solver.Plan) (solver.Result, error) {
	if err := session.Send(ctx, solver.Message{
		Kind: solver.MessageKindStrategy, Namespace: demoEdgeStrategyName, Type: "endpoint_ready",
		Payload: []byte(s.spec.LocalNodeID), ReceivedAt: time.Now().UTC(),
	}); err != nil {
		return solver.Result{}, err
	}
	select {
	case <-ctx.Done():
		return solver.Result{}, ctx.Err()
	case <-s.remoteCh:
	}
	packetTransport, err := s.broker.take(s.spec.LocalNodeID)
	if err != nil {
		return solver.Result{}, err
	}
	return solver.Result{
		Transport: packetTransport,
		Summary: solver.PathSummary{
			PathID: "demo/direct", ConnectionType: "direct", RemoteAddr: packetTransport.RemoteAddr(),
			Role:    solver.PathRoleProtectedDirect,
			Metrics: map[string]string{"solver": demoEdgeStrategyName, "underlay": "loopback_udp"},
		},
	}, nil
}

func (s *demoEdgeStrategy) HandleMessage(_ context.Context, _ solver.SessionIO, message solver.Message) error {
	if message.Namespace == demoEdgeStrategyName && message.Type == "endpoint_ready" {
		select {
		case s.remoteCh <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *demoEdgeStrategy) Close() error { return nil }

type demoEdgeBroker struct {
	mu    sync.Mutex
	conns map[string]*net.UDPConn
	peers map[string]*net.UDPAddr
	taken map[string]bool
}

func newDemoEdgeBroker(leftID, rightID string) (*demoEdgeBroker, error) {
	leftID = strings.TrimSpace(leftID)
	rightID = strings.TrimSpace(rightID)
	if leftID == "" || rightID == "" || leftID == rightID {
		return nil, fmt.Errorf("demo edge requires two distinct node IDs")
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
	return &demoEdgeBroker{
		conns: map[string]*net.UDPConn{leftID: left, rightID: right},
		peers: map[string]*net.UDPAddr{
			leftID:  copyUDPAddr(right.LocalAddr().(*net.UDPAddr)),
			rightID: copyUDPAddr(left.LocalAddr().(*net.UDPAddr)),
		},
		taken: make(map[string]bool),
	}, nil
}

func (b *demoEdgeBroker) take(nodeID string) (transport.PacketTransport, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	conn := b.conns[nodeID]
	peer := b.peers[nodeID]
	if conn == nil || peer == nil || b.taken[nodeID] {
		return nil, fmt.Errorf("demo edge transport for %s is unavailable", nodeID)
	}
	b.taken[nodeID] = true
	result := &puncher.Result{
		Conn: conn, LocalAddr: copyUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
		RemoteAddr: copyUDPAddr(peer), Method: "demo",
	}
	return iceadapter.New(result.Connected(), "demo/direct"), nil
}

func (b *demoEdgeBroker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var closeErr error
	for _, conn := range b.conns {
		if conn != nil {
			closeErr = errors.Join(closeErr, conn.Close())
		}
	}
	return closeErr
}

func copyUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func packetEcho(
	ctx context.Context,
	left *routed.PacketTransport,
	right *routed.PacketTransport,
	payload []byte,
) ([]byte, error) {
	echoResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, mesh.MaxDataPayloadSize)
		n, _, err := right.ReadPacket(ctx, buffer)
		if err == nil {
			err = right.WritePacket(ctx, append([]byte("ECHO:"), buffer[:n]...))
		}
		echoResult <- err
	}()
	if err := left.WritePacket(ctx, payload); err != nil {
		return nil, err
	}
	buffer := make([]byte, mesh.MaxDataPayloadSize)
	n, _, err := left.ReadPacket(ctx, buffer)
	if err != nil {
		return nil, err
	}
	if err := <-echoResult; err != nil {
		return nil, err
	}
	return append([]byte(nil), buffer[:n]...), nil
}

var _ solver.Strategy = (*demoEdgeStrategy)(nil)
var _ solver.MessageHandler = (*demoEdgeStrategy)(nil)

type streamAttacher interface {
	AttachStream(string, net.Conn) error
}

type dualStreamAttacher interface {
	AttachStreams(string, net.Conn, net.Conn) error
}

func attachTCPPair(left streamAttacher, leftPeer string, right streamAttacher, rightPeer string) error {
	leftConn, rightConn, err := openTCPPair()
	if err != nil {
		return err
	}
	if err := left.AttachStream(leftPeer, leftConn); err != nil {
		_ = rightConn.Close()
		return err
	}
	if err := right.AttachStream(rightPeer, rightConn); err != nil {
		return err
	}
	return nil
}

func attachDualTCPPair(left dualStreamAttacher, leftPeer string, right dualStreamAttacher, rightPeer string) error {
	leftControl, rightControl, err := openTCPPair()
	if err != nil {
		return err
	}
	leftData, rightData, err := openTCPPair()
	if err != nil {
		_ = leftControl.Close()
		_ = rightControl.Close()
		return err
	}
	if err := left.AttachStreams(leftPeer, leftControl, leftData); err != nil {
		_ = rightControl.Close()
		_ = rightData.Close()
		return err
	}
	if err := right.AttachStreams(rightPeer, rightControl, rightData); err != nil {
		return err
	}
	return nil
}

func openTCPPair() (net.Conn, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()
	leftConn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		return nil, nil, err
	}
	acceptedConn := <-accepted
	if acceptedConn.err != nil {
		_ = leftConn.Close()
		return nil, nil, acceptedConn.err
	}
	return leftConn, acceptedConn.conn, nil
}

func writeBytes(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}
