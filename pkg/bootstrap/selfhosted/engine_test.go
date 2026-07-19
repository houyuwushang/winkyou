package selfhosted

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/recoverycard"
)

func TestEnginesRecoverDirectEdgeWithoutRouteOrCoordinator(t *testing.T) {
	portA := reserveUDPPort(t)
	portB := reserveUDPPort(t)
	stalePortB := reserveDistinctUDPPort(t, portA, portB)
	now := time.Now().UTC().Add(-time.Minute)
	storeA := saveEngineCard(t, "A", portA, recoverycard.Peer{
		NodeID: "B", LastSuccessfulLocalBindPort: uint16(portA), LastSuccessAt: now,
		Endpoints: []recoverycard.Endpoint{engineEndpoint(stalePortB, now)},
	})
	storeB := saveEngineCard(t, "B", portB, recoverycard.Peer{
		NodeID: "A", LastSuccessfulLocalBindPort: uint16(portB), LastSuccessAt: now,
		Endpoints: []recoverycard.Endpoint{engineEndpoint(portA, now)},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	nodeA := startEngineNode(t, ctx, "A")
	nodeB := startEngineNode(t, ctx, "B")
	engineA := startTestEngine(t, ctx, nodeA, storeA, "B")
	engineB := startTestEngine(t, ctx, nodeB, storeB, "A")
	defer engineA.Close()
	defer engineB.Close()

	eventuallyEngine(t, ctx, func() bool {
		return nodeA.HasNeighbor("B") && nodeB.HasNeighbor("A")
	}, "self-bootstrap engines did not attach a direct edge")
	eventuallyEngine(t, ctx, func() bool {
		forward, forwardOK := nodeA.Route("B")
		reverse, reverseOK := nodeB.Route("A")
		return forwardOK && reverseOK && slices.Equal(forward.Path, []string{"A", "B"}) &&
			slices.Equal(reverse.Path, []string{"B", "A"})
	}, "self-bootstrap direct routes did not converge")

	// Keep the edge alive beyond one peer timeout. This proves ownership moved
	// from punch/HELLO to PacketNeighborSession on both endpoints.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(500 * time.Millisecond):
	}
	if !nodeA.HasNeighbor("B") || !nodeB.HasNeighbor("A") {
		t.Fatal("self-bootstrap edge did not survive packet-neighbor liveness")
	}

	cardA, err := storeA.Load()
	if err != nil {
		t.Fatal(err)
	}
	peerA := findEnginePeer(t, cardA, "B")
	if peerA.Endpoints[0].AddrPort != net.JoinHostPort("127.0.0.1", itoaPort(portB)) {
		t.Fatalf("A newest learned B endpoint = %q, want actual port %d; history=%+v", peerA.Endpoints[0].AddrPort, portB, peerA.Endpoints)
	}
	if len(peerA.Endpoints) < 2 {
		t.Fatalf("A discarded stale endpoint instead of retaining bounded history: %+v", peerA.Endpoints)
	}
	if peerA.LastSuccessfulLocalBindPort != uint16(portA) {
		t.Fatalf("A local bind port = %d, want %d", peerA.LastSuccessfulLocalBindPort, portA)
	}
}

func TestEngineWaitsForHintWithoutCreatingFalseNeighbor(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "missing-card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	node := startEngineNode(t, ctx, "A")
	engine := startTestEngine(t, ctx, node, store, "B")
	defer engine.Close()
	eventuallyEngine(t, ctx, func() bool {
		status := engine.Snapshot()
		return len(status) == 1 && status[0].State == StateWaitingHint && status[0].LastError == ErrNoCandidate.Error()
	}, "engine did not expose waiting-hint state")
	if node.HasNeighbor("B") {
		t.Fatal("engine invented a neighbor without a recovery hint")
	}
}

func TestObservationRejectsUnconfiguredPeerAndPersistsConfiguredPeer(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	engine := newObservationEngine(t, store)
	defer engine.Close()
	now := time.Now().UTC()
	observation := Observation{
		PeerID: "C", RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 45000},
		LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 42000}, At: now,
	}
	if err := engine.Observe(observation); err == nil {
		t.Fatal("observation for an unconfigured peer was accepted")
	}
	observation.PeerID = "B"
	observation.Source = "shortcut"
	if err := engine.Observe(observation); err != nil {
		t.Fatal(err)
	}
	card, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	peer := findEnginePeer(t, card, "B")
	if peer.Endpoints[0].AddrPort != "203.0.113.8:45000" || peer.Endpoints[0].Source != "shortcut" {
		t.Fatalf("persisted observation = %+v", peer.Endpoints[0])
	}
}

func TestAttemptWindowIsPairDeterministic(t *testing.T) {
	left, _ := pairKey("A", "B", []byte("secret"))
	right, _ := pairKey("B", "A", []byte("secret"))
	now := time.Unix(1_800_000_000, 123456789)
	leftStart, leftEnd, leftActive := attemptWindow(left, now, time.Minute, 45*time.Second)
	rightStart, rightEnd, rightActive := attemptWindow(right, now, time.Minute, 45*time.Second)
	if !leftStart.Equal(rightStart) || !leftEnd.Equal(rightEnd) || leftActive != rightActive {
		t.Fatalf("pair windows differ: left=%s..%s/%t right=%s..%s/%t", leftStart, leftEnd, leftActive, rightStart, rightEnd, rightActive)
	}
}

func TestConfigAcceptsSingleBirthdayPortAndRejectsReversedRange(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if _, err := New(Config{
		Node: node, Store: store, PeerIDs: []string{"B"},
		BirthdayLo: 45000, BirthdayHi: 45000,
	}); err != nil {
		t.Fatalf("single-port birthday range rejected: %v", err)
	}
	if _, err := New(Config{
		Node: node, Store: store, PeerIDs: []string{"B"},
		BirthdayLo: 50000, BirthdayHi: 45000,
	}); err == nil {
		t.Fatal("reversed birthday range was accepted")
	}
}

func TestNormalizeNATModelClearsNonFiniteConfidence(t *testing.T) {
	at := time.Now().UTC()
	for _, confidence := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		model := normalizeNATModel(recoverycard.NATModel{
			Pattern: recoverycard.PortPatternUnknown, Confidence: confidence, ObservedAt: at,
		}, at)
		if model.Confidence != 0 {
			t.Fatalf("normalized confidence = %v, want 0", model.Confidence)
		}
	}
}

func TestObservationDoesNotOverwriteNewerPeerEvidence(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	engine := newObservationEngine(t, store)
	defer engine.Close()
	newer := time.Now().UTC()
	remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 45000}
	if err := engine.Observe(Observation{
		PeerID: "B", RemoteAddr: remote,
		LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 42001},
		Source:    "newer", RemoteNAT: recoverycard.NATModel{
			Pattern: recoverycard.PortPatternSequential, Delta: 2, Confidence: 0.9, ObservedAt: newer,
		}, At: newer,
	}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Observe(Observation{
		PeerID: "B", RemoteAddr: remote,
		LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 42000},
		Source:    "older", RemoteNAT: recoverycard.NATModel{
			Pattern: recoverycard.PortPatternRandom, Confidence: 0.1, ObservedAt: newer.Add(-time.Minute),
		}, At: newer.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	card, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	peer := findEnginePeer(t, card, "B")
	if peer.LastSuccessfulLocalBindPort != 42001 {
		t.Fatalf("latest local bind = %d, want 42001", peer.LastSuccessfulLocalBindPort)
	}
	if endpoint := peer.Endpoints[0]; endpoint.Source != "newer" || endpoint.NAT.Pattern != recoverycard.PortPatternSequential || endpoint.NAT.Delta != 2 {
		t.Fatalf("newer endpoint evidence was overwritten: %+v", endpoint)
	}
}

func TestObservationEvictsOldBindHistoryInsteadOfFailing(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	engine := newObservationEngine(t, store)
	defer engine.Close()
	base := time.Now().UTC().Add(-time.Minute)
	for i := 0; i <= recoverycard.MaxLocalBindPorts; i++ {
		at := base.Add(time.Duration(i) * time.Millisecond)
		if err := engine.Observe(Observation{
			PeerID:     "B",
			RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 45000},
			LocalAddr:  &net.UDPAddr{IP: net.IPv4zero, Port: 10000 + i},
			Source:     "rotation", At: at,
		}); err != nil {
			t.Fatalf("observation %d: %v", i, err)
		}
	}
	card, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(card.LocalBindPorts) != recoverycard.MaxLocalBindPorts {
		t.Fatalf("bind history length = %d, want %d", len(card.LocalBindPorts), recoverycard.MaxLocalBindPorts)
	}
	latest := uint16(10000 + recoverycard.MaxLocalBindPorts)
	if !containsPort(card.LocalBindPorts, latest) || containsPort(card.LocalBindPorts, 10000) {
		t.Fatalf("bind history did not evict oldest/add newest: %v", card.LocalBindPorts)
	}
	if peer := findEnginePeer(t, card, "B"); peer.LastSuccessfulLocalBindPort != latest {
		t.Fatalf("latest peer bind = %d, want %d", peer.LastSuccessfulLocalBindPort, latest)
	}
}

func TestObservationPrunesOldestPeerWhenBindSchemaIsSaturated(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	peerIDs := make([]string, 0, recoverycard.MaxLocalBindPorts+1)
	for i := 0; i <= recoverycard.MaxLocalBindPorts; i++ {
		peerIDs = append(peerIDs, fmt.Sprintf("P%03d", i))
	}
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	engine, err := New(Config{Node: node, Store: store, PeerIDs: peerIDs})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	base := time.Now().UTC().Add(-time.Minute)
	for i, peerID := range peerIDs {
		if err := engine.Observe(Observation{
			PeerID: peerID,
			RemoteAddr: &net.UDPAddr{
				IP: net.IPv4(203, 0, 113, byte(i+1)), Port: 45000 + i,
			},
			LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 11000 + i},
			Source:    "peer_rotation", At: base.Add(time.Duration(i) * time.Millisecond),
		}); err != nil {
			t.Fatalf("observe %s: %v", peerID, err)
		}
	}
	card, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(card.Peers) != recoverycard.MaxLocalBindPorts || len(card.LocalBindPorts) != recoverycard.MaxLocalBindPorts {
		t.Fatalf("bounded card sizes = peers %d, ports %d; want %d each", len(card.Peers), len(card.LocalBindPorts), recoverycard.MaxLocalBindPorts)
	}
	if indexOfPeer(card.Peers, peerIDs[0]) >= 0 {
		t.Fatalf("oldest peer %s was retained after schema saturation", peerIDs[0])
	}
	if indexOfPeer(card.Peers, peerIDs[len(peerIDs)-1]) < 0 {
		t.Fatalf("newest peer %s was not retained after schema saturation", peerIDs[len(peerIDs)-1])
	}
	if containsPort(card.LocalBindPorts, 11000) || !containsPort(card.LocalBindPorts, uint16(11000+recoverycard.MaxLocalBindPorts)) {
		t.Fatalf("bind ports did not follow peer eviction: %v", card.LocalBindPorts)
	}
}

func TestEngineStartCloseRaceIsLifecycleSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	node := startEngineNode(t, ctx, "A")
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		engine, err := New(Config{Node: node, Store: store, PeerIDs: []string{"B"}})
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		startResult := make(chan error, 1)
		var closeDone sync.WaitGroup
		closeDone.Add(1)
		go func() {
			defer closeDone.Done()
			<-start
			engine.Close()
		}()
		go func() {
			<-start
			startResult <- engine.Start(ctx)
		}()
		close(start)
		startErr := <-startResult
		closeDone.Wait()
		engine.Close()
		if startErr != nil && !errors.Is(startErr, mesh.ErrClosed) {
			t.Fatalf("iteration %d Start error = %v", i, startErr)
		}
	}
}

func startTestEngine(t *testing.T, ctx context.Context, node *mesh.Node, store *recoverycard.Store, peerID string) *Engine {
	t.Helper()
	engine, err := New(Config{
		Node: node, Store: store, PeerIDs: []string{peerID}, SharedSecret: []byte("test mesh"),
		PacketNeighbor: mesh.PacketNeighborConfig{
			KeepAliveInterval: 20 * time.Millisecond, PeerTimeout: 300 * time.Millisecond,
			ReadPollInterval: 20 * time.Millisecond, WriteTimeout: 100 * time.Millisecond,
		},
		AttemptWindow: 1500 * time.Millisecond, AttemptCycle: 1800 * time.Millisecond,
		HelloTimeout: 200 * time.Millisecond, HelloInterval: 10 * time.Millisecond,
		HelloSettle: 40 * time.Millisecond, PunchGrace: 20 * time.Millisecond,
		RoundDelay: 10 * time.Millisecond, AllowNonPublic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return engine
}

func newObservationEngine(t *testing.T, store *recoverycard.Store) *Engine {
	t.Helper()
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	engine, err := New(Config{Node: node, Store: store, PeerIDs: []string{"B"}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func startEngineNode(t *testing.T, ctx context.Context, nodeID string) *mesh.Node {
	t.Helper()
	node, err := mesh.NewNode(mesh.NodeConfig{
		NodeID: nodeID, Lease: 2 * time.Second, RefreshInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func saveEngineCard(t *testing.T, nodeID string, localPort int, peer recoverycard.Peer) *recoverycard.Store {
	t.Helper()
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "recovery-card.json"), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	now := peer.LastSuccessAt
	card := recoverycard.Card{
		Version: recoverycard.CurrentVersion, NodeID: nodeID, UpdatedAt: now.Add(time.Second),
		LastSuccessAt: now, LocalBindPorts: []uint16{uint16(localPort)},
		LocalNAT: recoverycard.NATModel{
			Pattern: recoverycard.PortPatternPreserving, Confidence: 1, ObservedAt: now,
		},
		Peers: []recoverycard.Peer{peer},
	}
	if err := store.Save(card); err != nil {
		t.Fatal(err)
	}
	return store
}

func engineEndpoint(port int, at time.Time) recoverycard.Endpoint {
	return recoverycard.Endpoint{
		AddrPort: net.JoinHostPort("127.0.0.1", itoaPort(port)), ObservedAt: at,
		Source: "previous_direct", LastSuccessAt: at,
		NAT: recoverycard.NATModel{
			Pattern: recoverycard.PortPatternPreserving, Confidence: 1, ObservedAt: at,
		},
	}
}

func findEnginePeer(t *testing.T, card recoverycard.Card, peerID string) recoverycard.Peer {
	t.Helper()
	for _, peer := range card.Peers {
		if peer.NodeID == peerID {
			return peer
		}
	}
	t.Fatalf("peer %s missing from card %+v", peerID, card)
	return recoverycard.Peer{}
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func reserveDistinctUDPPort(t *testing.T, excluded ...int) int {
	t.Helper()
	for {
		port := reserveUDPPort(t)
		if !slices.Contains(excluded, port) {
			return port
		}
	}
}

func itoaPort(port int) string {
	return strconv.Itoa(port)
}

func eventuallyEngine(t *testing.T, ctx context.Context, condition func() bool, message string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
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
