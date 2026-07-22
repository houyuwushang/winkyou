package selfhosted

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/netutil"
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
	for label, engine := range map[string]*Engine{"A": engineA, "B": engineB} {
		status := engine.Snapshot()
		if len(status) != 1 || status[0].LocalBindAddr == "" || status[0].LocalBindIP != "" || status[0].LocalBindInterface != "" {
			t.Fatalf("%s unbound status must expose only the winning socket, not explicit-binding evidence: %+v", label, status)
		}
		event := engine.event(status[0].PeerID, StateAttached, "test", "", mesh.NeighborHandle{}, nil)
		if event.LocalBindIP != status[0].LocalBindIP || event.LocalBindAddr != status[0].LocalBindAddr {
			t.Fatalf("%s attached event lost local binding: status=%+v event=%+v", label, status[0], event)
		}
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

func TestEnginesRecoverUsingOlderIPGroupWithoutRouteOrCoordinator(t *testing.T) {
	portA := reserveUDPPort(t)
	portB := reserveDistinctUDPPort(t, portA)
	stalePortA := reserveDistinctUDPPort(t, portA, portB)
	stalePortB := reserveDistinctUDPPort(t, portA, portB, stalePortA)
	newest := time.Now().UTC().Add(-time.Minute)
	older := newest.Add(-time.Minute)
	storeA := saveEngineCard(t, "A", portA, recoverycard.Peer{
		NodeID: "B", LastSuccessfulLocalBindPort: uint16(portA), LastSuccessAt: newest,
		Endpoints: []recoverycard.Endpoint{
			engineEndpointAt("192.0.2.11", stalePortB, newest),
			engineEndpointAt("127.0.0.1", portB, older),
		},
	})
	storeB := saveEngineCard(t, "B", portB, recoverycard.Peer{
		NodeID: "A", LastSuccessfulLocalBindPort: uint16(portB), LastSuccessAt: newest,
		Endpoints: []recoverycard.Endpoint{
			engineEndpointAt("198.51.100.12", stalePortA, newest),
			engineEndpointAt("127.0.0.1", portA, older),
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodeA := startEngineNode(t, ctx, "A")
	nodeB := startEngineNode(t, ctx, "B")
	engineA := startTestEngine(t, ctx, nodeA, storeA, "B")
	engineB := startTestEngine(t, ctx, nodeB, storeB, "A")
	defer engineA.Close()
	defer engineB.Close()

	eventuallyEngine(t, ctx, func() bool {
		return nodeA.HasNeighbor("B") && nodeB.HasNeighbor("A")
	}, "engines did not rotate from stale newest IP groups to the older direct endpoints")
	eventuallyEngine(t, ctx, func() bool {
		statusA, statusB := engineA.Snapshot(), engineB.Snapshot()
		return len(statusA) == 1 && len(statusB) == 1 &&
			statusA[0].LearnedRemote != "" && statusB[0].LearnedRemote != ""
	}, "portfolio edge attached before both learned-remote statuses converged")
	selectedOlderGroup := false
	for label, engine := range map[string]*Engine{"A": engineA, "B": engineB} {
		status := engine.Snapshot()
		if len(status) != 1 {
			t.Fatalf("%s status = %+v", label, status)
		}
		peerStatus := status[0]
		if peerStatus.Attempts < 1 {
			t.Fatalf("%s did not attempt the bounded portfolio: %+v", label, peerStatus)
		}
		if peerStatus.CandidateTotal != 2 {
			t.Fatalf("%s retained candidate total = %d, want 2; status=%+v", label, peerStatus.CandidateTotal, peerStatus)
		}
		if peerStatus.CandidateGroup == "127.0.0.1" && peerStatus.CandidateIndex == 2 {
			selectedOlderGroup = true
		}
		if peerStatus.LearnedRemote == "" {
			t.Fatalf("%s did not expose the actual learned remote: %+v", label, peerStatus)
		}
	}
	if !selectedOlderGroup {
		t.Fatal("neither endpoint selected the older usable IP group")
	}
	for label, check := range map[string]struct {
		store    *recoverycard.Store
		peerID   string
		wantPort int
	}{
		"A": {store: storeA, peerID: "B", wantPort: portB},
		"B": {store: storeB, peerID: "A", wantPort: portA},
	} {
		card, err := check.store.Load()
		if err != nil {
			t.Fatal(err)
		}
		peerCard := findEnginePeer(t, card, check.peerID)
		want := net.JoinHostPort("127.0.0.1", itoaPort(check.wantPort))
		if peerCard.Endpoints[0].AddrPort != want {
			t.Fatalf("%s newest learned endpoint = %q, want %q; history=%+v", label, peerCard.Endpoints[0].AddrPort, want, peerCard.Endpoints)
		}
	}

	// Keep the recovered fallback edge alive beyond one peer timeout.
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-time.After(500 * time.Millisecond):
	}
	if !nodeA.HasNeighbor("B") || !nodeB.HasNeighbor("A") {
		t.Fatal("fallback edge did not survive packet-neighbor liveness")
	}
}

func TestRecoveryCandidateScheduleCoversAsymmetricRanksAcrossRestart(t *testing.T) {
	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	portfolio := buildCandidatePortfolio(recoverycard.Peer{Endpoints: []recoverycard.Endpoint{
		portfolioTestEndpoint("8.8.8.8:8000", base.Add(4*time.Hour), base, recoverycard.PortPatternUnknown, 1, "first"),
		portfolioTestEndpoint("9.9.9.9:9000", base.Add(3*time.Hour), base, recoverycard.PortPatternUnknown, 1, "second"),
		portfolioTestEndpoint("1.1.1.1:1000", base.Add(2*time.Hour), base, recoverycard.PortPatternUnknown, 1, "third"),
		portfolioTestEndpoint("4.4.4.4:4000", base.Add(time.Hour), base, recoverycard.PortPatternUnknown, 1, "fourth"),
	}}, false)

	for selectorCount := 1; selectorCount <= maxCandidateGroups; selectorCount++ {
		for receiverCount := 1; receiverCount <= maxCandidateGroups; receiverCount++ {
			selectorPortfolio := portfolio
			selectorPortfolio.Groups = selectorPortfolio.Groups[:selectorCount]
			receiverPortfolio := portfolio
			receiverPortfolio.Groups = receiverPortfolio.Groups[:receiverCount]
			for firstOrdinal := int64(-16); firstOrdinal < 16; firstOrdinal++ {
				seen := make(map[[2]int]struct{}, maxCandidateGroups*maxCandidateGroups)
				foundAsymmetricWorkingPair := false
				for offset := int64(0); offset < int64(maxCandidateGroups*maxCandidateGroups); offset++ {
					ordinal := firstOrdinal + offset
					// Recreate both process-local runtimes every window. Selection must
					// remain an absolute pair-window function rather than reset to rank 1.
					selectorPeer := &peerRuntime{
						candidateFailures:   map[string]uint32{"8.8.8.8": 99, "retired": 99},
						punchDeadlineMisses: map[string]uint32{"8.8.8.8": 1, "retired": 1},
					}
					receiverPeer := &peerRuntime{candidateFailures: map[string]uint32{"9.9.9.9": 77}}
					selector, selectorOK := selectRecoveryCandidate(selectorPeer, selectorPortfolio, ordinal, puncher.RoleSelector)
					receiver, receiverOK := selectRecoveryCandidate(receiverPeer, receiverPortfolio, ordinal, puncher.RoleReceiver)
					if !selectorOK || !receiverOK {
						t.Fatalf("ordinal %d selection missing: selector=%t receiver=%t", ordinal, selectorOK, receiverOK)
					}
					pair := [2]int{selector.Index, receiver.Index}
					seen[pair] = struct{}{}
					if pair == [2]int{2, 3} {
						foundAsymmetricWorkingPair = true
					}
					if _, retained := selectorPeer.candidateFailures["retired"]; retained {
						t.Fatal("failure evidence for a group outside the bounded portfolio was retained")
					}
					if _, retained := selectorPeer.punchDeadlineMisses["retired"]; retained {
						t.Fatal("punch deadline evidence for a group outside the bounded portfolio was retained")
					}
				}
				wantPairs := selectorCount * receiverCount
				if len(seen) != wantPairs {
					t.Fatalf("selector groups %d receiver groups %d ordinals %d..%d covered %d candidate pairs, want %d: %v",
						selectorCount, receiverCount, firstOrdinal, firstOrdinal+15, len(seen), wantPairs, seen)
				}
				if selectorCount >= 2 && receiverCount >= 3 && !foundAsymmetricWorkingPair {
					t.Fatalf("selector groups %d receiver groups %d ordinals %d..%d never paired selector rank 2 with receiver rank 3",
						selectorCount, receiverCount, firstOrdinal, firstOrdinal+15)
				}
			}
		}
	}
}

func TestEngineNeverAttemptsTwoCandidateGroupsInOnePairWindow(t *testing.T) {
	localPort := reserveUDPPort(t)
	newest := time.Now().UTC().Add(-time.Minute)
	store := saveEngineCard(t, "A", localPort, recoverycard.Peer{
		NodeID: "B", LastSuccessfulLocalBindPort: uint16(localPort), LastSuccessAt: newest,
		Endpoints: []recoverycard.Endpoint{
			engineEndpointAt("8.8.8.8", 48000, newest),
			engineEndpointAt("9.9.9.9", 49000, newest.Add(-time.Minute)),
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	node := startEngineNode(t, ctx, "A")
	type punchCall struct {
		at     time.Time
		config puncher.Config
	}
	calls := make(chan punchCall, 4)
	events := make(chan Event, 8)
	callNumber := 0
	engine, err := New(Config{
		Node: node, Store: store, PeerIDs: []string{"B"}, SharedSecret: []byte("test mesh"),
		AttemptWindow: 1600 * time.Millisecond, AttemptCycle: 1800 * time.Millisecond,
		HelloTimeout: 100 * time.Millisecond, HelloInterval: 10 * time.Millisecond,
		HelloSettle: 20 * time.Millisecond, PunchGrace: 20 * time.Millisecond,
		Punch: func(punchCtx context.Context, config puncher.Config) (*puncher.Result, error) {
			callNumber++
			calls <- punchCall{at: time.Now(), config: config}
			if callNumber == 1 {
				return nil, errors.New("synthetic immediate punch failure")
			}
			<-punchCtx.Done()
			return nil, punchCtx.Err()
		},
		OnEvent: func(event Event) {
			select {
			case events <- event:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	var first punchCall
	select {
	case first = <-calls:
	case <-ctx.Done():
		t.Fatalf("first candidate was not attempted: %v", ctx.Err())
	}
	firstGroup := first.config.RemoteIP.String()
	if firstGroup != "8.8.8.8" && firstGroup != "9.9.9.9" {
		t.Fatalf("first group = %s, want one retained portfolio group", firstGroup)
	}
	select {
	case second := <-calls:
		t.Fatalf("second group %s was attempted in the same pair window after %s", second.config.RemoteIP, second.at.Sub(first.at))
	case <-time.After(300 * time.Millisecond):
	}
	status := engine.Snapshot()
	if len(status) != 1 || status[0].CandidateGroup != firstGroup || status[0].FailureStage != "punch" ||
		status[0].LastError == "" || status[0].CandidateFailures != 0 {
		t.Fatalf("scheduled failure status mixed the next candidate with the failed attempt: %+v", status)
	}
	var failureEvent Event
	for failureEvent.Err == nil {
		select {
		case failureEvent = <-events:
		case <-time.After(200 * time.Millisecond):
			t.Fatal("failed attempt did not emit a terminal event")
		}
	}
	if failureEvent.AttemptID == "" || failureEvent.CandidateGroup != firstGroup || failureEvent.FailureStage != "punch" || failureEvent.AttemptWindowOrdinal == 0 {
		t.Fatalf("failure event lost immutable attempt identity: %+v", failureEvent)
	}

	select {
	case second := <-calls:
		wantSecond := "8.8.8.8"
		if firstGroup == wantSecond {
			wantSecond = "9.9.9.9"
		}
		if got := second.config.RemoteIP.String(); got != wantSecond {
			t.Fatalf("next-window group = %s, want complementary scheduled group %s", got, wantSecond)
		}
		if elapsed := second.at.Sub(first.at); elapsed < time.Second {
			t.Fatalf("candidate groups were only %s apart; want distinct pair windows", elapsed)
		}
		var secondEvent Event
		for secondEvent.State != StatePunching || secondEvent.AttemptID == failureEvent.AttemptID {
			select {
			case secondEvent = <-events:
			case <-time.After(200 * time.Millisecond):
				t.Fatal("second-window punch did not emit its immutable schedule coordinate")
			}
		}
		if secondEvent.AttemptWindowOrdinal != failureEvent.AttemptWindowOrdinal+1 ||
			!secondEvent.AttemptWindowStart.After(failureEvent.AttemptWindowStart) {
			t.Fatalf("attempts did not advance exactly one pair window: first=%+v second=%+v", failureEvent, secondEvent)
		}
		var deadlineFailure Event
		for deadlineFailure.Err == nil || deadlineFailure.AttemptID != secondEvent.AttemptID {
			select {
			case deadlineFailure = <-events:
			case <-ctx.Done():
				t.Fatalf("deadline failure event missing: %v", ctx.Err())
			}
		}
		if deadlineFailure.FailureStage != "punch" || deadlineFailure.CandidateFailures != 1 {
			t.Fatalf("punch deadline did not count as one candidate failure: %+v", deadlineFailure)
		}
	case <-ctx.Done():
		t.Fatalf("fallback candidate was not attempted in the next pair window: %v", ctx.Err())
	}
}

func TestRouteSupersedeKeepsAttemptIdentityWhenRouteDisappears(t *testing.T) {
	localPort := reserveUDPPort(t)
	now := time.Now().UTC().Add(-time.Minute)
	store := saveEngineCard(t, "A", localPort, recoverycard.Peer{
		NodeID: "B", LastSuccessfulLocalBindPort: uint16(localPort), LastSuccessAt: now,
		Endpoints: []recoverycard.Endpoint{engineEndpointAt("8.8.8.8", 48000, now)},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	node := startEngineNode(t, ctx, "A")
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAttempt := func() { releaseOnce.Do(func() { close(release) }) }
	events := make(chan Event, 16)
	engine, err := New(Config{
		Node: node, Store: store, PeerIDs: []string{"B"}, SharedSecret: []byte("test mesh"),
		AttemptWindow: 1600 * time.Millisecond, AttemptCycle: 1800 * time.Millisecond,
		HelloTimeout: 100 * time.Millisecond, HelloInterval: 10 * time.Millisecond,
		HelloSettle: 20 * time.Millisecond, PunchGrace: 20 * time.Millisecond,
		Punch: func(punchCtx context.Context, _ puncher.Config) (*puncher.Result, error) {
			started <- struct{}{}
			<-punchCtx.Done()
			canceled <- struct{}{}
			<-release
			return nil, punchCtx.Err()
		},
		OnEvent: func(event Event) { events <- event },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		releaseAttempt()
		engine.Close()
	}()

	select {
	case <-started:
	case <-ctx.Done():
		t.Fatalf("punch did not start: %v", ctx.Err())
	}
	var punching Event
	for punching.State != StatePunching {
		select {
		case punching = <-events:
		case <-ctx.Done():
			t.Fatalf("punching event missing: %v", ctx.Err())
		}
	}

	local, remote := net.Pipe()
	defer remote.Close()
	go func() {
		_, _ = io.Copy(io.Discard, remote)
	}()
	if err := node.AttachStream("B", local); err != nil {
		t.Fatal(err)
	}
	if !node.HasNeighbor("B") {
		t.Fatal("attached stream was not visible as a direct route")
	}
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatalf("new route did not cancel the active candidate: %v", ctx.Err())
	}
	if err := node.RemoveNeighbor("B"); err != nil {
		t.Fatal(err)
	}
	releaseAttempt()

	var superseded Event
	var observed []Event
	for superseded.FailureStage != "superseded_route" {
		select {
		case superseded = <-events:
			observed = append(observed, superseded)
		case <-ctx.Done():
			t.Fatalf("superseded attempt event missing: %v; status=%+v events=%+v", ctx.Err(), engine.Snapshot(), observed)
		}
	}
	if superseded.AttemptID == "" || superseded.AttemptID != punching.AttemptID || superseded.Err != nil {
		t.Fatalf("route-superseded event lost attempt identity: punching=%+v superseded=%+v", punching, superseded)
	}
	eventuallyEngine(t, ctx, func() bool {
		status := engine.Snapshot()
		return len(status) == 1 && status[0].State == StateScheduled &&
			status[0].FailureStage == "superseded_route" && status[0].CandidateFailures == 0 && status[0].LastError == ""
	}, "route disappearance misclassified a superseded attempt as candidate failure")
}

func TestPunchConfigMergesHistoricalPortsWithPrimaryPrediction(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	engine, err := New(Config{
		Node: node, Store: store, PeerIDs: []string{"B"},
		PredictSockets: 7, PredictSpan: 2,
		PunchInterface: "Ethernet-test",
		Binding: &netutil.UDPBinding{
			InterfaceName: "Ethernet-test", InterfaceIndex: 7, LocalIP: net.IPv4(192, 0, 2, 50),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	peer := recoverycard.Peer{
		NodeID: "B", LastSuccessfulLocalBindPort: 42000,
		Endpoints: []recoverycard.Endpoint{
			portfolioTestEndpoint("8.8.8.8:40000", base.Add(2*time.Hour), base.Add(2*time.Hour), recoverycard.PortPatternSequential, 1, "newest"),
			portfolioTestEndpoint("8.8.8.8:39990", base.Add(time.Hour), base.Add(time.Hour), recoverycard.PortPatternPreserving, 1, "older"),
		},
	}
	peer.Endpoints[0].NAT.Delta = 2
	portfolio := buildCandidatePortfolio(peer, false)
	config := engine.punchConfig([32]byte{}, recoverycard.Card{
		LocalNAT: recoverycard.NATModel{Pattern: recoverycard.PortPatternPreserving},
	}, peer, portfolio.Groups[0], 0)

	wantTargets := []int{40000, 39990, 39996, 39998, 40002, 40004}
	if !slices.Equal(config.TargetPorts, wantTargets) {
		t.Fatalf("merged target ports = %v, want %v", config.TargetPorts, wantTargets)
	}
	if got := config.RemoteIP.String(); got != "8.8.8.8" {
		t.Fatalf("remote IP = %s, want 8.8.8.8", got)
	}
	if config.Method != "cached_predictive" || config.BirthdayN != 0 || config.SocketCount != 7 || config.LocalPort != 42000 {
		t.Fatalf("predictive portfolio config = %+v", config)
	}
	if config.Binding == nil || config.Binding.InterfaceName != "Ethernet-test" || !config.Binding.LocalIP.Equal(net.IPv4(192, 0, 2, 50)) {
		t.Fatalf("predictive portfolio binding = %+v", config.Binding)
	}
	fallback := engine.punchConfig([32]byte{}, recoverycard.Card{
		LocalNAT: recoverycard.NATModel{Pattern: recoverycard.PortPatternRandom},
	}, peer, portfolio.Groups[0], 1)
	if !slices.Equal(fallback.TargetPorts, wantTargets) || fallback.Method != "cached_predictive_birthday_fallback" ||
		fallback.BirthdayN != 48 || fallback.SocketCount != 128 || fallback.LocalPort != 0 {
		t.Fatalf("predictive fallback portfolio config = %+v", fallback)
	}
	status := engine.Snapshot()
	if len(status) != 1 || status[0].LocalBindIP != "192.0.2.50" || status[0].LocalBindInterface != "Ethernet-test" {
		t.Fatalf("initial self-bootstrap binding status = %+v", status)
	}
	event := engine.event("B", StatePunching, "attempt", "8.8.8.8:40000", mesh.NeighborHandle{}, nil)
	if event.LocalBindIP != "192.0.2.50" || event.LocalBindInterface != "Ethernet-test" {
		t.Fatalf("self-bootstrap binding event = %+v", event)
	}
}

func TestCandidateFailureEscalatesBirthdayOnlyAfterPunchDeadline(t *testing.T) {
	const groupID = "8.8.8.8"
	peer := &peerRuntime{
		candidateFailures:   make(map[string]uint32),
		punchDeadlineMisses: make(map[string]uint32),
	}
	selection := candidateSelection{Group: candidateGroup{ID: groupID}}

	recordCandidateFailure(peer, &selection, "peer_hello", true)
	if selection.Failures != 1 || selection.PunchDeadlineMisses != 0 || peer.punchDeadlineMisses[groupID] != 0 {
		t.Fatalf("HELLO negative evidence enabled birthday fallback: selection=%+v peer=%+v", selection, peer.punchDeadlineMisses)
	}
	recordCandidateFailure(peer, &selection, "punch", false)
	if selection.Failures != 1 || selection.PunchDeadlineMisses != 0 {
		t.Fatalf("non-penalized local punch error changed fallback state: %+v", selection)
	}
	recordCandidateFailure(peer, &selection, "punch", true)
	if selection.Failures != 2 || selection.PunchDeadlineMisses != 1 || peer.punchDeadlineMisses[groupID] != 1 {
		t.Fatalf("deadline-confirmed punch miss did not enable birthday fallback: selection=%+v peer=%+v", selection, peer.punchDeadlineMisses)
	}
}

func TestLearnedRemoteNATUsesEvidenceForActualIPGroup(t *testing.T) {
	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	peer := recoverycard.Peer{Endpoints: []recoverycard.Endpoint{
		portfolioTestEndpoint("192.0.2.10:41000", base.Add(3*time.Hour), base, recoverycard.PortPatternRandom, 1, "selected-stale"),
		portfolioTestEndpoint("127.0.0.1:42000", base.Add(2*time.Hour), base, recoverycard.PortPatternSequential, 1, "actual-exact"),
		portfolioTestEndpoint("127.0.0.1:42001", base.Add(time.Hour), base, recoverycard.PortPatternPreserving, 1, "actual-same-ip"),
	}}
	peer.Endpoints[1].NAT.Delta = 2

	exact := learnedRemoteNAT(peer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42000})
	if exact.Pattern != recoverycard.PortPatternSequential || exact.Delta != 2 {
		t.Fatalf("exact learned endpoint NAT = %+v, want sequential group evidence", exact)
	}
	sameIP := learnedRemoteNAT(peer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42999})
	if sameIP.Pattern != recoverycard.PortPatternSequential || sameIP.Delta != 2 {
		t.Fatalf("same-IP learned endpoint NAT = %+v, want newest same-IP evidence", sameIP)
	}
	unknown := learnedRemoteNAT(peer, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 99), Port: 43000})
	if unknown.Pattern != recoverycard.PortPatternUnknown {
		t.Fatalf("unknown learned IP inherited unrelated NAT evidence: %+v", unknown)
	}
}

func TestClearCandidateStatusRemovesAttemptScopedMetadata(t *testing.T) {
	status := PeerStatus{
		Candidate: "8.8.8.8:48000", CandidateGroup: "8.8.8.8",
		CandidateIndex: 2, CandidateTotal: 4, CandidateEndpoints: 3, CandidateFailures: 1,
		AttemptWindowOrdinal: 42, AttemptWindowStart: time.Now(), AttemptWindowEnd: time.Now().Add(time.Minute),
		PunchMethod: "cached_predictive", LearnedRemote: "8.8.8.8:48001",
	}

	clearCandidateStatus(&status)
	if status.Candidate != "" || status.CandidateGroup != "" || status.CandidateIndex != 0 ||
		status.CandidateTotal != 0 || status.CandidateEndpoints != 0 || status.CandidateFailures != 0 ||
		status.AttemptWindowOrdinal != 0 || !status.AttemptWindowStart.IsZero() || !status.AttemptWindowEnd.IsZero() ||
		status.PunchMethod != "" || status.LearnedRemote != "" {
		t.Fatalf("attempt-scoped candidate metadata was retained: %+v", status)
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
	runtimePeer := engine.peers["B"]
	runtimePeer.candidateFailures["203.0.113.8"] = 3
	runtimePeer.punchDeadlineMisses["203.0.113.8"] = 1
	now := time.Now().UTC()
	observation := Observation{
		PeerID: "C", RemoteAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 45000},
		LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 42000}, At: now,
	}
	if err := engine.Observe(observation); err == nil {
		t.Fatal("observation for an unconfigured peer was accepted")
	}
	if runtimePeer.consumeCandidateFailureReset() {
		t.Fatal("rejected observation reset candidate failure diagnostics")
	}
	observation.PeerID = "B"
	observation.Source = "shortcut"
	if err := engine.Observe(observation); err != nil {
		t.Fatal(err)
	}
	if !runtimePeer.consumeCandidateFailureReset() || len(runtimePeer.candidateFailures) != 0 || len(runtimePeer.punchDeadlineMisses) != 0 {
		t.Fatalf("verified observation did not reset candidate failure diagnostics: failures=%v punch_misses=%v", runtimePeer.candidateFailures, runtimePeer.punchDeadlineMisses)
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
	leftStart, leftEnd, leftActive, leftOrdinal := attemptWindowDetails(left, now, time.Minute, 45*time.Second)
	rightStart, rightEnd, rightActive, rightOrdinal := attemptWindowDetails(right, now, time.Minute, 45*time.Second)
	if !leftStart.Equal(rightStart) || !leftEnd.Equal(rightEnd) || leftActive != rightActive || leftOrdinal != rightOrdinal {
		t.Fatalf("pair windows differ: left=%s..%s/%t/%d right=%s..%s/%t/%d",
			leftStart, leftEnd, leftActive, leftOrdinal, rightStart, rightEnd, rightActive, rightOrdinal)
	}
}

func TestAttemptIDsDifferAcrossEngineRestartInSameWindow(t *testing.T) {
	store, err := recoverycard.NewStore(filepath.Join(t.TempDir(), "card.json"), "A")
	if err != nil {
		t.Fatal(err)
	}
	node, err := mesh.NewNode(mesh.NodeConfig{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	first, err := New(Config{Node: node, Store: store, PeerIDs: []string{"B"}})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(Config{Node: node, Store: store, PeerIDs: []string{"B"}})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	windowStart := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	firstID := first.nextAttemptID("B", windowStart)
	secondID := second.nextAttemptID("B", windowStart)
	if firstID == secondID {
		t.Fatalf("same-window attempt ID collided across engine restart: %q", firstID)
	}
}

func TestSelfBootstrapPunchRolesAreComplementary(t *testing.T) {
	if got := selfBootstrapPunchRole("A", "B"); got != puncher.RoleSelector {
		t.Fatalf("A -> B role = %v, want selector", got)
	}
	if got := selfBootstrapPunchRole("B", "A"); got != puncher.RoleReceiver {
		t.Fatalf("B -> A role = %v, want receiver", got)
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
	return engineEndpointAt("127.0.0.1", port, at)
}

func engineEndpointAt(host string, port int, at time.Time) recoverycard.Endpoint {
	return recoverycard.Endpoint{
		AddrPort: net.JoinHostPort(host, itoaPort(port)), ObservedAt: at,
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
