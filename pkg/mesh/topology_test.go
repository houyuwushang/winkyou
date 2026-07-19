package mesh

import (
	"errors"
	"slices"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
)

func TestTopologyBuildsRouteFromReciprocalLinksAndWithdrawsIt(t *testing.T) {
	topology, err := NewTopology("A")
	if err != nil {
		t.Fatalf("NewTopology() error = %v", err)
	}
	now := time.Now()
	setTopologyMember(t, topology, "A", true, now)
	setTopologyMember(t, topology, "B", false, now)
	setTopologyMember(t, topology, "C", false, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID:         "A",
		Revision:       1,
		LeaseMillis:    10_000,
		TransitAllowed: true,
		Links:          []peercontrol.LinkStateLink{{PeerID: "B", RTTMillis: 10}},
	}, true, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID:         "B",
		Revision:       1,
		LeaseMillis:    10_000,
		TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "A", RTTMillis: 12},
			{PeerID: "C", RTTMillis: 20},
		},
	}, false, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID:         "C",
		Revision:       1,
		LeaseMillis:    10_000,
		TransitAllowed: true,
		Links:          []peercontrol.LinkStateLink{{PeerID: "B", RTTMillis: 24}},
	}, false, now)

	route, ok := topology.Route("C")
	if !ok {
		t.Fatal("route A->C was not calculated")
	}
	if route.NextHop != "B" || route.HopCount != 2 || route.RTT != 33*time.Millisecond {
		t.Fatalf("route A->C = %#v", route)
	}
	if !slices.Equal(route.Path, []string{"A", "B", "C"}) {
		t.Fatalf("route path = %v", route.Path)
	}

	withdrawn := peercontrol.LinkStateAdvertisement{
		NodeID:         "B",
		Revision:       2,
		LeaseMillis:    10_000,
		TransitAllowed: true,
		Links:          []peercontrol.LinkStateLink{{PeerID: "A", RTTMillis: 12}},
	}
	if changed, err := topology.ApplyLinkState(withdrawn, now.Add(time.Second)); err != nil || !changed {
		t.Fatalf("ApplyLinkState(withdraw) changed=%v error=%v", changed, err)
	}
	if route, ok := topology.Route("C"); ok {
		t.Fatalf("route survived withdrawal: %#v", route)
	}

	stale := withdrawn
	stale.Revision = 1
	stale.Links = append(stale.Links, peercontrol.LinkStateLink{PeerID: "C"})
	if changed, err := topology.ApplyLinkState(stale, now.Add(2*time.Second)); err != nil || changed {
		t.Fatalf("ApplyLinkState(stale) changed=%v error=%v", changed, err)
	}
	if _, ok := topology.Route("C"); ok {
		t.Fatal("stale LSA restored withdrawn route")
	}
}

func TestTopologyRequiresReciprocalLinkAndTransitPermission(t *testing.T) {
	topology, _ := NewTopology("A")
	now := time.Now()
	setTopologyMember(t, topology, "A", true, now)
	setTopologyMember(t, topology, "B", false, now)
	setTopologyMember(t, topology, "C", false, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "A", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{{PeerID: "B"}},
	}, true, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "B", Revision: 1, LeaseMillis: 10_000, TransitAllowed: false,
		Links: []peercontrol.LinkStateLink{{PeerID: "A"}, {PeerID: "C"}},
	}, false, now)

	if _, ok := topology.Route("C"); ok {
		t.Fatal("one-way B-C link produced a route")
	}
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "C", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{{PeerID: "B"}},
	}, false, now)
	if _, ok := topology.Route("B"); !ok {
		t.Fatal("direct A-B route missing")
	}
	if _, ok := topology.Route("C"); ok {
		t.Fatal("route crossed node B with transit disabled")
	}
}

func TestTopologyAlternateRouteExcludesOnlyDirectDestinationEdge(t *testing.T) {
	topology, _ := NewTopology("A")
	now := time.Now()
	for _, nodeID := range []string{"A", "B", "C"} {
		setTopologyMember(t, topology, nodeID, nodeID == "A", now)
	}
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "A", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "B", RTTMillis: 1},
			{PeerID: "C", RTTMillis: 5},
		},
	}, true, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "B", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "A", RTTMillis: 1},
			{PeerID: "C", RTTMillis: 1},
		},
	}, false, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "C", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "A", RTTMillis: 5},
			{PeerID: "B", RTTMillis: 1},
		},
	}, false, now)

	direct, ok := topology.Route("B")
	if !ok || !slices.Equal(direct.Path, []string{"A", "B"}) {
		t.Fatalf("direct A-B route = %+v, ok=%t", direct, ok)
	}
	alternate, ok := topology.AlternateRoute("B")
	if !ok || alternate.NextHop != "C" || alternate.HopCount != 2 ||
		!slices.Equal(alternate.Path, []string{"A", "C", "B"}) {
		t.Fatalf("alternate A-B route = %+v, ok=%t", alternate, ok)
	}
	// Excluding A-C for a different destination must leave A-B available.
	alternateToC, ok := topology.AlternateRoute("C")
	if !ok || !slices.Equal(alternateToC.Path, []string{"A", "B", "C"}) {
		t.Fatalf("alternate A-C route = %+v, ok=%t", alternateToC, ok)
	}
	alternate.Path[0] = "mutated"
	again, ok := topology.AlternateRoute("B")
	if !ok || !slices.Equal(again.Path, []string{"A", "C", "B"}) {
		t.Fatalf("alternate route was not cloned: %+v, ok=%t", again, ok)
	}
	if wrapped, ok := (&Node{topology: topology}).AlternateRoute("B"); !ok ||
		!slices.Equal(wrapped.Path, []string{"A", "C", "B"}) {
		t.Fatalf("Node.AlternateRoute() = %+v, ok=%t", wrapped, ok)
	}
	if _, ok := topology.AlternateRoute(""); ok {
		t.Fatal("empty alternate destination unexpectedly resolved")
	}
	if _, ok := topology.AlternateRoute("A"); ok {
		t.Fatal("local alternate destination unexpectedly resolved")
	}

	directOnly, _ := NewTopology("A")
	setTopologyMember(t, directOnly, "A", true, now)
	setTopologyMember(t, directOnly, "B", false, now)
	setTopologyLSA(t, directOnly, peercontrol.LinkStateAdvertisement{
		NodeID: "A", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{{PeerID: "B"}},
	}, true, now)
	setTopologyLSA(t, directOnly, peercontrol.LinkStateAdvertisement{
		NodeID: "B", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{{PeerID: "A"}},
	}, false, now)
	if _, ok := directOnly.AlternateRoute("B"); ok {
		t.Fatal("direct-only topology unexpectedly has an alternate route")
	}
}

func TestTopologyRejectsEqualRevisionConflictAndExpiresLease(t *testing.T) {
	topology, _ := NewTopology("A")
	now := time.Now()
	setTopologyMember(t, topology, "A", true, now)
	record := peercontrol.MemberRecord{NodeID: "B", Revision: 1, LeaseMillis: 20, VirtualIP: "fd00::b"}
	if changed, err := topology.ApplyMember(record, now); err != nil || !changed {
		t.Fatalf("ApplyMember() changed=%v error=%v", changed, err)
	}
	conflict := record
	conflict.VirtualIP = "fd00::different"
	if _, err := topology.ApplyMember(conflict, now); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("ApplyMember(conflict) error = %v", err)
	}
	if !topology.Expire(now.Add(21 * time.Millisecond)) {
		t.Fatal("Expire() did not remove expired member")
	}
	if _, ok := topology.Member("B"); ok {
		t.Fatal("expired member B still present")
	}
}

func TestTopologyDataRoutesGloballyExcludeThirdPartyControlOnlyEdge(t *testing.T) {
	now := time.Now()
	nodeIDs := []string{"A", "B", "C", "D", "E"}
	states := map[string]peercontrol.LinkStateAdvertisement{
		"A": {
			NodeID: "A", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
			Links: []peercontrol.LinkStateLink{
				{PeerID: "B", RTTMillis: 1},
				// Only A marks A-D control-only. The data graph must remove the
				// undirected edge for every observer, including third-party B.
				{PeerID: "D", RTTMillis: 1, ControlOnly: true},
			},
		},
		"B": {
			NodeID: "B", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
			Links: []peercontrol.LinkStateLink{
				{PeerID: "A", RTTMillis: 1}, {PeerID: "C", RTTMillis: 20},
			},
		},
		"C": {
			NodeID: "C", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
			Links: []peercontrol.LinkStateLink{
				{PeerID: "B", RTTMillis: 20}, {PeerID: "D", RTTMillis: 20},
			},
		},
		"D": {
			NodeID: "D", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
			Links: []peercontrol.LinkStateLink{
				{PeerID: "A", RTTMillis: 1}, {PeerID: "C", RTTMillis: 20},
				{PeerID: "E", RTTMillis: 1},
			},
		},
		"E": {
			NodeID: "E", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
			Links: []peercontrol.LinkStateLink{{PeerID: "D", RTTMillis: 1}},
		},
	}

	topologies := make(map[string]*Topology, len(nodeIDs))
	for _, localID := range nodeIDs {
		topology, err := NewTopology(localID)
		if err != nil {
			t.Fatal(err)
		}
		for _, nodeID := range nodeIDs {
			setTopologyMember(t, topology, nodeID, nodeID == localID, now)
		}
		for _, nodeID := range nodeIDs {
			setTopologyLSA(t, topology, states[nodeID], nodeID == localID, now)
		}
		topologies[localID] = topology
	}

	if route, ok := topologies["B"].Route("E"); !ok ||
		!slices.Equal(route.Path, []string{"B", "A", "D", "E"}) {
		t.Fatalf("control route B-E = %+v, ok=%t", route, ok)
	}
	checks := []struct {
		from string
		to   string
		path []string
	}{
		{from: "B", to: "D", path: []string{"B", "C", "D"}},
		{from: "B", to: "E", path: []string{"B", "C", "D", "E"}},
		{from: "A", to: "D", path: []string{"A", "B", "C", "D"}},
		{from: "D", to: "A", path: []string{"D", "C", "B", "A"}},
	}
	for _, check := range checks {
		route, ok := topologies[check.from].DataRoute(check.to)
		if !ok || !slices.Equal(route.Path, check.path) {
			t.Errorf("data route %s-%s = %+v, ok=%t, want %v", check.from, check.to, route, ok, check.path)
		}
		if got := topologies[check.from].DataNextHops()[check.to]; got != check.path[1] {
			t.Errorf("data next hop %s-%s = %q, want %q", check.from, check.to, got, check.path[1])
		}
	}
}

func setTopologyMember(t *testing.T, topology *Topology, nodeID string, local bool, now time.Time) {
	t.Helper()
	record := peercontrol.MemberRecord{NodeID: nodeID, Revision: 1, LeaseMillis: 10_000}
	if local {
		if err := topology.SetLocalMember(record); err != nil {
			t.Fatalf("SetLocalMember(%s) error = %v", nodeID, err)
		}
		return
	}
	if _, err := topology.ApplyMember(record, now); err != nil {
		t.Fatalf("ApplyMember(%s) error = %v", nodeID, err)
	}
}

func setTopologyLSA(t *testing.T, topology *Topology, state peercontrol.LinkStateAdvertisement, local bool, now time.Time) {
	t.Helper()
	if local {
		if err := topology.SetLocalLinkState(state); err != nil {
			t.Fatalf("SetLocalLinkState(%s) error = %v", state.NodeID, err)
		}
		return
	}
	if _, err := topology.ApplyLinkState(state, now); err != nil {
		t.Fatalf("ApplyLinkState(%s) error = %v", state.NodeID, err)
	}
}
