package mesh

import (
	"context"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
)

type recordingDataSession struct {
	*recordingSession

	dataMu sync.Mutex
	frames []DataFrame
}

func (s *recordingDataSession) SendData(_ context.Context, frame DataFrame) error {
	s.dataMu.Lock()
	s.frames = append(s.frames, cloneDataFrame(frame))
	s.dataMu.Unlock()
	return nil
}

func (s *recordingDataSession) dataSnapshot() []DataFrame {
	s.dataMu.Lock()
	defer s.dataMu.Unlock()
	result := make([]DataFrame, len(s.frames))
	for index, frame := range s.frames {
		result[index] = cloneDataFrame(frame)
	}
	return result
}

func TestDataRouterUsesPacketAlternateAroundControlOnlyDirectStream(t *testing.T) {
	router := newTestRouter(t, "A", nil)
	controlConn, peerConn := net.Pipe()
	t.Cleanup(func() { _ = peerConn.Close() })
	controlOnly, err := NewStreamNeighborSession(
		"C",
		controlConn,
		func(context.Context, string, peercontrol.Message) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	viaB := &recordingDataSession{recordingSession: &recordingSession{peerID: "B"}}
	addTestNeighbor(t, router, controlOnly)
	addTestNeighbor(t, router, viaB)

	topology, err := NewTopology("A")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, nodeID := range []string{"A", "B", "C", "D"} {
		setTopologyMember(t, topology, nodeID, nodeID == "A", now)
	}
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "A", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "B", RTTMillis: 20},
			{PeerID: "C", RTTMillis: 1, ControlOnly: true},
		},
	}, true, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "B", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "A", RTTMillis: 20},
			{PeerID: "C", RTTMillis: 1},
			{PeerID: "D", RTTMillis: 10},
		},
	}, false, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "C", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "A", RTTMillis: 1},
			{PeerID: "B", RTTMillis: 1},
			{PeerID: "D", RTTMillis: 1},
		},
	}, false, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "D", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "B", RTTMillis: 10},
			{PeerID: "C", RTTMillis: 1},
		},
	}, false, now)

	node := &Node{router: router, topology: topology}
	node.syncRoutes()
	if direct, ok := topology.Route("C"); !ok || !slices.Equal(direct.Path, []string{"A", "C"}) {
		t.Fatalf("control route to C = %+v, ok=%t", direct, ok)
	}
	if alternate, ok := topology.AlternateRoute("C"); !ok || !slices.Equal(alternate.Path, []string{"A", "B", "C"}) {
		t.Fatalf("alternate route to C = %+v, ok=%t", alternate, ok)
	}
	if direct, ok := topology.Route("D"); !ok || !slices.Equal(direct.Path, []string{"A", "C", "D"}) {
		t.Fatalf("control route to D = %+v, ok=%t", direct, ok)
	}

	frame := DataFrame{
		Version: DataFrameVersion, Type: DataTypeStreamData, HopLimit: 8,
		Source: "A", Destination: "C", FlowID: 9, Sequence: 1, Payload: []byte("packet alternate"),
	}
	if err := router.SendData(context.Background(), frame); err != nil {
		t.Fatalf("SendData through packet alternate: %v", err)
	}
	frame.Destination = "D"
	frame.Sequence++
	frame.Payload = []byte("packet alternate to fourth node")
	if err := router.SendData(context.Background(), frame); err != nil {
		t.Fatalf("SendData to D around control-only next hop: %v", err)
	}
	got := viaB.dataSnapshot()
	if len(got) != 2 || got[0].Destination != "C" || got[1].Destination != "D" ||
		!slices.Equal(got[1].Payload, frame.Payload) {
		t.Fatalf("frames sent through B = %+v, want frames for C and D", got)
	}
}

func TestDataRouterHonorsRemoteControlOnlyForDataCapableDirectNeighbor(t *testing.T) {
	router := newTestRouter(t, "A", nil)
	directB := &recordingDataSession{recordingSession: &recordingSession{peerID: "B"}}
	viaC := &recordingDataSession{recordingSession: &recordingSession{peerID: "C"}}
	addTestNeighbor(t, router, directB)
	addTestNeighbor(t, router, viaC)

	topology, err := NewTopology("A")
	if err != nil {
		t.Fatal(err)
	}
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
			// Only the remote endpoint marks A-B control-only. A's physical
			// session remains data-capable, but must not bypass the global view.
			{PeerID: "A", RTTMillis: 1, ControlOnly: true},
			{PeerID: "C", RTTMillis: 5},
		},
	}, false, now)
	setTopologyLSA(t, topology, peercontrol.LinkStateAdvertisement{
		NodeID: "C", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "A", RTTMillis: 5},
			{PeerID: "B", RTTMillis: 5},
		},
	}, false, now)

	node := &Node{router: router, topology: topology}
	node.syncRoutes()
	if route, ok := topology.Route("B"); !ok || !slices.Equal(route.Path, []string{"A", "B"}) {
		t.Fatalf("control route A-B = %+v, ok=%t", route, ok)
	}
	if route, ok := topology.DataRoute("B"); !ok || !slices.Equal(route.Path, []string{"A", "C", "B"}) {
		t.Fatalf("control-only data route A-B = %+v, ok=%t", route, ok)
	}

	frame := DataFrame{
		Version: DataFrameVersion, Type: DataTypeStreamData, HopLimit: 8,
		Source: "A", Destination: "B", FlowID: 10, Sequence: 1, Payload: []byte("via C"),
	}
	if err := router.SendData(context.Background(), frame); err != nil {
		t.Fatalf("SendData around remotely control-only direct edge: %v", err)
	}
	if got := directB.dataSnapshot(); len(got) != 0 {
		t.Fatalf("remote ControlOnly was bypassed through direct B: %+v", got)
	}
	if got := viaC.dataSnapshot(); len(got) != 1 || got[0].Destination != "B" {
		t.Fatalf("alternate frames through C = %+v, want one for B", got)
	}

	// Once both endpoints advertise the ordinary data-capable edge again, the
	// authoritative table is allowed to select the direct neighbor normally.
	if changed, applyErr := topology.ApplyLinkState(peercontrol.LinkStateAdvertisement{
		NodeID: "B", Revision: 2, LeaseMillis: 10_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{
			{PeerID: "A", RTTMillis: 1},
			{PeerID: "C", RTTMillis: 5},
		},
	}, now.Add(time.Millisecond)); applyErr != nil || !changed {
		t.Fatalf("restore B data-capable LSA changed=%t error=%v", changed, applyErr)
	}
	node.syncRoutes()
	if route, ok := topology.DataRoute("B"); !ok || !slices.Equal(route.Path, []string{"A", "B"}) {
		t.Fatalf("restored data route A-B = %+v, ok=%t", route, ok)
	}
	frame.Sequence++
	frame.Payload = []byte("direct B")
	if err := router.SendData(context.Background(), frame); err != nil {
		t.Fatalf("SendData over restored direct edge: %v", err)
	}
	if got := directB.dataSnapshot(); len(got) != 1 || !slices.Equal(got[0].Payload, frame.Payload) {
		t.Fatalf("restored direct frames to B = %+v", got)
	}
	if got := viaC.dataSnapshot(); len(got) != 1 {
		t.Fatalf("restored direct edge still used C: %+v", got)
	}
}
