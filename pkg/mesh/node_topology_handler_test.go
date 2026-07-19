package mesh

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
)

func TestNodeTopologyHandlerFiresOnlyAfterActualChanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	node := mustNode(t, NodeConfig{
		NodeID: "A", Lease: time.Second, RefreshInterval: 5 * time.Millisecond,
	})
	var notifications atomic.Int32
	callbackErr := make(chan error, 1)
	unregister, err := node.RegisterTopologyHandler(func() {
		notifications.Add(1)
		// Registering another callback takes Node.mu and proves notifications are
		// invoked outside that lock. The nested callback is immediately removed.
		removeNested, registerErr := node.RegisterTopologyHandler(func() {})
		if registerErr != nil {
			select {
			case callbackErr <- registerErr:
			default:
			}
			return
		}
		removeNested()
		_ = node.Routes()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Start(ctx); err != nil {
		t.Fatal(err)
	}

	member := peercontrol.MemberRecord{
		NodeID: "B", Revision: 1, LeaseMillis: 40, VirtualIP: "fd00::b",
	}
	if err := node.handleMessage(ctx, peercontrol.NewMemberAnnounce("B", member, 8)); err != nil {
		t.Fatal(err)
	}
	if got := notifications.Load(); got != 1 {
		t.Fatalf("member change notifications = %d, want 1", got)
	}
	// An identical equal-revision record refreshes its lease but does not change
	// the visible topology and therefore must not wake handlers.
	if err := node.handleMessage(ctx, peercontrol.NewMemberAnnounce("B", member, 8)); err != nil {
		t.Fatal(err)
	}
	if got := notifications.Load(); got != 1 {
		t.Fatalf("identical member notifications = %d, want 1", got)
	}
	conflict := member
	conflict.VirtualIP = "fd00::different"
	if err := node.handleMessage(ctx, peercontrol.NewMemberAnnounce("B", conflict, 8)); err == nil {
		t.Fatal("equal-revision member conflict unexpectedly succeeded")
	}
	if got := notifications.Load(); got != 1 {
		t.Fatalf("conflicting member notifications = %d, want 1", got)
	}

	state := peercontrol.LinkStateAdvertisement{
		NodeID: "B", Revision: 1, LeaseMillis: 40, TransitAllowed: true,
	}
	if err := node.handleMessage(ctx, peercontrol.NewLinkState("B", state, 8)); err != nil {
		t.Fatal(err)
	}
	if err := node.handleMessage(ctx, peercontrol.NewLinkState("B", state, 8)); err != nil {
		t.Fatal(err)
	}
	if got := notifications.Load(); got != 2 {
		t.Fatalf("link-state notifications = %d, want 2", got)
	}

	neighbor := &recordingSession{peerID: "C"}
	if err := node.router.AddNeighbor(neighbor); err != nil {
		t.Fatal(err)
	}
	if got := notifications.Load(); got != 3 {
		t.Fatalf("neighbor-up notifications = %d, want 3", got)
	}
	if err := node.RemoveNeighbor("C"); err != nil {
		t.Fatal(err)
	}
	if got := notifications.Load(); got != 4 {
		t.Fatalf("neighbor-down notifications = %d, want 4", got)
	}

	eventually(t, ctx, func() bool { return notifications.Load() == 5 }, "remote topology did not notify once on expiry")
	time.Sleep(20 * time.Millisecond)
	if got := notifications.Load(); got != 5 {
		t.Fatalf("expiry notifications = %d, want exactly 5", got)
	}
	select {
	case err := <-callbackErr:
		t.Fatalf("topology callback ran under an unusable lock: %v", err)
	default:
	}

	unregister()
	memberD := peercontrol.MemberRecord{NodeID: "D", Revision: 1, LeaseMillis: 100}
	if err := node.handleMessage(ctx, peercontrol.NewMemberAnnounce("D", memberD, 8)); err != nil {
		t.Fatal(err)
	}
	if got := notifications.Load(); got != 5 {
		t.Fatalf("unregistered handler notifications = %d, want 5", got)
	}
}

func TestNodeRegisterTopologyHandlerRejectsNilAndClosedNode(t *testing.T) {
	node := mustNode(t, NodeConfig{NodeID: "A"})
	if _, err := node.RegisterTopologyHandler(nil); err == nil {
		t.Fatal("nil topology handler unexpectedly registered")
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := node.RegisterTopologyHandler(func() {}); err == nil {
		t.Fatal("topology handler registered after close")
	}
}

type topologyTestNeighbor struct {
	*recordingSession
	kind NeighborKind
}

func (s *topologyTestNeighbor) neighborKind() NeighborKind { return s.kind }

type topologyTestDataNeighbor struct {
	*topologyTestNeighbor
}

func (s *topologyTestDataNeighbor) SendData(context.Context, DataFrame) error { return nil }

func TestNodeNeighborReplacementRebuildsRoutesAndPublishesCapability(t *testing.T) {
	tests := []struct {
		name             string
		newSession       func() NeighborSession
		wantControlOnly  bool
		wantDataRouteVia string
	}{
		{
			name: "same kind data-capable",
			newSession: func() NeighborSession {
				return &topologyTestDataNeighbor{topologyTestNeighbor: &topologyTestNeighbor{
					recordingSession: &recordingSession{peerID: "B"}, kind: NeighborKindPacket,
				}}
			},
			wantDataRouteVia: "B",
		},
		{
			name: "different kind control-only",
			newSession: func() NeighborSession {
				return &topologyTestNeighbor{
					recordingSession: &recordingSession{peerID: "B"}, kind: NeighborKindStream,
				}
			},
			wantControlOnly: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			node := mustNode(t, NodeConfig{NodeID: "A", Lease: time.Second})
			t.Cleanup(func() { _ = node.Close() })
			now := time.Now()
			for _, nodeID := range []string{"B", "C"} {
				setTopologyMember(t, node.topology, nodeID, false, now)
			}
			setTopologyLSA(t, node.topology, peercontrol.LinkStateAdvertisement{
				NodeID: "B", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
				Links: []peercontrol.LinkStateLink{{PeerID: "A"}, {PeerID: "C"}},
			}, false, now)
			setTopologyLSA(t, node.topology, peercontrol.LinkStateAdvertisement{
				NodeID: "C", Revision: 1, LeaseMillis: 10_000, TransitAllowed: true,
				Links: []peercontrol.LinkStateLink{{PeerID: "B"}},
			}, false, now)

			oldSession := &topologyTestDataNeighbor{topologyTestNeighbor: &topologyTestNeighbor{
				recordingSession: &recordingSession{peerID: "B"}, kind: NeighborKindPacket,
			}}
			oldHandle, err := node.router.addNeighbor(oldSession)
			if err != nil {
				t.Fatal(err)
			}
			if got := node.router.Routes()["C"]; got != "B" {
				t.Fatalf("initial control route to C = %q, want B", got)
			}
			if got := node.topology.DataNextHops()["C"]; got != "B" {
				t.Fatalf("initial data route to C = %q, want B", got)
			}
			before := node.localLinkState()

			var notifications atomic.Int32
			unregister, err := node.RegisterTopologyHandler(func() { notifications.Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			defer unregister()

			entry, removed := node.router.detachNeighborHandle(oldHandle)
			if !removed {
				t.Fatal("old neighbor was not detached")
			}
			defer entry.session.Close()
			if got := node.router.Routes()["C"]; got != "" {
				t.Fatalf("detach retained stale control route to C via %q", got)
			}

			// Attach the replacement before delivering the old Down event. Suppress
			// the replacement Up callback so the stale Down is solely responsible
			// for observing its new identity/kind/capability.
			onNeighborChange := node.router.onNeighborChange
			node.router.onNeighborChange = nil
			if _, err := node.router.addNeighbor(test.newSession()); err != nil {
				node.router.onNeighborChange = onNeighborChange
				t.Fatal(err)
			}
			node.router.onNeighborChange = onNeighborChange
			node.handleNeighborChange(NeighborEvent{PeerID: "B", Up: false})

			after := node.localLinkState()
			if after.Revision != before.Revision+1 {
				t.Fatalf("replacement LSA revision = %d, want %d", after.Revision, before.Revision+1)
			}
			if len(after.Links) != 1 || after.Links[0].PeerID != "B" ||
				after.Links[0].ControlOnly != test.wantControlOnly {
				t.Fatalf("replacement local LSA = %+v", after)
			}
			if got := node.router.Routes()["C"]; got != "B" {
				t.Fatalf("stale Down did not restore control route to C: %q", got)
			}
			if got := node.topology.DataNextHops()["C"]; got != test.wantDataRouteVia {
				t.Fatalf("replacement data route to C = %q, want %q", got, test.wantDataRouteVia)
			}
			if got := notifications.Load(); got != 1 {
				t.Fatalf("replacement notifications = %d, want 1", got)
			}

			// Even a duplicate event for the same current identity must rebuild
			// tables: detach may have purged them immediately before this callback.
			if err := node.router.replaceRouteTables(nil, nil); err != nil {
				t.Fatal(err)
			}
			revision := after.Revision
			node.handleNeighborChange(NeighborEvent{PeerID: "B", Up: true})
			if got := node.router.Routes()["C"]; got != "B" {
				t.Fatalf("unchanged event did not rebuild control route to C: %q", got)
			}
			if got := node.topology.DataNextHops()["C"]; got != test.wantDataRouteVia {
				t.Fatalf("unchanged event data route to C = %q, want %q", got, test.wantDataRouteVia)
			}
			if got := node.localLinkState().Revision; got != revision {
				t.Fatalf("logically unchanged event advanced LSA revision to %d, want %d", got, revision)
			}
			if got := notifications.Load(); got != 1 {
				t.Fatalf("unchanged event notifications = %d, want changed-only count 1", got)
			}
		})
	}
}
