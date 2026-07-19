package mesh

import (
	"errors"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
)

func TestRestartedControlPlaneUsesNewerCounters(t *testing.T) {
	first := mustNode(t, NodeConfig{NodeID: "A"})
	first.mu.Lock()
	first.member.Revision += 100
	first.lsaRevision += 100
	firstMemberRevision := first.member.Revision
	firstLSARevision := first.lsaRevision
	first.mu.Unlock()
	firstSequence := first.router.seq.Add(100)

	second := mustNode(t, NodeConfig{NodeID: "A"})
	second.mu.Lock()
	secondMemberRevision := second.member.Revision
	secondLSARevision := second.lsaRevision
	second.mu.Unlock()
	secondSequence := second.router.seq.Add(1)

	if secondMemberRevision <= firstMemberRevision {
		t.Fatalf("restarted member revision = %d, want > %d", secondMemberRevision, firstMemberRevision)
	}
	if secondLSARevision <= firstLSARevision {
		t.Fatalf("restarted LSA revision = %d, want > %d", secondLSARevision, firstLSARevision)
	}
	if secondSequence <= firstSequence {
		t.Fatalf("restarted message sequence base = %d, want > %d", secondSequence, firstSequence)
	}
	seenObserver, err := NewRouter(Config{NodeID: "observer-seen"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = seenObserver.Close() })
	oldMessage := peercontrol.Message{From: "A", Seq: firstSequence}
	if err := seenObserver.markSeen(oldMessage, time.Now()); err != nil {
		t.Fatalf("record old process sequence: %v", err)
	}
	if err := seenObserver.markSeen(oldMessage, time.Now()); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("repeat old process sequence error = %v, want duplicate", err)
	}
	if err := seenObserver.markSeen(peercontrol.Message{From: "A", Seq: secondSequence}, time.Now()); err != nil {
		t.Fatalf("restarted process sequence collided with seen cache: %v", err)
	}

	observer, err := NewTopology("observer")
	if err != nil {
		t.Fatal(err)
	}
	oldMember := peercontrol.MemberRecord{
		NodeID: "A", Revision: firstMemberRevision, LeaseMillis: 30_000, VirtualIP: "fd00::old",
	}
	if changed, err := observer.ApplyMember(oldMember, time.Now()); err != nil || !changed {
		t.Fatalf("apply old member: changed=%t err=%v", changed, err)
	}
	newMember := peercontrol.MemberRecord{
		NodeID: "A", Revision: secondMemberRevision, LeaseMillis: 30_000, VirtualIP: "fd00::new",
	}
	if changed, err := observer.ApplyMember(newMember, time.Now()); err != nil || !changed {
		t.Fatalf("apply restarted member without waiting for lease expiry: changed=%t err=%v", changed, err)
	}
	if got, ok := observer.Member("A"); !ok || got.Revision != secondMemberRevision || got.VirtualIP != "fd00::new" {
		t.Fatalf("observer retained stale pre-restart member: %+v, ok=%t", got, ok)
	}
	oldState := peercontrol.LinkStateAdvertisement{
		NodeID: "A", Revision: firstLSARevision, LeaseMillis: 30_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{{PeerID: "old-peer", RTTMillis: 1}},
	}
	if changed, err := observer.ApplyLinkState(oldState, time.Now()); err != nil || !changed {
		t.Fatalf("apply old LSA: changed=%t err=%v", changed, err)
	}
	newState := peercontrol.LinkStateAdvertisement{
		NodeID: "A", Revision: secondLSARevision, LeaseMillis: 30_000, TransitAllowed: true,
		Links: []peercontrol.LinkStateLink{{PeerID: "new-peer", RTTMillis: 1}},
	}
	if changed, err := observer.ApplyLinkState(newState, time.Now()); err != nil || !changed {
		t.Fatalf("apply restarted LSA without waiting for lease expiry: changed=%t err=%v", changed, err)
	}
	observer.mu.RLock()
	stored, ok := observer.lsas["A"]
	got := stored.record
	observer.mu.RUnlock()
	if !ok || got.Revision != secondLSARevision || len(got.Links) != 1 || got.Links[0].PeerID != "new-peer" {
		t.Fatalf("observer retained stale pre-restart LSA: %+v, ok=%t", got, ok)
	}
}

func TestBootCounterCandidateReservesInProcessStride(t *testing.T) {
	const previous = uint64(10_000_000)
	got := bootCounterCandidate(int64(previous+17), previous)
	if want := previous + bootCounterStride; got != want {
		t.Fatalf("boot counter candidate = %d, want reserved minimum %d", got, want)
	}
}
