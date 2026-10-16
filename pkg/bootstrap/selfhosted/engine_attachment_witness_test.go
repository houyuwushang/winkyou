package selfhosted

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/recoverycard"
)

// One bounded receipt per endpoint records the successful attachment before
// Observe promotes its endpoint and a later attempt can replace Snapshot.
type engineFirstAttachment struct {
	once  sync.Once
	ready chan Event
}

func newEngineFirstAttachment() *engineFirstAttachment {
	return &engineFirstAttachment{ready: make(chan Event, 1)}
}

func (w *engineFirstAttachment) observe(event Event) {
	if event.State != StateAttached || event.Err != nil {
		return
	}
	w.once.Do(func() { w.ready <- event })
}

func (w *engineFirstAttachment) wait(t *testing.T, ctx context.Context) Event {
	t.Helper()
	select {
	case event := <-w.ready:
		return event
	case <-ctx.Done():
		t.Fatalf("first successful attachment was not observed: %v", ctx.Err())
		return Event{}
	}
}

func TestEngineFirstAttachmentSurvivesCandidateRankPromotion(t *testing.T) {
	// No engine is started and no socket is opened. Exercise the real card
	// promotion, candidate selection and event/status paths deterministically.
	newest := time.Now().UTC().Add(-time.Minute)
	store := saveEngineCard(t, "A", 41000, recoverycard.Peer{
		NodeID: "B", LastSuccessfulLocalBindPort: 41000, LastSuccessAt: newest,
		Endpoints: []recoverycard.Endpoint{
			engineEndpointAt("192.0.2.11", 42001, newest),
			engineEndpointAt("127.0.0.1", 42000, newest.Add(-time.Minute)),
		},
	})
	engine := newObservationEngine(t, store)
	witness := newEngineFirstAttachment()
	engine.cfg.OnEvent = witness.observe
	selectAndAttach := func(ordinal int64) {
		t.Helper()
		card, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		portfolio := buildCandidatePortfolio(findEnginePeer(t, card, "B"), true)
		selection, ok := selectRecoveryCandidate(engine.peers["B"], portfolio, ordinal, puncher.RoleSelector)
		if !ok {
			t.Fatal("candidate missing")
		}
		engine.setStatus("B", func(status *PeerStatus) {
			applyCandidateSelection(status, selection)
			status.LearnedRemote = "127.0.0.1:42000"
		})
		engine.emitAttached("B", "fixture", "127.0.0.1:42000", mesh.NeighborHandle{}, nil)
	}
	selectAndAttach(1) // The initially older loopback group has rank 2.
	if err := engine.Observe(Observation{
		PeerID: "B", RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 42000},
		LocalAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41000},
		At:        newest.Add(time.Second), Source: "selfbootstrap",
	}); err != nil {
		t.Fatal(err)
	}
	selectAndAttach(0) // The same endpoint is now rank 1 after persistence.
	current := engine.Snapshot()[0]
	if current.CandidateGroup != "127.0.0.1" || current.CandidateIndex != 1 || current.CandidateTotal != 2 {
		t.Fatalf("promotion control did not replace the original snapshot: %+v", current)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first := witness.wait(t, ctx)
	if first.CandidateGroup != "127.0.0.1" || first.CandidateIndex != 2 || first.CandidateTotal != 2 {
		t.Fatalf("first attachment lost the older selection: %+v", first)
	}
	t.Logf("SELFHOSTED_RANK_PROMOTION snapshot_index=%d first_attachment_index=%d old_snapshot_oracle=false", current.CandidateIndex, first.CandidateIndex)
}

func TestEngineFirstAttachmentRejectsIncompleteEvents(t *testing.T) {
	witness := newEngineFirstAttachment()
	for _, event := range []Event{
		{State: StatePunching, CandidateIndex: 2},
		{State: StateHello, CandidateIndex: 2},
		{State: StateAttached, CandidateIndex: 2, Err: errors.New("attachment failed")},
	} {
		witness.observe(event)
		select {
		case got := <-witness.ready:
			t.Fatalf("incomplete event counted as an attachment: %+v", got)
		default:
		}
	}
	witness.observe(Event{State: StateAttached, CandidateIndex: 1})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := witness.wait(t, ctx); got.CandidateIndex != 1 {
		t.Fatalf("successful event was not retained: %+v", got)
	}
}
