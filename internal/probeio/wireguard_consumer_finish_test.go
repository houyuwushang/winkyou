package probeio

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Uses synthetic message-type packets, not WireGuard authentication. Full
// crypto/journal composition is exercised separately by the C1b CLI proof.
func prepareCompletionGate(t *testing.T, role WireGuardRole, complete bool) (*WireGuardSessionGate, *wireGuardGateTransport, *TransportLease) {
	t.Helper()
	gate, packets, lease := newWireGuardGate(t, role)
	if err := beginReadyChallenge(gate, packets); err != nil {
		t.Fatal(err)
	}
	write := func(kind WireGuardMessageType) {
		t.Helper()
		if err := gate.WritePacket(context.Background(), wireGuardPacket(kind)); err != nil {
			t.Fatal(err)
		}
	}
	read := func(kind WireGuardMessageType) {
		t.Helper()
		packets.queueRead(wireGuardPacket(kind))
		if _, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); err != nil {
			t.Fatal(err)
		}
	}
	if role == WireGuardInitiator {
		write(WireGuardHandshakeInitiation)
		read(WireGuardHandshakeResponse)
		write(WireGuardTransportData)
	} else {
		read(WireGuardHandshakeInitiation)
		write(WireGuardHandshakeResponse)
		read(WireGuardTransportData)
	}
	if complete {
		if err := gate.CompleteChallenge(); err != nil {
			t.Fatal(err)
		}
	}
	return gate, packets, lease
}

func TestConsumerFinishedDelaysInitiatorUntilPeerDurableFinish(t *testing.T) {
	left, leftIO, leftLease := prepareCompletionGate(t, WireGuardInitiator, true)
	right, rightIO, rightLease := prepareCompletionGate(t, WireGuardResponder, true)
	leftIO.peer, rightIO.peer = rightIO, leftIO
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var leftFinished atomic.Bool
	leftDone, rightDone := make(chan error, 1), make(chan error, 1)
	entered, commit := make(chan struct{}), make(chan struct{})
	go func() { leftDone <- left.FinishAndActivate(ctx, func() error { leftFinished.Store(true); return nil }) }()
	go func() {
		rightDone <- right.FinishAndActivate(ctx, func() error { close(entered); <-commit; return nil })
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("peer FINISH callback not entered")
	}
	// No sleeps or retry: hold the precise durable callback boundary. The
	// original unilateral-FINISH diagnostic permitted left success here.
	if leftFinished.Load() || leftLease.Witness().AttemptDetached || rightLease.Witness().AttemptDetached ||
		leftIO.writeCount() != 3 || rightIO.writeCount() != 2 {
		close(commit)
		t.Fatal("initiator FINISH/detach or confirmation preceded peer durability")
	}
	close(commit)
	for _, done := range []chan error{rightDone, leftDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("R1 did not finish")
		}
	}
	if !leftFinished.Load() || leftIO.writeCount() != 3 || rightIO.writeCount() != 3 {
		t.Fatal("R1 changed frozen three-packet allowances")
	}
	for _, gate := range []*WireGuardSessionGate{left, right} {
		w := gate.Witness()
		if !w.FinishRecorded || !w.AttemptDetached || w.State != WireGuardGateActive || w.ActiveWrites != 0 ||
			len(w.Outbound)+w.ReadinessWrites+w.CompletionWrites != 3 || len(w.Inbound)+w.ReadinessReads+w.CompletionReads != 3 {
			t.Fatalf("R1 witness = %+v", w)
		}
	}
}

func TestConsumerFinishedBufferedBeforeLocalCompletionNeverReachesBinder(t *testing.T) {
	gate, packets, _ := prepareCompletionGate(t, WireGuardInitiator, false)
	packets.queueRead(fakeConsumerFinishedFrame())
	if n, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); n != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("binder consumed a completion frame")
	}
	if w := gate.Witness(); w.PeerFinishConfirmed || w.FinishRecorded || w.CompletionReads != 1 {
		t.Fatal("buffering granted completion authority")
	}
	if err := gate.CompleteChallenge(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gate.FinishAndActivate(ctx, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	packets.queueRead(fakeConsumerFinishedFrame())
	if _, _, err := gate.ReadPacket(ctx, make([]byte, 256)); err == nil || !packets.isClosed() {
		t.Fatal("post-completion replay accepted")
	}
}

func TestConsumerFinishedFailureNeverDetachesOrRetries(t *testing.T) {
	for _, mode := range []string{"peer-absent", "invalid", "durable-failure", "early-eof", "cancel-during-finish", "writer-failure", "fourth-write"} {
		t.Run(mode, func(t *testing.T) {
			role := WireGuardResponder
			if mode == "peer-absent" || mode == "invalid" {
				role = WireGuardInitiator
			}
			gate, packets, lease := prepareCompletionGate(t, role, true)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			callback := func() error { return nil }
			switch mode {
			case "peer-absent":
				gate.challengeCtx, gate.challengeStop = context.WithTimeout(gate.challengeCtx, 10*time.Millisecond)
			case "invalid":
				packets.queueRead(make([]byte, 40))
			case "durable-failure":
				callback = func() error { return errors.New("synthetic durable failure") }
			case "early-eof":
				gate.attemptCancel()
			case "cancel-during-finish":
				callback = func() error { gate.attemptCancel(); return nil }
			case "writer-failure":
				_ = packets.Close()
			case "fourth-write":
				gate.completionWrites = 1
			}
			if err := gate.FinishAndActivate(ctx, callback); err == nil {
				t.Fatal("failure activated")
			}
			if lease.Witness().AttemptDetached || !packets.isClosed() || packets.writeCount() > 3 {
				t.Fatal("failure leaked or retried")
			}
			if mode == "durable-failure" && gate.Witness().CompletionWrites != 0 {
				t.Fatal("confirmation preceded durable success")
			}
		})
	}
}

func TestConsumerFinishedDrainedReaderCannotCloseLaterOwnershipState(t *testing.T) {
	for _, state := range []WireGuardGateState{wireGuardGateChallengeDrain, WireGuardGateChallengePassed,
		wireGuardGateFinishConfirming, WireGuardGateFinishDetached, WireGuardGateActive} {
		t.Run(string(state), func(t *testing.T) {
			gate, _, _ := newWireGuardGate(t, WireGuardInitiator)
			gate.state = state
			if err, ok := gate.benignReadContextEnd(context.Background(), WireGuardGateChallengeCapped, context.Canceled); !ok || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("handoff mistook its own drained read for a session failure")
			}
		})
	}
}

func TestConsumerFinishedExpiredQueuedBinderPollDoesNotCloseActiveSession(t *testing.T) {
	gate, _, _ := prepareCompletionGate(t, WireGuardResponder, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gate.FinishAndActivate(ctx, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	pollCtx, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stop()
	if _, _, err := gate.ReadPacket(pollCtx, make([]byte, 256)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired poll was not a polling sentinel")
	}
	if gate.Witness().Closed {
		t.Fatal("queued expired polling receive closed the active session")
	}
}
