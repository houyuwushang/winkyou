package probeio

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/pkg/transport"
)

// The fake codec/packets prove gate ownership and actual transport calls, not
// cryptography. The c1bproof composition separately exercises real FINISHED
// authentication and the durable journal. Every fixture is independent, so
// parallel tests preserve the real 3s deadline without inflating the existing
// repeated-test CI wall-clock allowance.
func TestConsumerFinishedCompletionAfterChallengeDeadline(t *testing.T) {
	t.Parallel()
	for _, buffered := range []bool{false, true} {
		name := "received"
		if buffered {
			name = "buffered_then_authenticated"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gate, packets, lease, calls := completionPhaseFixture(t, WireGuardInitiator, buffered, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			deadline := completionChallengeDeadline(t, gate)
			finishCalls := 0
			err := gate.FinishAndActivate(ctx, func() error {
				finishCalls++
				if !gate.Witness().PeerFinishConfirmed {
					t.Error("local FINISH preceded authenticated peer FINISHED")
				}
				waitCompletionBoundary(deadline.Add(200 * time.Millisecond))
				return nil
			})
			w := gate.Witness()
			if err != nil {
				t.Fatalf("completion after challenge deadline rejected: gate_error=%t deadline=%t finish=%t peer_finish=%t detached=%t state=%s reads=%d writes=%d",
					errors.Is(err, ErrWireGuardGate), errors.Is(err, context.DeadlineExceeded),
					w.FinishRecorded, w.PeerFinishConfirmed, w.AttemptDetached, w.State, calls.reads.Load(), calls.writes.Load())
			}
			if finishCalls != 1 || !errors.Is(gate.challengeCtx.Err(), context.DeadlineExceeded) || gate.attemptCtx.Err() != nil {
				t.Fatal("fixture did not cross only the original challenge deadline exactly once")
			}
			assertCompletionPhaseActive(t, gate, packets, lease, calls)
		})
	}
}

func TestConsumerFinishedCompletionAbsoluteExpiryStillCloses(t *testing.T) {
	t.Parallel()
	gate, packets, lease, calls := completionPhaseFixture(t, WireGuardInitiator, false, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := gate.FinishAndActivate(ctx, func() error {
		<-gate.attemptCtx.Done()
		return nil // the durable write succeeded; its record must not be undone
	})
	if !errors.Is(err, ErrWireGuardGate) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("absolute expiry = %v, want gate/deadline failure", err)
	}
	assertCompletionPhaseClosed(t, gate, packets, lease, calls, 3)
}

func TestConsumerFinishedCompletionSessionCancelStillCloses(t *testing.T) {
	t.Parallel()
	gate, packets, lease, calls := completionPhaseFixture(t, WireGuardInitiator, false, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := gate.FinishAndActivate(ctx, func() error {
		cancel() // do not wait for the AfterFunc goroutine before returning
		return nil
	})
	if !errors.Is(err, ErrWireGuardGate) || !errors.Is(err, context.Canceled) {
		t.Fatalf("session cancellation = %v, want gate/cancel failure", err)
	}
	assertCompletionPhaseClosed(t, gate, packets, lease, calls, 3)
}

func TestConsumerFinishedResponderWriteRetainsChallengeDeadline(t *testing.T) {
	t.Parallel()
	gate, packets, lease, calls := completionPhaseFixture(t, WireGuardResponder, false, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	deadline := completionChallengeDeadline(t, gate)
	err := gate.FinishAndActivate(ctx, func() error {
		waitCompletionBoundary(deadline.Add(200 * time.Millisecond))
		return nil
	})
	if !errors.Is(err, ErrWireGuardGate) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late responder FINISHED = %v, want gate/deadline failure", err)
	}
	if gate.Witness().CompletionWrites != 0 {
		t.Fatal("expired responder entered FINISHED I/O")
	}
	assertCompletionPhaseClosed(t, gate, packets, lease, calls, 2)
}

func TestConsumerFinishedDetachAfterChallengeDeadline(t *testing.T) {
	t.Parallel()
	for _, role := range []WireGuardRole{WireGuardInitiator, WireGuardResponder} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			gate, packets, lease, calls := completionPhaseFixture(t, role, false, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			deadline := completionChallengeDeadline(t, gate)
			lease.mu.Lock()
			lease.drain = &completionPhaseDrain{DrainHandle: lease.drain, beforeComplete: func() {
				w := gate.Witness()
				if !w.FinishRecorded || calls.reads.Load() != 3 || calls.writes.Load() != 3 ||
					(role == WireGuardResponder && w.CompletionWrites != 1) {
					t.Error("detach preceded durable FINISH and the exact 3/3 exchange")
				}
				waitCompletionBoundary(deadline.Add(200 * time.Millisecond))
			}}
			lease.mu.Unlock()
			if err := gate.FinishAndActivate(ctx, func() error { return nil }); err != nil {
				t.Fatalf("local detach after completed datagrams was rejected: %v; witness=%+v", err, gate.Witness())
			}
			if !errors.Is(gate.challengeCtx.Err(), context.DeadlineExceeded) || gate.attemptCtx.Err() != nil {
				t.Fatal("detach fixture did not cross only the original challenge deadline")
			}
			assertCompletionPhaseActive(t, gate, packets, lease, calls)
		})
	}
}

func completionPhaseFixture(t *testing.T, role WireGuardRole, buffered bool, absolute time.Duration) (
	*WireGuardSessionGate, *wireGuardGateTransport, *TransportLease, *completionPhaseCalls,
) {
	t.Helper()
	gate, packets, lease := newWireGuardGate(t, role) // original 10s absolute fixture
	if absolute > 0 {
		ctx, cancel := context.WithTimeout(gate.attemptCtx, absolute)
		t.Cleanup(cancel)
		gate.attemptCtx = ctx // before BeginChallenge: both phases inherit this bound
	}
	calls := &completionPhaseCalls{PacketTransport: packets}
	lease.mu.Lock()
	lease.transport = calls // still accessed through the actual leaseTransport
	lease.mu.Unlock()
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
		packets.queueRead(fakeConsumerFinishedFrame())
		if buffered {
			if n, _, err := gate.ReadPacket(context.Background(), make([]byte, 256)); n != 0 || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("buffered completion escaped to binder")
			}
			if gate.Witness().PeerFinishConfirmed {
				t.Fatal("buffering conferred authentication")
			}
		}
	} else {
		read(WireGuardHandshakeInitiation)
		write(WireGuardHandshakeResponse)
		read(WireGuardTransportData)
	}
	if err := gate.CompleteChallenge(); err != nil {
		t.Fatal(err)
	}
	return gate, packets, lease, calls
}

func completionChallengeDeadline(t *testing.T, gate *WireGuardSessionGate) time.Time {
	t.Helper()
	deadline, ok := gate.challengeCtx.Deadline()
	if !ok {
		t.Fatal("challenge lacks its original deadline")
	}
	return deadline
}

func waitCompletionBoundary(at time.Time) {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	<-timer.C
}

func assertCompletionPhaseActive(t *testing.T, gate *WireGuardSessionGate, packets *wireGuardGateTransport,
	lease *TransportLease, calls *completionPhaseCalls,
) {
	t.Helper()
	w := gate.Witness()
	if !w.FinishRecorded || !w.AttemptDetached || w.State != WireGuardGateActive || w.Closed ||
		!lease.Witness().AttemptDetached || packets.isClosed() || w.ActiveReads != 0 || w.ActiveWrites != 0 ||
		(gate.role == WireGuardInitiator && !w.PeerFinishConfirmed) {
		t.Fatalf("completion ownership witness = %+v", w)
	}
	if calls.reads.Load() != 3 || calls.writes.Load() != 3 || packets.writeCount() != 3 ||
		lease.Witness().PacketsRead != 3 || lease.Witness().PacketsWritten != 3 {
		t.Fatalf("completion changed actual I/O: reads=%d writes=%d", calls.reads.Load(), calls.writes.Load())
	}
	t.Logf("completion active: role=%s FINISH=true detached=true reads=3 writes=3 extra_packets=0", gate.role)
}

func assertCompletionPhaseClosed(t *testing.T, gate *WireGuardSessionGate, packets *wireGuardGateTransport,
	lease *TransportLease, calls *completionPhaseCalls, writes int32,
) {
	t.Helper()
	w := gate.Witness()
	if !w.FinishRecorded || w.AttemptDetached || w.State != WireGuardGateClosed || !w.Closed ||
		lease.Witness().AttemptDetached || !packets.isClosed() || w.ActiveReads != 0 || w.ActiveWrites != 0 ||
		(gate.role == WireGuardInitiator && !w.PeerFinishConfirmed) {
		t.Fatalf("failed completion ownership witness = %+v", w)
	}
	if calls.reads.Load() != 3 || calls.writes.Load() != writes || packets.writeCount() != int(writes) {
		t.Fatalf("failed completion reached extra I/O: reads=%d writes=%d", calls.reads.Load(), calls.writes.Load())
	}
}

type completionPhaseCalls struct {
	transport.PacketTransport
	reads  atomic.Int32
	writes atomic.Int32
}

func (calls *completionPhaseCalls) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	calls.reads.Add(1)
	return calls.PacketTransport.ReadPacket(ctx, dst)
}

func (calls *completionPhaseCalls) WritePacket(ctx context.Context, packet []byte) error {
	calls.writes.Add(1)
	return calls.PacketTransport.WritePacket(ctx, packet)
}

type completionPhaseDrain struct {
	governor.DrainHandle
	beforeComplete func()
}

func (drain *completionPhaseDrain) Complete() error {
	drain.beforeComplete()
	return drain.DrainHandle.Complete()
}
