package governor_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/loopbackcarrier"
)

func TestLoopbackTerminalRevokeRetainsSecondDrainTripwire(t *testing.T) {
	for _, finishComplete := range []bool{true, false} {
		name := "finish-complete"
		if !finishComplete {
			name = "owner-drain-missing"
		}
		t.Run(name, func(t *testing.T) {
			namespace := t.TempDir()
			if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, time.Now()); err != nil {
				t.Fatal(err)
			}
			machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "terminal-second-drain-test")
			if err != nil {
				t.Fatal(err)
			}
			defer machine.Close()
			peer, err := machine.AcquirePeer("terminal-drain-peer")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cost := loopbackcarrier.AttemptCost()
			attempt, err := peer.AcquireAttempt(ctx, governor.AttemptRequest{ID: processID(2), Operation: governor.OperationConnectTest, Cost: cost})
			if err != nil {
				t.Fatal(err)
			}
			defer attempt.Close()
			// This deliberately uncompleted *other owner's* drain tests the
			// unchanged second tripwire, not a replacement pairing FINISH.
			other, err := attempt.RegisterDrain("terminal-test-other-owner")
			if err != nil {
				t.Fatal(err)
			}
			defer other.Complete()
			factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: netip.MustParseAddrPort("127.0.0.1:0"), AllowedTargetScope: probeio.AllowedTargetScopeLoopback})
			if err != nil {
				t.Fatal(err)
			}
			controller, err := probeio.New(probeio.Config{Lease: attempt, Generation: probeio.NewGeneration(1), ExpectedGeneration: 1, Factory: factory, BuildVersion: "terminal-second-drain-test"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.OpenProbeSocket(ctx); err != nil {
				t.Fatal(err)
			}
			if err := controller.RevokeForTerminal(); err != nil {
				t.Fatal(err)
			}
			snapshot := machine.Snapshot()
			if snapshot.ActiveAttempts != 1 || snapshot.Reserved != cost.Resources || snapshot.SafetyTrip.State != governor.SafetyTripClear {
				t.Fatal("revoke released the attempt reservation or tripped")
			}
			select {
			case <-attempt.Stopping():
				t.Fatal("revoke closed the attempt before its owner's FINISH")
			default:
			}
			if finishComplete {
				_ = other.Complete()
			}
			started := time.Now()
			closeErr := controller.Close()
			elapsed := time.Since(started)
			snapshot = machine.Snapshot()
			if finishComplete {
				if closeErr != nil || snapshot.SafetyTrip.State != governor.SafetyTripClear {
					t.Fatal("completed drains did not close cleanly")
				}
			} else {
				if closeErr == nil || snapshot.SafetyTrip.State != governor.SafetyTripTripped || snapshot.SafetyTrip.Record.Reason != governor.SafetyTripCancellation {
					t.Fatal("terminal revoke disabled the second cancellation tripwire")
				}
				_ = other.Complete()
				_ = machine.Close()
				_, reopenErr := governor.AcquireLoopbackCarrierTestGovernor(namespace, "terminal-second-drain-reopen")
				var trip *governor.SafetyTripError
				if !errors.As(reopenErr, &trip) || trip.Status.Record.Reason != governor.SafetyTripCancellation {
					t.Fatal("second tripwire was not durable")
				}
			}
			if snapshot.ActiveAttempts != 0 || snapshot.Reserved != (governor.Resources{}) || ctx.Err() != nil {
				t.Fatal("terminal Close leaked resources or required caller timeout")
			}
			t.Logf("O2_SECOND_DRAIN finish_complete=%t close_ns=%d safety=%s reason=%s attempts=0 reserved_zero=true", finishComplete, elapsed.Nanoseconds(), snapshot.SafetyTrip.State, snapshot.SafetyTrip.Record.Reason)
		})
	}
}
