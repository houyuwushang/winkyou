package governor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/loopbackcarrier"
)

// The invalidation occurs after the real UDP socket exists but before the
// first emission check. Both cases use the production gate, owner and journal.
func TestLoopbackCarrierPreFinishInvalidation(t *testing.T) {
	for _, test := range []struct {
		name         string
		delay        time.Duration
		cancelCaller bool
	}{
		{"carrier_deadline_2500ms", 2500 * time.Millisecond, false},
		{"R4_cancel_10000ms", 10 * time.Second, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			namespace := t.TempDir()
			if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
				t.Fatal("namespace setup failed")
			}
			machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "prefinish-regression")
			if err != nil {
				t.Fatal("governor setup failed")
			}
			defer machine.Close()
			journal, err := governor.ObserveCarrierAbsenceJournal(machine)
			if err != nil {
				t.Fatal("journal observer setup failed")
			}
			delay, err := governor.InjectLoopbackCarrierFinishDelay(machine, test.delay)
			if err != nil {
				t.Fatal("delay setup failed")
			}
			local, absent := reserveLoopbackEndpoint(t), reserveLoopbackEndpoint(t)
			bundle, unused := processBundles(t, local, absent, absent, local, repeatedKey(81), now)
			clear(unused)
			defer clear(bundle)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			ready := 0
			started := time.Now()
			_, connectErr := loopbackcarrier.Connect(ctx, machine, bundle, "prefinish-regression", func(stage loopbackcarrier.ProgressStage) error {
				if stage != loopbackcarrier.ProgressStageSocketReady {
					t.Error("unexpected stage")
				}
				ready++
				if test.cancelCaller {
					cancel()
				} else {
					// Cross the unchanged 13s carrier deadline before the first
					// authorization check. This is fault injection, not headroom.
					timer := time.NewTimer(13 * time.Second)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Error("fixture hang guard fired")
					}
				}
				return nil
			})
			elapsed := time.Since(started)
			memory := machine.Snapshot()
			j, d := journal(), delay()
			closeErr := machine.Close()
			reopened, reopenErr := governor.AcquireLoopbackCarrierTestGovernor(namespace, "prefinish-readback")
			persisted := governor.SafetyTripStatus{}
			checked := false
			if reopenErr == nil {
				persisted, checked = reopened.Snapshot().SafetyTrip, true
				_ = reopened.Close()
			} else {
				var trip *governor.SafetyTripError
				if errors.As(reopenErr, &trip) {
					persisted, checked = trip.Status, true
				}
			}
			ledger, ledgerErr := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
			unfinished, _, occupancyErr := governor.InspectLoopbackCarrierTestOccupancy(namespace, time.Now())
			rebound := t.Run("port-rebind", func(t *testing.T) { assertReusable(t, local) })
			wantReason := governor.PairingTerminalExpired
			wantError := context.DeadlineExceeded
			if test.cancelCaller {
				wantReason, wantError = governor.PairingTerminalCancelled, context.Canceled
			}
			t.Logf("PREFINISH_REGRESSION elapsed_ns=%d delay_ns=%d delay_calls=%d ready=%d finish_reason=%s memory_state=%s memory_reason=%s persisted_checked=%t persisted_state=%s persisted_reason=%s attempts=%d peers=%d reserved_zero=%t admissions_24h=%d packets_24h=%d unfinished=%d port_rebound=%t close_ok=%t",
				elapsed.Nanoseconds(), d.Ended.Sub(d.Started).Nanoseconds(), d.Calls, ready, j.FinishReason,
				memory.SafetyTrip.State, memory.SafetyTrip.Record.Reason, checked, persisted.State, persisted.Record.Reason,
				memory.ActiveAttempts, memory.ActivePeers, memory.Reserved == (governor.Resources{}),
				ledger.TwentyFourHourAdmissions, ledger.TwentyFourHourPackets, unfinished, rebound, closeErr == nil)
			// The watcher may select cancellation before BeforeFirstEmission
			// validates the caller. Both orders must deny all emission.
			invalidated := errors.Is(connectErr, wantError) || test.cancelCaller && errors.Is(connectErr, governor.ErrCommittedAttemptInvalid)
			if !invalidated || ready != 1 || d.Calls != 1 || j.FinishReason != wantReason ||
				d.Ended.Sub(d.Started) < test.delay || !checked || ledgerErr != nil || occupancyErr != nil ||
				ledger.TwentyFourHourAdmissions != 1 || ledger.TwentyFourHourPackets != 3 || unfinished != 0 ||
				memory.ActiveAttempts != 0 || memory.ActivePeers != 0 || memory.Reserved != (governor.Resources{}) || !rebound {
				t.Error("pre-finish terminal/accounting/residue witness failed")
			}
			if memory.SafetyTrip.BlocksActiveWork || persisted.BlocksActiveWork || closeErr != nil {
				t.Error("pre-finish invalidation caused a safety trip despite drained network")
			}
		})
	}
}
