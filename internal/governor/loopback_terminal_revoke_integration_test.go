package governor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/loopbackcarrier"
)

// These are real in-process loopback attempts, not a fake clock or synthetic
// trip. The original default absence regression and its AST gate stay intact.
func TestLoopbackCarrierSlowFinishRevokesBeforeDurableIO(t *testing.T) {
	for _, test := range []struct {
		name  string
		delay time.Duration
	}{
		{"R1_2500ms", 2500 * time.Millisecond},
		{"R2_10000ms", 10 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			namespace := t.TempDir()
			if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
				t.Fatal("o2 namespace preparation failed")
			}
			machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "loopback-o2-slow-finish")
			if err != nil {
				t.Fatal("o2 governor acquisition failed")
			}
			t.Cleanup(func() { closeAbsentPeerGovernor(t, machine, namespace) })
			journalTiming, err := governor.ObserveCarrierAbsenceJournal(machine)
			if err != nil {
				t.Fatal("o2 journal observer installation failed")
			}
			delayWitness, err := governor.InjectLoopbackCarrierFinishDelay(machine, test.delay)
			if err != nil {
				t.Fatal("o2 FINISH delay installation failed")
			}
			local, absentPeer := reserveLoopbackEndpoint(t), reserveLoopbackEndpoint(t)
			bundle, unused := processBundles(t, local, absentPeer, absentPeer, local, repeatedKey(81), now)
			clear(unused)
			defer clear(bundle)
			// This independent hang guard must not terminate the carrier's
			// own 13s path plus either explicit FINISH delay.
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			started := time.Now()
			_, connectErr := loopbackcarrier.Connect(ctx, machine, bundle, "loopback-o2-slow-finish", nil)
			returned := time.Now()
			observed := absentPeerObservation{
				ConnectErr: connectErr, Started: started, Returned: returned,
				Journal: journalTiming(), CallerErr: ctx.Err(), Memory: machine.Snapshot(),
			}
			observed.CallerDeadline, _ = ctx.Deadline()
			// Collect the durable trip even on RED. A failed early assertion
			// must never erase the persisted hard_limit_exceeded witness.
			observed.CloseErr = machine.Close()
			reopened, reopenErr := governor.AcquireLoopbackCarrierTestGovernor(namespace, "loopback-o2-readback")
			observed.ReopenErr = reopenErr
			if reopenErr == nil {
				t.Cleanup(func() { closeAbsentPeerGovernor(t, reopened, namespace) })
				observed.Persisted = reopened.Snapshot().SafetyTrip
				observed.PersistedChecked = true
				observed.ReopenedCloseErr = reopened.Close()
			} else {
				var trip *governor.SafetyTripError
				if errors.As(reopenErr, &trip) {
					observed.Persisted = trip.Status
					observed.PersistedChecked = true
				}
			}
			observed.Ledger, observed.LedgerErr = governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
			observed.UnfinishedAdmissions, observed.UnfinishedPackets, observed.OccupancyErr = governor.InspectLoopbackCarrierTestOccupancy(namespace, time.Now())
			observed.PortRebound = t.Run("port-rebind", func(t *testing.T) { assertReusable(t, local) })
			observed.Collected = true
			delayed := delayWitness()
			t.Logf("O2_SLOW_FINISH delay_ns=%d injected_calls=%d actual_delay_ns=%d connect_ns=%d finish_sync_ns=%d finish_reason=%s memory_state=%s persisted_checked=%t persisted_state=%s persisted_reason=%s peers=%d attempts=%d reserved_zero=%t admissions_24h=%d packets_24h=%d unfinished=%d port_rebound=%t",
				test.delay.Nanoseconds(), delayed.Calls, delayed.Ended.Sub(delayed.Started).Nanoseconds(),
				returned.Sub(started).Nanoseconds(), observed.Journal.FinishSynced.Sub(observed.Journal.FinishAppended).Nanoseconds(),
				observed.Journal.FinishReason, observed.Memory.SafetyTrip.State, observed.PersistedChecked,
				observed.Persisted.State, observed.Persisted.Record.Reason, observed.Memory.ActivePeers,
				observed.Memory.ActiveAttempts, observed.Memory.Reserved == (governor.Resources{}),
				observed.Ledger.TwentyFourHourAdmissions, observed.Ledger.TwentyFourHourPackets,
				observed.UnfinishedAdmissions, observed.PortRebound)
			if delayed.Calls != 1 || delayed.Reason != governor.PairingTerminalExpired ||
				delayed.Started.IsZero() || delayed.Ended.Sub(delayed.Started) < test.delay ||
				observed.Journal.FinishSynced.Sub(observed.Journal.FinishAppended) < test.delay {
				t.Error("o2 exact FINISH injection witness missing")
			}
			requireAbsentPeerObservation(t, observed)
		})
	}
}
