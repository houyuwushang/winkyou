package governor_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/loopbackcarrier"
)

// This is an in-process test observation, not a wire DTO or production hook.
// It contains no invented internal start/stop timestamp. Journal times only
// prove order inside Connect; their interval is not its resource lifetime.
type absentPeerObservation struct {
	ConnectErr, CloseErr, ReopenErr, ReopenedCloseErr error
	LedgerErr, OccupancyErr                           error
	Started, Returned                                 time.Time
	Journal                                           governor.CarrierAbsenceJournalTiming
	Memory                                            governor.Snapshot
	Persisted                                         governor.SafetyTripStatus
	Ledger                                            governor.PairingLedgerStatus
	UnfinishedAdmissions, UnfinishedPackets           int
	PersistedChecked, PortRebound, Collected          bool
}

func requireAbsentPeerObservation(t *testing.T, observed absentPeerObservation) {
	t.Helper()
	for _, violation := range absentPeerObservationViolations(observed) {
		t.Error("absence_postcondition " + violation)
	}
}

func absentPeerObservationViolations(observed absentPeerObservation) []string {
	var violations []string
	reject := func(condition bool, class string) {
		if condition {
			violations = append(violations, class)
		}
	}
	reject(!observed.Collected, "collection_incomplete")
	reject(!errors.Is(observed.ConnectErr, context.DeadlineExceeded), "wrong_terminal")
	ordered := []time.Time{
		observed.Started, observed.Journal.AdmissionAppended, observed.Journal.AdmissionSynced,
		observed.Journal.FinishAppended, observed.Journal.FinishSynced, observed.Returned,
	}
	for index, at := range ordered {
		if at.IsZero() {
			violations = append(violations, "journal_witness_missing")
			break
		}
		if index > 0 && at.Before(ordered[index-1]) {
			violations = append(violations, "journal_order_invalid")
			break
		}
	}
	reject(observed.Memory.SafetyTrip.State != governor.SafetyTripClear ||
		observed.Memory.SafetyTrip.BlocksActiveWork, "memory_safety_not_clear")
	reject(observed.Memory.ActivePeers != 0 || observed.Memory.ActiveAttempts != 0 ||
		observed.Memory.HeavyweightAttempts != 0 || observed.Memory.Reserved != (governor.Resources{}), "resources_remaining")
	reject(observed.CloseErr != nil, "governor_close_failed")
	reject(observed.ReopenErr != nil, "owner_reopen_failed")
	reject(observed.ReopenedCloseErr != nil, "reopened_owner_close_failed")
	reject(!observed.PersistedChecked, "persistent_safety_unchecked")
	reject(observed.Persisted.State != governor.SafetyTripClear || observed.Persisted.BlocksActiveWork, "persistent_safety_not_clear")
	reject(observed.LedgerErr != nil, "ledger_unreadable")
	reject(observed.Ledger.Sequence != 3 || observed.Ledger.Records != 3 ||
		observed.Ledger.OneHourAdmissions != 1 || observed.Ledger.TwentyFourHourAdmissions != 1 ||
		observed.Ledger.ConsecutiveFailures != 1 || observed.Ledger.TwentyFourHourPackets != loopbackcarrier.MaxOutboundPackets, "charged_finish_missing_or_duplicated")
	reject(observed.OccupancyErr != nil, "occupancy_unreadable")
	reject(observed.UnfinishedAdmissions != 0 || observed.UnfinishedPackets != 0, "unfinished_durable_charge")
	reject(!observed.PortRebound, "socket_not_reusable")
	return violations
}

func TestAbsentPeerObservationRejectsMissingUnsafeOrUndrainedWitness(t *testing.T) {
	base := time.Now()
	valid := absentPeerObservation{
		ConnectErr: context.DeadlineExceeded, Started: base, Returned: base.Add(13 * time.Second),
		Journal: governor.CarrierAbsenceJournalTiming{
			AdmissionAppended: base.Add(time.Millisecond), AdmissionSynced: base.Add(2 * time.Millisecond),
			FinishAppended: base.Add(12 * time.Second), FinishSynced: base.Add(12*time.Second + time.Millisecond),
		},
		Memory:    governor.Snapshot{SafetyTrip: governor.SafetyTripStatus{State: governor.SafetyTripClear}},
		Persisted: governor.SafetyTripStatus{State: governor.SafetyTripClear},
		Ledger: governor.PairingLedgerStatus{
			Sequence: 3, Records: 3, OneHourAdmissions: 1, TwentyFourHourAdmissions: 1,
			ConsecutiveFailures: 1, TwentyFourHourPackets: loopbackcarrier.MaxOutboundPackets,
		},
		PersistedChecked: true, PortRebound: true, Collected: true,
	}
	if violations := absentPeerObservationViolations(valid); len(violations) != 0 {
		t.Fatalf("valid in-process observation rejected: %v", violations)
	}
	// An exact-limit or delayed Connect return must not resurrect the old
	// elapsed-time assertion. Neither case claims an internal timer-stop time.
	for _, elapsed := range []time.Duration{15 * time.Second, 16 * time.Second} {
		delayed := valid
		delayed.Returned = base.Add(elapsed)
		delayed.ConnectErr = errors.Join(errors.New("synthetic wrapper"), context.DeadlineExceeded)
		if violations := absentPeerObservationViolations(delayed); len(violations) != 0 {
			t.Fatalf("diagnostic wall time became an admission limit: %v", violations)
		}
	}
	if len(absentPeerObservationViolations(absentPeerObservation{})) == 0 {
		t.Fatal("empty observation accepted")
	}
	synthetic := errors.New("synthetic test failure")
	for _, mutation := range []struct {
		name, class string
		change      func(*absentPeerObservation)
	}{
		{"not-collected", "collection_incomplete", func(o *absentPeerObservation) { o.Collected = false }},
		{"success", "wrong_terminal", func(o *absentPeerObservation) { o.ConnectErr = nil }},
		{"canceled", "wrong_terminal", func(o *absentPeerObservation) { o.ConnectErr = context.Canceled }},
		{"text-only-deadline", "wrong_terminal", func(o *absentPeerObservation) { o.ConnectErr = errors.New(context.DeadlineExceeded.Error()) }},
		{"missing-burn", "journal_witness_missing", func(o *absentPeerObservation) { o.Journal.AdmissionAppended = time.Time{} }},
		{"missing-burn-sync", "journal_witness_missing", func(o *absentPeerObservation) { o.Journal.AdmissionSynced = time.Time{} }},
		{"missing-finish", "journal_witness_missing", func(o *absentPeerObservation) { o.Journal.FinishAppended = time.Time{} }},
		{"missing-finish-sync", "journal_witness_missing", func(o *absentPeerObservation) { o.Journal.FinishSynced = time.Time{} }},
		{"finish-before-burn", "journal_order_invalid", func(o *absentPeerObservation) { o.Journal.FinishAppended = o.Started }},
		{"finish-after-return", "journal_order_invalid", func(o *absentPeerObservation) { o.Journal.FinishSynced = o.Returned.Add(time.Nanosecond) }},
		{"memory-trip", "memory_safety_not_clear", func(o *absentPeerObservation) { o.Memory.SafetyTrip.State = governor.SafetyTripTripped }},
		{"memory-blocked", "memory_safety_not_clear", func(o *absentPeerObservation) { o.Memory.SafetyTrip.BlocksActiveWork = true }},
		{"peer", "resources_remaining", func(o *absentPeerObservation) { o.Memory.ActivePeers = 1 }},
		{"attempt", "resources_remaining", func(o *absentPeerObservation) { o.Memory.ActiveAttempts = 1 }},
		{"heavyweight", "resources_remaining", func(o *absentPeerObservation) { o.Memory.HeavyweightAttempts = 1 }},
		{"socket", "resources_remaining", func(o *absentPeerObservation) { o.Memory.Reserved.Sockets = 1 }},
		{"target", "resources_remaining", func(o *absentPeerObservation) { o.Memory.Reserved.Targets = 1 }},
		{"packets", "resources_remaining", func(o *absentPeerObservation) { o.Memory.Reserved.Packets = 1 }},
		{"pps", "resources_remaining", func(o *absentPeerObservation) { o.Memory.Reserved.PacketsPerSecond = 1 }},
		{"five-tuples", "resources_remaining", func(o *absentPeerObservation) { o.Memory.Reserved.FiveTuples = 1 }},
		{"close-failed", "governor_close_failed", func(o *absentPeerObservation) { o.CloseErr = synthetic }},
		{"owner-unavailable", "owner_reopen_failed", func(o *absentPeerObservation) { o.ReopenErr = synthetic }},
		{"owner-left-open", "reopened_owner_close_failed", func(o *absentPeerObservation) { o.ReopenedCloseErr = synthetic }},
		{"persistent-unchecked", "persistent_safety_unchecked", func(o *absentPeerObservation) { o.PersistedChecked = false }},
		{"persistent-trip", "persistent_safety_not_clear", func(o *absentPeerObservation) { o.Persisted.State = governor.SafetyTripTripped }},
		{"persistent-blocked", "persistent_safety_not_clear", func(o *absentPeerObservation) { o.Persisted.BlocksActiveWork = true }},
		{"ledger-read-failed", "ledger_unreadable", func(o *absentPeerObservation) { o.LedgerErr = synthetic }},
		{"missing-record", "charged_finish_missing_or_duplicated", func(o *absentPeerObservation) { o.Ledger.Records = 2 }},
		{"duplicate-record", "charged_finish_missing_or_duplicated", func(o *absentPeerObservation) { o.Ledger.Sequence = 4 }},
		{"missing-admission", "charged_finish_missing_or_duplicated", func(o *absentPeerObservation) { o.Ledger.OneHourAdmissions = 0 }},
		{"duplicate-admission", "charged_finish_missing_or_duplicated", func(o *absentPeerObservation) { o.Ledger.TwentyFourHourAdmissions = 2 }},
		{"missing-failed-finish", "charged_finish_missing_or_duplicated", func(o *absentPeerObservation) { o.Ledger.ConsecutiveFailures = 0 }},
		{"packet-refund", "charged_finish_missing_or_duplicated", func(o *absentPeerObservation) { o.Ledger.TwentyFourHourPackets = 0 }},
		{"occupancy-read-failed", "occupancy_unreadable", func(o *absentPeerObservation) { o.OccupancyErr = synthetic }},
		{"unfinished-admission", "unfinished_durable_charge", func(o *absentPeerObservation) { o.UnfinishedAdmissions = 1 }},
		{"unfinished-packets", "unfinished_durable_charge", func(o *absentPeerObservation) { o.UnfinishedPackets = 1 }},
		{"not-rebound", "socket_not_reusable", func(o *absentPeerObservation) { o.PortRebound = false }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := valid
			mutation.change(&changed)
			violations := absentPeerObservationViolations(changed)
			if !strings.Contains(" "+strings.Join(violations, " ")+" ", " "+mutation.class+" ") {
				t.Fatalf("mutation %s did not reject its required witness: %v", mutation.name, violations)
			}
		})
	}
}
