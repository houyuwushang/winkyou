package governor

import (
	"context"
	"os"
	"runtime/trace"
	"sync"
	"time"
)

// CarrierAbsenceJournalTiming exists only in this package's test binary. Its
// interval is a LOWER bound on attempt lifetime, not the start of the attempt:
// AcquireAttempt and BURN append have already happened at AdmissionAppended.
type CarrierAbsenceJournalTiming struct {
	AdmissionAppended time.Time
	AdmissionSynced   time.Time
	FinishAppended    time.Time
	FinishSynced      time.Time
	FinishReason      PairingTerminalReason
}

// ObserveCarrierAbsenceJournal only reads real monotonic time at the existing
// journal hooks. It never replaces the clock, write, sync, or admission policy.
// Install before Connect; this private test governor must have no other hooks.
func ObserveCarrierAbsenceJournal(machine *Governor) (func() CarrierAbsenceJournalTiming, error) {
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var timing CarrierAbsenceJournalTiming
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.hooks.writeFrame != nil || ledger.hooks.afterAppendBeforeSync != nil || ledger.hooks.afterSync != nil {
		return nil, ErrInvalidRequest
	}
	ledger.hooks.afterAppendBeforeSync = func(record pairingJournalRecord) error {
		at := time.Now()
		mu.Lock()
		defer mu.Unlock()
		switch record.Type {
		case pairingRecordBurnAndAdmit:
			timing.AdmissionAppended = at
			// Annotate this already-existing test observer, never production.
			// Only fixed labels enter the opt-in trace; no record payload does.
			if os.Getenv("WINKYOU_FLAKE_111_CPU_STRESS") == "1" && trace.IsEnabled() {
				trace.Log(context.Background(), "absence_journal", "burn_appended")
			}
		case pairingRecordFinish:
			timing.FinishAppended = at
		}
		return nil
	}
	ledger.hooks.afterSync = func(record pairingJournalRecord) error {
		at := time.Now()
		mu.Lock()
		defer mu.Unlock()
		switch record.Type {
		case pairingRecordBurnAndAdmit:
			timing.AdmissionSynced = at
		case pairingRecordFinish:
			timing.FinishSynced = at
			timing.FinishReason = record.Reason
		}
		return nil
	}
	return func() CarrierAbsenceJournalTiming {
		mu.Lock()
		defer mu.Unlock()
		return timing
	}, nil
}
