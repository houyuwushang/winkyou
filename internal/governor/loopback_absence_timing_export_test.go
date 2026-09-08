package governor

import (
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
		}
		return nil
	}
	return func() CarrierAbsenceJournalTiming {
		mu.Lock()
		defer mu.Unlock()
		return timing
	}, nil
}
