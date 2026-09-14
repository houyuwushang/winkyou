package governor

import "time"

// HoldGateB2BurnForDiagnostic uses the existing test journal hook, without
// changing Commit, cancellation, FINISH, or resource release semantics.
func HoldGateB2BurnForDiagnostic(machine *Governor, closed <-chan struct{}) error {
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return err
	}
	ledger.hooks.afterSync = func(record pairingJournalRecord) error {
		if record.Type != pairingRecordBurnAndAdmit {
			return nil
		}
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-closed:
			return nil
		case <-timer.C:
			return ErrInvalidRequest
		}
	}
	return nil
}

func GateB2AttemptDoneForDiagnostic(machine *Governor) <-chan struct{} {
	machine.mu.Lock()
	defer machine.mu.Unlock()
	for _, attempt := range machine.attempts {
		return attempt.Done()
	}
	return closedChannel()
}
