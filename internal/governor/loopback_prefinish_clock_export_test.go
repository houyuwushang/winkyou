package governor

import "time"

// InstallLoopbackCredentialClock installs the existing mutex-protected test
// clock before Commit. Later advancement changes no function pointer and is
// race-safe with watchInvalidation. No production clock or hook is added.
func InstallLoopbackCredentialClock(machine *Governor, at time.Time) (func(time.Time), error) {
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return nil, err
	}
	clock := &testPairingGateClock{value: at.UTC()}
	ledger.mu.Lock()
	ledger.now = clock.Now
	ledger.mu.Unlock()
	return clock.Set, nil
}
