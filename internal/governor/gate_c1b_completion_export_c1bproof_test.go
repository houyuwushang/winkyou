//go:build c1bproof

package governor

import (
	"errors"
	"sync/atomic"
	"time"
)

// DelayC1bSuccessFinishForProof is available only to this package's tagged
// external tests, never to a normal or c1bproof product build. It delays the
// return from an actual successful append+fsync, without replacing the journal,
// its owner, clocks, callback, or record ordering. Every fixture owns its ledger.
func DelayC1bSuccessFinishForProof(machine *Governor) (func() (int32, time.Duration), error) {
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return nil, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.hooks.afterSync != nil || ledger.hooks.afterAppendBeforeSync != nil || ledger.hooks.writeFrame != nil {
		return nil, errors.New("C1b completion proof requires an unmodified journal writer")
	}
	var calls atomic.Int32
	var waited atomic.Int64
	ledger.hooks.afterSync = func(record pairingJournalRecord) error {
		if record.Type != pairingRecordFinish || record.Reason != PairingTerminalSuccess {
			return nil
		}
		if calls.Add(1) != 1 {
			return errors.New("C1b completion proof observed repeated success FINISH")
		}
		started := time.Now()
		timer := time.NewTimer(3500 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		waited.Store(int64(time.Since(started)))
		return nil
	}
	return func() (int32, time.Duration) { return calls.Load(), time.Duration(waited.Load()) }, nil
}
