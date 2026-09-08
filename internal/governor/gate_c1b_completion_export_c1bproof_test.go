//go:build c1bproof

package governor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// DelayC1bSuccessFinishForProof is available only to this package's tagged
// external tests, never to a normal or c1bproof product build. It delays the
// return from an actual successful append+fsync, without replacing the journal,
// its owner, clocks, callback, or record ordering. Every fixture owns its ledger.
func DelayC1bSuccessFinishForProof(machine *Governor, snapshot func() [2]uint64) (func() C1bFinishDelayProof, error) {
	if snapshot == nil {
		return nil, errors.New("C1b completion proof requires packet snapshots")
	}
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return nil, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.hooks.afterSync != nil || ledger.hooks.afterAppendBeforeSync != nil || ledger.hooks.writeFrame != nil {
		return nil, errors.New("C1b completion proof requires an unmodified journal writer")
	}
	var proofMu sync.Mutex
	var proof C1bFinishDelayProof
	ledger.hooks.afterSync = func(record pairingJournalRecord) error {
		if record.Type != pairingRecordFinish || record.Reason != PairingTerminalSuccess {
			return nil
		}
		proofMu.Lock()
		proof.Calls++
		calls := proof.Calls
		proofMu.Unlock()
		if calls != 1 {
			return errors.New("C1b completion proof observed repeated success FINISH")
		}
		before := snapshot()
		started := time.Now()
		timer := time.NewTimer(3500 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		after := snapshot()
		proofMu.Lock()
		proof.Waited, proof.Before, proof.After = time.Since(started), before, after
		proofMu.Unlock()
		return nil
	}
	return func() C1bFinishDelayProof {
		proofMu.Lock()
		defer proofMu.Unlock()
		return proof
	}, nil
}

// C1bFinishDelayProof contains only counters from the test callback. It cannot
// expose a live endpoint, key, or journal handle to an ordinary product build.
type C1bFinishDelayProof struct {
	Calls         int32
	Waited        time.Duration
	Before, After [2]uint64
}

// CancelC1bAfterDurableFinishForProof cancels only the test caller after the
// actual success record has been appended and synced. It never rewrites FINISH.
func CancelC1bAfterDurableFinishForProof(machine *Governor, cancel context.CancelFunc) (func() int32, error) {
	if cancel == nil {
		return nil, errors.New("C1b cancellation proof requires a caller cancel")
	}
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return nil, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if ledger.hooks.afterSync != nil || ledger.hooks.afterAppendBeforeSync != nil || ledger.hooks.writeFrame != nil {
		return nil, errors.New("C1b cancellation proof requires an unmodified journal writer")
	}
	var calls atomic.Int32
	ledger.hooks.afterSync = func(record pairingJournalRecord) error {
		if record.Type != pairingRecordFinish || record.Reason != PairingTerminalSuccess {
			return nil
		}
		if calls.Add(1) != 1 {
			return errors.New("C1b cancellation proof observed repeated FINISH")
		}
		cancel()
		return nil
	}
	return calls.Load, nil
}
