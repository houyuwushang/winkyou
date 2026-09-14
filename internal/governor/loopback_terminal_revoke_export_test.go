package governor

import (
	"os"
	"sync"
	"time"
)

// BeforeLoopbackCarrierFinishWrite pauses the existing writeFrame test seam
// before any FINISH bytes reach the journal. Other records use their original
// write path. The subprocess test kills the holder; no recovery is replaced.
func BeforeLoopbackCarrierFinishWrite(machine *Governor, before func(PairingTerminalReason) error) error {
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if before == nil || ledger.hooks.writeFrame != nil {
		return ErrInvalidRequest
	}
	ledger.hooks.writeFrame = func(file *os.File, record pairingJournalRecord, frame []byte) (int, error) {
		if record.Type == pairingRecordFinish {
			if err := before(record.Reason); err != nil {
				return 0, err
			}
		}
		return file.Write(frame)
	}
	return nil
}

// CarrierFinishDelayWitness is test-only. The existing journal observer keeps
// measuring the actual append/sync boundaries; this witness proves that the
// requested delay was injected exactly once, only into FINISH.
type CarrierFinishDelayWitness struct {
	Calls   int
	Started time.Time
	Ended   time.Time
	Reason  PairingTerminalReason
}

// InjectLoopbackCarrierFinishDelay wraps the already-installed absence
// observer. It does not replace write/sync, clocks, admission, or recovery.
// Install before Connect on a fresh test namespace with no concurrent writer.
func InjectLoopbackCarrierFinishDelay(machine *Governor, delay time.Duration) (func() CarrierFinishDelayWitness, error) {
	if delay <= 0 {
		return nil, ErrInvalidRequest
	}
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return nil, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	previous := ledger.hooks.afterAppendBeforeSync
	if previous == nil || ledger.hooks.afterSync == nil || ledger.hooks.writeFrame != nil {
		return nil, ErrInvalidRequest
	}
	var mu sync.Mutex
	var witness CarrierFinishDelayWitness
	ledger.hooks.afterAppendBeforeSync = func(record pairingJournalRecord) error {
		if err := previous(record); err != nil {
			return err
		}
		if record.Type != pairingRecordFinish {
			return nil
		}
		mu.Lock()
		witness.Calls++
		witness.Started = time.Now()
		witness.Reason = record.Reason
		mu.Unlock()
		// Deliberate fault injection, not a production timing margin. The
		// journal still performs its real Sync after this hook returns.
		time.Sleep(delay)
		mu.Lock()
		witness.Ended = time.Now()
		mu.Unlock()
		return nil
	}
	return func() CarrierFinishDelayWitness {
		mu.Lock()
		defer mu.Unlock()
		return witness
	}, nil
}
