package governor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type testPairingGateEnvironment struct {
	ledger   *PairingAdmissionLedger
	clock    *testPairingGateClock
	path     string
	owner    *Owner
	governor *Governor
	attempt  *AttemptLease
	request  PairingAdmissionRequest
	context  context.Context
	cancel   context.CancelFunc
}

type testPairingGateClock struct {
	mu    sync.RWMutex
	value time.Time
}

func (clock *testPairingGateClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.value
}

func (clock *testPairingGateClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.value = value
	clock.mu.Unlock()
}

func TestPairingAdmissionGateReturnsOneTimeCommittedAttempt(t *testing.T) {
	environment := newTestPairingGateEnvironment(t, "success", OperationConnectTest)
	committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
	if err != nil || committed == nil {
		t.Fatalf("commit = %#v/%v", committed, err)
	}
	authorization, err := committed.ConsumeForCarrier(environment.context)
	if err != nil || authorization == nil {
		t.Fatalf("consume = %#v/%v", authorization, err)
	}
	if duplicate, err := committed.ConsumeForCarrier(environment.context); duplicate != nil || !errors.Is(err, ErrCommittedAttemptConsumed) {
		t.Fatalf("second consume = %#v/%v, want consumed", duplicate, err)
	}
	if err := authorization.Finish(PairingTerminalSuccess); !errors.Is(err, ErrCommittedAttemptInvalid) {
		t.Fatalf("success before first-emission check = %v, want invalid", err)
	}
	if err := authorization.BeforeFirstEmission(environment.context); err != nil {
		t.Fatalf("before first emission: %v", err)
	}
	if err := authorization.BeforeFirstEmission(environment.context); !errors.Is(err, ErrFirstEmissionAlreadyAuthorized) {
		t.Fatalf("second first-emission check = %v, want one-shot rejection", err)
	}
	if err := authorization.CheckActive(environment.context); err != nil {
		t.Fatalf("check active: %v", err)
	}
	if err := authorization.Finish(PairingTerminalSuccess); err != nil {
		t.Fatalf("finish success: %v", err)
	}
	if err := authorization.Finish(PairingTerminalSuccess); err != nil {
		t.Fatalf("idempotent finish success: %v", err)
	}
	if err := authorization.Finish(PairingTerminalCarrierError); !errors.Is(err, ErrCommittedAttemptInvalid) {
		t.Fatalf("different terminal reason = %v, want invalid", err)
	}
	if err := authorization.CheckActive(environment.context); !errors.Is(err, ErrCommittedAttemptInvalid) {
		t.Fatalf("check after finish = %v, want invalid", err)
	}

	snapshot, readErr := readPairingLedgerSnapshot(environment.path, environment.clock.Now(), environment.owner.Info().InstanceID, validateTestPairingLedgerFile)
	if readErr != nil {
		t.Fatalf("read finished journal: %v", readErr)
	}
	entry := snapshot.admissions[environment.request.CredentialID]
	if entry == nil || entry.finish == nil || entry.finish.Reason != PairingTerminalSuccess {
		t.Fatalf("finished admission = %#v", entry)
	}
}

func TestPairingAdmissionGateRejectsLeaseAndEnvelopeMismatchBeforeBurn(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testPairingGateEnvironment)
	}{
		{
			name: "attempt id",
			mutate: func(environment *testPairingGateEnvironment) {
				environment.request.AttemptID = testPairingOpaqueID("different-attempt")
			},
		},
		{
			name: "scope",
			mutate: func(environment *testPairingGateEnvironment) {
				environment.request.Scope = ScopeUserAcknowledged
			},
		},
		{
			name: "envelope",
			mutate: func(environment *testPairingGateEnvironment) {
				environment.request.Envelope.Packets--
			},
		},
		{
			name: "cancelled context",
			mutate: func(environment *testPairingGateEnvironment) {
				environment.cancel()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestPairingGateEnvironment(t, "mismatch-"+test.name, OperationConnectTest)
			test.mutate(environment)
			committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
			if committed != nil || !errors.Is(err, ErrPairingAdmissionRejected) {
				t.Fatalf("commit = %#v/%v, want rejected", committed, err)
			}
			assertPairingJournalSequence(t, environment, 1)
		})
	}

	environment := newTestPairingGateEnvironment(t, "wrong-operation", OperationDiagnose)
	committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
	if committed != nil || !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("diagnose commit = %#v/%v, want not allowed", committed, err)
	}
	assertPairingJournalSequence(t, environment, 1)
}

func TestPairingAdmissionGatePostcheckFailureBurnsAndFinishes(t *testing.T) {
	environment := newTestPairingGateEnvironment(t, "postcheck-failure", OperationConnectTest)
	gate := &PairingAdmissionGate{hooks: pairingAdmissionGateHooks{
		afterDurableAdmission: func() error {
			environment.cancel()
			return nil
		},
	}}
	committed, err := gate.Commit(environment.context, environment.attempt, environment.request)
	if committed != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("commit after cancellation = %#v/%v", committed, err)
	}
	assertPairingJournalSequence(t, environment, 3)
	snapshot, readErr := readPairingLedgerSnapshot(environment.path, environment.clock.Now(), environment.owner.Info().InstanceID, validateTestPairingLedgerFile)
	if readErr != nil {
		t.Fatalf("read cancelled journal: %v", readErr)
	}
	entry := snapshot.admissions[environment.request.CredentialID]
	if entry == nil || entry.finish == nil || entry.finish.Reason != PairingTerminalCancelled {
		t.Fatalf("cancelled admission = %#v", entry)
	}
}

func TestPairingAdmissionGateSafetyTripBeforeAndAfterBurn(t *testing.T) {
	t.Run("before burn", func(t *testing.T) {
		environment := newTestPairingGateEnvironment(t, "trip-before", OperationConnectTest)
		if _, err := environment.governor.Trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "test pre-burn stop"}); err != nil {
			t.Fatalf("trip governor: %v", err)
		}
		committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
		if committed != nil || !errors.Is(err, ErrSafetyTripped) {
			t.Fatalf("commit after trip = %#v/%v", committed, err)
		}
		assertPairingJournalSequence(t, environment, 1)
	})

	t.Run("after burn", func(t *testing.T) {
		environment := newTestPairingGateEnvironment(t, "trip-after", OperationConnectTest)
		gate := &PairingAdmissionGate{hooks: pairingAdmissionGateHooks{
			afterDurableAdmission: func() error {
				_, err := environment.governor.Trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "test post-burn stop"})
				return err
			},
		}}
		committed, err := gate.Commit(environment.context, environment.attempt, environment.request)
		if committed != nil || !errors.Is(err, ErrSafetyTripped) {
			t.Fatalf("commit during trip = %#v/%v", committed, err)
		}
		assertPairingJournalSequence(t, environment, 3)
	})
}

func TestCommittedAttemptInvalidatesBeforeFirstEmission(t *testing.T) {
	t.Run("context cancellation", func(t *testing.T) {
		environment := newTestPairingGateEnvironment(t, "token-cancel", OperationConnectTest)
		committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
		if err != nil {
			t.Fatalf("commit: %v", err)
		}
		environment.cancel()
		select {
		case <-committed.finished:
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled committed attempt did not finish")
		}
		if authorization, err := committed.ConsumeForCarrier(context.Background()); authorization != nil || !errors.Is(err, ErrCommittedAttemptInvalid) {
			t.Fatalf("consume cancelled token = %#v/%v", authorization, err)
		}
		assertPairingJournalSequence(t, environment, 3)
	})

	t.Run("safety trip after consume", func(t *testing.T) {
		environment := newTestPairingGateEnvironment(t, "token-trip", OperationConnectTest)
		committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
		if err != nil {
			t.Fatalf("commit: %v", err)
		}
		authorization, err := committed.ConsumeForCarrier(environment.context)
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if _, err := environment.governor.Trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "test before-first-byte stop"}); err != nil {
			t.Fatalf("trip: %v", err)
		}
		select {
		case <-authorization.Stopping():
		case <-time.After(5 * time.Second):
			t.Fatal("trip did not signal carrier authorization")
		}
		if err := authorization.BeforeFirstEmission(environment.context); !errors.Is(err, ErrCommittedAttemptInvalid) {
			t.Fatalf("first emission after trip = %v, want invalid", err)
		}
	})

	t.Run("credential expiry", func(t *testing.T) {
		environment := newTestPairingGateEnvironment(t, "token-expiry", OperationConnectTest)
		committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
		if err != nil {
			t.Fatalf("commit: %v", err)
		}
		environment.clock.Set(environment.request.ExpiresAt)
		if authorization, err := committed.ConsumeForCarrier(environment.context); authorization != nil || !errors.Is(err, ErrPairingCredentialExpired) {
			t.Fatalf("consume expired token = %#v/%v", authorization, err)
		}
		snapshot, readErr := readPairingLedgerSnapshot(environment.path, environment.clock.Now(), environment.owner.Info().InstanceID, validateTestPairingLedgerFile)
		if readErr != nil {
			t.Fatalf("read expired journal: %v", readErr)
		}
		entry := snapshot.admissions[environment.request.CredentialID]
		if entry == nil || entry.finish == nil || entry.finish.Reason != PairingTerminalExpired {
			t.Fatalf("expired admission = %#v", entry)
		}
	})
}

func TestPairingAdmissionGateMissingCorruptAndRollbackEmitNoToken(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *testPairingGateEnvironment)
		cause  error
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, environment *testPairingGateEnvironment) {
				if err := os.Remove(environment.path); err != nil {
					t.Fatalf("remove journal: %v", err)
				}
			},
			cause: ErrPairingLedgerNotInitialized,
		},
		{
			name: "corrupt",
			mutate: func(t *testing.T, environment *testPairingGateEnvironment) {
				if err := os.WriteFile(environment.path, []byte("corrupt"), 0o600); err != nil {
					t.Fatalf("corrupt journal: %v", err)
				}
			},
			cause: ErrPairingLedgerIndeterminate,
		},
		{
			name: "truncated",
			mutate: func(t *testing.T, environment *testPairingGateEnvironment) {
				data, err := os.ReadFile(environment.path)
				if err != nil {
					t.Fatalf("read journal: %v", err)
				}
				if err := os.WriteFile(environment.path, data[:len(data)/2], 0o600); err != nil {
					t.Fatalf("truncate journal: %v", err)
				}
			},
			cause: ErrPairingLedgerIndeterminate,
		},
		{
			name: "checksum mismatch",
			mutate: func(t *testing.T, environment *testPairingGateEnvironment) {
				initial := pairingJournalRecord{
					SchemaVersion: pairingLedgerSchemaVersion,
					Sequence:      1,
					Type:          pairingRecordInitialize,
					RecordedAt:    environment.clock.Now(),
				}
				frame := pairingFrameWithChecksum(t, initial, make([]byte, 32))
				if err := os.WriteFile(environment.path, frame, 0o600); err != nil {
					t.Fatalf("write checksum mismatch: %v", err)
				}
			},
			cause: ErrPairingLedgerIndeterminate,
		},
		{
			name: "capacity exhausted",
			mutate: func(t *testing.T, environment *testPairingGateEnvironment) {
				writeFullTestPairingJournal(t, environment.path, environment.clock.Now().Add(-25*time.Hour))
			},
			cause: ErrPairingLedgerCapacity,
		},
		{
			name: "clock rollback",
			mutate: func(_ *testing.T, environment *testPairingGateEnvironment) {
				environment.clock.Set(environment.clock.Now().Add(-pairingLedgerClockRollbackSkew - time.Second))
			},
			cause: ErrPairingLedgerClockRollback,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestPairingGateEnvironment(t, "blocked-"+test.name, OperationConnectTest)
			test.mutate(t, environment)
			committed, err := NewPairingAdmissionGate().Commit(environment.context, environment.attempt, environment.request)
			if committed != nil || !errors.Is(err, test.cause) {
				t.Fatalf("blocked commit = %#v/%v, want %v", committed, err, test.cause)
			}
		})
	}
}

func TestCommittedAttemptZeroValuesCarryNoAuthority(t *testing.T) {
	if authorization, err := new(CommittedAttempt).ConsumeForCarrier(context.Background()); authorization != nil || !errors.Is(err, ErrCommittedAttemptInvalid) {
		t.Fatalf("zero committed attempt = %#v/%v", authorization, err)
	}
	if err := new(CommittedCarrierAuthorization).BeforeFirstEmission(context.Background()); !errors.Is(err, ErrCommittedAttemptInvalid) {
		t.Fatalf("zero carrier authorization = %v", err)
	}
}

func newTestPairingGateEnvironment(t *testing.T, label string, operation Operation) *testPairingGateEnvironment {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Millisecond)
	ledger, _, path, owner := newTestPairingLedger(t, base, false)
	clock := &testPairingGateClock{value: base}
	ledger.now = clock.Now
	prepareTestSafetyTrip(t, filepath.Dir(path))
	owner.mu.Lock()
	owner.pairingLedger = ledger
	owner.mu.Unlock()
	governor, err := New(owner, ProfilePhase1Machine, nil)
	if err != nil {
		t.Fatalf("new pairing gate governor: %v", err)
	}
	contextValue, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() {
		if err := governor.Close(); err != nil {
			t.Errorf("close pairing gate governor: %v", err)
		}
	})
	peer, err := governor.AcquirePeer("pairing-gate-peer-" + label)
	if err != nil {
		t.Fatalf("acquire pairing gate peer: %v", err)
	}
	request := testPairingRequest("gate-"+label, base, 8)
	attempt, err := peer.AcquireAttempt(contextValue, AttemptRequest{
		ID:        request.AttemptID,
		Operation: operation,
		Cost: AttemptCost{
			Resources: request.Envelope.resources(),
			Duration:  time.Duration(request.Envelope.DurationMillis) * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("acquire pairing gate attempt: %v", err)
	}
	return &testPairingGateEnvironment{
		ledger:   ledger,
		clock:    clock,
		path:     path,
		owner:    owner,
		governor: governor,
		attempt:  attempt,
		request:  request,
		context:  contextValue,
		cancel:   cancel,
	}
}

func assertPairingJournalSequence(t *testing.T, environment *testPairingGateEnvironment, want uint64) {
	t.Helper()
	snapshot, _ := readPairingLedgerSnapshot(environment.path, environment.clock.Now(), environment.owner.Info().InstanceID, validateTestPairingLedgerFile)
	if snapshot.sequence != want {
		t.Fatalf("journal sequence = %d, want %d; status=%+v", snapshot.sequence, want, snapshot.status)
	}
}

func writeFullTestPairingJournal(t *testing.T, path string, recordedAt time.Time) {
	t.Helper()
	ownerID := testPairingOwnerID("full-journal-owner")
	initial := pairingJournalRecord{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      1,
		Type:          pairingRecordInitialize,
		RecordedAt:    recordedAt.UTC(),
	}
	data, err := encodePairingJournalFrame(initial)
	if err != nil {
		t.Fatalf("encode full journal initialization: %v", err)
	}
	sequence := uint64(1)
	for index := 0; int(sequence)+2 <= maxPairingLedgerRecords; index++ {
		admission := testPairingAdmissionRecord(sequence+1, "full-journal-"+strconv.Itoa(index), recordedAt, 1, ownerID)
		finish := pairingJournalRecord{
			SchemaVersion: pairingLedgerSchemaVersion,
			Sequence:      sequence + 2,
			Type:          pairingRecordFinish,
			RecordedAt:    recordedAt.UTC(),
			CredentialID:  admission.CredentialID,
			AttemptID:     admission.AttemptID,
			Reason:        PairingTerminalSuccess,
		}
		admissionFrame, err := encodePairingJournalFrame(admission)
		if err != nil {
			t.Fatalf("encode near-capacity admission: %v", err)
		}
		finishFrame, err := encodePairingJournalFrame(finish)
		if err != nil {
			t.Fatalf("encode near-capacity finish: %v", err)
		}
		if int64(len(data)+len(admissionFrame)+len(finishFrame)) > maxPairingLedgerBytes {
			break
		}
		data = append(data, admissionFrame...)
		data = append(data, finishFrame...)
		sequence += 2
		if int64(len(data)) > maxPairingLedgerBytes-(8<<10) {
			break
		}
	}
	if int64(len(data)) <= maxPairingLedgerBytes-(8<<10) {
		t.Fatalf("near-capacity fixture is only %d bytes", len(data))
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write full journal: %v", err)
	}
}
