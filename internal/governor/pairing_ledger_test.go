package governor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var errTestPairingWriteHook = errors.New("test pairing write hook failure")

func TestPairingJournalFormatRoundTripAndRejectsDamage(t *testing.T) {
	base := time.Date(2026, 8, 21, 1, 2, 3, 0, time.UTC)
	ownerID := testPairingOwnerID("format-owner")
	records := []pairingJournalRecord{
		{
			SchemaVersion: pairingLedgerSchemaVersion,
			Sequence:      1,
			Type:          pairingRecordInitialize,
			RecordedAt:    base,
		},
		testPairingAdmissionRecord(2, "format", base.Add(time.Minute), 8, ownerID),
		{
			SchemaVersion: pairingLedgerSchemaVersion,
			Sequence:      3,
			Type:          pairingRecordFinish,
			RecordedAt:    base.Add(time.Minute + time.Second),
			CredentialID:  testPairingOpaqueID("credential-format"),
			AttemptID:     testPairingOpaqueID("attempt-format"),
			Reason:        PairingTerminalSuccess,
		},
	}

	var journal []byte
	frames := make([][]byte, 0, len(records))
	for _, record := range records {
		frame, err := encodePairingJournalFrame(record)
		if err != nil {
			t.Fatalf("encode record %d: %v", record.Sequence, err)
		}
		frames = append(frames, frame)
		journal = append(journal, frame...)
	}
	decoded, err := decodePairingJournal(journal)
	if err != nil {
		t.Fatalf("decode journal: %v", err)
	}
	if !reflect.DeepEqual(decoded, records) {
		t.Fatalf("decoded records = %#v, want %#v", decoded, records)
	}
	if _, err := buildPairingLedgerSnapshot(decoded, int64(len(journal)), ownerID); err != nil {
		t.Fatalf("build snapshot: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "truncated prefix", data: append([]byte(nil), journal[:2]...)},
		{name: "truncated body", data: append([]byte(nil), journal[:len(journal)-1]...)},
		{name: "zero length", data: []byte{0, 0, 0, 0}},
		{name: "oversized length", data: []byte{0, 0, 0x40, 1}},
		{name: "checksum mismatch", data: pairingFrameWithChecksum(t, records[0], make([]byte, sha256.Size))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodePairingJournal(test.data); err == nil {
				t.Fatal("damaged journal was accepted")
			}
		})
	}

	outOfOrder := append(append([]byte(nil), frames[0]...), frames[2]...)
	decodedOutOfOrder, err := decodePairingJournal(outOfOrder)
	if err != nil {
		t.Fatalf("decode out-of-order framing: %v", err)
	}
	if _, err := buildPairingLedgerSnapshot(decodedOutOfOrder, int64(len(outOfOrder)), ownerID); err == nil {
		t.Fatal("out-of-order sequence was accepted")
	}

	invalidReset := append([]pairingJournalRecord(nil), records[:1]...)
	invalidReset = append(invalidReset, pairingJournalRecord{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      2,
		Type:          pairingRecordCircuitReset,
		RecordedAt:    base.Add(pairingAdmissionCircuitHorizon),
		ResetNote:     "no-open-circuit",
	})
	if _, err := buildPairingLedgerSnapshot(invalidReset, 0, ownerID); err == nil {
		t.Fatal("circuit reset without an open circuit was accepted")
	}
}

func TestPairingLedgerDistinguishesMissingAndIndeterminate(t *testing.T) {
	now := time.Date(2026, 8, 21, 2, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), pairingLedgerFilename)
	validator := validateTestPairingLedgerFile

	snapshot, err := readPairingLedgerSnapshot(path, now, "", validator)
	if !errors.Is(err, ErrPairingLedgerNotInitialized) || snapshot.status.State != PairingLedgerNotInitialized {
		t.Fatalf("missing journal = %+v/%v, want ledger_not_initialized", snapshot.status, err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing read created journal: %v", statErr)
	}

	if writeErr := os.WriteFile(path, nil, 0o600); writeErr != nil {
		t.Fatalf("create empty journal: %v", writeErr)
	}
	snapshot, err = readPairingLedgerSnapshot(path, now, "", validator)
	if !errors.Is(err, ErrPairingLedgerIndeterminate) || snapshot.status.State != PairingLedgerIndeterminate {
		t.Fatalf("empty journal = %+v/%v, want ledger_indeterminate", snapshot.status, err)
	}
}

func TestPairingAdmissionLedgerBurnIsDurableBeforeReceipt(t *testing.T) {
	base := time.Date(2026, 8, 21, 3, 0, 0, 0, time.UTC)
	ledger, clock, path, _ := newTestPairingLedger(t, base, false)
	ledger.hooks.afterSync = func(pairingJournalRecord) error { return errTestPairingWriteHook }
	request := testPairingRequest("durable", *clock, 8)

	receipt, err := ledger.Admit(request)
	if receipt != nil || !errors.Is(err, ErrPairingLedgerIndeterminate) || !errors.Is(err, errTestPairingWriteHook) {
		t.Fatalf("admit after sync hook = %#v/%v, want nil indeterminate receipt", receipt, err)
	}
	ledger.hooks = pairingLedgerWriteHooks{}
	*clock = clock.Add(pairingAdmissionMinimumInterval)
	if retry, retryErr := ledger.Admit(request); retry != nil || !errors.Is(retryErr, ErrPairingCredentialUsed) {
		t.Fatalf("retry durable credential = %#v/%v, want already burned", retry, retryErr)
	}
	snapshot, readErr := readPairingLedgerSnapshot(path, *clock, ledger.ownerInstanceID, validateTestPairingLedgerFile)
	if readErr != nil || len(snapshot.admissions) != 1 {
		t.Fatalf("durable snapshot admissions = %d/%v, want 1", len(snapshot.admissions), readErr)
	}
}

func TestPairingAdmissionLedgerActivePathNeverCreatesOrRepairs(t *testing.T) {
	now := time.Date(2026, 8, 21, 4, 0, 0, 0, time.UTC)
	namespace := t.TempDir()
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "pairing-missing")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	path := filepath.Join(namespace, pairingLedgerFilename)
	ledger := testPairingLedgerForOwner(owner, path, &now)

	if receipt, err := ledger.Admit(testPairingRequest("missing", now, 4)); receipt != nil || !errors.Is(err, ErrPairingLedgerNotInitialized) {
		t.Fatalf("missing admit = %#v/%v, want ledger_not_initialized", receipt, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active path created missing journal: %v", err)
	}

	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt journal: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corrupt journal: %v", err)
	}
	if receipt, err := ledger.Admit(testPairingRequest("corrupt", now, 4)); receipt != nil || !errors.Is(err, ErrPairingLedgerIndeterminate) {
		t.Fatalf("corrupt admit = %#v/%v, want ledger_indeterminate", receipt, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread corrupt journal: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("active path repaired or rewrote corrupt journal")
	}
}

func TestPairingAdmissionWindowsUseWorstCaseReservations(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	ownerID := testPairingOwnerID("window-owner")

	tests := []struct {
		name        string
		offsets     []time.Duration
		packets     []int
		newPackets  int
		wantBlocked bool
	}{
		{
			name:        "minimum interval blocks at 59 seconds",
			offsets:     []time.Duration{-59 * time.Second},
			packets:     []int{1},
			newPackets:  1,
			wantBlocked: true,
		},
		{
			name:        "minimum interval releases at 60 seconds",
			offsets:     []time.Duration{-60 * time.Second},
			packets:     []int{1},
			newPackets:  1,
			wantBlocked: false,
		},
		{
			name:        "four admissions in one hour",
			offsets:     []time.Duration{-59 * time.Minute, -45 * time.Minute, -30 * time.Minute, -15 * time.Minute},
			packets:     []int{1, 1, 1, 1},
			newPackets:  1,
			wantBlocked: true,
		},
		{
			name: "twelve admissions in one day",
			offsets: []time.Duration{
				-23 * time.Hour, -21 * time.Hour, -19 * time.Hour, -17 * time.Hour,
				-15 * time.Hour, -13 * time.Hour, -11 * time.Hour, -9 * time.Hour,
				-7 * time.Hour, -5 * time.Hour, -3 * time.Hour, -1 * time.Hour,
			},
			packets:     []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			newPackets:  1,
			wantBlocked: true,
		},
		{
			name:        "packet reservation may reach exact ceiling",
			offsets:     []time.Duration{-8 * time.Hour, -6 * time.Hour, -4 * time.Hour, -2 * time.Hour},
			packets:     []int{500, 500, 500, 500},
			newPackets:  48,
			wantBlocked: false,
		},
		{
			name:        "packet reservation cannot exceed ceiling",
			offsets:     []time.Duration{-8 * time.Hour, -6 * time.Hour, -4 * time.Hour, -2 * time.Hour},
			packets:     []int{500, 500, 500, 500},
			newPackets:  49,
			wantBlocked: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := testPairingSnapshot(t, now, ownerID, test.offsets, test.packets)
			err := snapshot.admissionError(now, testPairingEnvelope(test.newPackets))
			if test.wantBlocked && !errors.Is(err, ErrPairingAdmissionRateLimited) {
				t.Fatalf("admission error = %v, want rate limited", err)
			}
			if !test.wantBlocked && err != nil {
				t.Fatalf("admission error = %v, want allowed", err)
			}
		})
	}
}

func TestPairingAdmissionCircuitPersistsUntilExplicitEligibleReset(t *testing.T) {
	base := time.Date(2026, 8, 21, 5, 0, 0, 0, time.UTC)
	ledger, clock, _, _ := newTestPairingLedger(t, base, false)
	for index := 0; index < pairingAdmissionFailureLimit; index++ {
		if index > 0 {
			*clock = clock.Add(pairingAdmissionMinimumInterval)
		}
		receipt, err := ledger.Admit(testPairingRequest(fmt.Sprintf("failure-%d", index), *clock, 1))
		if err != nil {
			t.Fatalf("admit failure %d: %v", index, err)
		}
		if err := ledger.Finish(receipt, PairingTerminalCarrierError); err != nil {
			t.Fatalf("finish failure %d: %v", index, err)
		}
	}
	opened := ledger.Status()
	if opened.State != PairingLedgerCircuitOpen || !opened.ExplicitResetRequired || opened.ConsecutiveFailures < pairingAdmissionFailureLimit {
		t.Fatalf("opened status = %+v", opened)
	}

	*clock = opened.CircuitResetEligibleAt.Add(12 * time.Hour)
	if status := ledger.Status(); status.State != PairingLedgerCircuitOpen {
		t.Fatalf("time-only reopen status = %+v, want circuit open", status)
	}
	if _, err := ledger.ResetCircuit(opened.Sequence-1, "operator-reviewed-test-reset"); !errors.Is(err, ErrPairingLedgerResetRejected) {
		t.Fatalf("stale reset error = %v, want rejected", err)
	}
	reset, err := ledger.ResetCircuit(opened.Sequence, "operator-reviewed-test-reset")
	if err != nil {
		t.Fatalf("eligible reset: %v", err)
	}
	if reset.State != PairingLedgerReady || reset.ExplicitResetRequired {
		t.Fatalf("reset status = %+v, want ready", reset)
	}
}

func TestPairingCircuitLatchesAcrossLateSuccessAndRestartedPendingAttempts(t *testing.T) {
	now := time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)
	oldOwner := testPairingOwnerID("old-owner")
	newOwner := testPairingOwnerID("new-owner")
	records := []pairingJournalRecord{{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      1,
		Type:          pairingRecordInitialize,
		RecordedAt:    now.Add(-10 * time.Hour),
	}}
	late := testPairingAdmissionRecord(2, "late-success", now.Add(-9*time.Hour), 1, oldOwner)
	records = append(records, late)
	for index, offset := range []time.Duration{-8 * time.Hour, -7 * time.Hour, -6 * time.Hour} {
		admission := testPairingAdmissionRecord(uint64(len(records)+1), fmt.Sprintf("latch-%d", index), now.Add(offset), 1, oldOwner)
		records = append(records, admission, pairingJournalRecord{
			SchemaVersion: pairingLedgerSchemaVersion,
			Sequence:      uint64(len(records) + 2),
			Type:          pairingRecordFinish,
			RecordedAt:    now.Add(offset + time.Second),
			CredentialID:  admission.CredentialID,
			AttemptID:     admission.AttemptID,
			Reason:        PairingTerminalCarrierError,
		})
	}
	records = append(records, pairingJournalRecord{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      uint64(len(records) + 1),
		Type:          pairingRecordFinish,
		RecordedAt:    now.Add(-time.Hour),
		CredentialID:  late.CredentialID,
		AttemptID:     late.AttemptID,
		Reason:        PairingTerminalSuccess,
	})
	snapshot, err := buildPairingLedgerSnapshot(records, 0, newOwner)
	if err != nil {
		t.Fatalf("build late-success snapshot: %v", err)
	}
	if status := snapshot.statusAt(now); status.State != PairingLedgerCircuitOpen {
		t.Fatalf("late success cleared persistent circuit: %+v", status)
	}

	pending := records[:1]
	for index := 0; index < pairingAdmissionFailureLimit; index++ {
		pending = append(pending, testPairingAdmissionRecord(
			uint64(len(pending)+1),
			fmt.Sprintf("pending-%d", index),
			now.Add(time.Duration(index-pairingAdmissionFailureLimit)*time.Minute),
			1,
			oldOwner,
		))
	}
	currentSnapshot, err := buildPairingLedgerSnapshot(pending, 0, oldOwner)
	if err != nil {
		t.Fatalf("build current-owner pending snapshot: %v", err)
	}
	if failures := currentSnapshot.statusAt(now).ConsecutiveFailures; failures != 0 {
		t.Fatalf("current owner in-flight failures = %d, want 0", failures)
	}
	restartedSnapshot, err := buildPairingLedgerSnapshot(pending, 0, newOwner)
	if err != nil {
		t.Fatalf("build restarted pending snapshot: %v", err)
	}
	if status := restartedSnapshot.statusAt(now); status.State != PairingLedgerCircuitOpen || status.ConsecutiveFailures != pairingAdmissionFailureLimit {
		t.Fatalf("restarted pending status = %+v, want persistent circuit", status)
	}
}

func TestPairingLedgerRebuildColdStartsWithWindowsFull(t *testing.T) {
	base := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), pairingLedgerFilename)
	if err := createPairingLedgerFile(path, 0o600, base, true); err != nil {
		t.Fatalf("create rebuild baseline: %v", err)
	}
	snapshot, err := readPairingLedgerSnapshot(path, base, "", validateTestPairingLedgerFile)
	if err != nil {
		t.Fatalf("read rebuild baseline: %v", err)
	}
	status := snapshot.statusAt(base)
	if status.State != PairingLedgerRateLimited || status.OneHourAdmissions != pairingAdmissionOneHourLimit || status.TwentyFourHourAdmissions != pairingAdmissionDayLimit || status.TwentyFourHourPackets != pairingAdmissionDayPackets {
		t.Fatalf("rebuild status = %+v, want all windows full", status)
	}
	if status := snapshot.statusAt(base.Add(pairingAdmissionDayWindow)); status.State != PairingLedgerReady {
		t.Fatalf("rebuild status after 24h = %+v, want ready", status)
	}
}

func TestPairingLedgerClockRollbackAndCapacityAreFailClosed(t *testing.T) {
	base := time.Date(2026, 8, 21, 7, 0, 0, 0, time.UTC)
	records := []pairingJournalRecord{{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      1,
		Type:          pairingRecordInitialize,
		RecordedAt:    base,
	}}
	snapshot, err := buildPairingLedgerSnapshot(records, 128, "")
	if err != nil {
		t.Fatalf("build clock snapshot: %v", err)
	}
	if _, err := snapshot.effectiveNow(base.Add(-pairingLedgerClockRollbackSkew - time.Nanosecond)); !errors.Is(err, ErrPairingLedgerClockRollback) {
		t.Fatalf("rollback error = %v, want clock rollback", err)
	}
	if effective, err := snapshot.effectiveNow(base.Add(-pairingLedgerClockRollbackSkew)); err != nil || !effective.Equal(base) {
		t.Fatalf("tolerated rollback = %s/%v, want high-watermark %s", effective, err, base)
	}

	snapshot.records = make([]pairingJournalRecord, maxPairingLedgerRecords-1)
	if err := snapshot.ensureAdmissionCapacity(1); !errors.Is(err, ErrPairingLedgerCapacity) {
		t.Fatalf("record capacity error = %v, want exhausted", err)
	}
	snapshot.records = records
	snapshot.bytes = maxPairingLedgerBytes - 32
	if err := snapshot.ensureRecordCapacity(64); !errors.Is(err, ErrPairingLedgerCapacity) {
		t.Fatalf("byte capacity error = %v, want exhausted", err)
	}
}

func TestPairingLedgerSetupUsesExclusiveCreate(t *testing.T) {
	base := time.Date(2026, 8, 21, 8, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), pairingLedgerFilename)
	if err := createPairingLedgerFile(path, 0o600, base, false); err != nil {
		t.Fatalf("initial exclusive create: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read initial journal: %v", err)
	}
	if err := createPairingLedgerFile(path, 0o600, base.Add(time.Hour), false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second create error = %v, want os.ErrExist", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read retained journal: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("exclusive create rewrote existing journal")
	}
}

func TestPairingJournalAppendHoldsMachineOwnerThroughSync(t *testing.T) {
	base := time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)
	ledger, clock, _, owner := newTestPairingLedger(t, base, false)
	entered := make(chan struct{})
	release := make(chan struct{})
	ledger.hooks.afterAppendBeforeSync = func(pairingJournalRecord) error {
		close(entered)
		<-release
		return nil
	}

	admitDone := make(chan error, 1)
	go func() {
		_, err := ledger.Admit(testPairingRequest("owner-held", *clock, 1))
		admitDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("append hook was not reached")
	}
	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- owner.Close()
	}()
	<-closeStarted
	select {
	case err := <-closeDone:
		t.Fatalf("owner closed before journal sync completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-admitDone; err != nil {
		t.Fatalf("admit after release: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("close owner after sync: %v", err)
	}
}

func TestPairingLedgerRejectsUserAcknowledgedOwner(t *testing.T) {
	owner, err := AcquirePreparedNamespace(t.TempDir(), ScopeUserAcknowledged, "pairing-user")
	if err != nil {
		t.Fatalf("acquire user owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	if ledger, err := owner.PairingLedger(); ledger != nil || !errors.Is(err, ErrPairingMachineScopeRequired) {
		t.Fatalf("user pairing ledger = %#v/%v, want machine scope required", ledger, err)
	}
}

func newTestPairingLedger(t *testing.T, at time.Time, rebuild bool) (*PairingAdmissionLedger, *time.Time, string, *Owner) {
	t.Helper()
	namespace := t.TempDir()
	path := filepath.Join(namespace, pairingLedgerFilename)
	if err := createPairingLedgerFile(path, 0o600, at, rebuild); err != nil {
		t.Fatalf("create test pairing journal: %v", err)
	}
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "pairing-test")
	if err != nil {
		t.Fatalf("acquire test pairing owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	clock := at.UTC()
	return testPairingLedgerForOwner(owner, path, &clock), &clock, path, owner
}

func testPairingLedgerForOwner(owner *Owner, path string, clock *time.Time) *PairingAdmissionLedger {
	return &PairingAdmissionLedger{
		owner:           owner,
		ownerInstanceID: owner.Info().InstanceID,
		path:            path,
		now:             func() time.Time { return *clock },
		validateFile:    validateTestPairingLedgerFile,
	}
}

func validateTestPairingLedgerFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("test journal is not a regular file")
	}
	return nil
}

func testPairingRequest(label string, now time.Time, packets int) PairingAdmissionRequest {
	contextDigest := sha256.Sum256([]byte("context:" + label))
	return PairingAdmissionRequest{
		CredentialID:  testPairingOpaqueID("credential-" + label),
		AttemptID:     testPairingOpaqueID("attempt-" + label),
		ContextDigest: hex.EncodeToString(contextDigest[:]),
		Scope:         ScopeMachine,
		ExpiresAt:     now.UTC().Add(pairingCredentialMaxLifetime),
		Envelope:      testPairingEnvelope(packets),
	}
}

func testPairingEnvelope(packets int) PairingAdmissionEnvelope {
	return PairingAdmissionEnvelope{
		Sockets:          1,
		Targets:          1,
		PacketsPerSecond: 1,
		Packets:          packets,
		FiveTuples:       1,
		DurationMillis:   1000,
	}
}

func testPairingOpaqueID(label string) string {
	digest := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

func testPairingOwnerID(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:16])
}

func testPairingAdmissionRecord(sequence uint64, label string, at time.Time, packets int, ownerID string) pairingJournalRecord {
	request := testPairingRequest(label, at, packets)
	return pairingJournalRecord{
		SchemaVersion:   pairingLedgerSchemaVersion,
		Sequence:        sequence,
		Type:            pairingRecordBurnAndAdmit,
		RecordedAt:      at.UTC(),
		CredentialID:    request.CredentialID,
		AttemptID:       request.AttemptID,
		ContextDigest:   request.ContextDigest,
		OwnerInstanceID: ownerID,
		Scope:           ScopeMachine,
		ExpiresAt:       request.ExpiresAt,
		Envelope:        request.Envelope,
	}
}

func testPairingSnapshot(t *testing.T, now time.Time, ownerID string, offsets []time.Duration, packets []int) pairingLedgerSnapshot {
	t.Helper()
	if len(offsets) != len(packets) {
		t.Fatalf("offsets=%d packets=%d", len(offsets), len(packets))
	}
	records := []pairingJournalRecord{{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      1,
		Type:          pairingRecordInitialize,
		RecordedAt:    now.Add(-48 * time.Hour),
	}}
	for index, offset := range offsets {
		admission := testPairingAdmissionRecord(uint64(len(records)+1), fmt.Sprintf("window-%d", index), now.Add(offset), packets[index], ownerID)
		records = append(records, admission, pairingJournalRecord{
			SchemaVersion: pairingLedgerSchemaVersion,
			Sequence:      uint64(len(records) + 2),
			Type:          pairingRecordFinish,
			RecordedAt:    now.Add(offset + time.Nanosecond),
			CredentialID:  admission.CredentialID,
			AttemptID:     admission.AttemptID,
			Reason:        PairingTerminalSuccess,
		})
	}
	snapshot, err := buildPairingLedgerSnapshot(records, 0, ownerID)
	if err != nil {
		t.Fatalf("build window snapshot: %v", err)
	}
	return snapshot
}

func pairingFrameWithChecksum(t *testing.T, record pairingJournalRecord, checksum []byte) []byte {
	t.Helper()
	payload, err := json.Marshal(pairingJournalFrame{
		Record:   record,
		Checksum: hex.EncodeToString(checksum),
	})
	if err != nil {
		t.Fatalf("marshal checksum frame: %v", err)
	}
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(payload)))
	copy(framed[4:], payload)
	return framed
}
