package governor

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	pairingLedgerFilename      = "pairing-admission-v1.journal"
	pairingLedgerSchemaVersion = 1

	maxPairingLedgerBytes      int64 = 4 << 20
	maxPairingLedgerRecords          = 8192
	maxPairingLedgerFrameBytes       = 16 << 10

	pairingAdmissionMinimumInterval = 60 * time.Second
	pairingAdmissionOneHourWindow   = time.Hour
	pairingAdmissionOneHourLimit    = 4
	pairingAdmissionDayWindow       = 24 * time.Hour
	pairingAdmissionDayLimit        = 12
	pairingAdmissionDayPackets      = 2048
	pairingAdmissionFailureLimit    = 3
	pairingAdmissionCircuitHorizon  = 6 * time.Hour
	pairingLedgerClockRollbackSkew  = 2 * time.Minute
	pairingCredentialMaxLifetime    = 10 * time.Minute
)

var (
	ErrPairingLedgerNotInitialized = errors.New("pairing ledger is not initialized")
	ErrPairingLedgerIndeterminate  = errors.New("pairing ledger is indeterminate")
	ErrPairingCredentialUsed       = errors.New("pairing credential is already burned")
	ErrPairingAdmissionRateLimited = errors.New("pairing admission persistent budget is exhausted")
	ErrPairingAdmissionCircuitOpen = errors.New("pairing admission circuit is open")
	ErrPairingLedgerCapacity       = errors.New("pairing ledger capacity is exhausted")
	ErrPairingLedgerClockRollback  = errors.New("pairing ledger clock moved backwards")
	ErrPairingLedgerResetRejected  = errors.New("pairing ledger reset was rejected")
	ErrPairingLedgerInvalidRequest = errors.New("invalid pairing ledger request")
	ErrPairingMachineScopeRequired = errors.New("pairing ledger requires machine governor scope")
)

// PairingLedgerState is a stable read-only diagnostic state. All states other
// than ready block a new pairing admission, but they remain distinct from the
// persistent safety-trip latch.
type PairingLedgerState string

const (
	PairingLedgerReady          PairingLedgerState = "ready"
	PairingLedgerNotInitialized PairingLedgerState = "ledger_not_initialized"
	PairingLedgerIndeterminate  PairingLedgerState = "ledger_indeterminate"
	PairingLedgerRateLimited    PairingLedgerState = "admission_rate_limited"
	PairingLedgerCircuitOpen    PairingLedgerState = "admission_circuit_open"
	PairingLedgerCapacityFull   PairingLedgerState = "ledger_capacity_exhausted"
	PairingLedgerClockRollback  PairingLedgerState = "clock_rollback"
)

// PairingAdmissionLimits is the compiled cross-process and cross-restart
// ceiling. Runtime policy may lower but never raise these values.
type PairingAdmissionLimits struct {
	MinimumInterval          time.Duration `json:"minimum_interval"`
	OneHourAdmissions        int           `json:"one_hour_admissions"`
	TwentyFourHourAdmissions int           `json:"twenty_four_hour_admissions"`
	TwentyFourHourPackets    int           `json:"twenty_four_hour_packets"`
	FailureLimit             int           `json:"failure_limit"`
	CircuitHorizon           time.Duration `json:"circuit_horizon"`
	ClockRollbackTolerance   time.Duration `json:"clock_rollback_tolerance"`
	MaxJournalBytes          int64         `json:"max_journal_bytes"`
	MaxJournalRecords        int           `json:"max_journal_records"`
}

// PairingAdmissionHardLimits returns the immutable Phase 1a machine policy.
func PairingAdmissionHardLimits() PairingAdmissionLimits {
	return PairingAdmissionLimits{
		MinimumInterval:          pairingAdmissionMinimumInterval,
		OneHourAdmissions:        pairingAdmissionOneHourLimit,
		TwentyFourHourAdmissions: pairingAdmissionDayLimit,
		TwentyFourHourPackets:    pairingAdmissionDayPackets,
		FailureLimit:             pairingAdmissionFailureLimit,
		CircuitHorizon:           pairingAdmissionCircuitHorizon,
		ClockRollbackTolerance:   pairingLedgerClockRollbackSkew,
		MaxJournalBytes:          maxPairingLedgerBytes,
		MaxJournalRecords:        maxPairingLedgerRecords,
	}
}

// PairingLedgerStatus contains no credential, attempt, endpoint, or secret. It
// is safe for a future additive read-only stdio diagnostic field.
type PairingLedgerStatus struct {
	State                    PairingLedgerState     `json:"state"`
	BlocksActiveWork         bool                   `json:"blocks_active_work"`
	Sequence                 uint64                 `json:"sequence,omitempty"`
	Records                  int                    `json:"records,omitempty"`
	Bytes                    int64                  `json:"bytes,omitempty"`
	HighWatermark            time.Time              `json:"high_watermark,omitempty"`
	LastAdmissionAt          time.Time              `json:"last_admission_at,omitempty"`
	OneHourAdmissions        int                    `json:"one_hour_admissions,omitempty"`
	TwentyFourHourAdmissions int                    `json:"twenty_four_hour_admissions,omitempty"`
	TwentyFourHourPackets    int                    `json:"twenty_four_hour_packets,omitempty"`
	ConsecutiveFailures      int                    `json:"consecutive_failures,omitempty"`
	CircuitOpenedAt          time.Time              `json:"circuit_opened_at,omitempty"`
	CircuitResetEligibleAt   time.Time              `json:"circuit_reset_eligible_at,omitempty"`
	ExplicitResetRequired    bool                   `json:"explicit_reset_required,omitempty"`
	NextAdmissionAt          time.Time              `json:"next_admission_at,omitempty"`
	Limits                   PairingAdmissionLimits `json:"limits"`
	Detail                   string                 `json:"detail,omitempty"`
}

// PairingLedgerError preserves the stable state and machine-readable cause
// without reflecting a filesystem path or credential.
type PairingLedgerError struct {
	Status PairingLedgerStatus
	Cause  error
}

func (e *PairingLedgerError) Error() string {
	if e == nil {
		return ErrPairingLedgerIndeterminate.Error()
	}
	if e.Status.Detail != "" {
		return fmt.Sprintf("pairing ledger blocks active work: state=%s detail=%s", e.Status.State, e.Status.Detail)
	}
	return fmt.Sprintf("pairing ledger blocks active work: state=%s", e.Status.State)
}

func (e *PairingLedgerError) Unwrap() error {
	if e == nil || e.Cause == nil {
		return ErrPairingLedgerIndeterminate
	}
	return e.Cause
}

// PairingAdmissionEnvelope is the complete worst-case cost charged before any
// future carrier activity. It intentionally records declared maxima rather
// than observed best-case use.
type PairingAdmissionEnvelope struct {
	Sockets          int   `json:"sockets"`
	Targets          int   `json:"targets"`
	PacketsPerSecond int   `json:"packets_per_second"`
	Packets          int   `json:"packets"`
	FiveTuples       int   `json:"five_tuples"`
	DurationMillis   int64 `json:"duration_ms"`
	Heavyweight      bool  `json:"heavyweight"`
}

// PairingEnvelopeFromAttemptCost produces the durable representation used by
// pairing admission. Validation still occurs when the journal commits it.
func PairingEnvelopeFromAttemptCost(cost AttemptCost) PairingAdmissionEnvelope {
	return PairingAdmissionEnvelope{
		Sockets:          cost.Resources.Sockets,
		Targets:          cost.Resources.Targets,
		PacketsPerSecond: cost.Resources.PacketsPerSecond,
		Packets:          cost.Resources.Packets,
		FiveTuples:       cost.Resources.FiveTuples,
		DurationMillis:   cost.Duration.Milliseconds(),
		Heavyweight:      cost.Heavyweight,
	}
}

func (envelope PairingAdmissionEnvelope) resources() Resources {
	return Resources{
		Sockets:          envelope.Sockets,
		Targets:          envelope.Targets,
		PacketsPerSecond: envelope.PacketsPerSecond,
		Packets:          envelope.Packets,
		FiveTuples:       envelope.FiveTuples,
	}
}

// PairingAdmissionRequest contains only secret-free values already validated
// from a complete bundle. AdmittedAt is selected by the ledger, never caller
// input.
type PairingAdmissionRequest struct {
	CredentialID  string
	AttemptID     string
	ContextDigest string
	Scope         Scope
	ExpiresAt     time.Time
	Envelope      PairingAdmissionEnvelope
}

// PairingTerminalReason is append-only diagnostic metadata. Only success
// clears the consecutive-failure streak.
type PairingTerminalReason string

const (
	PairingTerminalSuccess       PairingTerminalReason = "success"
	PairingTerminalCancelled     PairingTerminalReason = "cancelled"
	PairingTerminalExpired       PairingTerminalReason = "expired"
	PairingTerminalProtocolError PairingTerminalReason = "protocol_error"
	PairingTerminalScopeChanged  PairingTerminalReason = "scope_changed"
	PairingTerminalCarrierError  PairingTerminalReason = "carrier_error"
)

func (reason PairingTerminalReason) valid() bool {
	switch reason {
	case PairingTerminalSuccess,
		PairingTerminalCancelled,
		PairingTerminalExpired,
		PairingTerminalProtocolError,
		PairingTerminalScopeChanged,
		PairingTerminalCarrierError:
		return true
	default:
		return false
	}
}

// PairingAdmissionReceipt has no exported fields, so only a successful durable
// commit can construct one. A future admission gate may consume it once.
type PairingAdmissionReceipt struct {
	sequence        uint64
	credentialID    string
	attemptID       string
	contextDigest   string
	ownerInstanceID string
	committedAt     time.Time
}

// Sequence is diagnostic only and does not grant authority.
func (receipt *PairingAdmissionReceipt) Sequence() uint64 {
	if receipt == nil {
		return 0
	}
	return receipt.sequence
}

type pairingLedgerWriteHooks struct {
	writeFrame            func(*os.File, pairingJournalRecord, []byte) (int, error)
	afterAppendBeforeSync func(pairingJournalRecord) error
	afterSync             func(pairingJournalRecord) error
}

// PairingAdmissionLedger is a machine-owner-bound handle. It has no network
// capability and never accepts a caller-supplied path.
type PairingAdmissionLedger struct {
	mu              sync.Mutex
	owner           *Owner
	ownerInstanceID string
	path            string
	now             func() time.Time
	validateFile    pairingLedgerFileValidator
	hooks           pairingLedgerWriteHooks
}

// PairingLedger returns the singleton journal handle bound to this held
// machine owner. The existing governor OS lock is the only process lock.
func (o *Owner) PairingLedger() (*PairingAdmissionLedger, error) {
	if o == nil {
		return nil, fmt.Errorf("%w: owner is nil", ErrPairingMachineScopeRequired)
	}
	o.mu.Lock()
	if o.closed || o.file == nil {
		o.mu.Unlock()
		return nil, fmt.Errorf("%w: owner is closed", ErrPairingMachineScopeRequired)
	}
	if o.info.Scope != ScopeMachine {
		o.mu.Unlock()
		return nil, ErrPairingMachineScopeRequired
	}
	if o.pairingLedger != nil {
		ledger := o.pairingLedger
		o.mu.Unlock()
		return ledger, nil
	}
	path := filepath.Join(filepath.Dir(o.lockPath), pairingLedgerFilename)
	instanceID := o.info.InstanceID
	o.mu.Unlock()

	snapshot, statusErr := readPairingLedgerSnapshot(path, time.Now().UTC(), instanceID, validateMachinePairingLedgerFile)
	if statusErr != nil && (snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate) {
		return nil, statusErr
	}
	ledger := &PairingAdmissionLedger{
		owner:           o,
		ownerInstanceID: instanceID,
		path:            path,
		now:             time.Now,
		validateFile:    validateMachinePairingLedgerFile,
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.file == nil || o.info.InstanceID != instanceID {
		return nil, fmt.Errorf("%w: owner changed while opening journal", ErrPairingMachineScopeRequired)
	}
	if o.pairingLedger == nil {
		o.pairingLedger = ledger
	}
	return o.pairingLedger, nil
}

// Preflight performs the same credential, clock, capacity, rate, circuit, and
// envelope checks as Admit without appending or reserving anything. Admit
// remains authoritative and rechecks every condition at the burn boundary.
func (ledger *PairingAdmissionLedger) Preflight(request PairingAdmissionRequest) error {
	if ledger == nil {
		return fmt.Errorf("%w: ledger is nil", ErrPairingLedgerInvalidRequest)
	}
	if err := validatePairingAdmissionRequest(request); err != nil {
		return err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		return err
	}
	defer releaseOwner()

	now := ledger.now().UTC()
	snapshot, err := readPairingLedgerSnapshot(ledger.path, now, ledger.ownerInstanceID, ledger.validateFile)
	if err != nil && (snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate) {
		return err
	}
	effectiveNow, err := snapshot.effectiveNow(now)
	if err != nil {
		return err
	}
	if !effectiveNow.Before(request.ExpiresAt) {
		return fmt.Errorf("%w: bundle expired before admission", ErrPairingLedgerInvalidRequest)
	}
	if _, exists := snapshot.admissions[request.CredentialID]; exists {
		return &PairingLedgerError{Status: snapshot.statusAt(effectiveNow), Cause: ErrPairingCredentialUsed}
	}
	if _, exists := snapshot.attempts[request.AttemptID]; exists {
		return fmt.Errorf("%w: attempt id already recorded", ErrPairingLedgerInvalidRequest)
	}
	if err := snapshot.admissionError(effectiveNow, request.Envelope); err != nil {
		return err
	}
	record := pairingJournalRecord{
		SchemaVersion:   pairingLedgerSchemaVersion,
		Sequence:        snapshot.sequence + 1,
		Type:            pairingRecordBurnAndAdmit,
		RecordedAt:      effectiveNow,
		CredentialID:    request.CredentialID,
		AttemptID:       request.AttemptID,
		ContextDigest:   request.ContextDigest,
		OwnerInstanceID: ledger.ownerInstanceID,
		Scope:           ScopeMachine,
		ExpiresAt:       request.ExpiresAt.UTC(),
		Envelope:        request.Envelope,
	}
	frame, err := encodePairingJournalFrame(record)
	if err != nil {
		return err
	}
	return snapshot.ensureAdmissionCapacity(int64(len(frame)))
}

// Admit atomically burns one credential and reserves its full persistent
// envelope. It returns only after the append is synchronized and verified.
func (ledger *PairingAdmissionLedger) Admit(request PairingAdmissionRequest) (*PairingAdmissionReceipt, error) {
	if ledger == nil {
		return nil, fmt.Errorf("%w: ledger is nil", ErrPairingLedgerInvalidRequest)
	}
	if err := validatePairingAdmissionRequest(request); err != nil {
		return nil, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		return nil, err
	}
	defer releaseOwner()

	now := ledger.now().UTC()
	snapshot, err := readPairingLedgerSnapshot(ledger.path, now, ledger.ownerInstanceID, ledger.validateFile)
	if err != nil && (snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate) {
		return nil, err
	}
	effectiveNow, clockErr := snapshot.effectiveNow(now)
	if clockErr != nil {
		return nil, clockErr
	}
	if !effectiveNow.Before(request.ExpiresAt) {
		return nil, fmt.Errorf("%w: bundle expired before admission", ErrPairingLedgerInvalidRequest)
	}
	if _, exists := snapshot.admissions[request.CredentialID]; exists {
		return nil, &PairingLedgerError{Status: snapshot.statusAt(effectiveNow), Cause: ErrPairingCredentialUsed}
	}
	if _, exists := snapshot.attempts[request.AttemptID]; exists {
		return nil, fmt.Errorf("%w: attempt id already recorded", ErrPairingLedgerInvalidRequest)
	}
	if policyErr := snapshot.admissionError(effectiveNow, request.Envelope); policyErr != nil {
		return nil, policyErr
	}

	record := pairingJournalRecord{
		SchemaVersion:   pairingLedgerSchemaVersion,
		Sequence:        snapshot.sequence + 1,
		Type:            pairingRecordBurnAndAdmit,
		RecordedAt:      effectiveNow,
		CredentialID:    request.CredentialID,
		AttemptID:       request.AttemptID,
		ContextDigest:   request.ContextDigest,
		OwnerInstanceID: ledger.ownerInstanceID,
		Scope:           ScopeMachine,
		ExpiresAt:       request.ExpiresAt.UTC(),
		Envelope:        request.Envelope,
	}
	frame, err := encodePairingJournalFrame(record)
	if err != nil {
		return nil, err
	}
	if err := snapshot.ensureAdmissionCapacity(int64(len(frame))); err != nil {
		return nil, err
	}
	if err := ledger.appendAndSync(record, frame); err != nil {
		return nil, err
	}
	verified, verifyErr := readPairingLedgerSnapshot(ledger.path, effectiveNow, ledger.ownerInstanceID, ledger.validateFile)
	if verifyErr != nil {
		return nil, verifyErr
	}
	admission, exists := verified.admissions[request.CredentialID]
	if !exists || admission.record.Sequence != record.Sequence {
		status := indeterminatePairingLedgerStatus("committed admission could not be verified")
		return nil, &PairingLedgerError{Status: status, Cause: ErrPairingLedgerIndeterminate}
	}
	return &PairingAdmissionReceipt{
		sequence:        record.Sequence,
		credentialID:    request.CredentialID,
		attemptID:       request.AttemptID,
		contextDigest:   request.ContextDigest,
		ownerInstanceID: ledger.ownerInstanceID,
		committedAt:     effectiveNow,
	}, nil
}

// Finish appends one monotonic terminal reason. Failure to append never removes
// or refunds the earlier burn and reservation.
func (ledger *PairingAdmissionLedger) Finish(receipt *PairingAdmissionReceipt, reason PairingTerminalReason) error {
	if ledger == nil || receipt == nil {
		return fmt.Errorf("%w: receipt is missing", ErrPairingLedgerInvalidRequest)
	}
	if !reason.valid() {
		return fmt.Errorf("%w: terminal reason %q", ErrPairingLedgerInvalidRequest, reason)
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		return err
	}
	defer releaseOwner()
	if receipt.ownerInstanceID != ledger.ownerInstanceID {
		return fmt.Errorf("%w: receipt belongs to another owner instance", ErrPairingLedgerInvalidRequest)
	}

	now := ledger.now().UTC()
	snapshot, err := readPairingLedgerSnapshot(ledger.path, now, ledger.ownerInstanceID, ledger.validateFile)
	if err != nil && (snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate) {
		return err
	}
	effectiveNow, clockErr := snapshot.effectiveNow(now)
	if clockErr != nil {
		return clockErr
	}
	admission, exists := snapshot.admissions[receipt.credentialID]
	if !exists || admission.record.Sequence != receipt.sequence || admission.record.AttemptID != receipt.attemptID || admission.record.ContextDigest != receipt.contextDigest {
		return fmt.Errorf("%w: receipt does not match durable admission", ErrPairingLedgerInvalidRequest)
	}
	if admission.finish != nil {
		if admission.finish.Reason == reason {
			return nil
		}
		return fmt.Errorf("%w: terminal reason already recorded", ErrPairingLedgerInvalidRequest)
	}
	record := pairingJournalRecord{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      snapshot.sequence + 1,
		Type:          pairingRecordFinish,
		RecordedAt:    effectiveNow,
		CredentialID:  receipt.credentialID,
		AttemptID:     receipt.attemptID,
		Reason:        reason,
	}
	frame, encodeErr := encodePairingJournalFrame(record)
	if encodeErr != nil {
		return encodeErr
	}
	if capacityErr := snapshot.ensureRecordCapacity(int64(len(frame))); capacityErr != nil {
		return capacityErr
	}
	return ledger.appendAndSync(record, frame)
}

// ResetCircuit appends the explicit CAS reset used by the future local safety
// workflow. Six hours is a minimum horizon and time alone never reopens it.
func (ledger *PairingAdmissionLedger) ResetCircuit(expectedSequence uint64, note string) (PairingLedgerStatus, error) {
	if ledger == nil {
		return indeterminatePairingLedgerStatus("ledger is unavailable"), ErrPairingLedgerResetRejected
	}
	if expectedSequence == 0 || validatePairingResetNote(note) != nil {
		return PairingLedgerStatus{}, fmt.Errorf("%w: expected sequence and operator note are required", ErrPairingLedgerResetRejected)
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		return PairingLedgerStatus{}, err
	}
	defer releaseOwner()
	now := ledger.now().UTC()
	snapshot, err := readPairingLedgerSnapshot(ledger.path, now, ledger.ownerInstanceID, ledger.validateFile)
	if err != nil && (snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate) {
		return snapshot.status, err
	}
	effectiveNow, clockErr := snapshot.effectiveNow(now)
	if clockErr != nil {
		return snapshot.statusAt(now), clockErr
	}
	status := snapshot.statusAt(effectiveNow)
	if expectedSequence != snapshot.sequence {
		return status, fmt.Errorf("%w: expected sequence %d, current %d", ErrPairingLedgerResetRejected, expectedSequence, snapshot.sequence)
	}
	if !status.ExplicitResetRequired || status.CircuitOpenedAt.IsZero() {
		return status, fmt.Errorf("%w: circuit is not open", ErrPairingLedgerResetRejected)
	}
	if effectiveNow.Before(status.CircuitResetEligibleAt) {
		return status, fmt.Errorf("%w: circuit minimum horizon has not elapsed", ErrPairingLedgerResetRejected)
	}
	record := pairingJournalRecord{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      snapshot.sequence + 1,
		Type:          pairingRecordCircuitReset,
		RecordedAt:    effectiveNow,
		ResetNote:     note,
	}
	frame, encodeErr := encodePairingJournalFrame(record)
	if encodeErr != nil {
		return status, encodeErr
	}
	if capacityErr := snapshot.ensureRecordCapacity(int64(len(frame))); capacityErr != nil {
		return status, capacityErr
	}
	if appendErr := ledger.appendAndSync(record, frame); appendErr != nil {
		return status, appendErr
	}
	verified, verifyErr := readPairingLedgerSnapshot(ledger.path, effectiveNow, ledger.ownerInstanceID, ledger.validateFile)
	if verifyErr != nil {
		return verified.status, verifyErr
	}
	return verified.statusAt(effectiveNow), nil
}

// Status returns a fresh, secret-free journal snapshot.
func (ledger *PairingAdmissionLedger) Status() PairingLedgerStatus {
	if ledger == nil {
		return indeterminatePairingLedgerStatus("ledger is unavailable")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		status := indeterminatePairingLedgerStatus("machine owner is no longer held")
		status.Detail = "machine owner is no longer held"
		return status
	}
	defer releaseOwner()
	now := ledger.now().UTC()
	snapshot, _ := readPairingLedgerSnapshot(ledger.path, now, ledger.ownerInstanceID, ledger.validateFile)
	return snapshot.statusAt(now)
}

func (ledger *PairingAdmissionLedger) holdOwner() (func(), error) {
	if ledger.owner == nil {
		return nil, fmt.Errorf("%w: owner is unavailable", ErrPairingMachineScopeRequired)
	}
	ledger.owner.mu.Lock()
	if ledger.owner.closed || ledger.owner.file == nil || ledger.owner.info.Scope != ScopeMachine || ledger.owner.info.InstanceID != ledger.ownerInstanceID {
		ledger.owner.mu.Unlock()
		return nil, fmt.Errorf("%w: machine owner is no longer held", ErrPairingMachineScopeRequired)
	}
	return ledger.owner.mu.Unlock, nil
}

func (ledger *PairingAdmissionLedger) appendAndSync(record pairingJournalRecord, frame []byte) error {
	if err := appendPairingJournalFrame(ledger.path, record, frame, ledger.validateFile, ledger.hooks); err != nil {
		status := indeterminatePairingLedgerStatus("journal append or synchronization failed")
		return &PairingLedgerError{Status: status, Cause: errors.Join(ErrPairingLedgerIndeterminate, err)}
	}
	return nil
}

func validatePairingAdmissionRequest(request PairingAdmissionRequest) error {
	if request.Scope != ScopeMachine {
		return ErrPairingMachineScopeRequired
	}
	if err := validatePairingOpaqueID("credential id", request.CredentialID); err != nil {
		return err
	}
	if err := validatePairingOpaqueID("attempt id", request.AttemptID); err != nil {
		return err
	}
	if request.CredentialID == request.AttemptID {
		return fmt.Errorf("%w: credential and attempt ids must differ", ErrPairingLedgerInvalidRequest)
	}
	digest, err := hex.DecodeString(request.ContextDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != request.ContextDigest {
		return fmt.Errorf("%w: context digest must be 32 lowercase hexadecimal bytes", ErrPairingLedgerInvalidRequest)
	}
	if request.ExpiresAt.IsZero() || request.ExpiresAt.Location() != time.UTC {
		return fmt.Errorf("%w: expiry must be UTC", ErrPairingLedgerInvalidRequest)
	}
	return validatePairingEnvelope(request.Envelope)
}

func validatePairingOpaqueID(field, value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return fmt.Errorf("%w: %s must encode exactly 16 bytes", ErrPairingLedgerInvalidRequest, field)
	}
	return nil
}

func validatePairingOwnerInstanceID(value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("%w: owner instance id must be 32 lowercase hexadecimal characters", ErrPairingLedgerInvalidRequest)
	}
	return nil
}

func validatePairingResetNote(note string) error {
	if strings.TrimSpace(note) != note || note == "" || !utf8.ValidString(note) || len(note) > maxSafetyTripNoteLen || strings.IndexFunc(note, unicode.IsControl) >= 0 {
		return errors.New("pairing circuit reset note is missing, malformed, or too long")
	}
	return nil
}

func validatePairingEnvelope(envelope PairingAdmissionEnvelope) error {
	resources := envelope.resources()
	if err := resources.validateNonNegative(); err != nil {
		return fmt.Errorf("%w: %v", ErrPairingLedgerInvalidRequest, err)
	}
	if resources == (Resources{}) {
		return fmt.Errorf("%w: envelope reserves no resources", ErrPairingLedgerInvalidRequest)
	}
	if envelope.Packets <= 0 {
		return fmt.Errorf("%w: packet reservation must be positive", ErrPairingLedgerInvalidRequest)
	}
	if envelope.DurationMillis <= 0 {
		return fmt.Errorf("%w: duration must be positive", ErrPairingLedgerInvalidRequest)
	}
	machine, err := HardLimits(ProfilePhase1Machine)
	if err != nil {
		return err
	}
	manual, err := HardLimits(ProfilePhase1ManualTraversal)
	if err != nil {
		return err
	}
	hard := resourceMaximum(machine.PerAttempt, manual.PerAttempt)
	if field, current, maximum, exceeded := firstResourceExcess(resources, hard); exceeded {
		return &LimitError{Field: "pairing_per_attempt_" + field, Requested: current, Maximum: maximum}
	}
	maximumDuration := machine.MaxAttemptDuration
	if manual.MaxAttemptDuration > maximumDuration {
		maximumDuration = manual.MaxAttemptDuration
	}
	if envelope.DurationMillis > maximumDuration.Milliseconds() {
		return &LimitError{Field: "pairing_attempt_duration_ms", Requested: envelope.DurationMillis, Maximum: maximumDuration.Milliseconds()}
	}
	if envelope.Heavyweight && machine.MaxHeavyweightAttempts == 0 && manual.MaxHeavyweightAttempts == 0 {
		return fmt.Errorf("%w: heavyweight attempt is unavailable", ErrPairingLedgerInvalidRequest)
	}
	return nil
}

func resourceMaximum(left, right Resources) Resources {
	maximum := func(a, b int) int {
		if a > b {
			return a
		}
		return b
	}
	return Resources{
		Sockets: maximum(left.Sockets, right.Sockets), Targets: maximum(left.Targets, right.Targets),
		PacketsPerSecond: maximum(left.PacketsPerSecond, right.PacketsPerSecond),
		Packets:          maximum(left.Packets, right.Packets), FiveTuples: maximum(left.FiveTuples, right.FiveTuples),
	}
}
