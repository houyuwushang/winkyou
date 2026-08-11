package governor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	safetyTripFilename      = "safety-trip.json"
	safetyTripSchemaVersion = 1
	maxSafetyTripFileBytes  = 16 << 10
	maxSafetyTripDetailLen  = 1024
	maxSafetyTripNoteLen    = 1024
	maxSafetyTripBuildLen   = 128

	safetyTripLatchClear   byte = 'C'
	safetyTripLatchTripped byte = 'T'
)

var (
	ErrSafetyTripped          = errors.New("machine safety trip blocks active work")
	ErrSafetyStateCorrupt     = errors.New("safety trip state is corrupt or indeterminate")
	ErrSafetyStateUnavailable = errors.New("safety trip state is unavailable")
	ErrSafetyResetRejected    = errors.New("safety trip reset was rejected")
)

// SafetyTripState is a stable, machine-readable circuit state.
type SafetyTripState string

const (
	SafetyTripClear         SafetyTripState = "clear"
	SafetyTripTripped       SafetyTripState = "tripped"
	SafetyTripIndeterminate SafetyTripState = "indeterminate"
	SafetyTripUnavailable   SafetyTripState = "unavailable"
)

// SafetyTripReason identifies one reviewed fail-closed trigger.
type SafetyTripReason string

const (
	SafetyTripResourceExhausted SafetyTripReason = "resource_exhausted"
	SafetyTripWriteFailures     SafetyTripReason = "consecutive_write_failures"
	SafetyTripHardLimit         SafetyTripReason = "hard_limit_exceeded"
	SafetyTripCancellation      SafetyTripReason = "cancellation_timeout"
	SafetyTripStaleGeneration   SafetyTripReason = "stale_generation_send"
	SafetyTripOperator          SafetyTripReason = "operator_stop"
)

// SafetyTripEvent is the bounded diagnostic context persisted for the first
// trip. It must not contain credentials, packet payloads, or private keys.
type SafetyTripEvent struct {
	Reason       SafetyTripReason `json:"reason"`
	Detail       string           `json:"detail,omitempty"`
	PeerID       string           `json:"peer_id,omitempty"`
	AttemptID    string           `json:"attempt_id,omitempty"`
	BuildVersion string           `json:"build_version,omitempty"`
	OccurredAt   time.Time        `json:"occurred_at,omitempty"`
}

// SafetyTripRecord is the checksummed durable record behind the one-byte
// fail-closed latch.
type SafetyTripRecord struct {
	SchemaVersion int              `json:"schema_version"`
	State         SafetyTripState  `json:"state"`
	Sequence      uint64           `json:"sequence"`
	UpdatedAt     time.Time        `json:"updated_at"`
	Reason        SafetyTripReason `json:"reason,omitempty"`
	Detail        string           `json:"detail,omitempty"`
	PeerID        string           `json:"peer_id,omitempty"`
	AttemptID     string           `json:"attempt_id,omitempty"`
	BuildVersion  string           `json:"build_version,omitempty"`
	ResetNote     string           `json:"reset_note,omitempty"`
}

// SafetyTripStatus is safe to expose in status and JSON diagnostics.
// BlocksActiveWork is true for tripped, corrupt, and unavailable state.
type SafetyTripStatus struct {
	State            SafetyTripState  `json:"state"`
	BlocksActiveWork bool             `json:"blocks_active_work"`
	Record           SafetyTripRecord `json:"record,omitempty"`
	Detail           string           `json:"detail,omitempty"`
}

// MarshalJSON omits the zero record used by unavailable/indeterminate status.
func (status SafetyTripStatus) MarshalJSON() ([]byte, error) {
	type statusJSON struct {
		State            SafetyTripState   `json:"state"`
		BlocksActiveWork bool              `json:"blocks_active_work"`
		Record           *SafetyTripRecord `json:"record,omitempty"`
		Detail           string            `json:"detail,omitempty"`
	}
	encoded := statusJSON{
		State:            status.State,
		BlocksActiveWork: status.BlocksActiveWork,
		Detail:           status.Detail,
	}
	if status.Record.SchemaVersion != 0 {
		encoded.Record = &status.Record
	}
	return json.Marshal(encoded)
}

// SafetyTripError preserves the status that blocked governor construction or
// a new lease. Indeterminate state unwraps to both safety errors.
type SafetyTripError struct {
	Status SafetyTripStatus
}

func (e *SafetyTripError) Error() string {
	if e == nil {
		return ErrSafetyTripped.Error()
	}
	if e.Status.Detail != "" {
		return fmt.Sprintf("%s: state=%s detail=%s", ErrSafetyTripped, e.Status.State, e.Status.Detail)
	}
	return fmt.Sprintf("%s: state=%s sequence=%d", ErrSafetyTripped, e.Status.State, e.Status.Record.Sequence)
}

func (e *SafetyTripError) Unwrap() []error {
	errs := []error{ErrSafetyTripped}
	if e != nil && e.Status.State == SafetyTripIndeterminate {
		errs = append(errs, ErrSafetyStateCorrupt)
	}
	if e != nil && e.Status.State == SafetyTripUnavailable {
		errs = append(errs, ErrSafetyStateUnavailable)
	}
	return errs
}

type safetyTripEnvelope struct {
	Record   SafetyTripRecord `json:"record"`
	Checksum string           `json:"checksum"`
}

type safetyTripWriteHooks struct {
	afterTripLatchSync func() error
	beforeResetClear   func() error
}

type safetyTripStore struct {
	mu    sync.Mutex
	path  string
	now   func() time.Time
	hooks safetyTripWriteHooks
}

func newSafetyTripStore(namespace string) *safetyTripStore {
	return &safetyTripStore{
		path: filepath.Join(namespace, safetyTripFilename),
		now:  time.Now,
	}
}

func (store *safetyTripStore) status() SafetyTripStatus {
	if store == nil {
		return indeterminateSafetyTripStatus("safety trip store is unavailable")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.readLocked()
}

func (store *safetyTripStore) trip(event SafetyTripEvent) (SafetyTripStatus, error) {
	return store.tripThen(event, nil)
}

// tripThen invokes afterLatch after the blocking latch is durable and before
// diagnostic detail is written. Governor uses it to begin bounded attempt
// cancellation at the fail-closed commit point.
func (store *safetyTripStore) tripThen(event SafetyTripEvent, afterLatch func()) (SafetyTripStatus, error) {
	if store == nil {
		status := indeterminateSafetyTripStatus("safety trip store is unavailable")
		return status, &SafetyTripError{Status: status}
	}
	if err := validateSafetyTripEvent(event); err != nil {
		return SafetyTripStatus{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	current := store.readLocked()
	if current.State == SafetyTripTripped {
		if afterLatch != nil {
			afterLatch()
		}
		return current, nil
	}
	if current.BlocksActiveWork {
		if afterLatch != nil {
			afterLatch()
		}
		return current, &SafetyTripError{Status: current}
	}

	when := event.OccurredAt
	if when.IsZero() {
		when = store.now()
	}
	record := SafetyTripRecord{
		SchemaVersion: safetyTripSchemaVersion,
		State:         SafetyTripTripped,
		Sequence:      current.Record.Sequence + 1,
		UpdatedAt:     when.UTC(),
		Reason:        event.Reason,
		Detail:        event.Detail,
		PeerID:        event.PeerID,
		AttemptID:     event.AttemptID,
		BuildVersion:  event.BuildVersion,
	}

	file, err := openSafetyTripFile(store.path)
	if err != nil {
		status := indeterminateSafetyTripStatus(err.Error())
		return status, err
	}
	if err := writeSafetyTripLatch(file, safetyTripLatchTripped); err != nil {
		_ = file.Close()
		status := indeterminateSafetyTripStatus(err.Error())
		return status, err
	}
	if afterLatch != nil {
		afterLatch()
	}
	if hook := store.hooks.afterTripLatchSync; hook != nil {
		if err := hook(); err != nil {
			_ = file.Close()
			return store.readLocked(), fmt.Errorf("after trip latch commit: %w", err)
		}
	}
	if err := writeSafetyTripRecord(file, record); err != nil {
		_ = file.Close()
		return store.readLocked(), err
	}
	if err := file.Close(); err != nil {
		return store.readLocked(), fmt.Errorf("close safety trip file: %w", err)
	}
	status := store.readLocked()
	if status.State != SafetyTripTripped {
		return status, &SafetyTripError{Status: status}
	}
	return status, nil
}

func (store *safetyTripStore) reset(expectedSequence uint64, note, buildVersion string) (SafetyTripStatus, error) {
	if store == nil {
		status := indeterminateSafetyTripStatus("safety trip store is unavailable")
		return status, &SafetyTripError{Status: status}
	}
	if err := validateSafetyResetRequest(expectedSequence, note, buildVersion); err != nil {
		return SafetyTripStatus{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	current := store.readLocked()
	if current.State != SafetyTripTripped {
		if current.BlocksActiveWork {
			return current, &SafetyTripError{Status: current}
		}
		return current, fmt.Errorf("%w: state is %s", ErrSafetyResetRejected, current.State)
	}
	if expectedSequence == 0 || expectedSequence != current.Record.Sequence {
		return current, fmt.Errorf(
			"%w: expected sequence %d, current sequence %d",
			ErrSafetyResetRejected,
			expectedSequence,
			current.Record.Sequence,
		)
	}

	record := SafetyTripRecord{
		SchemaVersion: safetyTripSchemaVersion,
		State:         SafetyTripClear,
		Sequence:      current.Record.Sequence + 1,
		UpdatedAt:     store.now().UTC(),
		BuildVersion:  buildVersion,
		ResetNote:     note,
	}
	file, err := openSafetyTripFile(store.path)
	if err != nil {
		return current, err
	}
	// Keep the durable latch tripped until the complete clear record is synced.
	if err := writeSafetyTripRecord(file, record); err != nil {
		_ = file.Close()
		return store.readLocked(), err
	}
	if hook := store.hooks.beforeResetClear; hook != nil {
		if err := hook(); err != nil {
			_ = file.Close()
			return store.readLocked(), fmt.Errorf("before reset latch clear: %w", err)
		}
	}
	if err := writeSafetyTripLatch(file, safetyTripLatchClear); err != nil {
		_ = file.Close()
		return store.readLocked(), err
	}
	if err := file.Close(); err != nil {
		return store.readLocked(), fmt.Errorf("close safety trip file: %w", err)
	}
	status := store.readLocked()
	if status.State != SafetyTripClear {
		return status, &SafetyTripError{Status: status}
	}
	return status, nil
}

func (store *safetyTripStore) readLocked() SafetyTripStatus {
	data, err := readSafetyTripFile(store.path)
	if err != nil {
		return indeterminateSafetyTripStatus(err.Error())
	}
	latch := data[0]
	record, err := decodeSafetyTripRecord(data[1:])
	if err != nil {
		return indeterminateSafetyTripStatus(err.Error())
	}

	switch {
	case latch == safetyTripLatchClear && record.State == SafetyTripClear:
		return SafetyTripStatus{State: SafetyTripClear, Record: record}
	case latch == safetyTripLatchTripped && record.State == SafetyTripTripped:
		return SafetyTripStatus{State: SafetyTripTripped, BlocksActiveWork: true, Record: record}
	default:
		return indeterminateSafetyTripStatus(fmt.Sprintf("safety trip latch %q does not match record state %q", latch, record.State))
	}
}

func initializeSafetyTripFile(file *os.File, now time.Time) error {
	if file == nil {
		return errors.New("initialize safety trip file: file is nil")
	}
	record := SafetyTripRecord{
		SchemaVersion: safetyTripSchemaVersion,
		State:         SafetyTripClear,
		UpdatedAt:     now.UTC(),
	}
	payload, err := encodeSafetyTripRecord(record)
	if err != nil {
		return err
	}
	data := append([]byte{safetyTripLatchClear}, payload...)
	if _, err := file.WriteAt(data, 0); err != nil {
		return fmt.Errorf("write initial safety trip state: %w", err)
	}
	if err := file.Truncate(int64(len(data))); err != nil {
		return fmt.Errorf("truncate initial safety trip state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync initial safety trip state: %w", err)
	}
	return nil
}

func openSafetyTripFile(path string) (*os.File, error) {
	if err := validateSafetyTripFilePath(path); err != nil {
		return nil, fmt.Errorf("open safety trip state: %w", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open safety trip state: %w", err)
	}
	return file, nil
}

func readSafetyTripFile(path string) ([]byte, error) {
	if err := validateSafetyTripFilePath(path); err != nil {
		return nil, fmt.Errorf("read safety trip state: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read safety trip state: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxSafetyTripFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read safety trip state: %w", err)
	}
	if len(data) < 2 {
		return nil, errors.New("safety trip state is empty or truncated")
	}
	if len(data) > maxSafetyTripFileBytes {
		return nil, fmt.Errorf("safety trip state exceeds %d bytes", maxSafetyTripFileBytes)
	}
	return data, nil
}

func validateSafetyTripFilePath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("safety trip file is a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("safety trip path is not a regular file")
	}
	return nil
}

func writeSafetyTripLatch(file *os.File, latch byte) error {
	if _, err := file.WriteAt([]byte{latch}, 0); err != nil {
		return fmt.Errorf("write safety trip latch: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync safety trip latch: %w", err)
	}
	return nil
}

func writeSafetyTripRecord(file *os.File, record SafetyTripRecord) error {
	payload, err := encodeSafetyTripRecord(record)
	if err != nil {
		return err
	}
	if 1+len(payload) > maxSafetyTripFileBytes {
		return fmt.Errorf("safety trip state exceeds %d bytes", maxSafetyTripFileBytes)
	}
	if _, err := file.WriteAt(payload, 1); err != nil {
		return fmt.Errorf("write safety trip record: %w", err)
	}
	if err := file.Truncate(int64(1 + len(payload))); err != nil {
		return fmt.Errorf("truncate safety trip record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync safety trip record: %w", err)
	}
	return nil
}

func encodeSafetyTripRecord(record SafetyTripRecord) ([]byte, error) {
	if err := validateSafetyTripRecord(record); err != nil {
		return nil, err
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode safety trip record: %w", err)
	}
	checksum := sha256.Sum256(recordPayload)
	envelope := safetyTripEnvelope{
		Record:   record,
		Checksum: hex.EncodeToString(checksum[:]),
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode safety trip envelope: %w", err)
	}
	return append(payload, '\n'), nil
}

func decodeSafetyTripRecord(payload []byte) (SafetyTripRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope safetyTripEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return SafetyTripRecord{}, fmt.Errorf("%w: decode envelope: %v", ErrSafetyStateCorrupt, err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return SafetyTripRecord{}, fmt.Errorf("%w: trailing data", ErrSafetyStateCorrupt)
	}
	if err := validateSafetyTripRecord(envelope.Record); err != nil {
		return SafetyTripRecord{}, fmt.Errorf("%w: %v", ErrSafetyStateCorrupt, err)
	}
	recordPayload, err := json.Marshal(envelope.Record)
	if err != nil {
		return SafetyTripRecord{}, fmt.Errorf("%w: encode checksum input: %v", ErrSafetyStateCorrupt, err)
	}
	want := sha256.Sum256(recordPayload)
	got, err := hex.DecodeString(envelope.Checksum)
	if err != nil || len(got) != sha256.Size || !bytes.Equal(got, want[:]) {
		return SafetyTripRecord{}, fmt.Errorf("%w: checksum mismatch", ErrSafetyStateCorrupt)
	}
	return envelope.Record, nil
}

func validateSafetyTripEvent(event SafetyTripEvent) error {
	if !event.Reason.valid() {
		return fmt.Errorf("%w: unknown safety trip reason %q", ErrInvalidRequest, event.Reason)
	}
	if err := validateSafetyDiagnosticText("safety trip detail", event.Detail, maxSafetyTripDetailLen, true); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := validateSafetyDiagnosticText("build version", event.BuildVersion, maxSafetyTripBuildLen, true); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "peer id", value: event.PeerID},
		{field: "attempt id", value: event.AttemptID},
	} {
		if item.value != "" {
			if err := validateIdentifier(item.field, item.value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSafetyTripRecord(record SafetyTripRecord) error {
	if record.SchemaVersion != safetyTripSchemaVersion {
		return fmt.Errorf("schema version is %d, want %d", record.SchemaVersion, safetyTripSchemaVersion)
	}
	if record.UpdatedAt.IsZero() {
		return errors.New("updated_at is missing")
	}
	if err := validateSafetyDiagnosticText("detail", record.Detail, maxSafetyTripDetailLen, true); err != nil {
		return err
	}
	if err := validateSafetyDiagnosticText("reset note", record.ResetNote, maxSafetyTripNoteLen, true); err != nil {
		return err
	}
	if err := validateSafetyDiagnosticText("build version", record.BuildVersion, maxSafetyTripBuildLen, true); err != nil {
		return err
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "peer id", value: record.PeerID},
		{field: "attempt id", value: record.AttemptID},
	} {
		if item.value != "" {
			if err := validateIdentifier(item.field, item.value); err != nil {
				return err
			}
		}
	}
	switch record.State {
	case SafetyTripClear:
		if record.Reason != "" || record.Detail != "" || record.PeerID != "" || record.AttemptID != "" {
			return errors.New("clear record contains trip-only fields")
		}
		if record.Sequence > 0 && record.ResetNote == "" {
			return errors.New("reset clear record has no operator note")
		}
	case SafetyTripTripped:
		if !record.Reason.valid() {
			return fmt.Errorf("unknown trip reason %q", record.Reason)
		}
		if record.Sequence == 0 {
			return errors.New("tripped record sequence is zero")
		}
		if record.ResetNote != "" {
			return errors.New("tripped record contains a reset note")
		}
	default:
		return fmt.Errorf("unknown record state %q", record.State)
	}
	return nil
}

func validateSafetyResetRequest(expectedSequence uint64, note, buildVersion string) error {
	if expectedSequence == 0 {
		return fmt.Errorf("%w: expected sequence must be greater than zero", ErrSafetyResetRejected)
	}
	if strings.TrimSpace(note) != note {
		return fmt.Errorf("%w: reset note must not have surrounding whitespace", ErrSafetyResetRejected)
	}
	if err := validateSafetyDiagnosticText("reset note", note, maxSafetyTripNoteLen, false); err != nil {
		return fmt.Errorf("%w: %v", ErrSafetyResetRejected, err)
	}
	if err := validateSafetyDiagnosticText("build version", buildVersion, maxSafetyTripBuildLen, true); err != nil {
		return fmt.Errorf("%w: %v", ErrSafetyResetRejected, err)
	}
	return nil
}

func validateSafetyDiagnosticText(field, value string, maximum int, allowEmpty bool) error {
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s is empty", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s exceeds %d bytes", field, maximum)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s contains a control character", field)
	}
	return nil
}

func (reason SafetyTripReason) valid() bool {
	switch reason {
	case SafetyTripResourceExhausted,
		SafetyTripWriteFailures,
		SafetyTripHardLimit,
		SafetyTripCancellation,
		SafetyTripStaleGeneration,
		SafetyTripOperator:
		return true
	default:
		return false
	}
}

func indeterminateSafetyTripStatus(detail string) SafetyTripStatus {
	return SafetyTripStatus{
		State:            SafetyTripIndeterminate,
		BlocksActiveWork: true,
		Detail:           detail,
	}
}

// InspectMachineSafetyTrip reads the canonical state without acquiring the
// owner lock or modifying the machine.
func InspectMachineSafetyTrip() SafetyTripStatus {
	namespace := InspectMachineNamespace()
	if !namespace.Ready {
		return SafetyTripStatus{
			State:            SafetyTripUnavailable,
			BlocksActiveWork: true,
			Detail:           namespace.Detail,
		}
	}
	return newSafetyTripStore(namespace.Path).status()
}

// ResetMachineSafetyTrip clears one exact observed trip. It requires machine
// elevation and exclusive namespace ownership, so a running official governor
// or a newer trip cannot be reset accidentally.
func ResetMachineSafetyTrip(expectedSequence uint64, note, buildVersion string) (status SafetyTripStatus, err error) {
	if requestErr := validateSafetyResetRequest(expectedSequence, note, buildVersion); requestErr != nil {
		return SafetyTripStatus{}, requestErr
	}
	namespace := InspectMachineNamespace()
	if !namespace.Ready {
		status = SafetyTripStatus{
			State:            SafetyTripUnavailable,
			BlocksActiveWork: true,
			Detail:           namespace.Detail,
		}
		return status, fmt.Errorf("%w: machine namespace is %s", ErrSafetyResetRejected, namespace.State)
	}
	elevated, elevationErr := machineScopeElevated()
	if elevationErr != nil {
		return newSafetyTripStore(namespace.Path).status(), fmt.Errorf("inspect reset elevation: %w", elevationErr)
	}
	if !elevated {
		return newSafetyTripStore(namespace.Path).status(), fmt.Errorf("%w: reset requires administrator or root", ErrElevationRequired)
	}

	owner, acquireErr := AcquireMachineNamespace(buildVersion)
	if acquireErr != nil {
		return newSafetyTripStore(namespace.Path).status(), fmt.Errorf("acquire machine namespace for reset: %w", acquireErr)
	}
	defer func() {
		if closeErr := owner.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	return owner.tripStore.reset(expectedSequence, note, buildVersion)
}
