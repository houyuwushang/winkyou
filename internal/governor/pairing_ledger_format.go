package governor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type pairingLedgerFileValidator func(string) error

type pairingJournalRecordType string

const (
	pairingRecordInitialize      pairingJournalRecordType = "initialize"
	pairingRecordRebuildBaseline pairingJournalRecordType = "rebuild_baseline"
	pairingRecordBurnAndAdmit    pairingJournalRecordType = "burn_and_admit"
	pairingRecordFinish          pairingJournalRecordType = "finish"
	pairingRecordCircuitReset    pairingJournalRecordType = "circuit_reset"
)

type pairingJournalRecord struct {
	SchemaVersion   int                      `json:"schema_version"`
	Sequence        uint64                   `json:"sequence"`
	Type            pairingJournalRecordType `json:"type"`
	RecordedAt      time.Time                `json:"recorded_at"`
	RecordClass     PairingLedgerRecordClass `json:"record_class,omitempty"`
	CredentialID    string                   `json:"credential_id,omitempty"`
	AttemptID       string                   `json:"attempt_id,omitempty"`
	ContextDigest   string                   `json:"context_digest,omitempty"`
	OwnerInstanceID string                   `json:"owner_instance_id,omitempty"`
	Scope           Scope                    `json:"scope,omitempty"`
	ExpiresAt       time.Time                `json:"expires_at,omitempty"`
	Envelope        PairingAdmissionEnvelope `json:"envelope,omitempty"`
	Reason          PairingTerminalReason    `json:"reason,omitempty"`
	ResetNote       string                   `json:"reset_note,omitempty"`
}

type pairingJournalFrame struct {
	Record   pairingJournalRecord `json:"record"`
	Checksum string               `json:"checksum"`
}

type pairingAdmissionEntry struct {
	record pairingJournalRecord
	finish *pairingJournalRecord
}

type pairingLedgerSnapshot struct {
	status          PairingLedgerStatus
	sequence        uint64
	records         []pairingJournalRecord
	admissions      map[string]*pairingAdmissionEntry
	attempts        map[string]*pairingAdmissionEntry
	admissionOrder  []*pairingAdmissionEntry
	rebuildAt       time.Time
	bytes           int64
	highWatermark   time.Time
	ownerInstanceID string
}

func readPairingLedgerSnapshot(path string, now time.Time, ownerInstanceID string, validateFile pairingLedgerFileValidator) (pairingLedgerSnapshot, error) {
	if validateFile == nil {
		validateFile = validateMachinePairingLedgerFile
	}
	if err := validateFile(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			status := PairingLedgerStatus{
				State:            PairingLedgerNotInitialized,
				BlocksActiveWork: true,
				Limits:           PairingAdmissionHardLimits(),
				Detail:           "explicit machine setup has not initialized the pairing journal",
			}
			return pairingLedgerSnapshot{status: status}, &PairingLedgerError{Status: status, Cause: ErrPairingLedgerNotInitialized}
		}
		status := indeterminatePairingLedgerStatus("journal metadata is unavailable or untrusted")
		return pairingLedgerSnapshot{status: status}, &PairingLedgerError{Status: status, Cause: errors.Join(ErrPairingLedgerIndeterminate, err)}
	}
	return readValidatedPairingLedgerSnapshot(path, now, ownerInstanceID)
}

func readValidatedPairingLedgerSnapshot(path string, now time.Time, ownerInstanceID string) (pairingLedgerSnapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		status := indeterminatePairingLedgerStatus("journal cannot be opened")
		return pairingLedgerSnapshot{status: status}, &PairingLedgerError{Status: status, Cause: errors.Join(ErrPairingLedgerIndeterminate, err)}
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxPairingLedgerBytes+1))
	if err != nil {
		status := indeterminatePairingLedgerStatus("journal cannot be read")
		return pairingLedgerSnapshot{status: status}, &PairingLedgerError{Status: status, Cause: errors.Join(ErrPairingLedgerIndeterminate, err)}
	}
	if int64(len(data)) > maxPairingLedgerBytes {
		status := indeterminatePairingLedgerStatus("journal exceeds its compiled byte ceiling")
		return pairingLedgerSnapshot{status: status}, &PairingLedgerError{Status: status, Cause: ErrPairingLedgerIndeterminate}
	}
	records, err := decodePairingJournal(data)
	if err != nil {
		status := indeterminatePairingLedgerStatus("journal framing, sequence, or checksum is invalid")
		return pairingLedgerSnapshot{status: status}, &PairingLedgerError{Status: status, Cause: errors.Join(ErrPairingLedgerIndeterminate, err)}
	}
	snapshot, err := buildPairingLedgerSnapshot(records, int64(len(data)), ownerInstanceID)
	if err != nil {
		status := indeterminatePairingLedgerStatus("journal record transitions are invalid")
		return pairingLedgerSnapshot{status: status}, &PairingLedgerError{Status: status, Cause: errors.Join(ErrPairingLedgerIndeterminate, err)}
	}
	snapshot.status = snapshot.statusAt(now)
	if snapshot.status.State == PairingLedgerClockRollback {
		return snapshot, &PairingLedgerError{Status: snapshot.status, Cause: ErrPairingLedgerClockRollback}
	}
	return snapshot, nil
}

func decodePairingJournal(data []byte) ([]pairingJournalRecord, error) {
	if len(data) == 0 {
		return nil, errors.New("pairing journal is empty")
	}
	var records []pairingJournalRecord
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return nil, errors.New("pairing journal has a truncated length prefix")
		}
		bodyLength := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if bodyLength <= 0 || bodyLength > maxPairingLedgerFrameBytes {
			return nil, fmt.Errorf("pairing journal frame length %d is invalid", bodyLength)
		}
		if bodyLength > len(data)-offset {
			return nil, errors.New("pairing journal frame body is truncated")
		}
		record, err := decodePairingJournalFrame(data[offset : offset+bodyLength])
		if err != nil {
			return nil, err
		}
		records = append(records, record)
		if len(records) > maxPairingLedgerRecords {
			return nil, fmt.Errorf("pairing journal exceeds %d records", maxPairingLedgerRecords)
		}
		offset += bodyLength
	}
	return records, nil
}

func encodePairingJournalFrame(record pairingJournalRecord) ([]byte, error) {
	if err := validatePairingJournalRecord(record); err != nil {
		return nil, err
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode pairing journal record: %w", err)
	}
	checksum := sha256.Sum256(recordPayload)
	envelopePayload, err := json.Marshal(pairingJournalFrame{
		Record:   record,
		Checksum: hex.EncodeToString(checksum[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("encode pairing journal frame: %w", err)
	}
	if len(envelopePayload) == 0 || len(envelopePayload) > maxPairingLedgerFrameBytes {
		return nil, fmt.Errorf("pairing journal frame exceeds %d bytes", maxPairingLedgerFrameBytes)
	}
	framed := make([]byte, 4+len(envelopePayload))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(envelopePayload)))
	copy(framed[4:], envelopePayload)
	return framed, nil
}

func decodePairingJournalFrame(payload []byte) (pairingJournalRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var frame pairingJournalFrame
	if err := decoder.Decode(&frame); err != nil {
		return pairingJournalRecord{}, fmt.Errorf("decode pairing journal frame: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return pairingJournalRecord{}, errors.New("pairing journal frame contains trailing data")
	}
	if err := validatePairingJournalRecord(frame.Record); err != nil {
		return pairingJournalRecord{}, err
	}
	recordPayload, err := json.Marshal(frame.Record)
	if err != nil {
		return pairingJournalRecord{}, fmt.Errorf("encode pairing journal checksum input: %w", err)
	}
	want := sha256.Sum256(recordPayload)
	got, err := hex.DecodeString(frame.Checksum)
	if err != nil || len(got) != sha256.Size || !bytes.Equal(got, want[:]) {
		return pairingJournalRecord{}, errors.New("pairing journal checksum mismatch")
	}
	return frame.Record, nil
}

func buildPairingLedgerSnapshot(records []pairingJournalRecord, bytes int64, ownerInstanceID string) (pairingLedgerSnapshot, error) {
	snapshot := pairingLedgerSnapshot{
		records:         make([]pairingJournalRecord, 0, len(records)),
		admissions:      make(map[string]*pairingAdmissionEntry),
		attempts:        make(map[string]*pairingAdmissionEntry),
		bytes:           bytes,
		ownerInstanceID: ownerInstanceID,
		status: PairingLedgerStatus{
			State:  PairingLedgerReady,
			Limits: PairingAdmissionHardLimits(),
		},
	}
	if len(records) == 0 {
		return snapshot, errors.New("pairing journal has no initialization record")
	}
	for index, record := range records {
		wantSequence := uint64(index + 1)
		if record.Sequence != wantSequence {
			return snapshot, fmt.Errorf("pairing journal sequence %d, want %d", record.Sequence, wantSequence)
		}
		if index > 0 && record.RecordedAt.Before(records[index-1].RecordedAt) {
			return snapshot, errors.New("pairing journal timestamp regressed")
		}
		if record.RecordedAt.After(snapshot.highWatermark) {
			snapshot.highWatermark = record.RecordedAt
		}
		switch record.Type {
		case pairingRecordInitialize:
			if index != 0 {
				return snapshot, errors.New("initialize record is not first")
			}
		case pairingRecordRebuildBaseline:
			if index != 0 {
				return snapshot, errors.New("rebuild baseline is not first")
			}
			snapshot.rebuildAt = record.RecordedAt
		case pairingRecordBurnAndAdmit:
			if index == 0 {
				return snapshot, errors.New("burn record precedes initialization")
			}
			if _, exists := snapshot.admissions[record.CredentialID]; exists {
				return snapshot, errors.New("credential has duplicate burn records")
			}
			if _, exists := snapshot.attempts[record.AttemptID]; exists {
				return snapshot, errors.New("attempt id has duplicate burn records")
			}
			entry := &pairingAdmissionEntry{record: record}
			snapshot.admissions[record.CredentialID] = entry
			snapshot.attempts[record.AttemptID] = entry
			snapshot.admissionOrder = append(snapshot.admissionOrder, entry)
		case pairingRecordFinish:
			entry, exists := snapshot.admissions[record.CredentialID]
			if !exists || entry.record.AttemptID != record.AttemptID || entry.record.RecordClass != record.RecordClass {
				return snapshot, errors.New("finish record has no matching admission")
			}
			if entry.finish != nil {
				return snapshot, errors.New("admission has duplicate finish records")
			}
			finish := record
			entry.finish = &finish
		case pairingRecordCircuitReset:
			if index == 0 {
				return snapshot, errors.New("circuit reset precedes initialization")
			}
			if record.RecordClass == PairingRecordClassHardNATCampaign {
				status := snapshot.hardNATCampaignStatusAt(record.RecordedAt)
				if !status.ExplicitResetRequired || status.CircuitOpenedAt.IsZero() {
					return snapshot, errors.New("hard NAT campaign reset has no matching open circuit")
				}
			} else {
				status := snapshot.statusAt(record.RecordedAt)
				if !status.ExplicitResetRequired || status.CircuitOpenedAt.IsZero() {
					return snapshot, errors.New("circuit reset has no matching open circuit")
				}
				if record.RecordedAt.Before(status.CircuitResetEligibleAt) {
					return snapshot, errors.New("circuit reset precedes its minimum horizon")
				}
			}
		default:
			return snapshot, fmt.Errorf("unknown pairing journal record type %q", record.Type)
		}
		snapshot.records = append(snapshot.records, record)
	}
	snapshot.sequence = uint64(len(records))
	snapshot.status = PairingLedgerStatus{
		State:         PairingLedgerReady,
		Sequence:      snapshot.sequence,
		Records:       len(records),
		Bytes:         bytes,
		HighWatermark: snapshot.highWatermark,
		Limits:        PairingAdmissionHardLimits(),
	}
	return snapshot, nil
}

func validatePairingJournalRecord(record pairingJournalRecord) error {
	if record.SchemaVersion != pairingLedgerSchemaVersion {
		return fmt.Errorf("pairing journal schema version %d, want %d", record.SchemaVersion, pairingLedgerSchemaVersion)
	}
	if record.Sequence == 0 {
		return errors.New("pairing journal sequence is zero")
	}
	if record.RecordedAt.IsZero() || record.RecordedAt.Location() != time.UTC {
		return errors.New("pairing journal recorded_at must be UTC")
	}
	emptyEnvelope := PairingAdmissionEnvelope{}
	switch record.Type {
	case pairingRecordInitialize, pairingRecordRebuildBaseline:
		if record.RecordClass != PairingRecordClassOrdinary || record.CredentialID != "" || record.AttemptID != "" || record.ContextDigest != "" || record.OwnerInstanceID != "" || record.Scope != "" || !record.ExpiresAt.IsZero() || record.Envelope != emptyEnvelope || record.Reason != "" || record.ResetNote != "" {
			return errors.New("pairing journal initialization record has unexpected fields")
		}
	case pairingRecordBurnAndAdmit:
		request := PairingAdmissionRequest{
			RecordClass:   record.RecordClass,
			CredentialID:  record.CredentialID,
			AttemptID:     record.AttemptID,
			ContextDigest: record.ContextDigest,
			Scope:         record.Scope,
			ExpiresAt:     record.ExpiresAt,
			Envelope:      record.Envelope,
		}
		if err := validatePairingAdmissionRequest(request); err != nil {
			return err
		}
		if err := validatePairingOwnerInstanceID(record.OwnerInstanceID); err != nil {
			return err
		}
		if !record.RecordedAt.Before(record.ExpiresAt) || record.ExpiresAt.Sub(record.RecordedAt) > pairingCredentialMaxLifetime {
			return errors.New("pairing admission expiry is outside the ten-minute lifetime")
		}
		if record.Reason != "" || record.ResetNote != "" {
			return errors.New("pairing admission record has terminal-only fields")
		}
	case pairingRecordFinish:
		if !record.RecordClass.valid() {
			return fmt.Errorf("invalid pairing ledger record class %q", record.RecordClass)
		}
		if err := validatePairingOpaqueID("credential id", record.CredentialID); err != nil {
			return err
		}
		if err := validatePairingOpaqueID("attempt id", record.AttemptID); err != nil {
			return err
		}
		if !record.Reason.valid() {
			return fmt.Errorf("invalid pairing terminal reason %q", record.Reason)
		}
		if record.ContextDigest != "" || record.OwnerInstanceID != "" || record.Scope != "" || !record.ExpiresAt.IsZero() || record.Envelope != emptyEnvelope || record.ResetNote != "" {
			return errors.New("pairing finish record has unexpected fields")
		}
	case pairingRecordCircuitReset:
		if !record.RecordClass.valid() {
			return fmt.Errorf("invalid pairing ledger record class %q", record.RecordClass)
		}
		if err := validatePairingResetNote(record.ResetNote); err != nil {
			return err
		}
		if record.CredentialID != "" || record.AttemptID != "" || record.ContextDigest != "" || record.OwnerInstanceID != "" || record.Scope != "" || !record.ExpiresAt.IsZero() || record.Envelope != emptyEnvelope || record.Reason != "" {
			return errors.New("pairing circuit reset has unexpected fields")
		}
	default:
		return fmt.Errorf("unknown pairing journal record type %q", record.Type)
	}
	return nil
}

func (snapshot pairingLedgerSnapshot) effectiveNow(now time.Time) (time.Time, error) {
	now = now.UTC()
	if snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate {
		return time.Time{}, &PairingLedgerError{Status: snapshot.status, Cause: ErrPairingLedgerIndeterminate}
	}
	if now.Add(pairingLedgerClockRollbackSkew).Before(snapshot.highWatermark) {
		status := snapshot.status
		status.State = PairingLedgerClockRollback
		status.BlocksActiveWork = true
		status.Detail = "wall clock is behind the durable high-watermark"
		return time.Time{}, &PairingLedgerError{Status: status, Cause: ErrPairingLedgerClockRollback}
	}
	if now.Before(snapshot.highWatermark) {
		return snapshot.highWatermark, nil
	}
	return now, nil
}

func (snapshot pairingLedgerSnapshot) statusAt(now time.Time) PairingLedgerStatus {
	if snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate {
		return snapshot.status
	}
	effectiveNow, err := snapshot.effectiveNow(now)
	if err != nil {
		var ledgerErr *PairingLedgerError
		if errors.As(err, &ledgerErr) {
			return ledgerErr.Status
		}
		return indeterminatePairingLedgerStatus("journal clock evaluation failed")
	}
	status := snapshot.status
	status.State = PairingLedgerReady
	status.BlocksActiveWork = false
	status.Detail = ""
	status.OneHourAdmissions = 0
	status.TwentyFourHourAdmissions = 0
	status.TwentyFourHourPackets = 0
	status.ConsecutiveFailures = 0
	status.CircuitOpenedAt = time.Time{}
	status.CircuitResetEligibleAt = time.Time{}
	status.ExplicitResetRequired = false
	status.NextAdmissionAt = time.Time{}

	if !snapshot.rebuildAt.IsZero() {
		if effectiveNow.Before(snapshot.rebuildAt.Add(pairingAdmissionOneHourWindow)) {
			status.OneHourAdmissions += pairingAdmissionOneHourLimit
		}
		if effectiveNow.Before(snapshot.rebuildAt.Add(pairingAdmissionDayWindow)) {
			status.TwentyFourHourAdmissions += pairingAdmissionDayLimit
			status.TwentyFourHourPackets += pairingAdmissionDayPackets
		}
		status.LastAdmissionAt = snapshot.rebuildAt
	}

	oneHourCutoff := effectiveNow.Add(-pairingAdmissionOneHourWindow)
	dayCutoff := effectiveNow.Add(-pairingAdmissionDayWindow)
	for _, admission := range snapshot.admissionOrder {
		if admission.record.RecordClass != PairingRecordClassOrdinary {
			continue
		}
		when := admission.record.RecordedAt
		if when.After(status.LastAdmissionAt) {
			status.LastAdmissionAt = when
		}
		if when.After(oneHourCutoff) {
			status.OneHourAdmissions++
		}
		if when.After(dayCutoff) {
			status.TwentyFourHourAdmissions++
			status.TwentyFourHourPackets += admission.record.Envelope.Packets
		}
	}
	if !status.LastAdmissionAt.IsZero() {
		status.NextAdmissionAt = status.LastAdmissionAt.Add(pairingAdmissionMinimumInterval)
	}

	status.ConsecutiveFailures, status.CircuitOpenedAt = snapshot.failureState(PairingRecordClassOrdinary)
	if !status.CircuitOpenedAt.IsZero() {
		status.CircuitResetEligibleAt = status.CircuitOpenedAt.Add(pairingAdmissionCircuitHorizon)
		status.ExplicitResetRequired = true
		status.State = PairingLedgerCircuitOpen
		status.BlocksActiveWork = true
		status.Detail = "three consecutive terminal failures require explicit reset"
		return status
	}
	if status.Records >= maxPairingLedgerRecords || status.Bytes >= maxPairingLedgerBytes {
		status.State = PairingLedgerCapacityFull
		status.BlocksActiveWork = true
		status.Detail = "journal reached a compiled capacity ceiling"
		return status
	}
	if (!status.NextAdmissionAt.IsZero() && effectiveNow.Before(status.NextAdmissionAt)) ||
		status.OneHourAdmissions >= pairingAdmissionOneHourLimit ||
		status.TwentyFourHourAdmissions >= pairingAdmissionDayLimit ||
		status.TwentyFourHourPackets >= pairingAdmissionDayPackets {
		status.State = PairingLedgerRateLimited
		status.BlocksActiveWork = true
		status.Detail = "persistent admission interval or rolling window is exhausted"
	}
	return status
}

func (snapshot pairingLedgerSnapshot) failureState(recordClass PairingLedgerRecordClass) (int, time.Time) {
	finishBySequence := make(map[uint64]*pairingJournalRecord)
	for _, admission := range snapshot.admissionOrder {
		if admission.record.RecordClass == recordClass && admission.finish != nil {
			finishBySequence[admission.finish.Sequence] = admission.finish
		}
	}
	pending := make([]*pairingAdmissionEntry, 0)
	streak := 0
	var openedAt time.Time
	for _, record := range snapshot.records {
		if record.RecordClass != recordClass {
			continue
		}
		switch record.Type {
		case pairingRecordBurnAndAdmit:
			entry := snapshot.admissions[record.CredentialID]
			if entry != nil && entry.finish == nil {
				pending = append(pending, entry)
			}
		case pairingRecordFinish:
			finish := finishBySequence[record.Sequence]
			if finish == nil {
				continue
			}
			if finish.Reason == PairingTerminalSuccess && openedAt.IsZero() {
				streak = 0
			} else {
				if finish.Reason != PairingTerminalSuccess {
					streak++
				}
				limit := pairingAdmissionFailureLimit
				if recordClass == PairingRecordClassHardNATCampaign {
					limit = 1
				}
				if streak >= limit && openedAt.IsZero() {
					openedAt = finish.RecordedAt
				}
			}
		case pairingRecordCircuitReset:
			streak = 0
			openedAt = time.Time{}
			pending = pending[:0]
		}
	}
	for _, admission := range pending {
		if snapshot.ownerInstanceID != "" && admission.record.OwnerInstanceID == snapshot.ownerInstanceID {
			continue
		}
		streak++
		limit := pairingAdmissionFailureLimit
		if recordClass == PairingRecordClassHardNATCampaign {
			limit = 1
		}
		if streak >= limit && openedAt.IsZero() {
			openedAt = admission.record.RecordedAt
		}
	}
	return streak, openedAt
}

func (snapshot pairingLedgerSnapshot) admissionError(now time.Time, envelope PairingAdmissionEnvelope, recordClass PairingLedgerRecordClass) error {
	if recordClass == PairingRecordClassHardNATCampaign {
		return snapshot.hardNATCampaignAdmissionError(now, envelope)
	}
	status := snapshot.statusAt(now)
	switch status.State {
	case PairingLedgerCircuitOpen:
		return &PairingLedgerError{Status: status, Cause: ErrPairingAdmissionCircuitOpen}
	case PairingLedgerCapacityFull:
		return &PairingLedgerError{Status: status, Cause: ErrPairingLedgerCapacity}
	case PairingLedgerClockRollback:
		return &PairingLedgerError{Status: status, Cause: ErrPairingLedgerClockRollback}
	case PairingLedgerNotInitialized:
		return &PairingLedgerError{Status: status, Cause: ErrPairingLedgerNotInitialized}
	case PairingLedgerIndeterminate:
		return &PairingLedgerError{Status: status, Cause: ErrPairingLedgerIndeterminate}
	}
	if (!status.NextAdmissionAt.IsZero() && now.Before(status.NextAdmissionAt)) ||
		status.OneHourAdmissions+1 > pairingAdmissionOneHourLimit ||
		status.TwentyFourHourAdmissions+1 > pairingAdmissionDayLimit ||
		status.TwentyFourHourPackets+envelope.Packets > pairingAdmissionDayPackets {
		status.State = PairingLedgerRateLimited
		status.BlocksActiveWork = true
		status.Detail = "new worst-case envelope exceeds a persistent admission window"
		return &PairingLedgerError{Status: status, Cause: ErrPairingAdmissionRateLimited}
	}
	return nil
}

func (snapshot pairingLedgerSnapshot) ensureAdmissionCapacity(frameBytes int64) error {
	// Reserve one maximum-size terminal frame so a successful admission cannot
	// consume the final record slot or byte range needed for FINISH.
	if len(snapshot.records)+2 > maxPairingLedgerRecords || snapshot.bytes+frameBytes+4+maxPairingLedgerFrameBytes > maxPairingLedgerBytes {
		status := snapshot.status
		status.State = PairingLedgerCapacityFull
		status.BlocksActiveWork = true
		status.Detail = "journal lacks reserved capacity for admission and terminal records"
		return &PairingLedgerError{Status: status, Cause: ErrPairingLedgerCapacity}
	}
	return nil
}

func (snapshot pairingLedgerSnapshot) ensureRecordCapacity(frameBytes int64) error {
	if len(snapshot.records)+1 > maxPairingLedgerRecords || snapshot.bytes+frameBytes > maxPairingLedgerBytes {
		status := snapshot.status
		status.State = PairingLedgerCapacityFull
		status.BlocksActiveWork = true
		status.Detail = "journal reached a compiled capacity ceiling"
		return &PairingLedgerError{Status: status, Cause: ErrPairingLedgerCapacity}
	}
	return nil
}

func appendPairingJournalFrame(path string, record pairingJournalRecord, frame []byte, validateFile pairingLedgerFileValidator, hooks pairingLedgerWriteHooks) error {
	if validateFile == nil {
		validateFile = validateMachinePairingLedgerFile
	}
	if err := validateFile(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open pairing journal for append: %w", err)
	}
	defer func() { _ = file.Close() }()
	var written int
	if hooks.writeFrame != nil {
		written, err = hooks.writeFrame(file, record, frame)
	} else {
		written, err = file.Write(frame)
	}
	if err != nil {
		return fmt.Errorf("append pairing journal frame: %w", err)
	}
	if written != len(frame) {
		return io.ErrShortWrite
	}
	if hooks.afterAppendBeforeSync != nil {
		if err := hooks.afterAppendBeforeSync(record); err != nil {
			return err
		}
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync pairing journal frame: %w", err)
	}
	if hooks.afterSync != nil {
		if err := hooks.afterSync(record); err != nil {
			return err
		}
	}
	return file.Close()
}

func createPairingLedgerFile(path string, mode os.FileMode, now time.Time, rebuild bool) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, mode)
	if err != nil {
		return err
	}
	recordType := pairingRecordInitialize
	if rebuild {
		recordType = pairingRecordRebuildBaseline
	}
	record := pairingJournalRecord{
		SchemaVersion: pairingLedgerSchemaVersion,
		Sequence:      1,
		Type:          recordType,
		RecordedAt:    now.UTC(),
	}
	frame, encodeErr := encodePairingJournalFrame(record)
	if encodeErr != nil {
		_ = file.Close()
		return encodeErr
	}
	written, writeErr := file.Write(frame)
	if writeErr != nil || written != len(frame) {
		_ = file.Close()
		if writeErr != nil {
			return writeErr
		}
		return io.ErrShortWrite
	}
	if syncErr := file.Sync(); syncErr != nil {
		_ = file.Close()
		return syncErr
	}
	return file.Close()
}

func indeterminatePairingLedgerStatus(detail string) PairingLedgerStatus {
	return PairingLedgerStatus{
		State:            PairingLedgerIndeterminate,
		BlocksActiveWork: true,
		Limits:           PairingAdmissionHardLimits(),
		Detail:           detail,
	}
}

// InspectMachinePairingLedger reads the canonical journal without acquiring an
// owner lock or mutating state. The snapshot is diagnostic only.
func InspectMachinePairingLedger() PairingLedgerStatus {
	namespace := InspectMachineNamespace()
	if !namespace.Ready {
		return PairingLedgerStatus{
			State:            PairingLedgerNotInitialized,
			BlocksActiveWork: true,
			Limits:           PairingAdmissionHardLimits(),
			Detail:           "machine safety namespace is not ready",
		}
	}
	now := time.Now().UTC()
	snapshot, _ := readPairingLedgerSnapshot(filepath.Join(namespace.Path, pairingLedgerFilename), now, "", validateMachinePairingLedgerFile)
	return snapshot.statusAt(now)
}
