package governor

import (
	"errors"
	"fmt"
	"time"
)

const (
	// PairingRecordClassOrdinary is intentionally encoded as an omitted field
	// so every pre-Gate-B3 journal frame remains byte-for-byte decodable under
	// schema v1.
	PairingRecordClassOrdinary        PairingLedgerRecordClass = ""
	PairingRecordClassHardNATCampaign PairingLedgerRecordClass = "hard_nat_campaign/1"

	hardNATCampaignWindow     = 24 * time.Hour
	hardNATCampaignAdmissions = 1
	hardNATCampaignPackets    = 16_432
)

var (
	ErrHardNATCampaignRateLimited = errors.New("hard NAT campaign persistent budget is exhausted")
	ErrHardNATCampaignCircuitOpen = errors.New("hard NAT campaign circuit is open")
)

// PairingLedgerRecordClass partitions ordinary pairing admissions from the
// independently budgeted hard-NAT campaign while retaining one owner lock and
// one append-only journal.
type PairingLedgerRecordClass string

func (recordClass PairingLedgerRecordClass) valid() bool {
	return recordClass == PairingRecordClassOrdinary || recordClass == PairingRecordClassHardNATCampaign
}

type HardNATCampaignLimits struct {
	TwentyFourHourAdmissions int           `json:"twenty_four_hour_admissions"`
	TwentyFourHourPackets    int           `json:"twenty_four_hour_packets"`
	Window                   time.Duration `json:"window"`
	MaxJournalBytes          int64         `json:"max_journal_bytes"`
	MaxJournalRecords        int           `json:"max_journal_records"`
}

func HardNATCampaignHardLimits() HardNATCampaignLimits {
	return HardNATCampaignLimits{
		TwentyFourHourAdmissions: hardNATCampaignAdmissions,
		TwentyFourHourPackets:    hardNATCampaignPackets,
		Window:                   hardNATCampaignWindow,
		MaxJournalBytes:          maxPairingLedgerBytes,
		MaxJournalRecords:        maxPairingLedgerRecords,
	}
}

// HardNATCampaignStatus is internal/test-facing evidence only. It is not
// added to stdio or product schemas by Gate B3.
type HardNATCampaignStatus struct {
	State                    PairingLedgerState    `json:"state"`
	BlocksCampaign           bool                  `json:"blocks_campaign"`
	Sequence                 uint64                `json:"sequence,omitempty"`
	Records                  int                   `json:"records,omitempty"`
	Bytes                    int64                 `json:"bytes,omitempty"`
	HighWatermark            time.Time             `json:"high_watermark,omitempty"`
	LastAdmissionAt          time.Time             `json:"last_admission_at,omitempty"`
	TwentyFourHourAdmissions int                   `json:"twenty_four_hour_admissions,omitempty"`
	TwentyFourHourPackets    int                   `json:"twenty_four_hour_packets,omitempty"`
	CircuitOpenedAt          time.Time             `json:"circuit_opened_at,omitempty"`
	ExplicitResetRequired    bool                  `json:"explicit_reset_required,omitempty"`
	Limits                   HardNATCampaignLimits `json:"limits"`
	Detail                   string                `json:"detail,omitempty"`
}

// CampaignStatus returns a fresh secret-free view of the hard-campaign
// partition. Ordinary rate limiting does not consume this partition, while an
// ordinary open circuit, capacity/clock failure, or indeterminate journal
// still blocks it.
func (ledger *PairingAdmissionLedger) CampaignStatus() HardNATCampaignStatus {
	if ledger == nil {
		return indeterminateHardNATCampaignStatus("ledger is unavailable")
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		return indeterminateHardNATCampaignStatus("machine owner is no longer held")
	}
	defer releaseOwner()
	now := ledger.now().UTC()
	snapshot, _ := readPairingLedgerSnapshot(ledger.path, now, ledger.ownerInstanceID, ledger.validateFile)
	return snapshot.hardNATCampaignStatusAt(now)
}

func (snapshot pairingLedgerSnapshot) hardNATCampaignStatusAt(now time.Time) HardNATCampaignStatus {
	limits := HardNATCampaignHardLimits()
	if snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate {
		return HardNATCampaignStatus{State: snapshot.status.State, BlocksCampaign: true, Limits: limits, Detail: snapshot.status.Detail}
	}
	effectiveNow, err := snapshot.effectiveNow(now)
	if err != nil {
		var ledgerErr *PairingLedgerError
		if errors.As(err, &ledgerErr) {
			return HardNATCampaignStatus{State: ledgerErr.Status.State, BlocksCampaign: true, Sequence: snapshot.sequence,
				Records: len(snapshot.records), Bytes: snapshot.bytes, HighWatermark: snapshot.highWatermark,
				Limits: limits, Detail: ledgerErr.Status.Detail}
		}
		return indeterminateHardNATCampaignStatus("journal clock evaluation failed")
	}
	status := HardNATCampaignStatus{State: PairingLedgerReady, Sequence: snapshot.sequence,
		Records: len(snapshot.records), Bytes: snapshot.bytes, HighWatermark: snapshot.highWatermark, Limits: limits}
	if !snapshot.rebuildAt.IsZero() && effectiveNow.Before(snapshot.rebuildAt.Add(hardNATCampaignWindow)) {
		status.LastAdmissionAt = snapshot.rebuildAt
		status.TwentyFourHourAdmissions = hardNATCampaignAdmissions
		status.TwentyFourHourPackets = hardNATCampaignPackets
	}
	cutoff := effectiveNow.Add(-hardNATCampaignWindow)
	for _, admission := range snapshot.admissionOrder {
		if admission.record.RecordClass != PairingRecordClassHardNATCampaign {
			continue
		}
		when := admission.record.RecordedAt
		if when.After(status.LastAdmissionAt) {
			status.LastAdmissionAt = when
		}
		if when.After(cutoff) {
			status.TwentyFourHourAdmissions++
			status.TwentyFourHourPackets += admission.record.Envelope.Packets
		}
	}
	_, status.CircuitOpenedAt = snapshot.failureState(PairingRecordClassHardNATCampaign)
	if !status.CircuitOpenedAt.IsZero() {
		status.State = PairingLedgerCircuitOpen
		status.BlocksCampaign = true
		status.ExplicitResetRequired = true
		status.Detail = "a post-burn hard NAT campaign failure requires explicit reset"
		return status
	}
	ordinary := snapshot.statusAt(effectiveNow)
	switch ordinary.State {
	case PairingLedgerCircuitOpen, PairingLedgerCapacityFull, PairingLedgerClockRollback,
		PairingLedgerNotInitialized, PairingLedgerIndeterminate:
		status.State = ordinary.State
		status.BlocksCampaign = true
		status.Detail = ordinary.Detail
		return status
	}
	if status.Records >= maxPairingLedgerRecords || status.Bytes >= maxPairingLedgerBytes {
		status.State = PairingLedgerCapacityFull
		status.BlocksCampaign = true
		status.Detail = "journal reached a compiled capacity ceiling"
		return status
	}
	if status.TwentyFourHourAdmissions >= hardNATCampaignAdmissions || status.TwentyFourHourPackets >= hardNATCampaignPackets {
		status.State = PairingLedgerRateLimited
		status.BlocksCampaign = true
		status.Detail = "hard NAT campaign 24-hour reservation is exhausted"
	}
	return status
}

func (snapshot pairingLedgerSnapshot) hardNATCampaignAdmissionError(now time.Time, envelope PairingAdmissionEnvelope) error {
	status := snapshot.hardNATCampaignStatusAt(now)
	switch status.State {
	case PairingLedgerCircuitOpen:
		// An ordinary circuit also blocks the campaign, but retains its ordinary
		// error so callers cannot use the campaign to bypass it.
		ordinary := snapshot.statusAt(now)
		if ordinary.State == PairingLedgerCircuitOpen {
			return &PairingLedgerError{Status: ordinary, Cause: ErrPairingAdmissionCircuitOpen}
		}
		return fmt.Errorf("%w: sequence=%d", ErrHardNATCampaignCircuitOpen, status.Sequence)
	case PairingLedgerRateLimited:
		return fmt.Errorf("%w: admissions=%d packets=%d", ErrHardNATCampaignRateLimited,
			status.TwentyFourHourAdmissions, status.TwentyFourHourPackets)
	case PairingLedgerCapacityFull:
		return &PairingLedgerError{Status: snapshot.statusAt(now), Cause: ErrPairingLedgerCapacity}
	case PairingLedgerClockRollback:
		return &PairingLedgerError{Status: snapshot.statusAt(now), Cause: ErrPairingLedgerClockRollback}
	case PairingLedgerNotInitialized:
		return &PairingLedgerError{Status: snapshot.statusAt(now), Cause: ErrPairingLedgerNotInitialized}
	case PairingLedgerIndeterminate:
		return &PairingLedgerError{Status: snapshot.statusAt(now), Cause: ErrPairingLedgerIndeterminate}
	}
	if envelope != hardNATCampaignEnvelope() {
		return fmt.Errorf("%w: hard NAT campaign envelope is not exact", ErrPairingLedgerInvalidRequest)
	}
	if status.TwentyFourHourAdmissions+1 > hardNATCampaignAdmissions ||
		status.TwentyFourHourPackets+envelope.Packets > hardNATCampaignPackets {
		return ErrHardNATCampaignRateLimited
	}
	return nil
}

func hardNATCampaignEnvelope() PairingAdmissionEnvelope {
	return PairingAdmissionEnvelope{
		Sockets: 16, Targets: 16_400, PacketsPerSecond: 512, Packets: 16_432,
		FiveTuples: 16_400, DurationMillis: 47_000, Heavyweight: true,
	}
}

func indeterminateHardNATCampaignStatus(detail string) HardNATCampaignStatus {
	return HardNATCampaignStatus{State: PairingLedgerIndeterminate, BlocksCampaign: true,
		Limits: HardNATCampaignHardLimits(), Detail: detail}
}

// ResetHardNATCampaignCircuit appends a class-scoped CAS reset. Passage of
// time never clears this circuit, and reset does not refund the 24-hour
// admission or packet reservation.
func (ledger *PairingAdmissionLedger) ResetHardNATCampaignCircuit(expectedSequence uint64, note string) (HardNATCampaignStatus, error) {
	if ledger == nil || expectedSequence == 0 || validatePairingResetNote(note) != nil {
		return indeterminateHardNATCampaignStatus("reset request is invalid"), ErrPairingLedgerResetRejected
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		return indeterminateHardNATCampaignStatus("machine owner is no longer held"), err
	}
	defer releaseOwner()
	now := ledger.now().UTC()
	snapshot, readErr := readPairingLedgerSnapshot(ledger.path, now, ledger.ownerInstanceID, ledger.validateFile)
	if readErr != nil && (snapshot.status.State == PairingLedgerNotInitialized || snapshot.status.State == PairingLedgerIndeterminate) {
		return snapshot.hardNATCampaignStatusAt(now), readErr
	}
	effectiveNow, clockErr := snapshot.effectiveNow(now)
	if clockErr != nil {
		return snapshot.hardNATCampaignStatusAt(now), clockErr
	}
	status := snapshot.hardNATCampaignStatusAt(effectiveNow)
	if expectedSequence != snapshot.sequence || !status.ExplicitResetRequired || status.CircuitOpenedAt.IsZero() {
		return status, fmt.Errorf("%w: campaign circuit or expected sequence does not match", ErrPairingLedgerResetRejected)
	}
	record := pairingJournalRecord{SchemaVersion: pairingLedgerSchemaVersion, Sequence: snapshot.sequence + 1,
		Type: pairingRecordCircuitReset, RecordedAt: effectiveNow, RecordClass: PairingRecordClassHardNATCampaign, ResetNote: note}
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
		return verified.hardNATCampaignStatusAt(effectiveNow), verifyErr
	}
	return verified.hardNATCampaignStatusAt(effectiveNow), nil
}
