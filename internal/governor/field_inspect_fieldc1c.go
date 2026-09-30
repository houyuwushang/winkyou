//go:build fieldc1c

package governor

import (
	"path/filepath"
	"time"
)

// FieldPairingEntry exposes recorded facts only. Null members were never
// persisted; neither a credential ID nor a context digest is a fingerprint.
type FieldPairingEntry struct {
	AttemptPrefix     string                `json:"attempt_prefix"`
	RecordClass       string                `json:"record_class"`
	State             string                `json:"state"`
	Reason            PairingTerminalReason `json:"reason,omitempty"`
	BurnedAt          time.Time             `json:"burned_at"`
	ExpiresAt         time.Time             `json:"expires_at"`
	FinishedAt        *time.Time            `json:"finished_at"`
	Role              *string               `json:"role"`
	Profile           *string               `json:"profile"`
	FingerprintPrefix *string               `json:"fingerprint_prefix"`
	MissingReason     string                `json:"missing_reason"`
}

// FieldPairingLedgerReport is a non-atomic diagnostic, never an admission
// permit. Unfinished burns are conservatively evaluated as on owner restart.
type FieldPairingLedgerReport struct {
	Pairing    PairingLedgerStatus   `json:"pairing"`
	Campaign   HardNATCampaignStatus `json:"campaign"`
	EntryCount int                   `json:"entry_count"`
	Entries    []FieldPairingEntry   `json:"entries"`
}

// InspectFieldPairingLedger reads the canonical existing journal with the
// same validation and status functions as ordinary diagnostics. No owner,
// setup, append, reset, repair, or caller-selected path is available.
func InspectFieldPairingLedger() FieldPairingLedgerReport {
	namespace := InspectMachineNamespace()
	if !namespace.Ready {
		return FieldPairingLedgerReport{
			Pairing:  PairingLedgerStatus{State: PairingLedgerNotInitialized, BlocksActiveWork: true, Limits: PairingAdmissionHardLimits()},
			Campaign: HardNATCampaignStatus{State: PairingLedgerNotInitialized, BlocksCampaign: true, Limits: HardNATCampaignHardLimits()},
			Entries:  []FieldPairingEntry{},
		}
	}
	return inspectFieldPairingAt(filepath.Join(namespace.Path, pairingLedgerFilename), time.Now().UTC(), validateMachinePairingLedgerFile)
}

func inspectFieldPairingAt(path string, now time.Time, validator pairingLedgerFileValidator) FieldPairingLedgerReport {
	snapshot, _ := readPairingLedgerSnapshot(path, now, "", validator)
	report := FieldPairingLedgerReport{Pairing: snapshot.statusAt(now), Campaign: snapshot.hardNATCampaignStatusAt(now), Entries: []FieldPairingEntry{}}
	// Detail is intentionally not part of the tool's public projection.
	report.Pairing.Detail, report.Campaign.Detail = "", ""
	for _, admission := range snapshot.admissionOrder {
		record := admission.record
		entry := FieldPairingEntry{RecordClass: string(record.RecordClass), State: "burned_unfinished", BurnedAt: record.RecordedAt,
			ExpiresAt: record.ExpiresAt, MissingReason: "not_recorded"}
		// The existing journal parser has already validated the record class.
		// Project its value; interpreting campaign authority belongs to the
		// existing status calculation above, never this read-only formatter.
		if entry.RecordClass == "" {
			entry.RecordClass = "ordinary"
		}
		if len(record.AttemptID) >= 8 {
			entry.AttemptPrefix = record.AttemptID[:8]
		}
		if admission.finish != nil {
			entry.State, entry.Reason = "finish_recorded", admission.finish.Reason
			at := admission.finish.RecordedAt
			entry.FinishedAt = &at
		}
		report.Entries = append(report.Entries, entry)
	}
	report.EntryCount = len(report.Entries)
	return report
}
