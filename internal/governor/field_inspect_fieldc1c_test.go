//go:build fieldc1c

package governor

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFieldToolsLedgerProjectionIsReadOnlyAndUsesExistingRules(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	ledger, clock, path, owner := newTestPairingLedger(t, now, false)
	request := testPairingRequest("field-read-only", now, 8)
	receipt, err := ledger.Admit(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Finish(receipt, PairingTerminalExpired); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report := inspectFieldPairingAt(path, *clock, validateTestPairingLedgerFile)
	if report.Pairing.State != ledger.Status().State || report.Campaign.State != ledger.CampaignStatus().State ||
		report.EntryCount != 1 || len(report.Entries) != 1 || report.Pairing.TwentyFourHourPackets != 8 {
		t.Fatal("projection does not match existing status rules")
	}
	entry := report.Entries[0]
	if entry.Role != nil || entry.Profile != nil || entry.FingerprintPrefix != nil || entry.MissingReason != "not_recorded" ||
		entry.State != "finish_recorded" || entry.Reason != PairingTerminalExpired || entry.FinishedAt == nil || entry.AttemptPrefix != request.AttemptID[:8] {
		t.Fatal("projection invented an unrecorded fact")
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	golden := `{"attempt_prefix":"` + request.AttemptID[:8] + `","record_class":"ordinary","state":"finish_recorded","reason":"expired","burned_at":"2026-09-29T00:00:00Z","expires_at":"2026-09-29T00:10:00Z","finished_at":"2026-09-29T00:00:00Z","role":null,"profile":null,"fingerprint_prefix":null,"missing_reason":"not_recorded"}`
	if string(encoded) != golden {
		t.Fatal("entry golden mismatch")
	}
	for _, secret := range []string{request.AttemptID, request.CredentialID, request.ContextDigest, owner.Info().InstanceID} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("projection leaked full identifier")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection changed journal")
	}
	if !owner.usable() {
		t.Fatal("inspection changed owner")
	}
}

func TestFieldToolsLedgerMissingCorruptUnfinishedAndCampaign(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	ledger, clock, path, _ := newTestPairingLedger(t, now, false)
	_, err := ledger.Admit(testHardNATCampaignRequest("unfinished-field", *clock))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	report := inspectFieldPairingAt(path, *clock, validateTestPairingLedgerFile)
	if !report.Campaign.BlocksCampaign || report.EntryCount != 1 || report.Entries[0].State != "burned_unfinished" || report.Entries[0].FinishedAt != nil ||
		report.Entries[0].RecordClass != string(PairingRecordClassHardNATCampaign) {
		t.Fatal("unfinished burn was advertised as ready")
	}
	if err := os.WriteFile(path, append(before, 0), 0600); err != nil {
		t.Fatal(err)
	}
	broken, _ := os.ReadFile(path)
	report = inspectFieldPairingAt(path, *clock, validateTestPairingLedgerFile)
	if report.Pairing.State != PairingLedgerIndeterminate || !report.Pairing.BlocksActiveWork || !report.Campaign.BlocksCampaign || report.EntryCount != 0 {
		t.Fatal("corrupt journal did not fail closed")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(broken, after) {
		t.Fatal("corrupt journal was repaired")
	}
	report = inspectFieldPairingAt(path+"-absent", *clock, validateTestPairingLedgerFile)
	if report.Pairing.State != PairingLedgerNotInitialized || !report.Pairing.BlocksActiveWork {
		t.Fatal("missing ledger was accepted")
	}
	if _, err := os.Lstat(path + "-absent"); !os.IsNotExist(err) {
		t.Fatal("inspection created ledger")
	}
}
