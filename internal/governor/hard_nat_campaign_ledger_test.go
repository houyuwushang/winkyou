package governor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestHardNATCampaignLedgerUsesIndependentWindowAndExactReservation(t *testing.T) {
	base := time.Date(2026, 8, 30, 1, 0, 0, 0, time.UTC)
	ledger, clock, _, _ := newTestPairingLedger(t, base, false)

	ordinary := testPairingRequest("ordinary-independent", *clock, 8)
	ordinaryReceipt, err := ledger.Admit(ordinary)
	if err != nil {
		t.Fatalf("ordinary admit: %v", err)
	}
	if err := ledger.Finish(ordinaryReceipt, PairingTerminalSuccess); err != nil {
		t.Fatalf("ordinary finish: %v", err)
	}
	*clock = clock.Add(pairingAdmissionMinimumInterval)

	request := testHardNATCampaignRequest("campaign-first", *clock)
	if err := ledger.Preflight(request); err != nil {
		t.Fatalf("campaign preflight after ordinary admission: %v", err)
	}
	receipt, err := ledger.Admit(request)
	if err != nil {
		t.Fatalf("campaign admit: %v", err)
	}
	if receipt.recordClass != PairingRecordClassHardNATCampaign {
		t.Fatalf("receipt class = %q", receipt.recordClass)
	}
	if err := ledger.Finish(receipt, PairingTerminalSuccess); err != nil {
		t.Fatalf("campaign finish: %v", err)
	}
	status := ledger.CampaignStatus()
	if status.State != PairingLedgerRateLimited || !status.BlocksCampaign ||
		status.TwentyFourHourAdmissions != 1 || status.TwentyFourHourPackets != hardNATCampaignPackets {
		t.Fatalf("campaign status = %+v", status)
	}
	if ordinaryStatus := ledger.Status(); ordinaryStatus.TwentyFourHourAdmissions != 1 || ordinaryStatus.TwentyFourHourPackets != 8 {
		t.Fatalf("ordinary status consumed campaign reservation: %+v", ordinaryStatus)
	}
	*clock = clock.Add(time.Minute)
	if _, err := ledger.Admit(testHardNATCampaignRequest("campaign-second", *clock)); !errors.Is(err, ErrHardNATCampaignRateLimited) {
		t.Fatalf("second campaign error = %v", err)
	}

	wrong := testHardNATCampaignRequest("campaign-wrong-envelope", *clock)
	wrong.Envelope.Packets--
	if err := ledger.Preflight(wrong); !errors.Is(err, ErrPairingLedgerInvalidRequest) {
		t.Fatalf("inexact campaign envelope error = %v", err)
	}
}

func TestHardNATCampaignFailureCircuitRequiresExplicitResetWithoutRefund(t *testing.T) {
	base := time.Date(2026, 8, 30, 2, 0, 0, 0, time.UTC)
	ledger, clock, _, _ := newTestPairingLedger(t, base, false)
	receipt, err := ledger.Admit(testHardNATCampaignRequest("campaign-failure", *clock))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Finish(receipt, PairingTerminalCarrierError); err != nil {
		t.Fatal(err)
	}
	opened := ledger.CampaignStatus()
	if opened.State != PairingLedgerCircuitOpen || !opened.ExplicitResetRequired || opened.CircuitOpenedAt.IsZero() {
		t.Fatalf("opened campaign status = %+v", opened)
	}
	// Passage of time does not reopen the circuit.
	*clock = clock.Add(48 * time.Hour)
	if status := ledger.CampaignStatus(); status.State != PairingLedgerCircuitOpen {
		t.Fatalf("time cleared campaign circuit: %+v", status)
	}
	ordinary := testPairingRequest("ordinary-while-campaign-circuit", *clock, 1)
	if receipt, err := ledger.Admit(ordinary); err != nil {
		t.Fatalf("campaign circuit blocked ordinary admission: %v", err)
	} else if err := ledger.Finish(receipt, PairingTerminalSuccess); err != nil {
		t.Fatal(err)
	}
	current := ledger.CampaignStatus()
	if _, err := ledger.ResetHardNATCampaignCircuit(current.Sequence-1, "reviewed-campaign-reset"); !errors.Is(err, ErrPairingLedgerResetRejected) {
		t.Fatalf("stale reset error = %v", err)
	}
	reset, err := ledger.ResetHardNATCampaignCircuit(current.Sequence, "reviewed-campaign-reset")
	if err != nil || reset.State != PairingLedgerReady || reset.ExplicitResetRequired {
		t.Fatalf("reset campaign = %+v/%v", reset, err)
	}
	if _, err := ledger.Admit(testHardNATCampaignRequest("campaign-after-reset", *clock)); err != nil {
		t.Fatalf("campaign after elapsed window and reset: %v", err)
	}
}

func TestHardNATCampaignIgnoresOrdinaryRateWindowButNotOrdinaryCircuit(t *testing.T) {
	base := time.Date(2026, 8, 30, 2, 30, 0, 0, time.UTC)
	ledger, clock, _, _ := newTestPairingLedger(t, base, false)
	for index := 0; index < pairingAdmissionOneHourLimit; index++ {
		if index > 0 {
			*clock = clock.Add(pairingAdmissionMinimumInterval)
		}
		request := testPairingRequest(fmt.Sprintf("ordinary-rate-%d", index), *clock, 1)
		receipt, err := ledger.Admit(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := ledger.Finish(receipt, PairingTerminalSuccess); err != nil {
			t.Fatal(err)
		}
	}
	*clock = clock.Add(pairingAdmissionMinimumInterval)
	if status := ledger.Status(); status.State != PairingLedgerRateLimited {
		t.Fatalf("ordinary rate fixture = %+v", status)
	}
	if err := ledger.Preflight(testHardNATCampaignRequest("campaign-after-ordinary-rate", *clock)); err != nil {
		t.Fatalf("ordinary rate window blocked independent campaign: %v", err)
	}
}

func TestHardNATCampaignPendingRestartAndOrdinaryCircuitBlockAdmission(t *testing.T) {
	base := time.Date(2026, 8, 30, 3, 0, 0, 0, time.UTC)
	ledger, clock, path, _ := newTestPairingLedger(t, base, false)
	if _, err := ledger.Admit(testHardNATCampaignRequest("campaign-pending", *clock)); err != nil {
		t.Fatal(err)
	}
	// The current owner may still be finishing. A different owner instance
	// after restart turns the pending record into an open campaign circuit.
	snapshot, err := readPairingLedgerSnapshot(path, *clock, testPairingOwnerID("different-restart-owner"), validateTestPairingLedgerFile)
	if err != nil {
		t.Fatal(err)
	}
	status := snapshot.hardNATCampaignStatusAt(*clock)
	if status.State != PairingLedgerCircuitOpen {
		t.Fatalf("pending restart status = %+v", status)
	}

	ordinaryLedger, ordinaryClock, _, _ := newTestPairingLedger(t, base.Add(time.Hour), false)
	for index := 0; index < pairingAdmissionFailureLimit; index++ {
		request := testPairingRequest("ordinary-circuit-"+string(rune('a'+index)), *ordinaryClock, 1)
		receipt, err := ordinaryLedger.Admit(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := ordinaryLedger.Finish(receipt, PairingTerminalCarrierError); err != nil {
			t.Fatal(err)
		}
		*ordinaryClock = ordinaryClock.Add(pairingAdmissionMinimumInterval)
	}
	if err := ordinaryLedger.Preflight(testHardNATCampaignRequest("blocked-by-ordinary", *ordinaryClock)); !errors.Is(err, ErrPairingAdmissionCircuitOpen) {
		t.Fatalf("ordinary circuit did not block campaign: %v", err)
	}
}

func TestHardNATCampaignRebuildBaselineSaturatesWindow(t *testing.T) {
	base := time.Date(2026, 8, 30, 4, 0, 0, 0, time.UTC)
	ledger, clock, _, _ := newTestPairingLedger(t, base, true)
	if err := ledger.Preflight(testHardNATCampaignRequest("campaign-rebuild", *clock)); !errors.Is(err, ErrHardNATCampaignRateLimited) {
		t.Fatalf("rebuild campaign preflight = %v", err)
	}
	status := ledger.CampaignStatus()
	if status.TwentyFourHourAdmissions != hardNATCampaignAdmissions || status.TwentyFourHourPackets != hardNATCampaignPackets {
		t.Fatalf("rebuild campaign status = %+v", status)
	}
}

func TestHardNATCampaignSharedClockCapacityAndIndeterminateStatesFailClosed(t *testing.T) {
	base := time.Date(2026, 8, 30, 5, 0, 0, 0, time.UTC)
	ledger, clock, path, _ := newTestPairingLedger(t, base, false)
	*clock = clock.Add(-pairingLedgerClockRollbackSkew - time.Second)
	if err := ledger.Preflight(testHardNATCampaignRequest("campaign-clock-rollback", *clock)); !errors.Is(err, ErrPairingLedgerClockRollback) {
		t.Fatalf("campaign clock rollback = %v", err)
	}
	if status := ledger.CampaignStatus(); status.State != PairingLedgerClockRollback || !status.BlocksCampaign {
		t.Fatalf("campaign rollback status = %+v", status)
	}

	*clock = base
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 0, 0, 8, '{'}); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Preflight(testHardNATCampaignRequest("campaign-indeterminate", *clock)); !errors.Is(err, ErrPairingLedgerIndeterminate) {
		t.Fatalf("campaign corrupt journal = %v", err)
	}
	if status := ledger.CampaignStatus(); status.State != PairingLedgerIndeterminate || !status.BlocksCampaign {
		t.Fatalf("campaign indeterminate status = %+v", status)
	}

	records := []pairingJournalRecord{{SchemaVersion: pairingLedgerSchemaVersion, Sequence: 1, Type: pairingRecordInitialize, RecordedAt: base}}
	snapshot, err := buildPairingLedgerSnapshot(records, maxPairingLedgerBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.hardNATCampaignAdmissionError(base, hardNATCampaignEnvelope()); !errors.Is(err, ErrPairingLedgerCapacity) {
		t.Fatalf("campaign capacity = %v", err)
	}
}

func testHardNATCampaignRequest(label string, now time.Time) PairingAdmissionRequest {
	digest := sha256.Sum256([]byte("hard-campaign-context:" + label))
	return PairingAdmissionRequest{
		RecordClass:   PairingRecordClassHardNATCampaign,
		CredentialID:  testPairingOpaqueID("hard-campaign-credential-" + label),
		AttemptID:     testPairingOpaqueID("hard-campaign-attempt-" + label),
		ContextDigest: hex.EncodeToString(digest[:]), Scope: ScopeMachine,
		ExpiresAt: now.UTC().Add(pairingCredentialMaxLifetime), Envelope: hardNATCampaignEnvelope(),
	}
}
