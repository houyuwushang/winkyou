package governor

import (
	"os"
	"path/filepath"
	"time"
)

// PrepareLoopbackCarrierTestNamespace is compiled only into the governor test
// binary. It gives the external loopback-carrier integration tests the same
// framing and gate implementation without weakening production namespace
// validation or exporting a runtime bypass.
func PrepareLoopbackCarrierTestNamespace(namespace string, at time.Time) error {
	if err := createPairingLedgerFile(filepath.Join(namespace, pairingLedgerFilename), 0o600, at.UTC(), false); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(namespace, safetyTripFilename), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := initializeSafetyTripFile(file, at.UTC()); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// AcquireLoopbackCarrierTestGovernor installs only the test file validator on
// a temp namespace. The production carrier still receives a real Governor,
// PairingAdmissionGate, journal, AttemptLease, and OS owner lock.
func AcquireLoopbackCarrierTestGovernor(namespace, buildVersion string) (*Governor, error) {
	return acquireCarrierTestGovernor(namespace, buildVersion, ProfilePhase1Machine)
}

// AcquireManualTraversalTestGovernor is compiled only into governor tests. It
// preserves the same OS owner and durable journal while selecting Gate B2's
// exact manual-traversal profile.
func AcquireManualTraversalTestGovernor(namespace, buildVersion string) (*Governor, error) {
	return acquireCarrierTestGovernor(namespace, buildVersion, ProfilePhase1ManualTraversal)
}

// AcquireHardNATCampaignTestGovernor is available only to the in-memory and
// natsim Gate B3 proof. It does not create a production constructor.
func AcquireHardNATCampaignTestGovernor(namespace, buildVersion string) (*Governor, error) {
	return acquireCarrierTestGovernor(namespace, buildVersion, ProfilePhase1HardNATCampaign)
}

func acquireCarrierTestGovernor(namespace, buildVersion string, profile Profile) (*Governor, error) {
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, buildVersion)
	if err != nil {
		return nil, err
	}
	ledger := &PairingAdmissionLedger{
		owner: owner, ownerInstanceID: owner.Info().InstanceID,
		path: filepath.Join(namespace, pairingLedgerFilename),
		now:  time.Now, validateFile: validateTestPairingLedgerFile,
	}
	owner.mu.Lock()
	owner.pairingLedger = ledger
	owner.mu.Unlock()
	machine, err := New(owner, profile, nil)
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	return machine, nil
}

func InspectLoopbackCarrierTestLedger(namespace string, at time.Time) (PairingLedgerStatus, error) {
	snapshot, err := readPairingLedgerSnapshot(filepath.Join(namespace, pairingLedgerFilename), at.UTC(), "", validateTestPairingLedgerFile)
	return snapshot.status, err
}

func InspectHardNATCampaignTestLedger(namespace string, at time.Time) (HardNATCampaignStatus, error) {
	snapshot, err := readPairingLedgerSnapshot(filepath.Join(namespace, pairingLedgerFilename), at.UTC(), "", validateTestPairingLedgerFile)
	return snapshot.hardNATCampaignStatusAt(at.UTC()), err
}

// InspectLoopbackCarrierTestOccupancy exposes unfinished durable charge only
// inside the governor test binary; it does not extend PairingLedgerStatus or
// any stdio/product schema.
func InspectLoopbackCarrierTestOccupancy(namespace string, at time.Time) (int, int, error) {
	snapshot, err := readPairingLedgerSnapshot(filepath.Join(namespace, pairingLedgerFilename), at.UTC(), "", validateTestPairingLedgerFile)
	if err != nil {
		return 0, 0, err
	}
	return unfinishedTestOccupancy(snapshot)
}

// LoopbackCarrierTestLedger returns the already owner-bound test journal. It
// exists only in the governor test binary and cannot weaken a normal build.
func LoopbackCarrierTestLedger(machine *Governor) (*PairingAdmissionLedger, error) {
	if machine == nil || machine.owner == nil {
		return nil, ErrPairingMachineScopeRequired
	}
	return machine.owner.PairingLedger()
}

// SetCarrierTestLedgerTime freezes only the test journal clock. It is not
// compiled into production and cannot alter governor or safety-trip clocks.
func SetCarrierTestLedgerTime(machine *Governor, at time.Time) error {
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return err
	}
	fixed := at.UTC()
	ledger.mu.Lock()
	ledger.now = func() time.Time { return fixed }
	ledger.mu.Unlock()
	return nil
}

// LoopbackCarrierTestOccupancy reads the held test journal without exposing
// its unfinished state through production status DTOs.
func LoopbackCarrierTestOccupancy(machine *Governor) (int, int, error) {
	ledger, err := LoopbackCarrierTestLedger(machine)
	if err != nil {
		return 0, 0, err
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	releaseOwner, err := ledger.holdOwner()
	if err != nil {
		return 0, 0, err
	}
	defer releaseOwner()
	snapshot, err := readPairingLedgerSnapshot(ledger.path, ledger.now().UTC(), ledger.ownerInstanceID, ledger.validateFile)
	if err != nil {
		return 0, 0, err
	}
	return unfinishedTestOccupancy(snapshot)
}

func unfinishedTestOccupancy(snapshot pairingLedgerSnapshot) (int, int, error) {
	admissions, packets := 0, 0
	for _, admission := range snapshot.admissionOrder {
		if admission.finish == nil {
			admissions++
			packets += admission.record.Envelope.Packets
		}
	}
	return admissions, packets, nil
}

func LoopbackCarrierSubprocessRaceEnabled() bool { return pairingGateRaceEnabled }
