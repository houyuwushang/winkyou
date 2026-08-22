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
	machine, err := New(owner, ProfilePhase1Machine, nil)
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

func LoopbackCarrierSubprocessRaceEnabled() bool { return pairingGateRaceEnabled }
