//go:build linux && natlab

package governor

import (
	"os"
	"path/filepath"
	"time"
)

// PrepareN2DTestNamespace initializes the durable pairing ledger and safety
// trip files used by the isolated N2d subprocess harness. It is absent from
// normal builds, performs no network I/O, and does not relax production
// machine-scope acquisition or file validation.
func PrepareN2DTestNamespace(namespace string, at time.Time) error {
	clean, err := validatePreparedNamespace(namespace)
	if err != nil {
		return err
	}
	ledgerPath := filepath.Join(clean, pairingLedgerFilename)
	if err := rejectSymlink(ledgerPath); err != nil {
		return err
	}
	if err := createPairingLedgerFile(ledgerPath, 0o666, at.UTC(), false); err != nil {
		return err
	}
	if err := os.Chmod(ledgerPath, 0o666); err != nil {
		return err
	}

	tripPath := filepath.Join(clean, safetyTripFilename)
	if err := rejectSymlink(tripPath); err != nil {
		return err
	}
	file, err := os.OpenFile(tripPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := initializeSafetyTripFile(file, at.UTC()); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// N2DTestPairingLedger returns only the owner-bound ledger already protected
// by the supplied test governor. It does not accept a path or acquire another
// authority and is absent from non-natlab builds.
func N2DTestPairingLedger(machine *Governor) (*PairingAdmissionLedger, error) {
	if machine == nil || machine.owner == nil {
		return nil, ErrPairingMachineScopeRequired
	}
	return machine.owner.PairingLedger()
}
