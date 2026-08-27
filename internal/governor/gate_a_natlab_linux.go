//go:build linux && natlab

package governor

import "time"

// PrepareGateATestNamespace initializes the existing N2 durable-ledger test
// format for the required Gate A namespace harness. It is absent from normal
// builds and grants no network capability.
func PrepareGateATestNamespace(namespace string, at time.Time) error {
	return PrepareN2DTestNamespace(namespace, at)
}

// GateATestPairingLedger returns only the ledger already bound to the held
// machine governor. It cannot acquire a path, owner lock, or second writer.
func GateATestPairingLedger(machine *Governor) (*PairingAdmissionLedger, error) {
	return N2DTestPairingLedger(machine)
}

// GateATestLedgerOccupancy exposes unfinished charge only to the natlab-tagged
// harness. PairingLedgerStatus and the stdio product schema remain unchanged.
func GateATestLedgerOccupancy(machine *Governor) (int, int, error) {
	ledger, err := GateATestPairingLedger(machine)
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
	admissions, packets := 0, 0
	for _, admission := range snapshot.admissionOrder {
		if admission.finish == nil {
			admissions++
			packets += admission.record.Envelope.Packets
		}
	}
	return admissions, packets, nil
}
