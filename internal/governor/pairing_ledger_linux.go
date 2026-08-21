//go:build linux

package governor

import (
	"os"
)

func validateMachinePairingLedgerFile(path string) error {
	return validateLinuxPairingLedgerFileAt(path, 0, 0)
}

func validateLinuxPairingLedgerFileAt(path string, expectedUID, expectedGID int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validateLinuxPath(path, info, false, 0o666, expectedUID, expectedGID)
}
