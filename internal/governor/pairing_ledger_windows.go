//go:build windows

package governor

import (
	"fmt"
	"os"
)

func validateMachinePairingLedgerFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: pairing journal is not a regular file", ErrNamespaceUnsafe)
	}
	if err := rejectWindowsReparsePoint(path); err != nil {
		return err
	}
	if err := validateWindowsSingleLink(path); err != nil {
		return err
	}
	return validateWindowsNamespaceDACL(path, ScopeMachine, windowsFileAccessMask())
}
