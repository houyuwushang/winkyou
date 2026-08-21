//go:build !linux && !windows

package governor

import (
	"fmt"
	"runtime"
)

func validateMachinePairingLedgerFile(string) error {
	return fmt.Errorf("%w on %s", ErrUnsupportedPlatform, runtime.GOOS)
}
