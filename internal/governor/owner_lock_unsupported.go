//go:build !windows && !linux

package governor

import (
	"fmt"
	"os"
	"runtime"
)

func lockOwnerFile(*os.File) error {
	return fmt.Errorf("governor namespace locking is unsupported on %s", runtime.GOOS)
}

func unlockOwnerFile(*os.File) error {
	return nil
}
