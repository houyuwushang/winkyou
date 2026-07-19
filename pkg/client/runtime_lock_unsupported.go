//go:build !windows && !linux

package client

import (
	"fmt"
	"os"
	"runtime"
)

func lockRuntimeStateFile(*os.File) error {
	return fmt.Errorf("runtime state locking is unsupported on %s", runtime.GOOS)
}

func unlockRuntimeStateFile(*os.File) error { return nil }
