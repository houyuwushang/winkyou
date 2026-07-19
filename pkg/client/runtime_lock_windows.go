//go:build windows

package client

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func lockRuntimeStateFile(file *os.File) error {
	overlapped := new(windows.Overlapped)
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return ErrRuntimeStateLocked
	}
	if err != nil {
		return fmt.Errorf("lock runtime state: %w", err)
	}
	return nil
}

func unlockRuntimeStateFile(file *os.File) error {
	overlapped := new(windows.Overlapped)
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped); err != nil {
		return fmt.Errorf("unlock runtime state: %w", err)
	}
	return nil
}
