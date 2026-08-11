//go:build windows

package governor

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func lockOwnerFile(file *os.File) error {
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		new(windows.Overlapped),
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return ErrOwnerHeld
	}
	if err != nil {
		return fmt.Errorf("lock governor owner file: %w", err)
	}
	return nil
}

func unlockOwnerFile(file *os.File) error {
	if err := windows.UnlockFileEx(
		windows.Handle(file.Fd()),
		0,
		1,
		0,
		new(windows.Overlapped),
	); err != nil {
		return fmt.Errorf("unlock governor owner file: %w", err)
	}
	return nil
}
