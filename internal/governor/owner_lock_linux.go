//go:build linux

package governor

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockOwnerFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrOwnerHeld
	}
	if err != nil {
		return fmt.Errorf("lock governor owner file: %w", err)
	}
	return nil
}

func unlockOwnerFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("unlock governor owner file: %w", err)
	}
	return nil
}
