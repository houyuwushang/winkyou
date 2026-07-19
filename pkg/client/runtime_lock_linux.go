//go:build linux

package client

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockRuntimeStateFile(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrRuntimeStateLocked
	}
	if err != nil {
		return fmt.Errorf("lock runtime state: %w", err)
	}
	return nil
}

func unlockRuntimeStateFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("unlock runtime state: %w", err)
	}
	return nil
}
