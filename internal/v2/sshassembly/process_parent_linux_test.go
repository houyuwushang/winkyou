//go:build linux

package sshassembly

import (
	"errors"
	"syscall"
)

func processGoneForTest(pid int) bool {
	err := syscall.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func killProcessForTest(pid int) {
	if pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
