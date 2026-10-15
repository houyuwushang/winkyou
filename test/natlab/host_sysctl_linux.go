//go:build linux && natlab

package natlab

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// Capture an I/O failure and both namespace identities on the same OS thread.
// Error text deliberately excludes paths, command output and arbitrary errors.
type hostSysctlError struct {
	op        string
	errno     string
	threadNet uint64
	initNet   uint64
	cause     error
}

func (e *hostSysctlError) Error() string {
	return fmt.Sprintf("GATE_B3_HOST_SYSCTL op=%s errno=%s thread_net=%d init_net=%d", e.op, e.errno, e.threadNet, e.initNet)
}

func (e *hostSysctlError) Unwrap() error { return e.cause }

func hostSysctlFailure(op string, err error) error {
	if err == nil {
		return nil
	}
	name := "UNKNOWN"
	var number syscall.Errno
	if errors.As(err, &number) {
		if value := unix.ErrnoName(number); value != "" {
			name = value
		}
	}
	var thread, initial unix.Stat_t
	_ = unix.Stat("/proc/thread-self/ns/net", &thread)
	_ = unix.Stat("/proc/1/ns/net", &initial)
	return &hostSysctlError{op: op, errno: name, threadNet: thread.Ino, initNet: initial.Ino, cause: err}
}

func readHostSysctlDiagnostic(path string) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	value, err := os.ReadFile(path)
	return value, hostSysctlFailure("read", err)
}

func writeHostSysctlDiagnostic(path string, value []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return hostSysctlFailure("write", os.WriteFile(path, value, 0))
}

func runHostSysctlDiagnostic(op string, args ...string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	value, err := runCommand("sysctl", args...)
	return value, hostSysctlFailure(op, err)
}
