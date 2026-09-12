//go:build !windows

package rendezvousserver

import (
	"os"
	"syscall"
)

func serverCrashKilledState(state *os.ProcessState) bool {
	status, ok := state.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}
