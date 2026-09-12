package rendezvousserver

import "os"

func serverCrashKilledState(state *os.ProcessState) bool {
	// os.Process.Kill uses TerminateProcess with exit code 1 on Windows. The
	// shared oracle additionally rejects all child terminal/test output.
	return state.ExitCode() == 1
}
