//go:build linux

package sshchildwrapper

import "os"

// PrepareRootExecution returns the frozen C1a plan only in a verified UID-0
// installation. It never elevates privilege, launches a process, or installs
// files. In C1b only the isolated SSH harness executes the returned plan.
func PrepareRootExecution(originalCommand string) (Execution, error) {
	return prepareRootExecution(originalCommand, os.Getuid(), os.Geteuid(), ValidateFixedInstallation)
}

func prepareRootExecution(originalCommand string, uid, euid int, installation func() error) (Execution, error) {
	plan, err := Plan(originalCommand)
	if err != nil || uid != 0 || euid != 0 || installation == nil {
		return Execution{}, ErrWrapperInvalid
	}
	if installation() != nil {
		return Execution{}, ErrWrapperInvalid
	}
	return plan, nil
}
