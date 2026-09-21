//go:build linux && fieldc1c

package main

import (
	"os"
	"winkyou/internal/v2/sshchildwrapper"
)

func dispatchDeploymentWrapper() (bool, error) {
	if len(os.Args) == 0 || os.Args[0] != sshchildwrapper.FixedWrapperPath {
		return false, nil
	}
	return true, sshchildwrapper.ExecFieldRoot(os.Getenv("SSH_ORIGINAL_COMMAND"))
}
