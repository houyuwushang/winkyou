//go:build !linux && !windows

package sshassembly

import "os/exec"

func startOwnedCommand(*exec.Cmd) (processContainment, error) {
	return nil, ErrProfileInvalid
}
