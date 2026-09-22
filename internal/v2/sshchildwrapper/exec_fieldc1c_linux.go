//go:build linux && fieldc1c

package sshchildwrapper

import "syscall"

// ExecFieldRoot replaces the existing forced-command process. It cannot
// fork, select an executable, alter arguments, or forward the caller's env.
func ExecFieldRoot(originalCommand string) error {
	plan, err := PrepareRootExecution(originalCommand)
	if err != nil {
		return ErrWrapperInvalid
	}
	syscall.Umask(int(plan.Umask))
	if syscall.Exec(plan.Executable, append([]string{plan.Executable}, plan.Arguments...), plan.Environment) != nil {
		return ErrWrapperInvalid
	}
	return nil
}
