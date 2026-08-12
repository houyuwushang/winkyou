//go:build !linux && !windows

package governor

import (
	"fmt"
	"runtime"
)

func platformMachineNamespacePath() (string, error) {
	return "", fmt.Errorf("%w on %s", ErrUnsupportedPlatform, runtime.GOOS)
}

func inspectMachineNamespaceAt(path string) NamespaceStatus {
	return NamespaceStatus{
		Scope:  ScopeMachine,
		Path:   path,
		State:  NamespaceUnavailable,
		Detail: fmt.Sprintf("%v on %s", ErrUnsupportedPlatform, runtime.GOOS),
	}
}

func setupMachineNamespaceAt(string) error {
	return fmt.Errorf("%w on %s", ErrUnsupportedPlatform, runtime.GOOS)
}
