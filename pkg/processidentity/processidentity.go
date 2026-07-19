// Package processidentity identifies a process instance, rather than only a
// process ID. The identity changes when an operating system reuses a PID.
package processidentity

import (
	"errors"
	"fmt"
	"os"
)

// ErrUnsupported is returned on platforms that do not expose a supported
// process-start identity.
var ErrUnsupported = errors.New("process identity is unsupported")

// Current returns the identity of the calling process.
func Current() (string, error) {
	id, alive, err := Inspect(os.Getpid())
	if err != nil {
		return "", err
	}
	if !alive {
		return "", errors.New("process identity: current process is not alive")
	}
	if id == "" {
		return "", errors.New("process identity: current process has an empty identity")
	}
	return id, nil
}

// Matches reports whether pid currently refers to a live process with want as
// its identity. It returns false, nil when pid no longer exists or has been
// reused for another process.
func Matches(pid int, want string) (bool, error) {
	if want == "" {
		return false, errors.New("process identity: identity must not be empty")
	}

	id, alive, err := Inspect(pid)
	if err != nil {
		return false, err
	}
	return alive && id == want, nil
}

func validatePID(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("process identity: pid must be positive: %d", pid)
	}
	return nil
}
