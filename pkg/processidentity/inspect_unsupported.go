//go:build !windows && !linux

package processidentity

import (
	"fmt"
	"runtime"
)

// Inspect reports that process identities are not implemented on this
// platform.
func Inspect(pid int) (id string, alive bool, err error) {
	if err := validatePID(pid); err != nil {
		return "", false, err
	}
	return "", false, fmt.Errorf("%w on %s", ErrUnsupported, runtime.GOOS)
}
