//go:build linux && natlab

package governor

import (
	"os"
	"path/filepath"
	"time"
)

// PrepareN1TestNamespace creates only the initial safety-trip record required
// by an isolated N1 machine-governor namespace. It is absent from normal
// builds, performs no network I/O, and is architecture-gated so production Go
// sources cannot consume it even in a natlab-tagged build.
func PrepareN1TestNamespace(namespace string, at time.Time) error {
	clean, err := validatePreparedNamespace(namespace)
	if err != nil {
		return err
	}
	path := filepath.Join(clean, safetyTripFilename)
	if err := rejectSymlink(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := initializeSafetyTripFile(file, at.UTC()); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
