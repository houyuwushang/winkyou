package governor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// OwnerState is a stable, machine-readable view of the OS lock authority.
type OwnerState string

const (
	OwnerIdle        OwnerState = "idle"
	OwnerHeld        OwnerState = "held"
	OwnerUnavailable OwnerState = "unavailable"
)

// OwnerStatus reports whether the canonical namespace lock is held. Owner is
// best-effort diagnostic metadata only; State is derived from the OS lock.
type OwnerStatus struct {
	Scope             Scope      `json:"scope"`
	State             OwnerState `json:"state"`
	Held              bool       `json:"held"`
	Owner             *OwnerInfo `json:"owner,omitempty"`
	MetadataAvailable bool       `json:"metadata_available"`
	Detail            string     `json:"detail,omitempty"`
}

// InspectMachineOwner probes the canonical lock without writing owner
// metadata or claiming a governor lifecycle. An idle lock is held only long
// enough to prove availability and is immediately released.
func InspectMachineOwner() OwnerStatus {
	namespace := InspectMachineNamespace()
	if !namespace.Ready {
		return OwnerStatus{
			Scope:  ScopeMachine,
			State:  OwnerUnavailable,
			Detail: fmt.Sprintf("machine namespace is %s: %s", namespace.State, namespace.Detail),
		}
	}
	return inspectPreparedNamespaceOwner(namespace.Path, ScopeMachine)
}

func inspectPreparedNamespaceOwner(namespace string, scope Scope) OwnerStatus {
	status := OwnerStatus{Scope: scope, State: OwnerUnavailable}
	if !scope.valid() {
		status.Detail = fmt.Sprintf("unsupported owner scope %q", scope)
		return status
	}
	clean, err := validatePreparedNamespace(namespace)
	if err != nil {
		status.Detail = err.Error()
		return status
	}
	lockPath := filepath.Join(clean, ownerLockFilename)
	metadataPath := filepath.Join(clean, ownerMetadataFilename)
	if err := rejectSymlink(lockPath); err != nil {
		status.Detail = err.Error()
		return status
	}
	if err := rejectSymlink(metadataPath); err != nil {
		status.Detail = err.Error()
		return status
	}

	file, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		status.Detail = fmt.Sprintf("open governor owner file: %v", err)
		return status
	}
	if err := lockOwnerFile(file); err != nil {
		_ = file.Close()
		if !errors.Is(err, ErrOwnerHeld) {
			status.Detail = err.Error()
			return status
		}
		status.State = OwnerHeld
		status.Held = true
		info, metadataErr := readOwnerInfo(metadataPath)
		if metadataErr != nil {
			status.Detail = fmt.Sprintf("OS lock is held; owner metadata unavailable: %v", metadataErr)
			return status
		}
		status.Owner = &info
		status.MetadataAvailable = true
		return status
	}

	unlockErr := unlockOwnerFile(file)
	closeErr := file.Close()
	if err := errors.Join(unlockErr, closeErr); err != nil {
		status.Detail = fmt.Sprintf("release diagnostic owner probe: %v", err)
		return status
	}
	status.State = OwnerIdle
	status.Detail = "OS lock is available; stale owner metadata, if any, is ignored"
	return status
}
