package governor

import (
	"errors"
	"fmt"
)

var (
	ErrNamespaceNotReady   = errors.New("governor namespace is not ready")
	ErrNamespaceUnsafe     = errors.New("governor namespace is unsafe")
	ErrElevationRequired   = errors.New("administrator privileges are required")
	ErrUnsupportedPlatform = errors.New("governor namespace is unsupported")
	ErrUserScopeNotNeeded  = errors.New("user-acknowledged scope is unavailable while machine scope is ready")
)

// NamespaceState is a stable, machine-readable setup state.
type NamespaceState string

const (
	NamespaceReady       NamespaceState = "ready"
	NamespaceMissing     NamespaceState = "missing"
	NamespaceUnsafe      NamespaceState = "unsafe"
	NamespaceUnavailable NamespaceState = "unavailable"
)

// NamespaceStatus describes the canonical local safety namespace. Detail is
// intended for operator diagnostics and must never be treated as authority.
type NamespaceStatus struct {
	Scope             Scope          `json:"scope"`
	Path              string         `json:"path,omitempty"`
	State             NamespaceState `json:"state"`
	Ready             bool           `json:"ready"`
	RequiresElevation bool           `json:"requires_elevation"`
	Detail            string         `json:"detail,omitempty"`
}

// MachineNamespacePath returns the platform canonical path without consulting
// a user-configurable WinkYou data directory.
func MachineNamespacePath() (string, error) {
	return platformMachineNamespacePath()
}

// InspectMachineNamespace performs a read-only validation of the canonical
// path, files, ownership, and permissions.
func InspectMachineNamespace() NamespaceStatus {
	path, err := MachineNamespacePath()
	if err != nil {
		return NamespaceStatus{
			Scope:  ScopeMachine,
			State:  NamespaceUnavailable,
			Detail: err.Error(),
		}
	}
	return inspectMachineNamespaceAt(path)
}

// SetupMachineNamespace creates the canonical namespace and validates it. It
// never starts a WinkYou runtime, opens a network socket, or changes routes.
func SetupMachineNamespace() (NamespaceStatus, error) {
	path, err := MachineNamespacePath()
	if err != nil {
		status := NamespaceStatus{
			Scope:  ScopeMachine,
			State:  NamespaceUnavailable,
			Detail: err.Error(),
		}
		return status, err
	}
	if err := setupMachineNamespaceAt(path); err != nil {
		status := inspectMachineNamespaceAt(path)
		if errors.Is(err, ErrElevationRequired) {
			status.RequiresElevation = true
			if status.Detail == "" {
				status.Detail = err.Error()
			}
		}
		return status, err
	}
	status := inspectMachineNamespaceAt(path)
	if !status.Ready {
		return status, fmt.Errorf("%w: %s", ErrNamespaceNotReady, status.Detail)
	}
	return status, nil
}

// AcquireMachineNamespace validates and acquires the canonical machine owner.
func AcquireMachineNamespace(buildVersion string) (*Owner, error) {
	status := InspectMachineNamespace()
	if !status.Ready {
		return nil, fmt.Errorf(
			"%w: state=%s path=%q detail=%s",
			ErrNamespaceNotReady,
			status.State,
			status.Path,
			status.Detail,
		)
	}
	return AcquirePreparedNamespace(status.Path, ScopeMachine, buildVersion)
}

// UserAcknowledgedNamespacePath returns the canonical per-user safety path.
// It is derived from operating-system identity, never configuration, a mesh
// data directory, or a caller-supplied environment override.
func UserAcknowledgedNamespacePath() (string, error) {
	return platformUserAcknowledgedNamespacePath()
}

// InspectUserAcknowledgedNamespace validates the canonical per-user path
// without creating it or acquiring its owner lock.
func InspectUserAcknowledgedNamespace() NamespaceStatus {
	path, err := UserAcknowledgedNamespacePath()
	if err != nil {
		return NamespaceStatus{
			Scope:  ScopeUserAcknowledged,
			State:  NamespaceUnavailable,
			Detail: err.Error(),
		}
	}
	return inspectUserAcknowledgedNamespaceAt(path)
}

func prepareUserAcknowledgedNamespace() (NamespaceStatus, error) {
	path, err := UserAcknowledgedNamespacePath()
	if err != nil {
		status := NamespaceStatus{
			Scope:  ScopeUserAcknowledged,
			State:  NamespaceUnavailable,
			Detail: err.Error(),
		}
		return status, err
	}
	status := inspectUserAcknowledgedNamespaceAt(path)
	if status.Ready {
		return status, nil
	}
	if status.State != NamespaceMissing {
		return status, fmt.Errorf("%w: %s", ErrNamespaceUnsafe, status.Detail)
	}
	if err := setupUserAcknowledgedNamespaceAt(path); err != nil {
		return inspectUserAcknowledgedNamespaceAt(path), err
	}
	status = inspectUserAcknowledgedNamespaceAt(path)
	if !status.Ready {
		return status, fmt.Errorf("%w: %s", ErrNamespaceNotReady, status.Detail)
	}
	return status, nil
}

func readyNamespaceStatus(scope Scope, path, detail string) NamespaceStatus {
	return NamespaceStatus{
		Scope:  scope,
		Path:   path,
		State:  NamespaceReady,
		Ready:  true,
		Detail: detail,
	}
}

func missingNamespaceStatus(scope Scope, path, detail string, requiresElevation bool) NamespaceStatus {
	return NamespaceStatus{
		Scope:             scope,
		Path:              path,
		State:             NamespaceMissing,
		RequiresElevation: requiresElevation,
		Detail:            detail,
	}
}

func unsafeNamespaceStatus(scope Scope, path string, err error, requiresElevation bool) NamespaceStatus {
	return NamespaceStatus{
		Scope:             scope,
		Path:              path,
		State:             NamespaceUnsafe,
		RequiresElevation: requiresElevation,
		Detail:            err.Error(),
	}
}

func namespaceFixedFilenames() []string {
	return []string{ownerLockFilename, ownerMetadataFilename, safetyTripFilename}
}
