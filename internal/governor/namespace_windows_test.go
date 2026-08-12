//go:build windows

package governor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsMachineNamespaceSetupAndInspect(t *testing.T) {
	requireWindowsElevation(t)
	path := filepath.Join(t.TempDir(), "safety")
	registerWindowsNamespaceCleanup(t, path)

	if status := inspectMachineNamespaceAt(path); status.State != NamespaceMissing {
		t.Fatalf("initial state = %q, want %q: %+v", status.State, NamespaceMissing, status)
	}
	if err := setupWindowsMachineNamespaceAt(path); err != nil {
		t.Fatalf("setup namespace: %v", err)
	}
	status := inspectMachineNamespaceAt(path)
	if !status.Ready || status.State != NamespaceReady {
		t.Fatalf("installed status = %+v, want ready", status)
	}
	if err := setupWindowsMachineNamespaceAt(path); err != nil {
		t.Fatalf("idempotent setup: %v", err)
	}
	owner, err := AcquirePreparedNamespace(path, ScopeMachine, "namespace-test")
	if err != nil {
		t.Fatalf("acquire installed namespace: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close installed namespace owner: %v", err)
	}
	if trip := newSafetyTripStore(path).status(); trip.State != SafetyTripClear || trip.BlocksActiveWork {
		t.Fatalf("initial safety trip status = %+v, want clear", trip)
	}
}

func TestWindowsMachineNamespaceRejectsACLDrift(t *testing.T) {
	requireWindowsElevation(t)
	path := filepath.Join(t.TempDir(), "safety")
	registerWindowsNamespaceCleanup(t, path)
	if err := setupWindowsMachineNamespaceAt(path); err != nil {
		t.Fatalf("setup namespace: %v", err)
	}

	if err := setWindowsDACL(filepath.Join(path, ownerLockFilename), windows.FILE_GENERIC_READ); err != nil {
		t.Fatalf("tamper lock DACL: %v", err)
	}
	status := inspectMachineNamespaceAt(path)
	if status.State != NamespaceUnsafe || status.Ready {
		t.Fatalf("tampered status = %+v, want unsafe", status)
	}
	if err := setupWindowsMachineNamespaceAt(path); !errors.Is(err, ErrNamespaceUnsafe) {
		t.Fatalf("setup unsafe namespace error = %v, want ErrNamespaceUnsafe", err)
	}
}

func TestWindowsMachineNamespaceRejectsOwnerDrift(t *testing.T) {
	requireWindowsElevation(t)
	path := filepath.Join(t.TempDir(), "safety")
	registerWindowsNamespaceCleanup(t, path)
	if err := setupWindowsMachineNamespaceAt(path); err != nil {
		t.Fatalf("setup namespace: %v", err)
	}

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("get token user: %v", err)
	}
	if user.User.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("test identity is itself an accepted namespace owner")
	}
	if err := setWindowsOwnerSID(filepath.Join(path, ownerLockFilename), user.User.Sid); err != nil {
		t.Fatalf("tamper lock owner: %v", err)
	}
	status := inspectMachineNamespaceAt(path)
	if status.State != NamespaceUnsafe || status.Ready {
		t.Fatalf("tampered status = %+v, want unsafe", status)
	}
}

func TestWindowsMachineNamespaceRejectsPrecreatedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "safety")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("precreate namespace: %v", err)
	}
	if err := setupWindowsMachineNamespaceAt(path); !errors.Is(err, ErrNamespaceUnsafe) {
		t.Fatalf("setup precreated namespace error = %v, want ErrNamespaceUnsafe", err)
	}
}

func TestWindowsMachineNamespaceUsesKnownFolder(t *testing.T) {
	fakeProgramData := filepath.Join(t.TempDir(), "spoofed-program-data")
	t.Setenv("ProgramData", fakeProgramData)
	path, err := MachineNamespacePath()
	if err != nil {
		t.Fatalf("MachineNamespacePath: %v", err)
	}
	if strings.HasPrefix(strings.ToLower(path), strings.ToLower(fakeProgramData)) {
		t.Fatalf("MachineNamespacePath trusted ProgramData environment override: %q", path)
	}
	if filepath.Base(path) != windowsMachineNamespaceDirectory {
		t.Fatalf("MachineNamespacePath = %q, want final directory %q", path, windowsMachineNamespaceDirectory)
	}
}

func registerWindowsNamespaceCleanup(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range namespaceFixedFilenames() {
			filePath := filepath.Join(path, name)
			if _, err := os.Lstat(filePath); err == nil {
				_ = setWindowsDACL(filePath, windows.GENERIC_ALL)
			}
		}
		if _, err := os.Lstat(path); err == nil {
			_ = setWindowsDACL(path, windows.GENERIC_ALL)
		}
	})
}

func requireWindowsElevation(t *testing.T) {
	t.Helper()
	elevated, err := windowsProcessElevated()
	if err != nil {
		t.Fatalf("inspect process elevation: %v", err)
	}
	if !elevated {
		t.Skip("Windows ACL setup integration requires an elevated test process")
	}
}
