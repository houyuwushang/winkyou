//go:build linux

package governor

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLinuxMachineNamespaceSetupAndInspect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "safety")
	uid, gid := os.Geteuid(), os.Getegid()

	if status := inspectLinuxMachineNamespaceAt(path, uid, gid); status.State != NamespaceMissing {
		t.Fatalf("initial state = %q, want %q: %+v", status.State, NamespaceMissing, status)
	}
	if err := setupLinuxMachineNamespaceAt(path, uid, gid); err != nil {
		t.Fatalf("setup namespace: %v", err)
	}
	status := inspectLinuxMachineNamespaceAt(path, uid, gid)
	if !status.Ready || status.State != NamespaceReady {
		t.Fatalf("installed status = %+v, want ready", status)
	}
	if err := setupLinuxMachineNamespaceAt(path, uid, gid); err != nil {
		t.Fatalf("idempotent setup: %v", err)
	}
	owner, err := AcquirePreparedNamespace(path, ScopeMachine, "namespace-test")
	if err != nil {
		t.Fatalf("acquire installed namespace: %v", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close installed namespace owner: %v", err)
	}

	for _, name := range namespaceFixedFilenames() {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o666 {
			t.Fatalf("%s mode = %04o, want 0666", name, got)
		}
	}
	if trip := newSafetyTripStore(path).status(); trip.State != SafetyTripClear || trip.BlocksActiveWork {
		t.Fatalf("initial safety trip status = %+v, want clear", trip)
	}
}

func TestLinuxMachineNamespaceRejectsPermissionDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "safety")
	uid, gid := os.Geteuid(), os.Getegid()
	if err := setupLinuxMachineNamespaceAt(path, uid, gid); err != nil {
		t.Fatalf("setup namespace: %v", err)
	}

	lockPath := filepath.Join(path, ownerLockFilename)
	if err := os.Chmod(lockPath, 0o600); err != nil {
		t.Fatalf("tamper lock mode: %v", err)
	}
	status := inspectLinuxMachineNamespaceAt(path, uid, gid)
	if status.State != NamespaceUnsafe || status.Ready {
		t.Fatalf("tampered status = %+v, want unsafe", status)
	}
	if err := setupLinuxMachineNamespaceAt(path, uid, gid); !errors.Is(err, ErrNamespaceUnsafe) {
		t.Fatalf("setup unsafe namespace error = %v, want ErrNamespaceUnsafe", err)
	}
}

func TestLinuxMachineNamespaceRejectsPrecreatedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "safety")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("precreate namespace: %v", err)
	}
	if err := setupLinuxMachineNamespaceAt(path, os.Geteuid(), os.Getegid()); !errors.Is(err, ErrNamespaceUnsafe) {
		t.Fatalf("setup precreated namespace error = %v, want ErrNamespaceUnsafe", err)
	}
}

func TestLinuxMachineNamespaceRejectsWritableParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatalf("make parent writable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	path := filepath.Join(parent, "safety")
	if err := setupLinuxMachineNamespaceAt(path, os.Geteuid(), os.Getegid()); !errors.Is(err, ErrNamespaceUnsafe) {
		t.Fatalf("setup below writable parent error = %v, want ErrNamespaceUnsafe", err)
	}
}

func TestLinuxMachineNamespacePathIsCanonical(t *testing.T) {
	path, err := MachineNamespacePath()
	if err != nil {
		t.Fatalf("MachineNamespacePath: %v", err)
	}
	if path != linuxMachineNamespace {
		t.Fatalf("MachineNamespacePath = %q, want %q", path, linuxMachineNamespace)
	}
}

func TestLinuxUserAcknowledgedNamespaceSetupAndInspect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-safety")
	uid := os.Geteuid()
	if status := inspectLinuxUserAcknowledgedNamespaceAt(path, uid); status.State != NamespaceMissing || status.RequiresElevation {
		t.Fatalf("initial user state = %+v, want non-elevated missing", status)
	}
	if err := setupLinuxUserAcknowledgedNamespaceAt(path, uid); err != nil {
		t.Fatalf("setup user namespace: %v", err)
	}
	status := inspectLinuxUserAcknowledgedNamespaceAt(path, uid)
	if !status.Ready || status.Scope != ScopeUserAcknowledged {
		t.Fatalf("installed user status = %+v, want ready", status)
	}
	for _, name := range namespaceFixedFilenames() {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", name, got)
		}
	}
}

func TestLinuxUserAcknowledgedNamespaceRejectsPermissionDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-safety")
	uid := os.Geteuid()
	if err := setupLinuxUserAcknowledgedNamespaceAt(path, uid); err != nil {
		t.Fatalf("setup user namespace: %v", err)
	}
	if err := os.Chmod(filepath.Join(path, ownerLockFilename), 0o666); err != nil {
		t.Fatalf("tamper user lock mode: %v", err)
	}
	status := inspectLinuxUserAcknowledgedNamespaceAt(path, uid)
	if status.State != NamespaceUnsafe || status.Ready || status.RequiresElevation {
		t.Fatalf("tampered user status = %+v, want non-elevated unsafe", status)
	}
}

func TestLinuxUserAcknowledgedNamespaceRejectsPrecreatedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-safety")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("precreate user namespace: %v", err)
	}
	if err := setupLinuxUserAcknowledgedNamespaceAt(path, os.Geteuid()); !errors.Is(err, ErrNamespaceUnsafe) {
		t.Fatalf("setup precreated user namespace error = %v, want ErrNamespaceUnsafe", err)
	}
}

func TestLinuxUserAcknowledgedNamespaceRejectsNonPrivateParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o750); err != nil {
		t.Fatalf("make user parent group-readable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	path := filepath.Join(parent, "user-safety")
	if err := setupLinuxUserAcknowledgedNamespaceAt(path, os.Geteuid()); !errors.Is(err, ErrNamespaceUnsafe) {
		t.Fatalf("setup below non-private user parent error = %v, want ErrNamespaceUnsafe", err)
	}
}

func TestLinuxUserAcknowledgedNamespacePathIsCanonical(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(t.TempDir(), "spoofed-runtime"))
	path, err := UserAcknowledgedNamespacePath()
	if err != nil {
		t.Fatalf("UserAcknowledgedNamespacePath: %v", err)
	}
	want := filepath.Join("/run/user", strconv.Itoa(os.Geteuid()), "winkyou-safety-v2")
	if path != want {
		t.Fatalf("UserAcknowledgedNamespacePath = %q, want %q", path, want)
	}
}
