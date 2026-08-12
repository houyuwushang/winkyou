package governor

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const ownerHelperEnv = "WINKYOU_GOVERNOR_OWNER_HELPER"

func TestPreparedNamespaceOwnerIsExclusiveAndReusable(t *testing.T) {
	namespace := t.TempDir()
	first, err := AcquirePreparedNamespace(namespace, ScopeMachine, "test-build")
	if err != nil {
		t.Fatalf("acquire first owner: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	second, err := AcquirePreparedNamespace(namespace, ScopeMachine, "other-build")
	if !errors.Is(err, ErrOwnerHeld) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("acquire second owner error = %v, want ErrOwnerHeld", err)
	}
	var held *OwnerHeldError
	if !errors.As(err, &held) {
		t.Fatalf("owner error type = %T, want *OwnerHeldError", err)
	}
	if held.Owner.PID != os.Getpid() {
		t.Fatalf("owner PID = %d, want %d", held.Owner.PID, os.Getpid())
	}
	if held.Owner.BuildVersion != "test-build" {
		t.Fatalf("owner build = %q, want test-build", held.Owner.BuildVersion)
	}
	firstInstance := held.Owner.InstanceID

	if err := first.Close(); err != nil {
		t.Fatalf("close first owner: %v", err)
	}
	third, err := AcquirePreparedNamespace(namespace, ScopeMachine, "third-build")
	if err != nil {
		t.Fatalf("reacquire owner: %v", err)
	}
	if third.Info().InstanceID == firstInstance {
		t.Fatal("reacquired owner reused stale instance id")
	}
	if err := third.Close(); err != nil {
		t.Fatalf("close reacquired owner: %v", err)
	}
	if _, err := os.Stat(filepath.Join(namespace, ownerLockFilename)); err != nil {
		t.Fatalf("retained owner file: %v", err)
	}
}

func TestPreparedNamespaceOwnerInspectionUsesOSLock(t *testing.T) {
	namespace := t.TempDir()
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "inspection-build")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	ownerInfo := owner.Info()

	held := inspectPreparedNamespaceOwner(namespace, ScopeMachine)
	if held.State != OwnerHeld || !held.Held || !held.MetadataAvailable || held.Owner == nil {
		t.Fatalf("held status = %+v", held)
	}
	if *held.Owner != ownerInfo {
		t.Fatalf("held owner = %+v, want %+v", *held.Owner, ownerInfo)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}

	metadataPath := filepath.Join(namespace, ownerMetadataFilename)
	metadataBefore, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read metadata before idle inspection: %v", err)
	}
	idle := inspectPreparedNamespaceOwner(namespace, ScopeMachine)
	if idle.State != OwnerIdle || idle.Held || idle.Owner != nil || idle.MetadataAvailable {
		t.Fatalf("idle status = %+v", idle)
	}
	metadataAfter, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read metadata after idle inspection: %v", err)
	}
	if string(metadataAfter) != string(metadataBefore) {
		t.Fatal("idle inspection rewrote owner metadata")
	}
}

func TestPreparedNamespaceOwnerInspectionKeepsHeldStateWhenMetadataIsCorrupt(t *testing.T) {
	namespace := t.TempDir()
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "inspection-build")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	if err := os.WriteFile(filepath.Join(namespace, ownerMetadataFilename), []byte("not-json"), 0o600); err != nil {
		t.Fatalf("corrupt owner metadata: %v", err)
	}

	status := inspectPreparedNamespaceOwner(namespace, ScopeMachine)
	if status.State != OwnerHeld || !status.Held {
		t.Fatalf("held status with corrupt metadata = %+v", status)
	}
	if status.MetadataAvailable || status.Owner != nil || status.Detail == "" {
		t.Fatalf("metadata status = %+v", status)
	}
}

func TestReadOwnerInfoRejectsUntrustedDiagnosticFieldsAndTrailingJSON(t *testing.T) {
	valid := OwnerInfo{
		PID:          42,
		InstanceID:   "0123456789abcdef0123456789abcdef",
		StartedAt:    time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC),
		BuildVersion: "test-build",
		Scope:        ScopeMachine,
	}
	validPayload, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal valid owner: %v", err)
	}
	path := filepath.Join(t.TempDir(), "owner.json")
	if err := os.WriteFile(path, validPayload, 0o600); err != nil {
		t.Fatalf("write valid owner: %v", err)
	}
	if got, err := readOwnerInfo(path); err != nil || got != valid {
		t.Fatalf("read valid owner = %+v/%v", got, err)
	}

	tests := []struct {
		name     string
		info     OwnerInfo
		trailing string
	}{
		{name: "zero pid", info: func() OwnerInfo { value := valid; value.PID = 0; return value }()},
		{name: "short instance", info: func() OwnerInfo { value := valid; value.InstanceID = "abcd"; return value }()},
		{name: "control build", info: func() OwnerInfo { value := valid; value.BuildVersion = "bad\nbuild"; return value }()},
		{name: "invalid scope", info: func() OwnerInfo { value := valid; value.Scope = Scope("forged"); return value }()},
		{name: "trailing object", info: valid, trailing: "{}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.info)
			if err != nil {
				t.Fatalf("marshal owner: %v", err)
			}
			payload = append(payload, test.trailing...)
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatalf("write owner: %v", err)
			}
			if _, err := readOwnerInfo(path); err == nil {
				t.Fatal("untrusted owner metadata was accepted")
			}
		})
	}
}

func TestPreparedNamespaceOwnerIsExclusiveAcrossProcesses(t *testing.T) {
	namespace := t.TempDir()
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "parent-build")
	if err != nil {
		t.Fatalf("acquire parent owner: %v", err)
	}
	t.Cleanup(func() { _ = owner.Close() })

	command := exec.Command(os.Args[0], "-test.run=^TestPreparedNamespaceOwnerHelper$")
	command.Env = append(
		os.Environ(),
		ownerHelperEnv+"=1",
		"WINKYOU_GOVERNOR_OWNER_NAMESPACE="+namespace,
		"WINKYOU_GOVERNOR_EXPECTED_PID="+strconv.Itoa(os.Getpid()),
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("owner helper failed: %v\n%s", err, output)
	}
}

func TestPreparedNamespaceOwnerHelper(t *testing.T) {
	if os.Getenv(ownerHelperEnv) != "1" {
		return
	}
	namespace := os.Getenv("WINKYOU_GOVERNOR_OWNER_NAMESPACE")
	expectedPID, err := strconv.Atoi(os.Getenv("WINKYOU_GOVERNOR_EXPECTED_PID"))
	if err != nil {
		t.Fatalf("parse expected pid: %v", err)
	}
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "child-build")
	if owner != nil {
		_ = owner.Close()
		t.Fatal("child unexpectedly acquired parent namespace")
	}
	if !errors.Is(err, ErrOwnerHeld) {
		t.Fatalf("child acquire error = %v, want ErrOwnerHeld", err)
	}
	var held *OwnerHeldError
	if !errors.As(err, &held) {
		t.Fatalf("child owner error type = %T, want *OwnerHeldError", err)
	}
	if held.Owner.PID != expectedPID {
		t.Fatalf("child observed owner pid = %d, want %d", held.Owner.PID, expectedPID)
	}
}

func TestPreparedNamespaceRejectsUnsafePaths(t *testing.T) {
	if _, err := AcquirePreparedNamespace("relative", ScopeMachine, "test"); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("relative namespace error = %v, want ErrInvalidNamespace", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := AcquirePreparedNamespace(missing, ScopeMachine, "test"); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("missing namespace error = %v, want ErrInvalidNamespace", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write namespace file: %v", err)
	}
	if _, err := AcquirePreparedNamespace(file, ScopeMachine, "test"); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("file namespace error = %v, want ErrInvalidNamespace", err)
	}
	if _, err := AcquirePreparedNamespace(t.TempDir(), Scope("directory"), "test"); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("invalid scope error = %v, want ErrInvalidNamespace", err)
	}
	if _, err := AcquirePreparedNamespace(t.TempDir(), ScopeMachine, "bad\nbuild"); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("control build version error = %v, want ErrInvalidNamespace", err)
	}
}

func TestPreparedNamespaceRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "namespace-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := AcquirePreparedNamespace(link, ScopeMachine, "test"); !errors.Is(err, ErrInvalidNamespace) {
		t.Fatalf("symlink namespace error = %v, want ErrInvalidNamespace", err)
	}
}
