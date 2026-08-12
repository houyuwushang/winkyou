package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"winkyou/internal/governor"
)

type fakeMachineScopeManager struct {
	inspectStatus governor.NamespaceStatus
	setupStatus   governor.NamespaceStatus
	setupErr      error
	inspectCalls  int
	setupCalls    int
}

func (manager *fakeMachineScopeManager) Inspect() governor.NamespaceStatus {
	manager.inspectCalls++
	return manager.inspectStatus
}

func (manager *fakeMachineScopeManager) Setup() (governor.NamespaceStatus, error) {
	manager.setupCalls++
	return manager.setupStatus, manager.setupErr
}

func TestSetupMachineScopeCreatesWithoutStartingRuntime(t *testing.T) {
	manager := &fakeMachineScopeManager{
		setupStatus: governor.NamespaceStatus{
			Scope:  governor.ScopeMachine,
			Path:   `C:\ProgramData\WinkYou-SafetyV2`,
			State:  governor.NamespaceReady,
			Ready:  true,
			Detail: "ready",
		},
	}
	cmd := newSetupMachineScopeCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup-machine-scope: %v", err)
	}
	if manager.setupCalls != 1 || manager.inspectCalls != 0 {
		t.Fatalf("calls = setup %d, inspect %d; want 1, 0", manager.setupCalls, manager.inspectCalls)
	}
	if got := output.String(); !strings.Contains(got, "Machine scope: ready") ||
		!strings.Contains(got, "No WinkYou runtime or network activity was started.") {
		t.Fatalf("unexpected output:\n%s", got)
	}
}

func TestSetupMachineScopeCheckIsReadOnlyAndFailsClosed(t *testing.T) {
	manager := &fakeMachineScopeManager{
		inspectStatus: governor.NamespaceStatus{
			Scope:             governor.ScopeMachine,
			Path:              "/var/lib/winkyou-safety-v2",
			State:             governor.NamespaceMissing,
			RequiresElevation: true,
			Detail:            "not installed",
		},
	}
	cmd := newSetupMachineScopeCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"--check"})

	err := cmd.Execute()
	if !errors.Is(err, governor.ErrNamespaceNotReady) {
		t.Fatalf("check error = %v, want ErrNamespaceNotReady", err)
	}
	if manager.inspectCalls != 1 || manager.setupCalls != 0 {
		t.Fatalf("calls = inspect %d, setup %d; want 1, 0", manager.inspectCalls, manager.setupCalls)
	}
	if got := output.String(); !strings.Contains(got, "Machine scope: missing") ||
		!strings.Contains(got, "elevated terminal") {
		t.Fatalf("unexpected output:\n%s", got)
	}
}

func TestSetupMachineScopeJSON(t *testing.T) {
	want := governor.NamespaceStatus{
		Scope:  governor.ScopeMachine,
		Path:   "/var/lib/winkyou-safety-v2",
		State:  governor.NamespaceReady,
		Ready:  true,
		Detail: "ready",
	}
	manager := &fakeMachineScopeManager{inspectStatus: want}
	cmd := newSetupMachineScopeCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"--check", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("setup-machine-scope --check --json: %v", err)
	}
	var got governor.NamespaceStatus
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, output.String())
	}
	if got != want {
		t.Fatalf("JSON status = %+v, want %+v", got, want)
	}
}

func TestSetupMachineScopeReportsSetupError(t *testing.T) {
	manager := &fakeMachineScopeManager{
		setupStatus: governor.NamespaceStatus{
			Scope:             governor.ScopeMachine,
			Path:              `C:\ProgramData\WinkYou-SafetyV2`,
			State:             governor.NamespaceMissing,
			RequiresElevation: true,
			Detail:            "not installed",
		},
		setupErr: governor.ErrElevationRequired,
	}
	cmd := newSetupMachineScopeCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)

	err := cmd.Execute()
	if !errors.Is(err, governor.ErrElevationRequired) {
		t.Fatalf("setup error = %v, want ErrElevationRequired", err)
	}
	if !strings.Contains(output.String(), "Machine scope: missing") {
		t.Fatalf("missing status output:\n%s", output.String())
	}
}
