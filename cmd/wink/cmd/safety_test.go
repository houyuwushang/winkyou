package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
)

type fakeSafetyManager struct {
	status        governor.SafetyTripStatus
	resetStatus   governor.SafetyTripStatus
	resetErr      error
	resetCalls    int
	resetSequence uint64
	resetNote     string
}

func (manager *fakeSafetyManager) Status() governor.SafetyTripStatus {
	return manager.status
}

func (manager *fakeSafetyManager) Reset(expectedSequence uint64, note string) (governor.SafetyTripStatus, error) {
	manager.resetCalls++
	manager.resetSequence = expectedSequence
	manager.resetNote = note
	return manager.resetStatus, manager.resetErr
}

func TestSafetyStatusClear(t *testing.T) {
	manager := &fakeSafetyManager{status: governor.SafetyTripStatus{
		State: governor.SafetyTripClear,
		Record: governor.SafetyTripRecord{
			SchemaVersion: 1,
			State:         governor.SafetyTripClear,
			UpdatedAt:     time.Date(2026, 8, 11, 1, 2, 3, 0, time.UTC),
		},
	}}
	cmd := newSafetyCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"status"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("safety status: %v", err)
	}
	if got := output.String(); !strings.Contains(got, "Safety trip:       clear") ||
		!strings.Contains(got, "No WinkYou runtime or network activity was started.") {
		t.Fatalf("unexpected output:\n%s", got)
	}
}

func TestSafetyStatusTrippedReturnsNonzeroAfterOutput(t *testing.T) {
	manager := &fakeSafetyManager{status: governor.SafetyTripStatus{
		State:            governor.SafetyTripTripped,
		BlocksActiveWork: true,
		Record: governor.SafetyTripRecord{
			State:    governor.SafetyTripTripped,
			Sequence: 7,
			Reason:   governor.SafetyTripHardLimit,
			Detail:   "packet budget exceeded",
		},
	}}
	cmd := newSafetyCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"status"})
	err := cmd.Execute()
	if !errors.Is(err, governor.ErrSafetyTripped) {
		t.Fatalf("safety status error = %v, want ErrSafetyTripped", err)
	}
	if got := output.String(); !strings.Contains(got, "Sequence:          7") ||
		!strings.Contains(got, "packet budget exceeded") {
		t.Fatalf("unexpected output:\n%s", got)
	}
}

func TestSafetyStatusJSON(t *testing.T) {
	want := governor.SafetyTripStatus{State: governor.SafetyTripClear}
	manager := &fakeSafetyManager{status: want}
	cmd := newSafetyCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"status", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("safety status --json: %v", err)
	}
	var got governor.SafetyTripStatus
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode status JSON: %v\n%s", err, output.String())
	}
	if got.State != want.State || got.BlocksActiveWork != want.BlocksActiveWork {
		t.Fatalf("JSON status = %+v, want %+v", got, want)
	}
}

func TestSafetyResetRequiresExplicitSequenceAndNote(t *testing.T) {
	manager := &fakeSafetyManager{}
	for _, args := range [][]string{
		{"reset", "--note", "reviewed"},
		{"reset", "--expected-sequence", "4"},
	} {
		cmd := newSafetyCmdWithManager(manager)
		cmd.SetOut(new(bytes.Buffer))
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs(args)
		if err := cmd.Execute(); !errors.Is(err, governor.ErrSafetyResetRejected) {
			t.Fatalf("safety %v error = %v, want ErrSafetyResetRejected", args, err)
		}
	}
	if manager.resetCalls != 0 {
		t.Fatalf("reset manager called %d times without complete acknowledgement", manager.resetCalls)
	}
}

func TestSafetyResetPassesObservedSequence(t *testing.T) {
	manager := &fakeSafetyManager{resetStatus: governor.SafetyTripStatus{
		State: governor.SafetyTripClear,
		Record: governor.SafetyTripRecord{
			State:    governor.SafetyTripClear,
			Sequence: 8,
		},
	}}
	cmd := newSafetyCmdWithManager(manager)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"reset", "--expected-sequence", "7", "--note", "operator reviewed packet budget"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("safety reset: %v", err)
	}
	if manager.resetCalls != 1 || manager.resetSequence != 7 || manager.resetNote != "operator reviewed packet budget" {
		t.Fatalf("reset call = count %d sequence %d note %q", manager.resetCalls, manager.resetSequence, manager.resetNote)
	}
	if !strings.Contains(output.String(), "Safety trip:       clear") {
		t.Fatalf("unexpected output:\n%s", output.String())
	}
}
