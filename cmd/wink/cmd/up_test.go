package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/processidentity"
)

func TestPrepareRuntimeStateForStartKeepsMatchingProcessEvenWhenTimestampIsOld(t *testing.T) {
	processStartID, err := processidentity.Current()
	if err != nil {
		t.Fatalf("current process identity: %v", err)
	}
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	state := &winkclient.RuntimeState{
		InstanceID:     "instance-a",
		PID:            os.Getpid(),
		ProcessStartID: processStartID,
		UpdatedAt:      time.Now().Add(-time.Hour),
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	err = prepareRuntimeStateForStart(stateKey)
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("prepare runtime state error = %v, want already running", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("matching runtime state was removed: %v", err)
	}
}

func TestPrepareRuntimeStateForStartRemovesReusedPIDState(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	state := &winkclient.RuntimeState{
		InstanceID:     "instance-a",
		PID:            os.Getpid(),
		ProcessStartID: "not-the-current-process",
		UpdatedAt:      time.Now(),
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	if err := prepareRuntimeStateForStart(stateKey); err != nil {
		t.Fatalf("prepare reused PID state: %v", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); !errors.Is(err, winkclient.ErrRuntimeStateNotFound) {
		t.Fatalf("runtime state after stale cleanup error = %v, want not found", err)
	}
}

func TestPrepareRuntimeStateForStartRefusesManagedStateWithoutProcessIdentity(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	state := &winkclient.RuntimeState{
		InstanceID:      "instance-a",
		PID:             os.Getpid(),
		UpdatedAt:       time.Now().Add(-time.Hour),
		ControlEndpoint: "127.0.0.1:32110",
	}
	if err := winkclient.WriteRuntimeState(stateKey, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	err := prepareRuntimeStateForStart(stateKey)
	if err == nil || !strings.Contains(err.Error(), "no process start identity") {
		t.Fatalf("prepare incomplete managed state error = %v", err)
	}
	if _, err := winkclient.LoadRuntimeState(stateKey); err != nil {
		t.Fatalf("incomplete managed state was removed: %v", err)
	}
}
