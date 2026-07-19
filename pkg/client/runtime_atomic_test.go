package client

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestWriteRuntimeStateRemainsReadableDuringReplacement(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	if err := WriteRuntimeState(stateKey, &RuntimeState{InstanceID: "initial", UpdatedAt: time.Now()}); err != nil {
		t.Fatalf("initial write: %v", err)
	}

	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			state := &RuntimeState{InstanceID: strconv.Itoa(i), PID: i + 1, UpdatedAt: time.Now()}
			if err := WriteRuntimeState(stateKey, state); err != nil {
				errCh <- err
				return
			}
		}
	}()

	var readErr error
	for {
		select {
		case err := <-errCh:
			if err != nil {
				readErr = errors.Join(readErr, err)
			}
		case <-done:
			if readErr != nil {
				t.Fatalf("runtime state concurrency: %v", readErr)
			}
			return
		default:
			state, err := LoadRuntimeState(stateKey)
			if err != nil {
				readErr = errors.Join(readErr, err)
				continue
			}
			if state.InstanceID == "" {
				readErr = errors.Join(readErr, errors.New("empty instance id observed during replacement"))
			}
		}
	}
}

func TestRemoveRuntimeStateIfInstance(t *testing.T) {
	stateKey := filepath.Join(t.TempDir(), "wink.yaml")
	if err := WriteRuntimeState(stateKey, &RuntimeState{InstanceID: "instance-a"}); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}
	if err := RemoveRuntimeStateIfInstance(stateKey, "instance-b"); err == nil {
		t.Fatal("remove replacement instance error = nil")
	}
	if state, err := LoadRuntimeState(stateKey); err != nil || state.InstanceID != "instance-a" {
		t.Fatalf("state after rejected removal = %+v, %v", state, err)
	}
	if err := RemoveRuntimeStateIfInstance(stateKey, "instance-a"); err != nil {
		t.Fatalf("remove matching instance: %v", err)
	}
	if _, err := LoadRuntimeState(stateKey); !errors.Is(err, ErrRuntimeStateNotFound) {
		t.Fatalf("state after matching removal error = %v, want not found", err)
	}
}
