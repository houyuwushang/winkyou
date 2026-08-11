package governor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestSafetyTripStore(t *testing.T) (*safetyTripStore, string) {
	t.Helper()
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	store := newSafetyTripStore(namespace)
	store.now = func() time.Time {
		return time.Date(2026, 8, 11, 1, 2, 3, 0, time.UTC)
	}
	return store, namespace
}

func TestSafetyTripStorePersistsFirstReasonAndSequence(t *testing.T) {
	store, _ := newTestSafetyTripStore(t)
	initial := store.status()
	if initial.State != SafetyTripClear || initial.BlocksActiveWork || initial.Record.Sequence != 0 {
		t.Fatalf("initial status = %+v, want clear sequence zero", initial)
	}

	event := SafetyTripEvent{
		Reason:       SafetyTripResourceExhausted,
		Detail:       "socket allocation failed",
		PeerID:       "peer-a",
		AttemptID:    "attempt-a",
		BuildVersion: "test-build",
	}
	tripped, err := store.trip(event)
	if err != nil {
		t.Fatalf("trip: %v", err)
	}
	if tripped.State != SafetyTripTripped || !tripped.BlocksActiveWork || tripped.Record.Sequence != 1 {
		t.Fatalf("tripped status = %+v", tripped)
	}
	if tripped.Record.Reason != event.Reason || tripped.Record.Detail != event.Detail {
		t.Fatalf("tripped record = %+v, want first event %+v", tripped.Record, event)
	}

	second, err := store.trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "later reason"})
	if err != nil {
		t.Fatalf("idempotent trip: %v", err)
	}
	if second.Record != tripped.Record {
		t.Fatalf("second trip replaced first record: got %+v want %+v", second.Record, tripped.Record)
	}
}

func TestGovernorTripStopsAttemptsAndSurvivesRestart(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "first-build")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	governor, err := New(owner, ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new governor: %v", err)
	}

	var attempts []*AttemptLease
	var peers []*PeerLease
	for index := 0; index < 2; index++ {
		peer, err := governor.AcquirePeer(fmt.Sprintf("peer-%d", index))
		if err != nil {
			t.Fatalf("acquire peer %d: %v", index, err)
		}
		attempt, err := peer.AcquireAttempt(context.Background(), testAttempt(fmt.Sprintf("attempt-%d", index)))
		if err != nil {
			t.Fatalf("acquire attempt %d: %v", index, err)
		}
		peers = append(peers, peer)
		attempts = append(attempts, attempt)
	}

	status, err := governor.Trip(SafetyTripEvent{
		Reason:       SafetyTripWriteFailures,
		Detail:       "three consecutive writes failed",
		PeerID:       "peer-0",
		AttemptID:    "attempt-0",
		BuildVersion: "first-build",
	})
	if err != nil {
		t.Fatalf("trip governor: %v", err)
	}
	if status.State != SafetyTripTripped || status.Record.Sequence != 1 {
		t.Fatalf("trip status = %+v", status)
	}
	for index, attempt := range attempts {
		select {
		case <-attempt.Done():
		default:
			t.Fatalf("attempt %d was not stopped by trip", index)
		}
	}
	if _, err := peers[0].AcquireAttempt(context.Background(), testAttempt("after-trip")); !errors.Is(err, ErrSafetyTripped) {
		t.Fatalf("attempt after trip error = %v, want ErrSafetyTripped", err)
	}
	if _, err := governor.AcquirePeer("after-trip"); !errors.Is(err, ErrSafetyTripped) {
		t.Fatalf("peer after trip error = %v, want ErrSafetyTripped", err)
	}
	snapshot := governor.Snapshot()
	if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.Reserved != (Resources{}) {
		t.Fatalf("snapshot after trip = %+v, want no active reservations", snapshot)
	}
	if err := governor.Close(); err != nil {
		t.Fatalf("close tripped governor: %v", err)
	}

	restartedOwner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "second-build")
	if err != nil {
		t.Fatalf("reacquire owner after trip: %v", err)
	}
	defer func() { _ = restartedOwner.Close() }()
	if _, err := New(restartedOwner, ProfilePhase1Machine, nil); !errors.Is(err, ErrSafetyTripped) {
		t.Fatalf("new governor after restart error = %v, want ErrSafetyTripped", err)
	}
}

func TestSafetyTripCorruptionFailsClosed(t *testing.T) {
	_, namespace := newTestSafetyTripStore(t)
	path := filepath.Join(namespace, safetyTripFilename)
	if err := os.WriteFile(path, []byte("C{\"record\":"), 0o600); err != nil {
		t.Fatalf("corrupt trip file: %v", err)
	}

	status := newSafetyTripStore(namespace).status()
	if status.State != SafetyTripIndeterminate || !status.BlocksActiveWork {
		t.Fatalf("corrupt status = %+v, want indeterminate and blocking", status)
	}
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "corrupt-build")
	if err != nil {
		t.Fatalf("acquire owner for corrupt state: %v", err)
	}
	defer func() { _ = owner.Close() }()
	_, err = New(owner, ProfilePhase1Machine, nil)
	if !errors.Is(err, ErrSafetyTripped) || !errors.Is(err, ErrSafetyStateCorrupt) {
		t.Fatalf("new governor corrupt state error = %v, want trip and corrupt errors", err)
	}
}

func TestSafetyTripChecksumMismatchFailsClosed(t *testing.T) {
	_, namespace := newTestSafetyTripStore(t)
	path := filepath.Join(namespace, safetyTripFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trip file: %v", err)
	}
	for index := len(data) - 1; index >= 0; index-- {
		if data[index] >= '0' && data[index] <= '9' {
			data[index] = 'a'
			break
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("tamper checksum: %v", err)
	}
	status := newSafetyTripStore(namespace).status()
	if status.State != SafetyTripIndeterminate || !status.BlocksActiveWork {
		t.Fatalf("checksum mismatch status = %+v, want blocking indeterminate", status)
	}
}

func TestEveryTruncatedTrippedRecordBlocksActiveWork(t *testing.T) {
	store, namespace := newTestSafetyTripStore(t)
	if _, err := store.trip(SafetyTripEvent{Reason: SafetyTripResourceExhausted}); err != nil {
		t.Fatalf("trip: %v", err)
	}
	path := filepath.Join(namespace, safetyTripFilename)
	complete, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read complete trip: %v", err)
	}
	for length := 0; length < len(complete); length++ {
		if err := os.WriteFile(path, complete[:length], 0o600); err != nil {
			t.Fatalf("write truncated length %d: %v", length, err)
		}
		status := newSafetyTripStore(namespace).status()
		if !status.BlocksActiveWork {
			t.Fatalf("truncated length %d did not block: %+v", length, status)
		}
	}
}

func TestSafetyTripLatchFailsClosedWhenDetailWriteIsInterrupted(t *testing.T) {
	store, namespace := newTestSafetyTripStore(t)
	injected := errors.New("injected interruption")
	callbackCalled := false
	store.hooks.afterTripLatchSync = func() error {
		if !callbackCalled {
			t.Error("after-latch callback was not called before diagnostic write")
		}
		return injected
	}

	status, err := store.tripThen(
		SafetyTripEvent{Reason: SafetyTripCancellation},
		func() { callbackCalled = true },
	)
	if !errors.Is(err, injected) {
		t.Fatalf("trip interruption error = %v, want injected error", err)
	}
	if status.State != SafetyTripIndeterminate || !status.BlocksActiveWork {
		t.Fatalf("interrupted status = %+v, want blocking indeterminate", status)
	}
	reloaded := newSafetyTripStore(namespace).status()
	if reloaded.State != SafetyTripIndeterminate || !reloaded.BlocksActiveWork {
		t.Fatalf("reloaded interrupted status = %+v, want blocking indeterminate", reloaded)
	}
}

func TestSafetyTripResetIsSequenceBound(t *testing.T) {
	store, _ := newTestSafetyTripStore(t)
	tripped, err := store.trip(SafetyTripEvent{Reason: SafetyTripOperator, Detail: "operator stop"})
	if err != nil {
		t.Fatalf("trip: %v", err)
	}
	if _, err := store.reset(tripped.Record.Sequence+1, "reviewed wrong sequence", "reset-build"); !errors.Is(err, ErrSafetyResetRejected) {
		t.Fatalf("wrong sequence reset error = %v, want ErrSafetyResetRejected", err)
	}
	if status := store.status(); status.State != SafetyTripTripped {
		t.Fatalf("wrong sequence cleared trip: %+v", status)
	}

	cleared, err := store.reset(tripped.Record.Sequence, "operator reviewed the first trip", "reset-build")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if cleared.State != SafetyTripClear || cleared.BlocksActiveWork || cleared.Record.Sequence != 2 {
		t.Fatalf("cleared status = %+v", cleared)
	}
	if cleared.Record.ResetNote == "" || cleared.Record.BuildVersion != "reset-build" {
		t.Fatalf("clear diagnostics = %+v", cleared.Record)
	}

	retripped, err := store.trip(SafetyTripEvent{Reason: SafetyTripHardLimit})
	if err != nil {
		t.Fatalf("trip after reset: %v", err)
	}
	if retripped.Record.Sequence != 3 {
		t.Fatalf("sequence after reset and retrip = %d, want 3", retripped.Record.Sequence)
	}
}

func TestSafetyTripResetInterruptionKeepsLatchBlocking(t *testing.T) {
	store, namespace := newTestSafetyTripStore(t)
	tripped, err := store.trip(SafetyTripEvent{Reason: SafetyTripStaleGeneration})
	if err != nil {
		t.Fatalf("trip: %v", err)
	}
	injected := errors.New("injected reset interruption")
	store.hooks.beforeResetClear = func() error { return injected }
	status, err := store.reset(tripped.Record.Sequence, "operator reviewed stale generation", "reset-build")
	if !errors.Is(err, injected) {
		t.Fatalf("reset interruption error = %v, want injected error", err)
	}
	if status.State != SafetyTripIndeterminate || !status.BlocksActiveWork {
		t.Fatalf("interrupted reset status = %+v, want blocking indeterminate", status)
	}
	if reloaded := newSafetyTripStore(namespace).status(); reloaded.State != SafetyTripIndeterminate || !reloaded.BlocksActiveWork {
		t.Fatalf("reloaded reset interruption = %+v, want blocking indeterminate", reloaded)
	}
}

func TestSafetyTripConcurrentTriggersRetainOneRecord(t *testing.T) {
	store, _ := newTestSafetyTripStore(t)
	const contenders = 16
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			status, err := store.trip(SafetyTripEvent{
				Reason: SafetyTripHardLimit,
				Detail: fmt.Sprintf("contender-%d", index),
			})
			if err != nil {
				t.Errorf("trip contender %d: %v", index, err)
				return
			}
			if status.Record.Sequence != 1 {
				t.Errorf("trip contender %d sequence = %d, want 1", index, status.Record.Sequence)
			}
		}(index)
	}
	close(start)
	wait.Wait()
	status := store.status()
	if status.State != SafetyTripTripped || status.Record.Sequence != 1 {
		t.Fatalf("final concurrent status = %+v", status)
	}
}

func TestSafetyTripRejectsUnknownReasonWithoutChangingState(t *testing.T) {
	store, _ := newTestSafetyTripStore(t)
	if _, err := store.trip(SafetyTripEvent{Reason: "future-unreviewed"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown reason error = %v, want ErrInvalidRequest", err)
	}
	if status := store.status(); status.State != SafetyTripClear || status.BlocksActiveWork {
		t.Fatalf("unknown reason changed state: %+v", status)
	}
}

func TestSafetyTripRejectsControlCharacters(t *testing.T) {
	store, _ := newTestSafetyTripStore(t)
	if _, err := store.trip(SafetyTripEvent{
		Reason: SafetyTripHardLimit,
		Detail: "line one\nline two",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("control detail error = %v, want ErrInvalidRequest", err)
	}
	if _, err := store.reset(1, "operator\nreviewed", "test-build"); !errors.Is(err, ErrSafetyResetRejected) {
		t.Fatalf("control reset note error = %v, want ErrSafetyResetRejected", err)
	}
	if status := store.status(); status.State != SafetyTripClear {
		t.Fatalf("invalid diagnostics changed state: %+v", status)
	}
}

func TestSafetyTripUnavailableJSONOmitsZeroRecord(t *testing.T) {
	payload, err := json.Marshal(SafetyTripStatus{
		State:            SafetyTripUnavailable,
		BlocksActiveWork: true,
		Detail:           "machine namespace is missing",
	})
	if err != nil {
		t.Fatalf("marshal unavailable status: %v", err)
	}
	if bytes.Contains(payload, []byte(`"record"`)) {
		t.Fatalf("unavailable JSON contains zero record: %s", payload)
	}
}
