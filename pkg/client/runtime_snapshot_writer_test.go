package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/logger"
)

func waitSnapshotSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("snapshot worker witness timed out")
	}
}

func joinSnapshotWriter(t *testing.T, w *runtimeSnapshotWriter) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return w.wait(ctx)
}

func TestRuntimeSnapshotWriterCoalescesLatestAndJoins(t *testing.T) {
	entered, release, latest := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	var revision, calls, active, maximum, removed atomic.Int64
	values := make(chan int64, 4)
	w := newRuntimeSnapshotWriter(func() {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		call := calls.Add(1)
		value := revision.Load()
		if call == 1 {
			close(entered)
			<-release
		}
		values <- value
		if call == 2 {
			close(latest)
		}
	}, func() error { removed.Add(1); return nil })
	t.Cleanup(func() {
		unblock.Do(func() { close(release) })
		w.seal()
		if err := joinSnapshotWriter(t, w); err != nil {
			t.Error(err)
		}
	})
	if !w.request() {
		t.Fatal("initial request rejected")
	}
	waitSnapshotSignal(t, entered)
	for i := int64(1); i <= 4096; i++ {
		revision.Store(i)
		if !w.request() {
			t.Fatal("live request rejected")
		}
	}
	if len(w.wake) != 1 || cap(w.wake) != 1 || calls.Load() != 1 {
		t.Fatalf("unbounded work: queued=%d capacity=%d calls=%d", len(w.wake), cap(w.wake), calls.Load())
	}
	unblock.Do(func() { close(release) })
	waitSnapshotSignal(t, latest)
	w.seal()
	if err := joinSnapshotWriter(t, w); err != nil {
		t.Fatal(err)
	}
	if first, second := <-values, <-values; first != 0 || second != 4096 {
		t.Fatalf("snapshots=%d,%d, want initial then latest", first, second)
	}
	if calls.Load() != 2 || maximum.Load() != 1 || active.Load() != 0 || removed.Load() != 1 || len(w.wake) != 0 {
		t.Fatal("single-writer/coalescing/drain witness failed")
	}
	if w.request() {
		t.Fatal("closed writer accepted work")
	}
	t.Log("notifications=4097 writes=2 peak_writers=1 pending_cap=1 drained=true")
}

func TestRuntimeSnapshotSealDiscardsPendingAndRemovesAfterWrite(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	var calls atomic.Int64
	var mu sync.Mutex
	var order []string
	w := newRuntimeSnapshotWriter(func() {
		calls.Add(1)
		close(entered)
		<-release
		mu.Lock()
		order = append(order, "write")
		mu.Unlock()
	}, func() error {
		mu.Lock()
		order = append(order, "remove")
		mu.Unlock()
		return nil
	})
	t.Cleanup(func() { unblock.Do(func() { close(release) }); w.seal(); _ = joinSnapshotWriter(t, w) })
	w.request()
	waitSnapshotSignal(t, entered)
	w.request()
	w.seal()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.wait(ctx); !errors.Is(err, ErrRuntimeSnapshotDrainPending) {
		t.Fatalf("pending write was reported as drained: %v", err)
	}
	if w.request() {
		t.Fatal("sealed writer accepted a request")
	}
	unblock.Do(func() { close(release) })
	if err := joinSnapshotWriter(t, w); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "write" || order[1] != "remove" || calls.Load() != 1 || len(w.wake) != 0 {
		t.Fatalf("write/remove order or pending work: %v calls=%d pending=%d", order, calls.Load(), len(w.wake))
	}
}

func TestRuntimeSnapshotRequestsRacingClose(t *testing.T) {
	var writes, removed, late atomic.Int64
	w := newRuntimeSnapshotWriter(func() {
		if removed.Load() != 0 {
			late.Add(1)
		}
		writes.Add(1)
	}, func() error { removed.Add(1); return nil })
	var producers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for j := 0; j < 128; j++ {
				w.request()
			}
			w.seal()
		}()
	}
	close(start)
	producers.Wait()
	if err := joinSnapshotWriter(t, w); err != nil {
		t.Fatal(err)
	}
	w.seal()
	if w.request() || late.Load() != 0 || removed.Load() != 1 || len(w.wake) != 0 {
		t.Fatal("close race accepted late work, repeated removal or retained notifications")
	}
}

func TestRuntimeSnapshotRemovalErrorIsSticky(t *testing.T) {
	want := errors.New("synthetic_remove_failure")
	var removes atomic.Int64
	w := newRuntimeSnapshotWriter(func() { t.Error("closed unused writer ran a write") }, func() error { removes.Add(1); return want })
	w.seal()
	for i := 0; i < 2; i++ {
		if err := joinSnapshotWriter(t, w); !errors.Is(err, want) {
			t.Fatalf("removal error lost: %v", err)
		}
	}
	if removes.Load() != 1 {
		t.Fatal("wait retried removal")
	}
	e := &engine{cfg: config.Default(), log: logger.Nop(), stopping: true, snapshotWriter: w}
	if err := e.Stop(); !errors.Is(err, want) {
		t.Fatalf("engine hid removal failure: %v", err)
	}
	if err := e.Start(context.Background()); !errors.Is(err, ErrRuntimeSnapshotDrainPending) {
		t.Fatalf("engine restarted after failed removal: %v", err)
	}
}

func TestRuntimeSnapshotEngineDrainTimeoutBlocksRestart(t *testing.T) {
	e := &engine{cfg: config.Default(), log: logger.Nop(), started: true, statePath: filepath.Join(t.TempDir(), "snapshot.yaml"), peers: make(map[string]*PeerStatus)}
	if err := WriteRuntimeState(e.statePath, &RuntimeState{InstanceID: "old"}); err != nil {
		t.Fatal(err)
	}
	release, err := lockRuntimeFile(e.statePath, false)
	if err != nil {
		t.Fatal(err)
	}
	var unblock sync.Once
	t.Cleanup(func() {
		unblock.Do(release)
		if err := e.Stop(); err != nil {
			t.Error(err)
		}
	})
	e.persistState()
	waitRuntimeFileRefs(t, e.statePath, 2) // worker has entered the actual file write
	e.mu.RLock()
	original := e.snapshotWriter
	e.mu.RUnlock()
	if err := e.Stop(); !errors.Is(err, ErrRuntimeSnapshotDrainPending) {
		t.Fatalf("in-flight I/O must report pending drain: %v", err)
	}
	if e.Status().State != EngineStateStopping {
		t.Fatal("pending drain falsely reported stopped")
	}
	if err := e.Start(context.Background()); !errors.Is(err, ErrRuntimeSnapshotDrainPending) {
		t.Fatalf("pending worker allowed restart: %v", err)
	}
	e.persistState()
	e.mu.RLock()
	same := e.snapshotWriter == original
	e.mu.RUnlock()
	if !same || original.request() {
		t.Fatal("pending drain replaced or reopened worker")
	}
	if _, err := os.Stat(RuntimeStatePath(e.statePath)); err != nil {
		t.Fatal("snapshot removed before in-flight write returned")
	}
	unblock.Do(release)
	if err := joinSnapshotWriter(t, original); err != nil {
		t.Fatal(err)
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntimeState(e.statePath); !errors.Is(err, ErrRuntimeStateNotFound) {
		t.Fatalf("drained snapshot resurrected: %v", err)
	}
	e.mu.RLock()
	cleared := e.snapshotWriter == nil && !e.stopping
	e.mu.RUnlock()
	if !cleared || e.Status().State != EngineStateStopped {
		t.Fatal("completed drain was not released")
	}
	assertRuntimeFileUnreferenced(t, e.statePath)
	t.Log("pending_error=true replacement_workers=0 write_before_remove=true joined=true file_residue=0")
}

func TestRuntimeSnapshotStartupFailureJoinsWriter(t *testing.T) {
	cfg := config.Default()
	cfg.Coordinator.URL = "" // fails before creating any network resources
	e := &engine{cfg: cfg, log: logger.Nop(), statePath: filepath.Join(t.TempDir(), "snapshot.yaml"), peers: make(map[string]*PeerStatus)}
	if err := e.Start(context.Background()); err == nil {
		t.Fatal("invalid config accepted")
	}
	if e.snapshotWriter != nil || e.stopping || e.started {
		t.Fatal("startup failure retained writer lifecycle")
	}
	if _, err := LoadRuntimeState(e.statePath); !errors.Is(err, ErrRuntimeStateNotFound) {
		t.Fatalf("startup failure snapshot residue: %v", err)
	}
	assertRuntimeFileUnreferenced(t, e.statePath)
}

func TestRuntimeSnapshotReentrantStopReportsPendingWithoutDeadlock(t *testing.T) {
	e := &engine{cfg: config.Default(), log: logger.Nop(), started: true, statePath: filepath.Join(t.TempDir(), "snapshot.yaml"), peers: make(map[string]*PeerStatus)}
	var calls atomic.Int64
	e.OnStatusChange(func(_ *EngineStatus) {
		calls.Add(1)
		if err := e.Stop(); !errors.Is(err, ErrRuntimeSnapshotDrainPending) {
			t.Errorf("recursive Stop must report the active lifecycle owner, got %v", err)
		}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := e.Stop(); err != nil {
			t.Error(err)
		}
	}()
	waitSnapshotSignal(t, done)
	if calls.Load() != 2 || e.snapshotWriter != nil || e.stopping {
		t.Fatal("recursive Stop lost status callbacks or failed to drain")
	}
	assertRuntimeFileUnreferenced(t, e.statePath)
}

type snapshotErrorLogger struct {
	logger.Logger
	errors chan error
}

func (l snapshotErrorLogger) Warn(_ string, fields ...logger.Field) {
	for _, field := range fields {
		if field.Key == "error" {
			if err, ok := field.Value.(error); ok {
				l.errors <- err
			}
		}
	}
}

func TestRuntimeSnapshotWriteErrorRemainsObservable(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := snapshotErrorLogger{Logger: logger.Nop(), errors: make(chan error, 1)}
	e := &engine{cfg: config.Default(), log: log, started: true, statePath: filepath.Join(parent, "snapshot.yaml"), peers: make(map[string]*PeerStatus)}
	t.Cleanup(func() {
		_ = e.Stop()
		e.mu.RLock()
		w := e.snapshotWriter
		e.mu.RUnlock()
		if w != nil {
			waitSnapshotSignal(t, w.done)
		}
	})
	e.persistState()
	select {
	case err := <-log.errors:
		if err == nil {
			t.Fatal("write failure lost its error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write failure was not observable")
	}
	// The file API itself determines whether removal of an impossible child
	// path is absent or an error on this OS. In either case the worker must join.
	_ = e.Stop()
	e.mu.RLock()
	w := e.snapshotWriter
	e.mu.RUnlock()
	if w != nil {
		waitSnapshotSignal(t, w.done)
	}
	assertRuntimeFileUnreferenced(t, e.statePath)
}
