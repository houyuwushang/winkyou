package client

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitRuntimeFileRefs(t *testing.T, path string, want int) {
	t.Helper()
	key, err := runtimeFileLockKey(path)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		runtimeFileLocks.Lock()
		entry := runtimeFileLocks.entries[key]
		refs := 0
		if entry != nil {
			refs = entry.refs
		}
		runtimeFileLocks.Unlock()
		if refs == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("file waiter refs=%d want=%d", refs, want)
		default:
			runtime.Gosched()
		}
	}
}

func assertRuntimeFileUnreferenced(t *testing.T, path string) {
	t.Helper()
	key, err := runtimeFileLockKey(path)
	if err != nil {
		t.Fatal(err)
	}
	runtimeFileLocks.Lock()
	_, retained := runtimeFileLocks.entries[key]
	runtimeFileLocks.Unlock()
	if retained {
		t.Error("unused file-lock registry entry retained")
	}
}

func TestRuntimeFileLocksIsolatePathsAndSerializeSameFile(t *testing.T) {
	operations := []struct {
		name string
		run  func(string) error
	}{
		{"load", func(p string) error { _, err := LoadRuntimeState(p); return err }},
		{"write", func(p string) error { return WriteRuntimeState(p, &RuntimeState{InstanceID: "synthetic"}) }},
		{"remove", RemoveRuntimeState},
		{"remove_instance", func(p string) error { return RemoveRuntimeStateIfInstance(p, "synthetic") }},
	}
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "held.yaml")
			other := filepath.Join(t.TempDir(), "independent.yaml")
			if err := WriteRuntimeState(path, &RuntimeState{InstanceID: "synthetic"}); err != nil {
				t.Fatal(err)
			}
			release, err := lockRuntimeFile(path, false)
			if err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			done := make(chan struct{})
			result := make(chan error, 1)
			t.Cleanup(func() { once.Do(release); waitSnapshotSignal(t, done) })
			go func() { defer close(done); result <- op.run(path) }()
			waitRuntimeFileRefs(t, path, 2)
			select {
			case <-done:
				t.Fatal("same-file operation escaped its lock")
			default:
			}
			// All four real file APIs must finish on another path while the
			// original holder and waiter are both still present.
			independent := make(chan error, 1)
			independentDone := make(chan struct{})
			t.Cleanup(func() { once.Do(release); waitSnapshotSignal(t, independentDone) })
			go func() {
				defer close(independentDone)
				err := WriteRuntimeState(other, &RuntimeState{InstanceID: "synthetic"})
				_, readErr := LoadRuntimeState(other)
				err = errors.Join(err, readErr, RemoveRuntimeStateIfInstance(other, "synthetic"), RemoveRuntimeState(other))
				independent <- err
			}()
			select {
			case err := <-independent:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("unrelated file was blocked by global I/O lock")
			}
			once.Do(release)
			waitSnapshotSignal(t, done)
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			assertRuntimeFileUnreferenced(t, path)
			assertRuntimeFileUnreferenced(t, other)
		})
	}
}

func TestRuntimeFileLockCanonicalKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.yaml")
	want, err := runtimeFileLockKey(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{RuntimeStatePath(path), filepath.Dir(path) + string(filepath.Separator) + "." + string(filepath.Separator) + "snapshot.yaml"} {
		got, err := runtimeFileLockKey(alias)
		if err != nil || got != want {
			t.Fatalf("lexical alias split a file lock: equal=%t err=%v", got == want, err)
		}
	}
	if runtime.GOOS == "windows" {
		got, err := runtimeFileLockKey(strings.ToUpper(path))
		if err != nil || got != want {
			t.Fatal("Windows case alias split a file lock")
		}
	}
}

func TestRuntimeFileLockRegistryContentionEvictsWaiters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.yaml")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 128; j++ {
				unlock, err := lockRuntimeFile(path, j%2 == 0)
				if err != nil {
					t.Error(err)
					return
				}
				unlock()
			}
		}()
	}
	wg.Wait()
	assertRuntimeFileUnreferenced(t, path)
}
