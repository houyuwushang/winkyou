package client

import (
	"context"
	"errors"
	"sync"
	"time"
)

// This is a presentation-I/O wait, not a connection or governor deadline. A
// filesystem syscall cannot necessarily be interrupted. Pending drain is an
// error, never permission to remove a file early or start a replacement writer.
const runtimeSnapshotDrainTimeout = 2 * time.Second

var ErrRuntimeSnapshotDrainPending = errors.New("runtime_snapshot_drain_pending")

// runtimeSnapshotWriter owns one worker and one coalesced notification. It
// retains no queued snapshots: write captures the latest state on that worker.
// seal discards unstarted work; remove runs only AFTER the active write returns.
// Neither the worker mutex nor an engine mutex is held across filesystem I/O.
type runtimeSnapshotWriter struct {
	mu      sync.Mutex
	closing bool
	err     error
	wake    chan struct{}
	done    chan struct{}
	write   func()
	remove  func() error
}

func newRuntimeSnapshotWriter(write func(), remove func() error) *runtimeSnapshotWriter {
	w := &runtimeSnapshotWriter{
		wake: make(chan struct{}, 1), done: make(chan struct{}),
		write: write, remove: remove,
	}
	go w.run()
	return w
}

func (w *runtimeSnapshotWriter) request() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closing {
		return false
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return true
}

func (w *runtimeSnapshotWriter) seal() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closing {
		return
	}
	w.closing = true
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *runtimeSnapshotWriter) run() {
	defer close(w.done)
	for range w.wake {
		w.mu.Lock()
		closing := w.closing
		w.mu.Unlock()
		if closing {
			// A notification may have arrived between receiving wake and seal.
			// Producers are now closed, so discard it rather than write stale data.
			select {
			case <-w.wake:
			default:
			}
			err := w.remove()
			w.mu.Lock()
			w.err = err
			w.mu.Unlock()
			return
		}
		// Choosing work under mu is the write/close linearization point. If
		// seal follows it, this is the one in-flight write that must be joined.
		w.write()
	}
}

func (w *runtimeSnapshotWriter) wait(ctx context.Context) error {
	select {
	case <-w.done:
	case <-ctx.Done():
		// Prefer a witnessed completion over a simultaneous wait deadline.
		select {
		case <-w.done:
		default:
			return ErrRuntimeSnapshotDrainPending
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}
