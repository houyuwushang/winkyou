package store

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"winkyou/pkg/solver"
)

const (
	observationQueueCapacity = 128
	observationLineLimit     = 16 * 1024 // includes JSONL newline
)

var (
	ErrObservationStoreClosed  = errors.New("observation_store_closed")
	ErrObservationDrainPending = errors.New("observation_persistence_drain_pending")
	ErrObservationRemoveFailed = errors.New("observation_persistence_remove_failed")
)

// ObservationPersistenceStats distinguishes memory admission from the
// best-effort disk copy. Encoding errors and oversize/full drops never affect
// in-memory history or become an instruction to retry a connection.
type ObservationPersistenceStats struct {
	Buffered, Sealed, Drained, Active, RemoveFailed bool
	Pending                                         int
	Accepted, Written, EncodingErrors, WriteErrors  uint64
	DroppedFull, DroppedOversize, DroppedOnSeal     uint64
}

// NewBufferedObservationStore opts into ONE bounded writer for an ordinary
// JSONL file, not a safety ledger. remove must perform the owner's existing
// cleanup; it runs on that writer, only after seal and any active write.
// Empty paths remain memory-only. LoadFromFile is still an explicit startup
// operation; callers must complete it before releasing observation producers.
func NewBufferedObservationStore(path string, remove func() error) *ObservationStore {
	s := NewObservationStore(path)
	if path != "" {
		s.writer = newObservationWriter(s.appendJSONLine, remove)
	}
	return s
}

type observationWriter struct {
	mu         sync.Mutex
	state      ObservationPersistenceStats
	queue      [observationQueueCapacity][]byte
	head, size int
	wake       chan struct{}
	done       chan struct{}
	write      func([]byte) error
	remove     func() error
}

func newObservationWriter(write func([]byte) error, remove func() error) *observationWriter {
	w := &observationWriter{wake: make(chan struct{}, 1), done: make(chan struct{}), write: write, remove: remove}
	w.state.Buffered = true
	go w.run()
	return w
}

// Called with store.mu held. The queue owns the serialized bytes; no map or
// caller-owned slice crosses onto the worker. Capacity is not a backpressure
// wait: only the disk copy is lost when full, with an explicit counter.
func (w *observationWriter) enqueue(obs solver.Observation) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.Sealed {
		return
	}
	if w.size == observationQueueCapacity {
		w.state.DroppedFull++
		return
	}
	data, err := json.Marshal(obs)
	if err != nil {
		w.state.EncodingErrors++
		return
	}
	if len(data)+1 > observationLineLimit {
		w.state.DroppedOversize++
		return
	}
	w.queue[(w.head+w.size)%observationQueueCapacity] = append(data, '\n')
	w.size++
	w.state.Accepted++
	w.signal()
}

// Caller holds mu; wake is a notification, never a second work queue.
func (w *observationWriter) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *observationWriter) seal() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.Sealed {
		return
	}
	w.state.Sealed = true
	w.state.DroppedOnSeal += uint64(w.size)
	clear(w.queue[:])
	w.size = 0
	w.signal()
}

func (w *observationWriter) run() {
	defer close(w.done)
	for range w.wake {
		for {
			w.mu.Lock()
			if w.state.Sealed {
				w.mu.Unlock()
				var err error
				if w.remove != nil {
					err = w.remove()
				}
				w.mu.Lock()
				w.state.RemoveFailed = err != nil
				w.mu.Unlock()
				return
			}
			if w.size == 0 {
				w.mu.Unlock()
				break
			}
			data := w.queue[w.head]
			w.queue[w.head] = nil
			w.head = (w.head + 1) % observationQueueCapacity
			w.size--
			w.state.Active = true // active-write/seal linearization point
			w.mu.Unlock()
			err := w.write(data) // sole filesystem writer; NEVER under a mutex
			w.mu.Lock()
			w.state.Active = false
			if err != nil {
				w.state.WriteErrors++
			} else {
				w.state.Written++
			}
			w.mu.Unlock()
		}
	}
}

func (w *observationWriter) stats() ObservationPersistenceStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	state := w.state
	state.Pending = w.size
	select {
	case <-w.done:
		state.Drained = true
	default:
	}
	return state
}

func (w *observationWriter) wait(ctx context.Context) error {
	select {
	case <-w.done:
	case <-ctx.Done():
		select {
		case <-w.done:
		default:
			return ErrObservationDrainPending
		}
	}
	if w.stats().RemoveFailed {
		return ErrObservationRemoveFailed
	}
	return nil
}
