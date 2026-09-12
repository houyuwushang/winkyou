package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/solver"
)

func awaitObservation(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("observation worker witness deadline")
	}
}

func drainObservation(t *testing.T, s *ObservationStore) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.Drain(ctx)
}

func TestBufferedObservationBlockedWritePreservesMemoryAndBounds(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	var active, maximum, writes, removes atomic.Int64
	s := NewObservationStore("")
	s.writer = newObservationWriter(func(data []byte) error {
		current := active.Add(1)
		defer active.Add(-1)
		maximum.Store(current)
		writes.Add(1)
		close(entered)
		<-release
		var obs solver.Observation
		if err := json.Unmarshal(data, &obs); err != nil || obs.Details["value"] != "owned" {
			t.Error("queued JSONL aliased input or invalid encoding")
		}
		return nil
	}, func() error {
		if active.Load() != 0 {
			t.Error("remove ran before write returned")
		}
		removes.Add(1)
		return nil
	})
	t.Cleanup(func() { unblock.Do(func() { close(release) }); s.Seal(); _ = drainObservation(t, s) })
	input := solver.Observation{Event: "synthetic", Details: map[string]string{"value": "owned"}}
	if err := s.Record(input); err != nil {
		t.Fatal(err)
	}
	awaitObservation(t, entered)
	input.Details["value"] = "changed"
	// No per-record goroutine: all admissions return while the writer is held.
	for i := 0; i < 4096; i++ {
		if err := s.Record(solver.Observation{Event: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	before := s.PersistenceStats()
	if len(s.List()) != 1000 || s.Recent(1)[0].Event != "4095" || before.Pending != 128 || before.Accepted != 129 || before.DroppedFull != 3968 || writes.Load() != 1 {
		t.Fatalf("memory/FIFO cap mismatch: %+v writes=%d", before, writes.Load())
	}
	s.Seal()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(s.Drain(ctx), ErrObservationDrainPending) || s.PersistenceStats().Drained {
		t.Fatal("active write falsely drained")
	}
	if !errors.Is(s.Record(input), ErrObservationStoreClosed) {
		t.Fatal("late record accepted")
	}
	unblock.Do(func() { close(release) })
	if err := drainObservation(t, s); err != nil {
		t.Fatal(err)
	}
	after := s.PersistenceStats()
	if !after.Drained || after.Active || after.Pending != 0 || after.Written != 1 || after.DroppedOnSeal != 128 || maximum.Load() != 1 || removes.Load() != 1 || active.Load() != 0 {
		t.Fatalf("drain mismatch: %+v", after)
	}
	t.Log("records=4097 memory=1000 pending_cap=128 full_drops=3968 seal_drops=128 writes=1 peak_writer=1 drained=true")
}

func TestBufferedObservationFIFOAndDeepCopies(t *testing.T) {
	written := make(chan solver.Observation, 4)
	s := NewObservationStore("")
	s.writer = newObservationWriter(func(data []byte) error {
		var obs solver.Observation
		if err := json.Unmarshal(data, &obs); err != nil {
			return err
		}
		written <- obs
		return nil
	}, nil)
	t.Cleanup(func() { s.Seal(); _ = drainObservation(t, s) })
	for i := 0; i < 4; i++ {
		obs := solver.Observation{Event: fmt.Sprint(i), Details: map[string]string{"value": "owned"}}
		if err := s.Record(obs); err != nil {
			t.Fatal(err)
		}
		obs.Details["value"] = "changed"
		s.List()[0].Details["value"] = "list changed"
		s.Recent(1)[0].Details["value"] = "recent changed"
	}
	for i := 0; i < 4; i++ {
		select {
		case obs := <-written:
			if obs.Event != fmt.Sprint(i) || obs.Details["value"] != "owned" {
				t.Fatalf("FIFO/ownership: %+v", obs)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("write deadline")
		}
	}
	s.Seal()
	if err := drainObservation(t, s); err != nil {
		t.Fatal(err)
	}
	if s.PersistenceStats().Written != 4 {
		t.Fatal("write count")
	}
}

func TestBufferedObservationErrorsAreCountedWithoutBlockingMemory(t *testing.T) {
	writes := make(chan struct{}, 1)
	s := NewObservationStore("")
	s.writer = newObservationWriter(func([]byte) error { writes <- struct{}{}; return errors.New("synthetic_write_error") }, func() error { return errors.New("synthetic_remove_error") })
	t.Cleanup(func() { s.Seal(); _ = drainObservation(t, s) })
	for _, obs := range []solver.Observation{
		{Event: "normal"},
		{Event: strings.Repeat("x", observationLineLimit)},
		{Event: "encoding", Timestamp: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		if err := s.Record(obs); err != nil {
			t.Fatal("disk failure reached producer", err)
		}
	}
	awaitObservation(t, writes)
	s.Seal()
	for i := 0; i < 2; i++ {
		if !errors.Is(drainObservation(t, s), ErrObservationRemoveFailed) {
			t.Fatal("sticky removal error lost")
		}
	}
	state := s.PersistenceStats()
	if len(s.List()) != 3 || state.DroppedOversize != 1 || state.EncodingErrors != 1 || state.WriteErrors != 1 || !state.Drained || !state.RemoveFailed {
		t.Fatalf("error accounting: %+v", state)
	}
	if len(writes) != 0 {
		t.Fatal("automatic write retry")
	}
}

func TestBufferedObservationLineLimit(t *testing.T) {
	base := solver.Observation{Timestamp: time.Unix(1, 0).UTC()}
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	// Existing empty Event is still encoded as a string. Adjust its payload to
	// cover exactly limit and limit+1, including the trailing newline.
	exact := base
	exact.Event = strings.Repeat("x", observationLineLimit-len(encoded)-1)
	over := exact
	over.Event += "x"
	written := make(chan int, 2)
	s := NewObservationStore("")
	s.writer = newObservationWriter(func(data []byte) error { written <- len(data); return nil }, nil)
	t.Cleanup(func() { s.Seal(); _ = drainObservation(t, s) })
	_ = s.Record(exact)
	_ = s.Record(over)
	select {
	case size := <-written:
		if size != observationLineLimit {
			t.Fatalf("line=%d", size)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("exact limit not admitted")
	}
	s.Seal()
	if err := drainObservation(t, s); err != nil {
		t.Fatal(err)
	}
	if s.PersistenceStats().DroppedOversize != 1 || s.PersistenceStats().Written != 1 {
		t.Fatalf("limit stats: %+v", s.PersistenceStats())
	}
}

func TestBufferedObservationConcurrentSealJoinsOneWriter(t *testing.T) {
	var writes, removed, late atomic.Int64
	s := NewObservationStore("")
	s.writer = newObservationWriter(func([]byte) error {
		if removed.Load() != 0 {
			late.Add(1)
		}
		writes.Add(1)
		return nil
	}, func() error { removed.Add(1); return nil })
	start := make(chan struct{})
	var producers sync.WaitGroup
	for i := 0; i < 32; i++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for j := 0; j < 128; j++ {
				err := s.Record(solver.Observation{Event: "synthetic"})
				if err != nil && !errors.Is(err, ErrObservationStoreClosed) {
					t.Error(err)
				}
			}
			s.Seal()
		}()
	}
	close(start)
	producers.Wait()
	if err := drainObservation(t, s); err != nil {
		t.Fatal(err)
	}
	if late.Load() != 0 || removed.Load() != 1 || s.PersistenceStats().Pending != 0 || s.PersistenceStats().Active {
		t.Fatal("late write or ownership residue")
	}
	if writes.Load()+int64(s.PersistenceStats().DroppedOnSeal) != int64(s.PersistenceStats().Accepted) {
		t.Fatal("admitted records lost from accounting")
	}
}

func TestBufferedObservationRealJSONLAndRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary.jsonl")
	s := NewBufferedObservationStore(path, func() error { return os.Remove(path) })
	t.Cleanup(func() { s.Seal(); _ = drainObservation(t, s) })
	if err := s.Record(solver.Observation{Event: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for s.PersistenceStats().Written != 1 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("file write not witnessed")
		}
	}
	reader := NewObservationStore(path)
	if err := reader.LoadFromFile(); err != nil {
		t.Fatal(err)
	}
	if len(reader.List()) != 1 || reader.List()[0].Event != "synthetic" {
		t.Fatal("synchronous reader compatibility")
	}
	s.Seal()
	if err := drainObservation(t, s); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file residue")
	}
	if !errors.Is(s.Record(solver.Observation{}), ErrObservationStoreClosed) {
		t.Fatal("closed file resurrected")
	}
}

func TestBufferedObservationEmptyPathHasNoWorker(t *testing.T) {
	s := NewBufferedObservationStore("", func() error { t.Error("memory-only store called file cleanup"); return nil })
	if s.writer != nil || s.PersistenceStats().Buffered {
		t.Fatal("memory-only spawned writer")
	}
	if err := s.Record(solver.Observation{}); err != nil {
		t.Fatal(err)
	}
	s.Seal()
	if err := drainObservation(t, s); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Record(solver.Observation{}), ErrObservationStoreClosed) {
		t.Fatal("sealed memory sink reopened")
	}
}
