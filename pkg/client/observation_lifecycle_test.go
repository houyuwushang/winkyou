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
	"winkyou/pkg/solver"
	solverstore "winkyou/pkg/solver/store"
)

func TestObservationEngineStopRetainsUndrainedOwner(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	var removes atomic.Int64
	e := &engine{cfg: config.Default(), log: logger.Nop(), started: true, peers: make(map[string]*PeerStatus)}
	s := solverstore.NewBufferedObservationStore(filepath.Join(t.TempDir(), "ordinary.jsonl"), func() error {
		removes.Add(1)
		close(entered)
		<-release
		return nil
	})
	e.observationStore = s
	t.Cleanup(func() {
		unblock.Do(func() { close(release) })
		if err := e.Stop(); err != nil {
			t.Error(err)
		}
	})
	if err := e.Stop(); !errors.Is(err, solverstore.ErrObservationDrainPending) {
		t.Fatalf("unwitnessed drain=%v", err)
	}
	waitSnapshotSignal(t, entered)
	if e.observationStore != s || !e.stopping || e.Status().State != EngineStateStopping {
		t.Fatal("lost undrained owner")
	}
	if err := e.Start(context.Background()); !errors.Is(err, solverstore.ErrObservationDrainPending) {
		t.Fatal("restart admitted", err)
	}
	if err := s.Record(solver.Observation{}); !errors.Is(err, solverstore.ErrObservationStoreClosed) {
		t.Fatal("sealed producer admitted")
	}
	unblock.Do(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if e.observationStore != nil || e.stopping || e.Status().State != EngineStateStopped || removes.Load() != 1 {
		t.Fatal("drain owner not released exactly once")
	}
	t.Log("observation_stop=pending restart=blocked late_record=refused removal=1 joined=true")
}

func TestObservationEngineRemovalFailureBlocksRestart(t *testing.T) {
	var removes atomic.Int64
	s := solverstore.NewBufferedObservationStore(filepath.Join(t.TempDir(), "ordinary.jsonl"), func() error { removes.Add(1); return errors.New("synthetic_remove") })
	e := &engine{cfg: config.Default(), log: logger.Nop(), started: true, observationStore: s, peers: make(map[string]*PeerStatus)}
	for i := 0; i < 2; i++ {
		if err := e.Stop(); !errors.Is(err, solverstore.ErrObservationRemoveFailed) {
			t.Fatal("removal failure hidden", err)
		}
	}
	if err := e.Start(context.Background()); !errors.Is(err, solverstore.ErrObservationDrainPending) {
		t.Fatal("failed removal allowed restart", err)
	}
	if removes.Load() != 1 || !s.PersistenceStats().Drained || e.observationStore != s {
		t.Fatal("retried or lost failed owner")
	}
}

func TestObservationEngineUsesBufferedSinkAndRemovesFile(t *testing.T) {
	e := &engine{cfg: config.Default(), log: logger.Nop(), started: true, statePath: filepath.Join(t.TempDir(), "state.yaml"), peers: make(map[string]*PeerStatus)}
	e.initObservationStore()
	s := e.observationStore
	t.Cleanup(func() {
		if err := e.Stop(); err != nil {
			t.Error(err)
		}
	})
	if !s.PersistenceStats().Buffered {
		t.Fatal("production sink is synchronous")
	}
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
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.observationStorePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ordinary file residue")
	}
	if e.observationStore != nil || e.snapshotWriter != nil || e.stopping || !s.PersistenceStats().Drained {
		t.Fatal("owner residue")
	}
}

func TestObservationStartupFailureSealsExistingStore(t *testing.T) {
	cfg := config.Default()
	cfg.Coordinator.URL = "" // no socket or network resource
	e := &engine{cfg: cfg, log: logger.Nop(), statePath: filepath.Join(t.TempDir(), "state.yaml"), peers: make(map[string]*PeerStatus)}
	e.initObservationStore()
	s := e.observationStore
	if err := e.Start(context.Background()); err == nil {
		t.Fatal("invalid startup accepted")
	}
	if !s.PersistenceStats().Drained || !s.PersistenceStats().Sealed || e.observationStore != nil || e.stopping {
		t.Fatal("failed startup retained producer")
	}
}
