package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"winkyou/pkg/solver"
	solverstore "winkyou/pkg/solver/store"
)

func TestBufferedObservationDiskErrorDoesNotStopEnvelope(t *testing.T) {
	// A regular file cannot be a parent directory: deterministic local write
	// failure without global hooks, permissions changes or network resources.
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	sink := solverstore.NewBufferedObservationStore(filepath.Join(parent, "ordinary.jsonl"), nil)
	t.Cleanup(func() {
		sink.Seal()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := sink.Drain(ctx); err != nil {
			t.Error(err)
		}
	})
	sender := &diagnosticObservationSender{}
	cfg := Config{SessionID: "synthetic-session", LocalNodeID: "synthetic-local", PeerID: "synthetic-peer", ObservationSink: sink, ObservationHistory: sink, Sender: sender}
	s := &Session{cfg: cfg, io: &solverIO{cfg: cfg}}
	s.io.session = s
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.reportObservation(ctx, solver.Observation{Event: "candidate_started"}); err != nil {
		t.Fatal("disk error stopped envelope", err)
	}
	if sender.calls.Load() != 1 || len(s.Observations()) != 1 || len(sink.Recent(1)) != 1 {
		t.Fatal("memory/send contract changed")
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for sink.PersistenceStats().WriteErrors != 1 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("write error missing")
		}
	}
	if err := s.reportObservation(ctx, solver.Observation{Event: "candidate_succeeded"}); err != nil || sender.calls.Load() != 2 {
		t.Fatal("sticky write failure became network failure")
	}
	t.Log("memory=2 envelopes=2 disk_error_observed=true network_packets=0")
}
