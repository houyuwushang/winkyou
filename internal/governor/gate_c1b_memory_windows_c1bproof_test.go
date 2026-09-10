//go:build c1bproof

package governor_test

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecorchestrator"
)

// Read-only observations of the real memory composition, not a clock override.
// The result is printed even on the first RED; no sample is retried or discarded.
type gateC1bMemoryTimingWitness struct {
	mu        sync.Mutex
	start     [2]time.Time
	candidate [2]time.Time
	winner    [2]time.Time
	ready     [2]time.Time
	packets   [2]int
	success   [2]bool
}

func (w *gateC1bMemoryTimingWitness) stage(side int, stage string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	switch stage {
	case gateb.StagePreflight:
		w.start[side] = now
	case gateb.StageCandidates:
		w.candidate[side] = now
	case gateb.StageWinner:
		w.winner[side] = now
	case gatecorchestrator.StageDataPlaneReady:
		w.ready[side] = now
	}
}

func (w *gateC1bMemoryTimingWitness) finish(side int, result gatecorchestrator.Result) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.packets[side] = result.Witness.GateB.Emissions.CandidatePackets
	w.success[side] = result.DataPlaneReady
}

func (w *gateC1bMemoryTimingWitness) report(t *testing.T, profile gateC1bMemoryProfile, started time.Time) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var candidateMS, activeMS [2]int64
	for side := range 2 {
		// Missing phase boundaries are explicit, never zero-time subtraction.
		candidateMS[side], activeMS[side] = -1, -1
		if !w.candidate[side].IsZero() && !w.winner[side].IsZero() {
			candidateMS[side] = w.winner[side].Sub(w.candidate[side]).Milliseconds()
		}
		if !w.start[side].IsZero() && !w.ready[side].IsZero() {
			activeMS[side] = w.ready[side].Sub(w.start[side]).Milliseconds()
		}
	}
	t.Logf("memory_fixture profile=%s gomaxprocs=%d busy_workers=2 candidate_ms=%v active_to_ready_ms=%v candidates=%v ready=%v wall_ms=%d",
		profile.name, runtime.GOMAXPROCS(0), candidateMS, activeMS, w.packets, w.success, time.Since(started).Milliseconds())
}

func startGateC1bMemoryFixturePressure(t *testing.T) {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{}, 2)
	var spins [2]atomic.Uint64
	for side := range 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			var value uint64 = 1
			for {
				select {
				case <-stop:
					return
				default:
				}
				for range 1024 {
					value = value*6364136223846793005 + 1
				}
				spins[side].Add(value | 1)
			}
		}()
	}
	t.Cleanup(func() {
		close(stop)
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for range 2 {
			select {
			case <-done:
			case <-deadline.C:
				t.Fatal("fixture pressure workers did not drain")
			}
		}
		if spins[0].Load() == 0 || spins[1].Load() == 0 {
			t.Fatal("both fixture pressure workers must actually run")
		}
		t.Log("memory_fixture pressure_workers=2 drained=2")
	})
}

func TestGateC1bMemoryFixtureStressSchedules(t *testing.T) {
	if os.Getenv("WINKYOU_FLAKE_119_STRESS") != "1" {
		t.Skip("fixture calibration requires explicit two-worker CPU pressure")
	}
	if runtime.GOMAXPROCS(0) != 2 {
		t.Fatal("fixture calibration requires GOMAXPROCS=2")
	}
	startGateC1bMemoryFixturePressure(t)
	for _, profile := range gateC1bMemoryProfiles {
		profile.cli, profile.timing = true, &gateC1bMemoryTimingWitness{}
		if !t.Run(profile.name, func(t *testing.T) {
			started := time.Now()
			defer profile.timing.report(t, profile, started)
			runGateC1bMemoryProductProfile(t, "fixture-stress-"+profile.name, profile)
		}) {
			t.FailNow()
		}
	}
}
