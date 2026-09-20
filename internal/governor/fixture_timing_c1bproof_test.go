//go:build c1bproof

package governor_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/gatecorchestrator"
)

// Only fixed numeric metadata and monotonic offsets leave this test witness.
// Missing events are -1, NOT zero; the profile's original budgets are copied.
type fixtureTimingRecord struct {
	Schema            int          `json:"schema"`
	Profile           int          `json:"profile"`
	Scenario          int          `json:"scenario"`
	Failed            int          `json:"failed"`
	CandidateBudgetNS int64        `json:"candidate_budget_ns"`
	ActiveBudgetNS    int64        `json:"active_budget_ns"`
	FinishDelayNS     [2]int64     `json:"finish_delay_ns"`
	StagesNS          [2][23]int64 `json:"stages_ns"`
}

func (w *gateC1bMemoryPhaseWitness) timingRecord(profile gateC1bMemoryProfile, windows memoryFixtureWindow, failed bool) (fixtureTimingRecord, error) {
	r := fixtureTimingRecord{Schema: 1, Profile: -1, CandidateBudgetNS: int64(windows.candidateTime), ActiveBudgetNS: int64(windows.activeTime)}
	for index, known := range gateC1bMemoryProfiles {
		if profile.profile == known.profile {
			r.Profile = index
		}
	}
	if r.Profile < 0 || len(gatecorchestrator.ProductProgressSequence) != len(r.StagesNS[0]) {
		return r, errors.New("fixture timing schema mismatch")
	}
	switch {
	case profile.slowFinish:
		r.Scenario, r.FinishDelayNS[0] = 2, int64(3500*time.Millisecond)
	case profile.slowResponderFinish:
		r.Scenario, r.FinishDelayNS[1] = 3, int64(3500*time.Millisecond)
	case profile.cancelAfterFinish:
		r.Scenario = 4
	case profile.fault == "evidence-drift":
		r.Scenario = 5
	case profile.fault == "candidate-exhaustion":
		r.Scenario = 6
	case profile.liveness != nil:
		r.Scenario = 7
	case profile.cli:
		r.Scenario = 1
	}
	if failed {
		r.Failed = 1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for side := range r.StagesNS {
		for slot := range r.StagesNS[side] {
			r.StagesNS[side][slot] = -1
			if w.seen[side][slot] {
				r.StagesNS[side][slot] = int64(w.at[side][slot])
			}
		}
	}
	return r, nil
}

func writeFixtureTiming(directory string, record fixtureTimingRecord) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return errors.New("fixture timing directory unavailable")
	}
	// Each invocation is a sample. Exclusive creation avoids overwriting the
	// same test's previous -count iteration or another concurrent profile.
	f, err := os.CreateTemp(directory, "sample-*.json")
	if err != nil {
		return errors.New("fixture timing sample creation failed")
	}
	encodeErr := json.NewEncoder(f).Encode(record)
	closeErr := f.Close()
	if encodeErr != nil || closeErr != nil {
		return errors.New("fixture timing sample write failed")
	}
	return nil
}

func (w *gateC1bMemoryPhaseWitness) persistTiming(t *testing.T, profile gateC1bMemoryProfile, windows memoryFixtureWindow) {
	t.Helper()
	directory := os.Getenv("WINKYOU_FIXTURE_TIMING_DIR")
	if directory == "" {
		return
	}
	record, err := w.timingRecord(profile, windows, t.Failed())
	if err != nil {
		t.Error("fixture timing schema mismatch")
		return
	}
	if err := writeFixtureTiming(directory, record); err != nil {
		// Never expose the host-specific error or sample path.
		t.Error("fixture timing capture failed")
	}
}

func TestGateC1bFixtureTimingFiles(t *testing.T) {
	wantStages := []string{"preflight", "ssh_spawn", "oob_adopt", "present", "burned", "activated", "handshake", "prepare", "sockets", "fresh_evidence", "plan_committed", "ready", "fire", "candidates", "winner", "verify", "transport_lease", "handoff", "data_plane_challenge", "finish_recorded", "oob_drained", "data_plane_ready", "terminal"}
	if !reflect.DeepEqual(gatecorchestrator.ProductProgressSequence, wantStages) {
		t.Fatal("numeric timing stage schema drifted")
	}
	w := newGateC1bMemoryPhaseWitness()
	profile := gateC1bMemoryProfiles[0]
	windows := memoryFixtureWindows(profile.profile)
	// Deliberately distinguish a real zero offset from an unobserved event.
	w.seen[0][0], w.at[0][0] = true, 0
	for _, failed := range []bool{false, true} {
		r, err := w.timingRecord(profile, windows, failed)
		if err != nil || (r.Failed == 1) != failed || r.StagesNS[0][0] != 0 || r.StagesNS[0][1] != -1 || r.StagesNS[1][0] != -1 {
			t.Fatal("success, failure or missing timing lost")
		}
		directory := t.TempDir()
		var workers sync.WaitGroup
		for range 20 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				if err := writeFixtureTiming(directory, r); err != nil {
					t.Error("concurrent timing write failed")
				}
			}()
		}
		workers.Wait()
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 20 {
			t.Fatal("sample collision or missing file")
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			var got fixtureTimingRecord
			if err != nil || json.Unmarshal(data, &got) != nil || !reflect.DeepEqual(r, got) {
				t.Fatal("timing round trip changed numeric values")
			}
		}
	}
	for index, profile := range gateC1bMemoryProfiles {
		for _, responder := range []bool{false, true} {
			profile.slowFinish, profile.slowResponderFinish = !responder, responder
			r, err := w.timingRecord(profile, memoryFixtureWindows(profile.profile), false)
			side, scenario := 0, 2
			if responder {
				side, scenario = 1, 3
			}
			if err != nil || r.Profile != index || r.Scenario != scenario || r.FinishDelayNS[side] != int64(3500*time.Millisecond) || r.FinishDelayNS[1-side] != 0 {
				t.Fatal("profile or injected delay metadata changed")
			}
		}
	}
	t.Setenv("WINKYOU_FIXTURE_TIMING_DIR", "")
	w.persistTiming(t, profile, windows) // Opt-out does not create a file.
	bad := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(bad, nil, 0600); err != nil {
		t.Fatal("cannot create synthetic obstruction")
	}
	err := writeFixtureTiming(bad, fixtureTimingRecord{})
	if err == nil || err.Error() != "fixture timing directory unavailable" {
		t.Fatal("capture failure leaked an OS path or was ignored")
	}
}
