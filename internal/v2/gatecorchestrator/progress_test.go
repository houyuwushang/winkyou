package gatecorchestrator

import (
	"reflect"
	"testing"
	"time"
)

func TestProductProgressSequenceIsFrozenAndTerminalMayFollowAnyPrefix(t *testing.T) {
	want := []string{
		"preflight", "ssh_spawn", "oob_adopt", "present", "burned", "activated", "handshake", "prepare",
		"sockets", "fresh_evidence", "plan_committed", "ready", "fire", "candidates", "winner", "verify",
		"transport_lease", "handoff", "data_plane_challenge", "finish_recorded", "oob_drained",
		"data_plane_ready", "terminal",
	}
	if !reflect.DeepEqual(ProductProgressSequence, want) {
		t.Fatalf("progress sequence=%v", ProductProgressSequence)
	}
	var stages []string
	sequence := newProgressSequence(func(progress Progress) error {
		if progress.RemainingBudget < 0 {
			t.Fatal("negative remaining budget")
		}
		stages = append(stages, progress.Stage)
		return nil
	}, time.Now().Add(time.Second))
	if err := sequence.emit(StagePreflight, true); err != nil {
		t.Fatal(err)
	}
	if err := sequence.emitTerminal(); err != nil {
		t.Fatal(err)
	}
	if err := sequence.emitTerminal(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stages, []string{StagePreflight, StageTerminal}) {
		t.Fatalf("failure prefix=%v", stages)
	}
}

func TestProductProgressRejectsSkippedOrRepeatedStage(t *testing.T) {
	sequence := newProgressSequence(func(Progress) error { return nil }, time.Now().Add(time.Second))
	if err := sequence.emit(StageSSHSpawn, true); err == nil {
		t.Fatal("skipped preflight was accepted")
	}
	if err := sequence.emit(StagePreflight, true); err != nil {
		t.Fatal(err)
	}
	if err := sequence.emit(StagePreflight, true); err == nil {
		t.Fatal("repeated preflight was accepted")
	}
}
