package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"winkyou/pkg/solver"
)

func TestObservationStore_MemoryOnly(t *testing.T) {
	store := NewObservationStore("")

	obs1 := solver.Observation{
		Strategy: "test",
		Event:    "started",
		PlanID:   "plan1",
	}

	if err := store.Record(obs1); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	list := store.List()
	if len(list) != 1 {
		t.Fatalf("List() len = %d, want 1", len(list))
	}
	if list[0].Strategy != "test" {
		t.Errorf("List()[0].Strategy = %s, want test", list[0].Strategy)
	}
}

func TestObservationStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "observations.jsonl")

	store := NewObservationStore(filePath)

	obs1 := solver.Observation{
		Strategy:  "test",
		Event:     "started",
		PlanID:    "plan1",
		Timestamp: time.Now(),
	}
	obs2 := solver.Observation{
		Strategy:  "test",
		Event:     "completed",
		PlanID:    "plan1",
		Timestamp: time.Now(),
	}

	if err := store.Record(obs1); err != nil {
		t.Fatalf("Record(obs1) error = %v", err)
	}
	if err := store.Record(obs2); err != nil {
		t.Fatalf("Record(obs2) error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatalf("file not created: %s", filePath)
	}

	// Load into new store
	store2 := NewObservationStore(filePath)
	if err := store2.LoadFromFile(); err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	list := store2.List()
	if len(list) != 2 {
		t.Fatalf("List() len = %d, want 2", len(list))
	}
	if list[0].Event != "started" {
		t.Errorf("List()[0].Event = %s, want started", list[0].Event)
	}
	if list[1].Event != "completed" {
		t.Errorf("List()[1].Event = %s, want completed", list[1].Event)
	}
}

func TestObservationStore_MemoryLimit(t *testing.T) {
	store := NewObservationStore("")

	// Add 1500 observations
	for i := 0; i < 1500; i++ {
		obs := solver.Observation{
			Strategy: "test",
			Event:    "event",
			PlanID:   "plan",
		}
		if err := store.Record(obs); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}

	list := store.List()
	if len(list) != 1000 {
		t.Errorf("List() len = %d, want 1000 (memory limit)", len(list))
	}
}

func TestObservationStore_Recent(t *testing.T) {
	store := NewObservationStore("")
	for i := 0; i < 5; i++ {
		if err := store.Record(solver.Observation{
			Strategy: "test",
			Event:    "event",
			PlanID:   "plan",
			Details:  map[string]string{"index": string(rune('0' + i))},
		}); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}

	recent := store.Recent(2)
	if len(recent) != 2 {
		t.Fatalf("Recent(2) len = %d, want 2", len(recent))
	}
	if got := recent[0].Details["index"]; got != "3" {
		t.Fatalf("Recent(2)[0] index = %q, want 3", got)
	}
	if got := recent[1].Details["index"]; got != "4" {
		t.Fatalf("Recent(2)[1] index = %q, want 4", got)
	}
}
