package store

import (
	"testing"

	"winkyou/pkg/solver"
)

func TestObservationStoreOwnsMapValues(t *testing.T) {
	s := NewObservationStore("")
	input := solver.Observation{Event: "synthetic", Details: map[string]string{"value": "original"}}
	if err := s.Record(input); err != nil {
		t.Fatal(err)
	}
	input.Details["value"] = "caller_changed"
	if got := s.Recent(1)[0].Details["value"]; got != "original" {
		t.Fatalf("caller still owns stored map: %s", got)
	}
	listed := s.List()
	listed[0].Details["value"] = "reader_changed"
	recent := s.Recent(1)
	if got := recent[0].Details["value"]; got != "original" {
		t.Fatalf("List aliases evidence map: %s", got)
	}
	recent[0].Details["value"] = "recent_changed"
	if s.List()[0].Details["value"] != "original" {
		t.Fatal("Recent aliases evidence map")
	}
}
