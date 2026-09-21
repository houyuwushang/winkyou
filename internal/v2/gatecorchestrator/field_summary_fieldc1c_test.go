//go:build fieldc1c

package gatecorchestrator

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

func TestFieldSummaryHasOnlyPublicWhitelistAndUnknownResidue(t *testing.T) {
	allowed := []string{"profile", "stage", "class", "duration_ns", "counts", "evidence_sha256"}
	shape := reflect.TypeOf(FieldSummary{})
	if shape.NumField() != len(allowed) {
		t.Fatal("public field whitelist changed")
	}
	for i := 0; i < shape.NumField(); i++ {
		if !slices.Contains(allowed, shape.Field(i).Tag.Get("json")) {
			t.Fatal("non-whitelisted public field")
		}
	}
	summary := invalidFieldSummary()
	summary.Counts = map[string]*uint64{"external_socket_residue": nil}
	data, err := json.Marshal(summary)
	var decoded struct {
		Counts map[string]*uint64 `json:"counts"`
	}
	if err != nil || json.Unmarshal(data, &decoded) != nil {
		t.Fatal("summary did not encode")
	}
	if value, present := decoded.Counts["external_socket_residue"]; !present || value != nil {
		t.Fatal("unknown external witness was reported as zero")
	}
}
