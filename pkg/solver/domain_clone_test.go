package solver

import (
	"reflect"
	"testing"
	"time"
)

func TestObservationCloneAndNormalizeOwnership(t *testing.T) {
	source := Observation{Details: map[string]string{"nat": "symmetric"}}
	cloned := CloneObservation(source)
	cloned.Details["nat"] = "cone"
	if source.Details["nat"] != "symmetric" {
		t.Fatalf("CloneObservation aliases source Details: %#v", source.Details)
	}
	source.Details["source_only"] = "yes"
	if _, ok := cloned.Details["source_only"]; ok {
		t.Fatalf("source mutation reached clone: %#v", cloned.Details)
	}

	empty := CloneObservation(Observation{Details: map[string]string{}})
	if empty.Details == nil {
		t.Fatal("CloneObservation changed an empty non-nil map to nil")
	}
	if normalized := NormalizeObservation(empty); normalized.Details != nil {
		t.Fatalf("NormalizeObservation Details = %#v, want nil", normalized.Details)
	}
	if normalized := NormalizeObservation(Observation{}); normalized.Details != nil {
		t.Fatalf("NormalizeObservation nil Details = %#v", normalized.Details)
	}
}

func TestProbeDomainCloneOwnsNestedCollections(t *testing.T) {
	script := ProbeScript{
		ScriptType: "preflight_v1",
		PlanID:     "probe/preflight",
		Steps: []ProbeStep{{
			Action:  "report",
			Params:  map[string]string{"event": "ready"},
			Timeout: 1500 * time.Millisecond,
		}},
	}
	clonedScript := CloneProbeScript(script)
	clonedScript.Steps[0].Params["event"] = "mutated"
	clonedScript.Steps = append(clonedScript.Steps, ProbeStep{Action: "sleep"})
	if script.Steps[0].Params["event"] != "ready" || len(script.Steps) != 1 {
		t.Fatalf("CloneProbeScript aliases source: source=%#v clone=%#v", script, clonedScript)
	}

	result := ProbeResult{
		ScriptType: "preflight_v1",
		Events: []Observation{{
			Event:   "ready",
			Details: map[string]string{"owner": "source"},
		}},
	}
	clonedResult := CloneProbeResult(result)
	clonedResult.Events[0].Details["owner"] = "clone"
	if result.Events[0].Details["owner"] != "source" {
		t.Fatalf("CloneProbeResult aliases event Details: %#v", result.Events)
	}

	summary := ProbeResultSummary{Details: map[string]string{"events": "1"}}
	clonedSummary := CloneProbeResultSummary(summary)
	clonedSummary.Details["events"] = "2"
	if summary.Details["events"] != "1" {
		t.Fatalf("CloneProbeResultSummary aliases Details: %#v", summary.Details)
	}
}

func TestProbeDomainNormalizeIsDeterministicAndPreservesOrder(t *testing.T) {
	script := ProbeScript{
		ScriptType: "preflight_v1",
		Steps: []ProbeStep{
			{Action: "first", Params: map[string]string{}},
			{Action: "second", Params: map[string]string{"b": "2", "a": "1"}},
		},
	}
	first := NormalizeProbeScript(script)
	second := NormalizeProbeScript(first)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("NormalizeProbeScript is not idempotent: first=%#v second=%#v", first, second)
	}
	if first.Steps[0].Action != "first" || first.Steps[1].Action != "second" {
		t.Fatalf("NormalizeProbeScript changed step order: %#v", first.Steps)
	}
	if first.Steps[0].Params != nil {
		t.Fatalf("empty Params = %#v, want canonical nil", first.Steps[0].Params)
	}
	first.Steps[1].Params["a"] = "mutated"
	if script.Steps[1].Params["a"] != "1" {
		t.Fatalf("NormalizeProbeScript aliases source Params: %#v", script.Steps[1].Params)
	}

	result := ProbeResult{Events: []Observation{{Event: "first"}, {Event: "second", Details: map[string]string{}}}}
	normalized := NormalizeProbeResult(result)
	if normalized.Events[0].Event != "first" || normalized.Events[1].Event != "second" {
		t.Fatalf("NormalizeProbeResult changed event order: %#v", normalized.Events)
	}
	if normalized.Events[1].Details != nil {
		t.Fatalf("normalized event Details = %#v, want nil", normalized.Events[1].Details)
	}
	if got := NormalizeProbeScript(ProbeScript{Steps: []ProbeStep{}}).Steps; got != nil {
		t.Fatalf("empty Steps = %#v, want canonical nil", got)
	}
}
