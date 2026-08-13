package wireadapter

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

func TestObservationAdapterRoundTripAndOwnership(t *testing.T) {
	domain := solver.Observation{
		Strategy:  "legacy_ice_udp",
		PlanID:    "legacyice/public_direct",
		Event:     "candidate_gathered",
		Details:   map[string]string{"candidate_count": "4"},
		Timestamp: time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC),
	}
	wire := ObservationToWire(domain)
	domain.Details["candidate_count"] = "mutated"
	if wire.Details["candidate_count"] != "4" {
		t.Fatalf("wire observation aliases domain Details: %#v", wire.Details)
	}

	roundTrip := ObservationFromWire(wire)
	wire.Details["candidate_count"] = "wire-mutated"
	if roundTrip.Details["candidate_count"] != "4" {
		t.Fatalf("domain observation aliases wire Details: %#v", roundTrip.Details)
	}
	want := solver.NormalizeObservation(solver.Observation{
		Strategy:  "legacy_ice_udp",
		PlanID:    "legacyice/public_direct",
		Event:     "candidate_gathered",
		Details:   map[string]string{"candidate_count": "4"},
		Timestamp: domain.Timestamp,
	})
	if !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("observation round trip = %#v, want %#v", roundTrip, want)
	}
}

func TestProbeStepAdapterRoundTripAndReservedDetailBoundary(t *testing.T) {
	domain := solver.ProbeStep{
		Action: "udp_send",
		Params: map[string]string{
			"addr":        "192.0.2.10:9999",
			"payload":     "ping",
			"duration_ms": "25",
			"trace":       "owned",
		},
		Timeout: 1500 * time.Millisecond,
	}
	wire := ProbeStepToWire(domain)
	domain.Params["trace"] = "mutated"
	if wire.Details["trace"] != "owned" {
		t.Fatalf("wire probe step aliases domain Params: %#v", wire.Details)
	}
	roundTrip := ProbeStepFromWire(wire)
	wire.Details["trace"] = "wire-mutated"
	if roundTrip.Params["trace"] != "owned" {
		t.Fatalf("domain probe step aliases wire Details: %#v", roundTrip.Params)
	}
	want := solver.NormalizeProbeStep(solver.ProbeStep{
		Action: "udp_send",
		Params: map[string]string{
			"addr":        "192.0.2.10:9999",
			"payload":     "ping",
			"duration_ms": "25",
			"trace":       "owned",
		},
		Timeout: 1500 * time.Millisecond,
	})
	if !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("probe step round trip = %#v, want %#v", roundTrip, want)
	}

	reserved := ProbeStepFromWire(rproto.ProbeStep{
		Type:    "udp_send",
		Addr:    "192.0.2.1:1",
		Details: map[string]string{"addr": "shadowed", "trace": "kept"},
	})
	if reserved.Params["addr"] != "192.0.2.1:1" || reserved.Params["trace"] != "kept" {
		t.Fatalf("structured/detail precedence = %#v", reserved.Params)
	}
	if details := ProbeStepDetails(reserved); details["addr"] != "shadowed" || details["trace"] != "kept" {
		t.Fatalf("colliding wire details were not retained: %#v", details)
	}
}

func TestProbeScriptAdapterRoundTripAndOwnership(t *testing.T) {
	domain := solver.ProbeScript{
		ScriptType: "preflight_v1",
		PlanID:     "probe/preflight",
		Steps: []solver.ProbeStep{{
			Action: "report",
			Params: map[string]string{"event": "probe_ready", "evidence": "none"},
		}},
	}
	wire := ProbeScriptToWire(domain)
	domain.Steps[0].Params["evidence"] = "mutated"
	if wire.Steps[0].Details["evidence"] != "none" {
		t.Fatalf("wire script aliases domain step Params: %#v", wire.Steps[0])
	}
	roundTrip := ProbeScriptFromWire(wire)
	wire.Steps[0].Details["evidence"] = "wire-mutated"
	if roundTrip.Steps[0].Params["evidence"] != "none" {
		t.Fatalf("domain script aliases wire step Details: %#v", roundTrip.Steps[0])
	}
	want := solver.NormalizeProbeScript(solver.ProbeScript{
		ScriptType: "preflight_v1",
		PlanID:     "probe/preflight",
		Steps: []solver.ProbeStep{{
			Action: "report",
			Params: map[string]string{"event": "probe_ready", "evidence": "none"},
		}},
	})
	if !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("probe script round trip = %#v, want %#v", roundTrip, want)
	}
}

func TestProbeResultAdapterRoundTripAndOwnership(t *testing.T) {
	domain := solver.ProbeResult{
		ScriptType: "preflight_v1",
		PlanID:     "probe/preflight",
		Success:    true,
		Events: []solver.Observation{{
			Event:   "probe_ready",
			Details: map[string]string{"source": "runner"},
		}},
		SelectedPathID: "direct/path",
		FinishedAt:     time.Date(2026, 8, 13, 2, 3, 4, 0, time.UTC),
	}
	wire := ProbeResultToWire(domain)
	domain.Events[0].Details["source"] = "mutated"
	if wire.Events[0].Details["source"] != "runner" {
		t.Fatalf("wire result aliases domain event Details: %#v", wire.Events)
	}
	roundTrip := ProbeResultFromWire(wire)
	wire.Events[0].Details["source"] = "wire-mutated"
	if roundTrip.Events[0].Details["source"] != "runner" {
		t.Fatalf("domain result aliases wire event Details: %#v", roundTrip.Events)
	}
	want := solver.NormalizeProbeResult(solver.ProbeResult{
		ScriptType: "preflight_v1",
		PlanID:     "probe/preflight",
		Success:    true,
		Events: []solver.Observation{{
			Event:   "probe_ready",
			Details: map[string]string{"source": "runner"},
		}},
		SelectedPathID: "direct/path",
		FinishedAt:     domain.FinishedAt,
	})
	if !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("probe result round trip = %#v, want %#v", roundTrip, want)
	}
}

func TestWireAdaptersTolerateUnknownJSONFields(t *testing.T) {
	var observation rproto.Observation
	if err := json.Unmarshal([]byte(`{"event":"ready","details":{"known":"yes"},"future_observation":{"v":1}}`), &observation); err != nil {
		t.Fatalf("decode observation with unknown field: %v", err)
	}
	if got := ObservationFromWire(observation); got.Event != "ready" || got.Details["known"] != "yes" {
		t.Fatalf("observation from future wire = %#v", got)
	}

	var script rproto.ProbeScript
	if err := json.Unmarshal([]byte(`{"script_type":"preflight_v1","future_script":true,"steps":[{"type":"report","event":"ready","future_step":"ignored"}]}`), &script); err != nil {
		t.Fatalf("decode probe script with unknown fields: %v", err)
	}
	if got := ProbeScriptFromWire(script); len(got.Steps) != 1 || got.Steps[0].Action != "report" {
		t.Fatalf("probe script from future wire = %#v", got)
	}

	var result rproto.ProbeResult
	if err := json.Unmarshal([]byte(`{"script_type":"preflight_v1","success":true,"future_result":"ignored","events":[{"event":"ready","future_event":42}]}`), &result); err != nil {
		t.Fatalf("decode probe result with unknown fields: %v", err)
	}
	if got := ProbeResultFromWire(result); !got.Success || len(got.Events) != 1 || got.Events[0].Event != "ready" {
		t.Fatalf("probe result from future wire = %#v", got)
	}
}

func TestWireAdaptersCanonicalizeNilAndEmptyCollections(t *testing.T) {
	if got := ObservationFromWire(rproto.Observation{Details: map[string]string{}}).Details; got != nil {
		t.Fatalf("empty observation Details = %#v, want nil", got)
	}
	if got := ObservationFromWire(rproto.Observation{}).Details; got != nil {
		t.Fatalf("nil observation Details = %#v, want nil", got)
	}
	if got := ProbeStepFromWire(rproto.ProbeStep{Details: map[string]string{}}).Params; got != nil {
		t.Fatalf("empty probe Details -> Params = %#v, want nil", got)
	}
	if got := ProbeScriptFromWire(rproto.ProbeScript{Steps: []rproto.ProbeStep{}}).Steps; got != nil {
		t.Fatalf("empty probe Steps = %#v, want nil", got)
	}
	if got := ProbeResultFromWire(rproto.ProbeResult{Events: []rproto.Observation{}}).Events; got != nil {
		t.Fatalf("empty result Events = %#v, want nil", got)
	}
}

func TestProbeResultFromWireKeepsLegacyPathIDIgnored(t *testing.T) {
	got := ProbeResultFromWire(rproto.ProbeResult{PathID: "legacy/path", SelectedPathID: "selected/path"})
	if got.SelectedPathID != "selected/path" {
		t.Fatalf("SelectedPathID = %q, want selected/path", got.SelectedPathID)
	}
	wire := ProbeResultToWire(got)
	if wire.PathID != "" || wire.SelectedPathID != "selected/path" {
		t.Fatalf("wire path fields = legacy %q selected %q", wire.PathID, wire.SelectedPathID)
	}
}

func TestObservationWireJSONGolden(t *testing.T) {
	domain := solver.Observation{
		Strategy:       "legacy_ice_udp",
		PlanID:         "legacyice/public_direct",
		Event:          "candidate_failed",
		PathID:         "direct/path",
		ConnectionType: "direct",
		LocalAddr:      "192.0.2.10:40000",
		RemoteAddr:     "198.51.100.20:50000",
		LocalKind:      "srflx",
		RemoteKind:     "prflx",
		ErrorClass:     "timeout",
		Reason:         "connectivity_check_timeout",
		TimeoutMS:      1500,
		Details:        map[string]string{"attempt": "1", "nat": "symmetric"},
		Timestamp:      time.Date(2026, 8, 13, 9, 30, 15, 123456789, time.UTC),
	}
	encoded, err := json.MarshalIndent(ObservationToWire(domain), "", "  ")
	if err != nil {
		t.Fatalf("marshal observation golden: %v", err)
	}
	encoded = append(encoded, '\n')
	want, err := os.ReadFile("testdata/observation.golden.json")
	if err != nil {
		t.Fatalf("read observation golden: %v", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(encoded, want) {
		t.Fatalf("observation JSON changed\ngot:\n%s\nwant:\n%s", encoded, want)
	}
}

// TODO(v2-phase1a): add equivalent ProbeScript and ProbeResult JSON goldens
// once their compatibility-field policy is frozen independently.
