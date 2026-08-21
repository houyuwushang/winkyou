package diagnose

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/stunobserve"
)

func TestRedactForExportOwnsSlicesAndRemovesLocalIdentifiers(t *testing.T) {
	source := Report{
		Redaction: "partial",
		Namespace: governor.NamespaceStatus{Scope: governor.ScopeMachine, State: governor.NamespaceReady, Ready: true, Path: filepath.Join("private", "namespace"), Detail: "private namespace detail"},
		Owner: governor.OwnerStatus{
			Scope: governor.ScopeMachine,
			State: governor.OwnerHeld,
			Held:  true,
			Owner: &governor.OwnerInfo{PID: 4242, InstanceID: "private-instance", BuildVersion: "private-build"},
		},
		SafetyTrip: governor.SafetyTripStatus{
			State:            governor.SafetyTripTripped,
			BlocksActiveWork: true,
			Record: governor.SafetyTripRecord{
				SchemaVersion: 1,
				State:         governor.SafetyTripTripped,
				Sequence:      7,
				UpdatedAt:     time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC),
				Reason:        governor.SafetyTripHardLimit,
				Detail:        "private detail",
				PeerID:        "private-peer",
				AttemptID:     "private-attempt",
				BuildVersion:  "private-build",
			},
		},
		Configuration: ConfigStatus{State: ConfigReady, Source: filepath.Join("private", "config.yaml"), ExplicitPath: true, Detail: "private config detail"},
		Interfaces:    InterfaceStatus{State: InterfacesReady, Interfaces: []InterfaceSummary{{Name: "private-interface", Index: 42, AddressClasses: []string{"private", "ipv4_private"}}}},
		DefaultRoute:  DefaultRouteStatus{State: RoutePresent, Interface: "private-interface", Source: "private-source", Detail: "private route detail"},
		ActiveProbe:   ActiveProbeStatus{State: "active_probe_blocked", Detail: "private active detail"},
	}
	redacted := RedactForExport(source)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}
	for _, forbidden := range []string{"private-instance", "private-build", "private-peer", "private-attempt", "private-interface", "private-source", "private config detail"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("redacted report contains %q: %s", forbidden, encoded)
		}
	}
	if redacted.Redaction != ExportRedaction || redacted.Owner.Owner != nil || redacted.Namespace.Path != "" {
		t.Fatalf("redaction boundary = %+v", redacted)
	}
	redacted.Interfaces.Interfaces[0].AddressClasses[0] = "changed"
	if source.Interfaces.Interfaces[0].AddressClasses[0] != "private" {
		t.Fatal("redacted report retained source slice ownership")
	}
}

func TestWriteRedactedReportCreatesPrivateNewFileOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	written, err := WriteRedactedReport(path, Report{SchemaVersion: SchemaVersion, Redaction: "partial"})
	if err != nil {
		t.Fatalf("write redacted report: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if written != info.Size() || written <= 0 {
		t.Fatalf("written=%d size=%d", written, info.Size())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report Report
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Redaction != ExportRedaction {
		t.Fatalf("redaction = %q", report.Redaction)
	}
	if _, err := WriteRedactedReport(path, Report{}); err == nil {
		t.Fatal("existing export target was overwritten")
	}
}

func TestWriteRedactedReportRejectsRelativeAndMissingParent(t *testing.T) {
	if _, err := WriteRedactedReport("relative.json", Report{}); err == nil {
		t.Fatal("relative export path accepted")
	}
	path := filepath.Join(t.TempDir(), "missing", "report.json")
	if _, err := WriteRedactedReport(path, Report{}); err == nil {
		t.Fatal("missing export parent accepted")
	}
}

func TestRedactForExportKeepsOnlyActiveSTUNPrefixesAndPortBehavior(t *testing.T) {
	source := Report{ActiveSTUN: &ActiveSTUNReport{
		State:            ActiveSTUNStateCompleted,
		ObservationScope: "time_window_only",
		Results: []ActiveSTUNTargetReport{
			{Target: "192.0.2.99:3478", MappedAddress: "198.51.100.123:42000", PortBehavior: "translated", ObservationScope: "time_window_only"},
			{Target: "[2001:db8:1:2::99]:3478", MappedAddress: "[2001:db8:abcd:1234::5]:43000", PortBehavior: "preserved", ObservationScope: "time_window_only"},
		},
	}}

	redacted := RedactForExport(source)
	if redacted.ActiveSTUN == nil || len(redacted.ActiveSTUN.Results) != 2 {
		t.Fatalf("redacted active STUN = %+v", redacted.ActiveSTUN)
	}
	first := redacted.ActiveSTUN.Results[0]
	second := redacted.ActiveSTUN.Results[1]
	if first.Target != "" || first.MappedAddress != "" || first.TargetPrefix != "192.0.2.0/24" || first.MappedPrefix != "198.51.100.0/24" || first.PortBehavior != "translated" {
		t.Fatalf("IPv4 redaction = %+v", first)
	}
	if second.Target != "" || second.MappedAddress != "" || second.TargetPrefix != "2001:db8:1::/48" || second.MappedPrefix != "2001:db8:abcd::/48" || second.PortBehavior != "preserved" {
		t.Fatalf("IPv6 redaction = %+v", second)
	}
	redacted.ActiveSTUN.Results[0].Reason = "changed"
	if source.ActiveSTUN.Results[0].Reason == "changed" {
		t.Fatal("redacted active STUN retained source slice ownership")
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}
	for _, forbidden := range []string{"192.0.2.99", "198.51.100.123", "2001:db8:1:2::99", "2001:db8:abcd:1234::5", "42000", "43000"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("redacted active STUN contains %q: %s", forbidden, encoded)
		}
	}
}

func TestRedactForExportKeepsMappingBehaviorAndRedactsNestedEvidence(t *testing.T) {
	source := Report{ActiveSTUN: &ActiveSTUNReport{
		State:            ActiveSTUNStateCompleted,
		ObservationScope: "time_window_only",
		MappingBehavior: &MappingBehaviorReport{
			Behavior:          stunobserve.MappingBehaviorPortDependent,
			EvidenceScope:     stunobserve.MappingEvidenceSameAddressMultiplePorts,
			Limitations:       []stunobserve.MappingLimitation{stunobserve.MappingLimitationAddressComparisonUnavailable},
			SuccessfulTargets: 2,
			Results: []ActiveSTUNTargetReport{
				{Target: "203.0.113.10:3478", MappedAddress: "198.51.100.123:42000", PortBehavior: "translated", ObservationScope: "time_window_only"},
				{Target: "203.0.113.10:3479", MappedAddress: "198.51.100.123:42001", PortBehavior: "translated", ObservationScope: "time_window_only"},
			},
		},
	}}

	redacted := RedactForExport(source)
	if redacted.ActiveSTUN == nil || redacted.ActiveSTUN.MappingBehavior == nil {
		t.Fatalf("redacted mapping report = %+v", redacted.ActiveSTUN)
	}
	mapping := redacted.ActiveSTUN.MappingBehavior
	if mapping.Behavior != stunobserve.MappingBehaviorPortDependent ||
		mapping.EvidenceScope != stunobserve.MappingEvidenceSameAddressMultiplePorts ||
		len(mapping.Limitations) != 1 ||
		mapping.Limitations[0] != stunobserve.MappingLimitationAddressComparisonUnavailable {
		t.Fatalf("mapping classification changed = %+v", mapping)
	}
	if len(mapping.Results) != 2 {
		t.Fatalf("mapping results = %+v", mapping.Results)
	}
	for _, result := range mapping.Results {
		if result.Target != "" || result.MappedAddress != "" || result.TargetPrefix != "203.0.113.0/24" || result.MappedPrefix != "198.51.100.0/24" {
			t.Fatalf("nested redaction = %+v", result)
		}
	}
	mapping.Limitations[0] = "changed"
	mapping.Results[0].Reason = "changed"
	if source.ActiveSTUN.MappingBehavior.Limitations[0] == "changed" || source.ActiveSTUN.MappingBehavior.Results[0].Reason == "changed" {
		t.Fatal("redacted mapping report retained source slice ownership")
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted mapping report: %v", err)
	}
	for _, forbidden := range []string{"203.0.113.10", "198.51.100.123", "42000", "42001"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("redacted mapping report contains %q: %s", forbidden, encoded)
		}
	}
}

func TestRedactForExportKeepsAllocationDeltasAndClearsRawPorts(t *testing.T) {
	source := Report{ActiveSTUN: &ActiveSTUNReport{
		State:            ActiveSTUNStateCompleted,
		ObservationScope: "time_window_only",
		PortAllocation: &PortAllocationReport{
			Behavior:          stunobserve.AllocationBehaviorSequentialUniform,
			EvidenceScope:     stunobserve.AllocationEvidenceSingleTargetMultipleSockets,
			Limitations:       []stunobserve.AllocationLimitation{stunobserve.AllocationLimitationSingleTimeWindow, stunobserve.AllocationLimitationSingleTarget},
			SuccessfulSockets: 3,
			TotalSockets:      3,
			Deltas:            []int{10, 10},
			Results: []PortAllocationSocketReport{
				{LocalAddress: "192.0.2.25:31001", Target: "203.0.113.10:3478", MappedAddress: "198.51.100.123:42000", PortBehavior: "translated", ObservationScope: "time_window_only"},
				{LocalAddress: "192.0.2.25:31002", Target: "203.0.113.10:3478", MappedAddress: "198.51.100.123:42010", PortBehavior: "translated", ObservationScope: "time_window_only"},
				{LocalAddress: "192.0.2.25:31003", Target: "203.0.113.10:3478", MappedAddress: "198.51.100.123:42020", PortBehavior: "translated", ObservationScope: "time_window_only"},
			},
		},
	}}

	redacted := RedactForExport(source)
	allocation := redacted.ActiveSTUN.PortAllocation
	if allocation == nil || allocation.Behavior != stunobserve.AllocationBehaviorSequentialUniform || allocation.EvidenceScope != stunobserve.AllocationEvidenceSingleTargetMultipleSockets {
		t.Fatalf("allocation classification = %+v", allocation)
	}
	if len(allocation.Deltas) != 2 || allocation.Deltas[0] != 10 || allocation.Deltas[1] != 10 {
		t.Fatalf("allocation deltas = %v", allocation.Deltas)
	}
	for _, result := range allocation.Results {
		if result.LocalAddress != "" || result.Target != "" || result.MappedAddress != "" || result.LocalPrefix != "192.0.2.0/24" || result.TargetPrefix != "203.0.113.0/24" || result.MappedPrefix != "198.51.100.0/24" {
			t.Fatalf("allocation redaction = %+v", result)
		}
	}
	allocation.Deltas[0] = 99
	allocation.Limitations[0] = "changed"
	allocation.Results[0].Reason = "changed"
	if source.ActiveSTUN.PortAllocation.Deltas[0] != 10 || source.ActiveSTUN.PortAllocation.Limitations[0] == "changed" || source.ActiveSTUN.PortAllocation.Results[0].Reason == "changed" {
		t.Fatal("redacted allocation report retained source slice ownership")
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted allocation report: %v", err)
	}
	for _, forbidden := range []string{"192.0.2.25", "203.0.113.10", "198.51.100.123", "31001", "31002", "31003", "42000", "42010", "42020"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("redacted allocation report contains %q: %s", forbidden, encoded)
		}
	}
}
