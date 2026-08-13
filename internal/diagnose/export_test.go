package diagnose

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
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
