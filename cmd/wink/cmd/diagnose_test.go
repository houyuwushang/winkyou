package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
)

type fakePassiveDiagnoseRunner struct {
	report  passivediagnose.Report
	options passivediagnose.Options
	calls   int
}

func (runner *fakePassiveDiagnoseRunner) Run(_ context.Context, options passivediagnose.Options) passivediagnose.Report {
	runner.calls++
	runner.options = options
	return runner.report
}

func passiveDiagnoseFixture() passivediagnose.Report {
	return passivediagnose.Report{
		SchemaVersion: passivediagnose.SchemaVersion,
		GeneratedAt:   time.Date(2026, 8, 11, 4, 0, 0, 0, time.UTC),
		Mode:          "passive_only",
		Redaction:     "partial",
		BuildVersion:  "test-build",
		Platform:      passivediagnose.Platform{OS: "windows", Arch: "amd64"},
		GovernorScope: governor.ScopeMachine,
		Namespace: governor.NamespaceStatus{
			Scope:             governor.ScopeMachine,
			State:             governor.NamespaceMissing,
			RequiresElevation: true,
			Detail:            "not installed",
		},
		Owner:      governor.OwnerStatus{Scope: governor.ScopeMachine, State: governor.OwnerUnavailable},
		SafetyTrip: governor.SafetyTripStatus{State: governor.SafetyTripUnavailable, BlocksActiveWork: true},
		Configuration: passivediagnose.ConfigStatus{
			State:  passivediagnose.ConfigReady,
			Source: "defaults_and_environment",
		},
		Interfaces: passivediagnose.InterfaceStatus{
			State:   passivediagnose.InterfacesReady,
			Count:   1,
			UpCount: 1,
			Interfaces: []passivediagnose.InterfaceSummary{{
				Name:                 "Ethernet",
				Index:                4,
				MTU:                  1500,
				Up:                   true,
				AddressClasses:       []string{"ipv4_private"},
				AddressesAreRedacted: true,
			}},
		},
		DefaultRoute: passivediagnose.DefaultRouteStatus{State: passivediagnose.RoutePresent, Family: "ipv4", Interface: "Ethernet"},
		ActiveProbe: passivediagnose.ActiveProbeStatus{
			State:  "active_probe_blocked",
			Reason: "machine_scope_not_ready",
			Detail: "machine scope is missing; passive diagnostics remain available",
			Action: "wink setup-machine-scope",
		},
	}
}

func TestDiagnosePrintsPassiveReportAndDoesNotFailOnMissingScope(t *testing.T) {
	runner := &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}
	cmd := newDiagnoseCmdWithRunner(&Options{ConfigPath: "custom.yaml"}, runner)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	if runner.calls != 1 || runner.options.ConfigPath != "custom.yaml" {
		t.Fatalf("runner calls/options = %d/%+v", runner.calls, runner.options)
	}
	got := output.String()
	for _, want := range []string{
		"WinkYou passive diagnose",
		"Machine scope:   missing",
		"address_classes=ipv4_private",
		"Active probe:    active_probe_blocked",
		"Action:          wink setup-machine-scope",
		"Network started: false",
		"No WinkYou runtime or active network activity was started.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestDiagnoseJSONPreservesBlockedAndRedactedBoundary(t *testing.T) {
	runner := &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}
	cmd := newDiagnoseCmdWithRunner(&Options{}, runner)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose --json: %v", err)
	}
	var report passivediagnose.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, output.String())
	}
	if report.ActiveProbe.State != "active_probe_blocked" || report.NetworkActivityStarted || report.Redaction != "partial" {
		t.Fatalf("JSON boundary = %+v", report)
	}
	if len(report.Interfaces.Interfaces) != 1 || !report.Interfaces.Interfaces[0].AddressesAreRedacted {
		t.Fatalf("JSON interfaces = %+v", report.Interfaces)
	}
}

func TestRootExposesDiagnoseSeparatelyFromLegacyDoctor(t *testing.T) {
	root := newRootCmd()
	var diagnoseFound, doctorFound bool
	for _, child := range root.Commands() {
		switch child.Name() {
		case "diagnose":
			diagnoseFound = true
		case "doctor":
			doctorFound = true
		}
	}
	if !diagnoseFound || !doctorFound {
		t.Fatalf("root commands diagnose=%t doctor=%t", diagnoseFound, doctorFound)
	}
}
