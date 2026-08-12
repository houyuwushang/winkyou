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

func TestDiagnoseUserAcknowledgedFlagIsExplicitAndKeepsJSONClean(t *testing.T) {
	report := passiveDiagnoseFixture()
	report.Mode = "user_acknowledged_passive_only"
	report.GovernorScope = governor.ScopeUserAcknowledged
	report.Namespace.Scope = governor.ScopeUserAcknowledged
	report.UserAcknowledged = &passivediagnose.UserAcknowledgedBoundary{
		ExplicitAcknowledgement: true,
		Profile:                 governor.ProfilePhase1UserAcknowledged,
		Acquired:                true,
		Released:                true,
		Warning:                 passivediagnose.UserAcknowledgedWarning,
	}
	runner := &fakePassiveDiagnoseRunner{report: report}
	cmd := newDiagnoseCmdWithRunner(&Options{ConfigPath: "explicit.yaml"}, runner)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"--governor-scope", "user-acknowledged", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose user-acknowledged: %v", err)
	}
	if runner.calls != 1 || runner.options.GovernorScope != governor.ScopeUserAcknowledged || runner.options.ConfigPath != "explicit.yaml" {
		t.Fatalf("runner calls/options = %d/%+v", runner.calls, runner.options)
	}
	var decoded passivediagnose.Report
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON stdout: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "not machine-wide safety") {
		t.Fatalf("stderr warning = %q", stderr.String())
	}
}

func TestDiagnoseGovernorScopeCannotComeFromEnvironment(t *testing.T) {
	t.Setenv("WINK_GOVERNOR_SCOPE", "user-acknowledged")
	runner := &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}
	cmd := newDiagnoseCmdWithRunner(&Options{ConfigPath: "imported.yaml"}, runner)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose default: %v", err)
	}
	if runner.options.GovernorScope != governor.ScopeMachine {
		t.Fatalf("environment selected governor scope %q", runner.options.GovernorScope)
	}
}

func TestDiagnoseRejectsUnknownGovernorScopeBeforeCollection(t *testing.T) {
	runner := &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}
	cmd := newDiagnoseCmdWithRunner(&Options{}, runner)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--governor-scope", "user_acknowledged"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid --governor-scope") {
		t.Fatalf("invalid scope error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("invalid scope collector calls = %d, want 0", runner.calls)
	}
}

func TestGovernorScopeFlagIsLocalToDiagnose(t *testing.T) {
	root := newRootCmd()
	if root.PersistentFlags().Lookup("governor-scope") != nil {
		t.Fatal("governor-scope became a persistent flag")
	}
	for _, child := range root.Commands() {
		flag := child.Flags().Lookup("governor-scope")
		if child.Name() == "diagnose" {
			if flag == nil {
				t.Fatal("diagnose has no governor-scope flag")
			}
			continue
		}
		if flag != nil {
			t.Fatalf("command %s unexpectedly exposes governor-scope", child.Name())
		}
	}
}
