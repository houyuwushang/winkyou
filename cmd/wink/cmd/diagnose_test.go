package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/probeio"
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

func TestDiagnoseWithoutActiveSTUNNeverCallsActiveRunner(t *testing.T) {
	passive := &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}
	active := &fakeActiveSTUNRunner{t: t, forbid: true}
	cmd := newDiagnoseCmdWithRunners(&Options{}, passive, active)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("passive diagnose: %v", err)
	}
	if active.calls != 0 || strings.Contains(stdout.String(), `"active_stun"`) || stderr.Len() != 0 {
		t.Fatalf("default path changed: active_calls=%d stderr=%q\n%s", active.calls, stderr.String(), stdout.String())
	}
	want, err := os.ReadFile(filepath.Join("testdata", "diagnose-passive.json.golden"))
	if err != nil {
		t.Fatalf("read passive golden: %v", err)
	}
	normalize := func(value string) string {
		return strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "\n"))
	}
	if normalize(stdout.String()) != normalize(string(want)) {
		t.Fatalf("passive JSON changed\n\ngot:\n%s\n\nwant:\n%s", stdout.String(), want)
	}
}

func TestDiagnoseActiveSTUNRealLoopbackCLIPath(t *testing.T) {
	target := startCLIStunResponder(t, false)
	limits, err := governor.HardLimits(governor.ProfilePhase1Machine)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	authority := &cliActiveSTUNAuthority{snapshot: governor.Snapshot{
		Profile:    governor.ProfilePhase1Machine,
		Scope:      governor.ScopeMachine,
		Limits:     limits,
		SafetyTrip: governor.SafetyTripStatus{State: governor.SafetyTripClear},
	}}
	active := passivediagnose.ActiveSTUNInspector{
		AcquireMachine: func(string) (passivediagnose.ActiveSTUNAuthority, error) { return authority, nil },
		BuildVersion:   "test-build",
	}
	passive := &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}
	cmd := newDiagnoseCmdWithRunners(&Options{}, passive, active)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"--json", "--active-stun", target.String()})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("active diagnose: %v\nstderr: %s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "source IP address") || !strings.Contains(stderr.String(), "observation timing") {
		t.Fatalf("active disclosure = %q", stderr.String())
	}
	var report passivediagnose.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode active report: %v\n%s", err, stdout.String())
	}
	if report.ActiveSTUN == nil || report.ActiveSTUN.State != passivediagnose.ActiveSTUNStateCompleted || !report.NetworkActivityStarted {
		t.Fatalf("active report = %+v", report)
	}
	if len(report.ActiveSTUN.Results) != 1 {
		t.Fatalf("active results = %+v", report.ActiveSTUN.Results)
	}
	result := report.ActiveSTUN.Results[0]
	if result.MappedAddress == "" || result.Transmissions != 1 || result.PortBehavior != "preserved" || result.ObservationScope != "time_window_only" {
		t.Fatalf("loopback observation = %+v", result)
	}
	if authority.peer == nil || authority.peer.acquireCalls != 1 || authority.closeCalls != 1 {
		t.Fatalf("authority lifecycle = %+v", authority)
	}
}

func TestDiagnoseActiveSTUNRealLoopbackMixedTargets(t *testing.T) {
	successTarget := startCLIStunResponder(t, false)
	protocolFailureTarget := startCLIStunResponder(t, true)
	limits, err := governor.HardLimits(governor.ProfilePhase1Machine)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	authority := &cliActiveSTUNAuthority{snapshot: governor.Snapshot{
		Profile:    governor.ProfilePhase1Machine,
		Scope:      governor.ScopeMachine,
		Limits:     limits,
		SafetyTrip: governor.SafetyTripStatus{State: governor.SafetyTripClear},
	}}
	active := passivediagnose.ActiveSTUNInspector{
		AcquireMachine: func(string) (passivediagnose.ActiveSTUNAuthority, error) { return authority, nil },
		BuildVersion:   "test-build",
	}
	cmd := newDiagnoseCmdWithRunners(&Options{}, &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}, active)
	stdout := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--json", "--active-stun", successTarget.String(), "--active-stun", protocolFailureTarget.String()})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("active diagnose mixed targets: %v", err)
	}
	var report passivediagnose.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode mixed report: %v\n%s", err, stdout.String())
	}
	if report.ActiveSTUN == nil || report.ActiveSTUN.State != passivediagnose.ActiveSTUNStateCompletedWithErrs || len(report.ActiveSTUN.Results) != 2 {
		t.Fatalf("mixed active report = %+v", report.ActiveSTUN)
	}
	if report.ActiveSTUN.Results[0].MappedAddress == "" || report.ActiveSTUN.Results[0].ErrorClass != "" {
		t.Fatalf("mixed success = %+v", report.ActiveSTUN.Results[0])
	}
	if report.ActiveSTUN.Results[1].ErrorClass != "protocol_error" || report.ActiveSTUN.Results[1].Reason != "magic_cookie_mismatch" {
		t.Fatalf("mixed protocol failure = %+v", report.ActiveSTUN.Results[1])
	}
	if authority.peer == nil || authority.peer.acquireCalls != 2 {
		t.Fatalf("serial attempt count = %+v", authority.peer)
	}
}

func TestDiagnoseActiveSTUNRejectsDNSAndMoreThanThreeBeforeCollection(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "DNS", args: []string{"--active-stun", "stun.invalid:3478"}, want: "DNS names are not accepted"},
		{name: "too many", args: []string{"--active-stun", "127.0.0.1:1", "--active-stun", "127.0.0.1:2", "--active-stun", "127.0.0.1:3", "--active-stun", "127.0.0.1:4"}, want: "maximum 3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			passive := &fakePassiveDiagnoseRunner{report: passiveDiagnoseFixture()}
			active := &fakeActiveSTUNRunner{t: t, forbid: true}
			cmd := newDiagnoseCmdWithRunners(&Options{}, passive, active)
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs(test.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
			if passive.calls != 0 || active.calls != 0 {
				t.Fatalf("collectors ran before validation: passive=%d active=%d", passive.calls, active.calls)
			}
		})
	}
}

func TestDiagnoseActiveSTUNPassesOnlyExplicitUserScopeToRunner(t *testing.T) {
	passiveReport := passiveDiagnoseFixture()
	passiveReport.GovernorScope = governor.ScopeUserAcknowledged
	passive := &fakePassiveDiagnoseRunner{report: passiveReport}
	active := &fakeActiveSTUNRunner{report: passivediagnose.ActiveSTUNReport{
		State:                  passivediagnose.ActiveSTUNStateCompleted,
		ObservationScope:       "time_window_only",
		TargetCount:            1,
		NetworkActivityStarted: true,
	}}
	cmd := newDiagnoseCmdWithRunners(&Options{}, passive, active)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"--governor-scope", "user-acknowledged", "--active-stun", "127.0.0.1:3478", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("explicit user active STUN: %v", err)
	}
	if active.calls != 1 || active.options.GovernorScope != governor.ScopeUserAcknowledged || len(active.options.Targets) != 1 {
		t.Fatalf("active options = %+v calls=%d", active.options, active.calls)
	}
	for _, warning := range []string{"not machine-wide safety", "source IP address", "observation timing"} {
		if !strings.Contains(stderr.String(), warning) {
			t.Fatalf("stderr missing %q: %s", warning, stderr.String())
		}
	}
}

type fakeActiveSTUNRunner struct {
	t       *testing.T
	forbid  bool
	report  passivediagnose.ActiveSTUNReport
	err     error
	calls   int
	options passivediagnose.ActiveSTUNOptions
}

func (runner *fakeActiveSTUNRunner) Run(_ context.Context, options passivediagnose.ActiveSTUNOptions) (passivediagnose.ActiveSTUNReport, error) {
	runner.calls++
	runner.options = options
	if runner.forbid {
		runner.t.Fatal("active STUN runner called without an explicit flag")
	}
	return runner.report, runner.err
}

type cliActiveSTUNAuthority struct {
	snapshot   governor.Snapshot
	peer       *cliActiveSTUNPeer
	closeCalls int
}

func (authority *cliActiveSTUNAuthority) Snapshot() governor.Snapshot { return authority.snapshot }

func (authority *cliActiveSTUNAuthority) AcquireDiagnosticPeer(string) (passivediagnose.ActiveSTUNPeer, error) {
	authority.peer = &cliActiveSTUNPeer{}
	return authority.peer, nil
}

func (authority *cliActiveSTUNAuthority) Close() error {
	authority.closeCalls++
	return nil
}

type cliActiveSTUNPeer struct {
	acquireCalls int
	closeCalls   int
}

func (peer *cliActiveSTUNPeer) AcquireDiagnosticAttempt(_ context.Context, id string, cost governor.AttemptCost) (probeio.AttemptLease, error) {
	peer.acquireCalls++
	return newCLIActiveSTUNLease(governor.AttemptRequest{ID: id, Operation: governor.OperationDiagnose, Cost: cost}), nil
}

func (peer *cliActiveSTUNPeer) Close() error {
	peer.closeCalls++
	return nil
}

type cliActiveSTUNLease struct {
	request  governor.AttemptRequest
	stopping chan struct{}
	done     chan struct{}
	once     sync.Once
}

func newCLIActiveSTUNLease(request governor.AttemptRequest) *cliActiveSTUNLease {
	return &cliActiveSTUNLease{request: request, stopping: make(chan struct{}), done: make(chan struct{})}
}

func (lease *cliActiveSTUNLease) Request() governor.AttemptRequest { return lease.request }
func (*cliActiveSTUNLease) PeerID() string                         { return "diagnose-active-stun" }
func (lease *cliActiveSTUNLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *cliActiveSTUNLease) Done() <-chan struct{}            { return lease.done }
func (*cliActiveSTUNLease) RegisterDrain(string) (governor.DrainHandle, error) {
	return cliActiveSTUNDrain{}, nil
}
func (lease *cliActiveSTUNLease) Close() error {
	lease.once.Do(func() {
		close(lease.stopping)
		close(lease.done)
	})
	return nil
}
func (*cliActiveSTUNLease) Trip(governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	return governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true}, nil
}

type cliActiveSTUNDrain struct{}

func (cliActiveSTUNDrain) Complete() error { return nil }

func startCLIStunResponder(t *testing.T, corruptCookie bool) netip.AddrPort {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen loopback STUN responder: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 1024)
		count, source, readErr := connection.ReadFromUDPAddrPort(buffer)
		if readErr != nil || count < 20 {
			return
		}
		response := make([]byte, 32)
		binary.BigEndian.PutUint16(response[0:2], 0x0101)
		binary.BigEndian.PutUint16(response[2:4], 12)
		cookieValue := uint32(0x2112a442)
		if corruptCookie {
			cookieValue++
		}
		binary.BigEndian.PutUint32(response[4:8], cookieValue)
		copy(response[8:20], buffer[8:20])
		binary.BigEndian.PutUint16(response[20:22], 0x0020)
		binary.BigEndian.PutUint16(response[22:24], 8)
		response[25] = 0x01
		binary.BigEndian.PutUint16(response[26:28], source.Port()^0x2112)
		address := source.Addr().As4()
		cookie := [4]byte{0x21, 0x12, 0xa4, 0x42}
		for index := range address {
			response[28+index] = address[index] ^ cookie[index]
		}
		_, _ = connection.WriteToUDPAddrPort(response, source)
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		<-done
	})
	return connection.LocalAddr().(*net.UDPAddr).AddrPort()
}
