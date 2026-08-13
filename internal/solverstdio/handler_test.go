package solverstdio

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
)

func TestSupportedMethodsAreExactAndExcludeNetworkCapabilities(t *testing.T) {
	want := []string{"handshake", "status", "diagnose", "export_redacted_report", "connect_test", "cancel"}
	if got := SupportedMethods(); !reflect.DeepEqual(got, want) {
		t.Fatalf("methods = %v, want %v", got, want)
	}
	joined := strings.Join(SupportedMethods(), "\n")
	for _, forbidden := range []string{"open_socket", "send_packet", "scan_ports", "port_scan", "bulk_targets", "raise_limits"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("v1 method set contains forbidden capability %q", forbidden)
		}
	}
	copyMethods := SupportedMethods()
	copyMethods[0] = "mutated"
	if SupportedMethods()[0] != MethodHandshake {
		t.Fatal("supported method list leaked mutable ownership")
	}
}

func TestHandshakeRequiresExactVersions(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodHandshake, `{"schema_version":"future","framing_version":"lsp-content-length/v1"}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != ClassIncompatibleVersion || handler.handshaken.Load() {
		t.Fatalf("incompatible handshake = %+v, complete=%t", rpcErr, handler.handshaken.Load())
	}
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodHandshake, `{"schema_version":"winkyou.stdio/v1","framing_version":"lsp-content-length/v1"}`), discardProgress{})
	if rpcErr != nil {
		t.Fatalf("valid handshake: %+v", rpcErr)
	}
	handshake, ok := result.(HandshakeResult)
	if !ok || handshake.SchemaVersion != SchemaVersion || handshake.FramingVersion != FramingVersion || !handler.handshaken.Load() {
		t.Fatalf("handshake result = %+v", result)
	}
}

func TestHandshakeIsRequiredBeforeEveryNonCancelMethod(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	for _, method := range []string{MethodStatus, MethodDiagnose, MethodExportRedactedReport, MethodConnectTest, "open_socket"} {
		_, rpcErr := handler.Handle(context.Background(), testRequest(t, method, `{}`), discardProgress{})
		if rpcErr == nil || rpcErr.Data.Class != ClassHandshakeRequired {
			t.Fatalf("%s before handshake = %+v", method, rpcErr)
		}
	}
}

func TestSafetyTripAllowsOnlyHandshakeStatusAndFrameworkCancel(t *testing.T) {
	authority := &fakeAuthority{status: governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true}}
	diagnose := staticDiagnose{report: passivediagnose.Report{GeneratedAt: time.Date(2026, 8, 13, 1, 2, 3, 0, time.UTC), GovernorScope: governor.ScopeMachine}}
	writes := 0
	handler := newTestHandler(t, authority, diagnose, func(string, passivediagnose.Report) (int64, error) {
		writes++
		return 0, nil
	})
	if _, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodHandshake, validHandshakeParams()), discardProgress{}); rpcErr != nil {
		t.Fatalf("handshake under trip: %+v", rpcErr)
	}
	if _, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodStatus, `{}`), discardProgress{}); rpcErr != nil {
		t.Fatalf("status under trip: %+v", rpcErr)
	}
	for _, request := range []stdiojsonrpc.Request{
		testRequest(t, MethodDiagnose, `{}`),
		testRequest(t, MethodExportRedactedReport, `{"path":"ignored"}`),
		testRequest(t, MethodConnectTest, `{"auth_scope":"test_only","complete_bundle":{}}`),
	} {
		_, rpcErr := handler.Handle(context.Background(), request, discardProgress{})
		if rpcErr == nil || rpcErr.Data.Class != ClassSafetyTripActive || rpcErr.Data.Reason != string(governor.SafetyTripTripped) {
			t.Fatalf("%s under trip = %+v", request.Method, rpcErr)
		}
	}
	if writes != 0 {
		t.Fatalf("trip-blocked export wrote %d file(s)", writes)
	}
	if !contains(SupportedMethods(), MethodCancel) {
		t.Fatal("framework cancel is missing from the safety allowlist")
	}
}

func TestDiagnoseReturnsExistingPassiveReportAndProgress(t *testing.T) {
	report := passivediagnose.Report{
		SchemaVersion:          passivediagnose.SchemaVersion,
		Mode:                   "passive_only",
		Redaction:              "partial",
		GovernorScope:          governor.ScopeMachine,
		NetworkActivityStarted: false,
	}
	runner := &recordingDiagnose{report: report}
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, runner, nil)
	handler.handshaken.Store(true)
	progress := &recordingProgress{}
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodDiagnose, `{}`), progress)
	if rpcErr != nil {
		t.Fatalf("diagnose: %+v", rpcErr)
	}
	if !reflect.DeepEqual(result, report) {
		t.Fatalf("diagnose result = %+v, want %+v", result, report)
	}
	if got := progress.stages(); !reflect.DeepEqual(got, []string{"collecting_passive_report", "complete"}) {
		t.Fatalf("progress stages = %v", got)
	}
	if runner.options.ConfigPath != "test-config.yaml" || runner.options.GovernorScope != governor.ScopeMachine {
		t.Fatalf("diagnose options = %+v", runner.options)
	}
}

func TestExportWritesStrictReportWithoutReturningReportOrPath(t *testing.T) {
	privateMarker := "sensitive-local-marker"
	report := passivediagnose.Report{
		SchemaVersion: passivediagnose.SchemaVersion,
		Redaction:     "partial",
		Configuration: passivediagnose.ConfigStatus{State: passivediagnose.ConfigInvalid, Source: privateMarker, Detail: privateMarker},
	}
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{report: report}, passivediagnose.WriteRedactedReport)
	handler.handshaken.Store(true)
	path := filepath.Join(t.TempDir(), "shareable.json")
	params, err := json.Marshal(map[string]any{"path": path})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodExportRedactedReport, string(params)), &recordingProgress{})
	if rpcErr != nil {
		t.Fatalf("export: %+v", rpcErr)
	}
	export, ok := result.(ExportResult)
	if !ok || !export.Written || export.Redaction != passivediagnose.ExportRedaction || export.Bytes <= 0 {
		t.Fatalf("export result = %+v", result)
	}
	encodedResult, _ := json.Marshal(result)
	if strings.Contains(string(encodedResult), path) || strings.Contains(string(encodedResult), privateMarker) {
		t.Fatalf("export response reflected private data: %s", encodedResult)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if strings.Contains(string(payload), privateMarker) || !strings.Contains(string(payload), `"redaction": "strict"`) {
		t.Fatalf("exported payload is not strictly redacted: %s", payload)
	}
}

func TestExportErrorDoesNotReflectDestination(t *testing.T) {
	privatePath := filepath.Join(t.TempDir(), "private-destination.json")
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, func(string, passivediagnose.Report) (int64, error) {
		return 0, errors.New("failure at " + privatePath)
	})
	handler.handshaken.Store(true)
	params, _ := json.Marshal(map[string]any{"path": privatePath})
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodExportRedactedReport, string(params)), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != ClassExportFailed || strings.Contains(rpcErr.Message, privatePath) || strings.Contains(rpcErr.Data.Reason, privatePath) {
		t.Fatalf("export error = %+v", rpcErr)
	}
}

func TestConnectTestIsStableNotImplementedGate(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, `{"auth_scope":"test_only","complete_bundle":{},"deadline_ms":15000}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != ClassNotImplemented || rpcErr.Data.Reason != "crypto_adr_vectors_and_independent_security_review_required" {
		t.Fatalf("connect_test gate = %+v", rpcErr)
	}
}

func TestUnknownAndLimitRaisingMethodsAreRejected(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	for _, method := range []string{"open_socket", "send_packet", "scan_ports", "set_hard_limits"} {
		_, rpcErr := handler.Handle(context.Background(), testRequest(t, method, `{}`), discardProgress{})
		if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassMethodNotFound {
			t.Fatalf("%s error = %+v", method, rpcErr)
		}
	}
}

func TestDeadlineRejectsOverflowAndHardLimitExcess(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	for _, params := range []string{`{"deadline_ms":9223372036854775807}`, `{"deadline_ms":30001}`, `{"deadline_ms":0}`} {
		_, rpcErr := handler.deadline(testRequest(t, MethodStatus, params))
		if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInvalidParams {
			t.Fatalf("deadline %s = %+v", params, rpcErr)
		}
	}
	deadline, rpcErr := handler.deadline(testRequest(t, MethodStatus, `{"deadline_ms":1234}`))
	if rpcErr != nil || deadline != 1234*time.Millisecond {
		t.Fatalf("valid deadline = %s, %+v", deadline, rpcErr)
	}
}

type fakeAuthority struct {
	info   governor.OwnerInfo
	status governor.SafetyTripStatus
	closed bool
	mu     sync.Mutex
}

func (authority *fakeAuthority) Info() governor.OwnerInfo {
	return authority.info
}

func (authority *fakeAuthority) SafetyTripStatus() governor.SafetyTripStatus {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.status
}

func (authority *fakeAuthority) Close() error {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.closed = true
	return nil
}

type staticDiagnose struct {
	report passivediagnose.Report
}

func (runner staticDiagnose) Run(context.Context, passivediagnose.Options) passivediagnose.Report {
	return runner.report
}

type recordingDiagnose struct {
	report  passivediagnose.Report
	options passivediagnose.Options
}

func (runner *recordingDiagnose) Run(_ context.Context, options passivediagnose.Options) passivediagnose.Report {
	runner.options = options
	return runner.report
}

type discardProgress struct{}

func (discardProgress) Report(string, bool) error { return nil }

type recordingProgress struct {
	mu      sync.Mutex
	reports []string
}

func (progress *recordingProgress) Report(stage string, _ bool) error {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	progress.reports = append(progress.reports, stage)
	return nil
}

func (progress *recordingProgress) stages() []string {
	progress.mu.Lock()
	defer progress.mu.Unlock()
	return append([]string(nil), progress.reports...)
}

func newTestHandler(t *testing.T, authority authority, diagnose diagnoseRunner, writer func(string, passivediagnose.Report) (int64, error)) *handler {
	t.Helper()
	if writer == nil {
		writer = func(string, passivediagnose.Report) (int64, error) { return 1, nil }
	}
	limits := stdiojsonrpc.DefaultLimits()
	handler, err := newHandler(authority, diagnose, writer, Options{ConfigPath: "test-config.yaml"}, BuildInfo{Version: "test"}, limits)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

func testRequest(t *testing.T, method, params string) stdiojsonrpc.Request {
	t.Helper()
	payload := `{"jsonrpc":"2.0","id":"test-request","method":` + quoteJSON(method) + `,"params":` + params + `}`
	request, rpcErr := stdiojsonrpc.ParseRequest([]byte(payload))
	if rpcErr != nil {
		t.Fatalf("parse test request: %+v", rpcErr)
	}
	return request
}

func quoteJSON(value string) string {
	payload, _ := json.Marshal(value)
	return string(payload)
}

func validHandshakeParams() string {
	return `{"schema_version":"winkyou.stdio/v1","framing_version":"lsp-content-length/v1"}`
}

func clearTrip() governor.SafetyTripStatus {
	return governor.SafetyTripStatus{State: governor.SafetyTripClear}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
