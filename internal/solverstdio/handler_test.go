package solverstdio

import (
	"bytes"
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
	"winkyou/internal/v2/directconnect"
	"winkyou/internal/v2/loopbackcarrier"
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

func TestHandshakeV2IsExplicitAndCannotSwitchVersions(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodHandshake, `{"schema_version":"winkyou.stdio/v2","framing_version":"lsp-content-length/v1"}`), discardProgress{})
	if rpcErr != nil {
		t.Fatalf("v2 handshake: %+v", rpcErr)
	}
	handshake, ok := result.(HandshakeResultV2)
	wantProfiles := []string{"loopback_complete_bundle", "winkyou-test-direct-attempt-oob/1"}
	if !ok || handshake.SchemaVersion != SchemaVersionV2 || !reflect.DeepEqual(handshake.ConnectTestProfiles, wantProfiles) || handler.version.Load() != 2 {
		t.Fatalf("v2 handshake = %+v", result)
	}
	if _, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodHandshake, validHandshakeParams()), discardProgress{}); rpcErr == nil || rpcErr.Data.Class != ClassIncompatibleVersion {
		t.Fatalf("v2 to v1 switch = %+v", rpcErr)
	}

	v1 := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	if _, rpcErr := v1.Handle(context.Background(), testRequest(t, MethodHandshake, validHandshakeParams()), discardProgress{}); rpcErr != nil {
		t.Fatal(rpcErr)
	}
	if _, rpcErr := v1.Handle(context.Background(), testRequest(t, MethodHandshake, `{"schema_version":"winkyou.stdio/v2","framing_version":"lsp-content-length/v1"}`), discardProgress{}); rpcErr == nil || rpcErr.Data.Class != ClassIncompatibleVersion {
		t.Fatalf("v1 to v2 switch = %+v", rpcErr)
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
	statusResult, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodStatus, `{}`), discardProgress{})
	if rpcErr != nil {
		t.Fatalf("status under trip: %+v", rpcErr)
	}
	status, ok := statusResult.(StatusResult)
	if !ok || status.PairingLedger.State != governor.PairingLedgerIndeterminate || !status.PairingLedger.BlocksActiveWork {
		t.Fatalf("status pairing ledger = %+v", statusResult)
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
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal stdio diagnose result: %v", err)
	}
	if strings.Contains(string(encoded), `"active_stun"`) || strings.Contains(string(encoded), `"mapping_behavior"`) || strings.Contains(string(encoded), `"port_allocation"`) {
		t.Fatalf("CLI-only active STUN mode leaked into stdio diagnose schema: %s", encoded)
	}
}

func TestDiagnoseRejectsCLIOnlyMapBehaviorParameter(t *testing.T) {
	runner := &recordingDiagnose{}
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, runner, nil)
	handler.handshaken.Store(true)
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodDiagnose, `{"map_behavior":true}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInvalidParams {
		t.Fatalf("mapping parameter error = %+v", rpcErr)
	}
	if runner.options != (passivediagnose.Options{}) {
		t.Fatalf("passive runner called with %+v", runner.options)
	}
}

func TestDiagnoseRejectsCLIOnlyPortAllocationParameter(t *testing.T) {
	runner := &recordingDiagnose{}
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, runner, nil)
	handler.handshaken.Store(true)
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodDiagnose, `{"port_allocation":5}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInvalidParams {
		t.Fatalf("port allocation parameter error = %+v", rpcErr)
	}
	if runner.options != (passivediagnose.Options{}) {
		t.Fatalf("passive runner called with %+v", runner.options)
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

func TestConnectTestWithoutReviewedAuthorityFailsStable(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, `{"auth_scope":"test_only","complete_bundle":{},"deadline_ms":15000}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != ClassNotImplemented || rpcErr.Data.Reason != "loopback_carrier_not_available" {
		t.Fatalf("connect_test gate = %+v", rpcErr)
	}
}

func TestConnectTestExecutesReviewedLoopbackAuthorityAndRedactsBundle(t *testing.T) {
	authority := &fakeConnectAuthority{
		fakeAuthority: fakeAuthority{status: clearTrip()},
		result: loopbackcarrier.Result{
			Established: true, Bidirectional: true, Promoted: true,
			Terminal: "success", NetworkScope: "loopback", OutboundPackets: 3,
			WorstCaseEnvelope: governor.PairingEnvelopeFromAttemptCost(loopbackcarrier.AttemptCost()),
		},
		ledger: governor.PairingLedgerStatus{State: governor.PairingLedgerReady, Limits: governor.PairingAdmissionHardLimits()},
	}
	handler := newTestHandler(t, authority, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	progress := &recordingProgress{}
	secretMarker := "bundle-secret-marker"
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, `{"auth_scope":"test_only","complete_bundle":{"marker":"`+secretMarker+`"},"deadline_ms":15000}`), progress)
	if rpcErr != nil {
		t.Fatalf("connect_test: %+v", rpcErr)
	}
	if got := progress.stages(); !reflect.DeepEqual(got, []string{"validating_complete_bundle", "loopback_socket_ready", "terminal_finish_recorded"}) {
		t.Fatalf("progress stages = %v", got)
	}
	response, ok := result.(ConnectTestResult)
	if !ok || !response.Result.Established || response.PairingLedger.State != governor.PairingLedgerReady {
		t.Fatalf("connect result = %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), secretMarker) || strings.Contains(string(encoded), "complete_bundle") {
		t.Fatalf("connect response reflected bundle: %s", encoded)
	}
	if string(authority.payload) != `{"marker":"`+secretMarker+`"}` {
		t.Fatalf("authority payload = %s", authority.payload)
	}
}

func TestConnectTestSocketReadyProgressFailureReturnsInternalError(t *testing.T) {
	authority := &fakeConnectAuthority{fakeAuthority: fakeAuthority{status: clearTrip()}}
	handler := newTestHandler(t, authority, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	progress := &stageFailingProgress{stage: string(loopbackcarrier.ProgressStageSocketReady)}
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, `{"auth_scope":"test_only","complete_bundle":{}}`), progress)
	if result != nil || rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInternalError {
		t.Fatalf("progress failure = result %+v error %+v", result, rpcErr)
	}
}

func TestConnectTestReturnsStableLoopbackErrorsAndRejectsUnknownFields(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		class string
	}{
		{"non-loopback", loopbackcarrier.ErrNonLoopbackBlocked, ClassNonLoopbackBlocked},
		{"user scope", loopbackcarrier.ErrUserScopeBlocked, ClassUserScopeBlocked},
		{"invalid bundle", loopbackcarrier.ErrInvalidBundle, ClassInvalidCompleteBundle},
		{"admission", governor.ErrPairingAdmissionRejected, ClassPairingAdmissionBlocked},
		{"carrier", loopbackcarrier.ErrCarrierProtocol, ClassConnectTestFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := &fakeConnectAuthority{fakeAuthority: fakeAuthority{status: clearTrip()}, err: test.err}
			handler := newTestHandler(t, authority, staticDiagnose{}, nil)
			handler.handshaken.Store(true)
			_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, `{"auth_scope":"test_only","complete_bundle":{}}`), discardProgress{})
			if rpcErr == nil || rpcErr.Data.Class != test.class || rpcErr.Data.Reason != test.class {
				t.Fatalf("error = %+v", rpcErr)
			}
		})
	}
	handler := newTestHandler(t, &fakeConnectAuthority{fakeAuthority: fakeAuthority{status: clearTrip()}}, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, `{"auth_scope":"test_only","complete_bundle":{},"unexpected":true}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInvalidParams {
		t.Fatalf("unknown field = %+v", rpcErr)
	}
}

func TestConnectTestV2LoopbackKeepsExistingParserAndProgress(t *testing.T) {
	authority := &fakeConnectAuthority{
		fakeAuthority: fakeAuthority{status: clearTrip()},
		result:        loopbackcarrier.Result{Established: true, Terminal: "success"},
	}
	handler := newTestHandler(t, authority, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	handler.version.Store(2)
	progress := &recordingProgress{}
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest,
		`{"auth_scope":"test_only","attempt":{"kind":"loopback_complete_bundle","complete_bundle":{"marker":"secret"}},"deadline_ms":15000}`), progress)
	if rpcErr != nil {
		t.Fatalf("v2 loopback: %+v", rpcErr)
	}
	if _, ok := result.(ConnectTestResult); !ok || string(authority.payload) != `{"marker":"secret"}` {
		t.Fatalf("v2 loopback result=%+v payload=%s", result, authority.payload)
	}
	if got := progress.stages(); !reflect.DeepEqual(got, []string{"validating_complete_bundle", "loopback_socket_ready", "terminal_finish_recorded"}) {
		t.Fatalf("progress = %v", got)
	}
}

func TestConnectTestCrossVersionRequestsFailClosedBeforeAuthority(t *testing.T) {
	legacy := &fakeConnectAuthority{fakeAuthority: fakeAuthority{status: clearTrip()}}
	v2Handler := newTestHandler(t, legacy, staticDiagnose{}, nil)
	v2Handler.handshaken.Store(true)
	v2Handler.version.Store(2)
	_, rpcErr := v2Handler.Handle(context.Background(), testRequest(t, MethodConnectTest,
		`{"auth_scope":"test_only","complete_bundle":{},"deadline_ms":15000}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInvalidParams || legacy.calls != 0 {
		t.Fatalf("v1 request under v2 = %+v calls=%d", rpcErr, legacy.calls)
	}

	direct := &fakeDirectAuthority{fakeAuthority: fakeAuthority{status: clearTrip()}}
	v1Handler := newTestHandler(t, direct, staticDiagnose{}, nil)
	v1Handler.handshaken.Store(true)
	v1Handler.version.Store(1)
	_, rpcErr = v1Handler.Handle(context.Background(), testRequest(t, MethodConnectTest,
		`{"auth_scope":"test_only","attempt":{"kind":"loopback_complete_bundle","complete_bundle":{}},"deadline_ms":15000}`), discardProgress{})
	if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInvalidParams || direct.calls != 0 {
		t.Fatalf("v2 request under v1 = %+v calls=%d", rpcErr, direct.calls)
	}
}

func TestConnectTestV2DirectUsesOnlyDirectAuthority(t *testing.T) {
	authority := &fakeDirectAuthority{
		fakeAuthority: fakeAuthority{status: clearTrip()},
		result:        directconnect.Result{AttemptKind: "direct_oob_artifact", Terminal: "success", Bidirectional: true},
	}
	handler := newTestHandler(t, authority, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	handler.version.Store(2)
	progress := &recordingProgress{}
	result, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, validDirectV2Params(`{"artifact":"synthetic"}`)), progress)
	if rpcErr != nil {
		t.Fatalf("v2 direct: %+v", rpcErr)
	}
	response, ok := result.(directconnect.Result)
	if !ok || !response.Bidirectional || string(authority.config.Artifact) != `{"artifact":"synthetic"}` {
		t.Fatalf("direct result=%+v config=%+v", result, authority.config)
	}
	wantStages := []string{"present", "burned", "activated", "handshake", "prepare", "socket", "stun", "ready", "fire", "punch_sent", "punch", "verify", "terminal"}
	if got := progress.stages(); !reflect.DeepEqual(got, wantStages) {
		t.Fatalf("direct progress = %v", got)
	}
}

func TestConnectTestV2TaggedUnionRejectsAmbiguityBeforeAuthority(t *testing.T) {
	authority := &fakeDirectAuthority{fakeAuthority: fakeAuthority{status: clearTrip()}}
	handler := newTestHandler(t, authority, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	handler.version.Store(2)
	tests := []string{
		`{"auth_scope":"test_only","attempt":{"kind":"loopback_complete_bundle","complete_bundle":{}},"stun_endpoint":""}`,
		`{"auth_scope":"test_only","attempt":{"kind":"loopback_complete_bundle","complete_bundle":{},"oob_artifact":null}}`,
		`{"auth_scope":"test_only","attempt":{"kind":"direct_oob_artifact","oob_artifact":{},"complete_bundle":{}},"rendezvous":{},"stun_endpoint":"192.0.2.1:3478"}`,
		`{"auth_scope":"test_only","attempt":{"kind":"direct_oob_artifact","oob_artifact":{},"unexpected":true},"rendezvous":{},"stun_endpoint":"192.0.2.1:3478"}`,
		`{"auth_scope":"test_only","auth_scope":"test_only","attempt":{"kind":"direct_oob_artifact","oob_artifact":{}},"rendezvous":{},"stun_endpoint":"192.0.2.1:3478"}`,
		`{"auth_scope":"test_only","attempt":{"kind":"direct_oob_artifact","kind":"direct_oob_artifact","oob_artifact":{}},"rendezvous":{},"stun_endpoint":"192.0.2.1:3478"}`,
		`{"auth_scope":"test_only","attempt":{"kind":"direct_oob_artifact","oob_artifact":{}},"rendezvous":{"endpoint":"192.0.2.10:443","endpoint":"192.0.2.11:443","deployment_tier":"self_hosted","tls":{"verification":"spki_sha256","spki_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},"stun_endpoint":"192.0.2.1:3478"}`,
		`{"auth_scope":"test_only","attempt":{"kind":"direct_oob_artifact","oob_artifact":{}},"rendezvous":{"endpoint":"192.0.2.10:443","deployment_tier":"self_hosted","tls":{"verification":"spki_sha256","verification":"spki_sha256","spki_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},"stun_endpoint":"192.0.2.1:3478"}`,
	}
	for _, params := range tests {
		_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest, params), discardProgress{})
		if rpcErr == nil || rpcErr.Data.Class != stdiojsonrpc.ClassInvalidParams {
			t.Fatalf("ambiguous params %s = %+v", params, rpcErr)
		}
	}
	if authority.calls != 0 {
		t.Fatalf("invalid union reached direct authority %d time(s)", authority.calls)
	}
}

func TestConnectTestV2UnknownProfileAndDirectFailureHaveFrozenData(t *testing.T) {
	handler := newTestHandler(t, &fakeDirectAuthority{fakeAuthority: fakeAuthority{status: clearTrip()}}, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	handler.version.Store(2)
	progress := &recordingProgress{}
	_, rpcErr := handler.Handle(context.Background(), testRequest(t, MethodConnectTest,
		`{"auth_scope":"test_only","attempt":{"kind":"future_profile"}}`), progress)
	assertDirectErrorData(t, rpcErr, directconnect.ClassUnsupportedAttemptProfile, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected)
	if got := progress.stages(); !reflect.DeepEqual(got, []string{"terminal"}) {
		t.Fatalf("unknown profile progress = %v", got)
	}

	failing := &fakeDirectAuthority{
		fakeAuthority: fakeAuthority{status: clearTrip()},
		err: &directconnect.Failure{
			Class: directconnect.ClassSTUNSilent, Stage: directconnect.StageSTUN,
			CredentialBurned: true, TerminalCategory: directconnect.CategoryAttemptFailed,
		},
	}
	handler = newTestHandler(t, failing, staticDiagnose{}, nil)
	handler.handshaken.Store(true)
	handler.version.Store(2)
	_, rpcErr = handler.Handle(context.Background(), testRequest(t, MethodConnectTest, validDirectV2Params(`{}`)), discardProgress{})
	assertDirectErrorData(t, rpcErr, directconnect.ClassSTUNSilent, directconnect.StageSTUN, true, directconnect.CategoryAttemptFailed)
}

func TestDirectErrorClassDataGoldenAndCauseRedaction(t *testing.T) {
	type entry struct {
		Class            string `json:"class"`
		Stage            string `json:"stage"`
		CredentialBurned bool   `json:"credential_burned"`
		TerminalCategory string `json:"terminal_category"`
	}
	entries := []entry{
		{directconnect.ClassUnsupportedAttemptProfile, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassInvalidDirectArtifact, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassArtifactNotYetValid, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassArtifactExpired, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassRendezvousEndpointInvalid, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassSTUNEndpointInvalid, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassRendezvousDNSFailed, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassRendezvousDNSAmbiguous, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassRendezvousTLSFailed, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassRendezvousUnreachable, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassPresenceTimeout, directconnect.StageTerminal, false, directconnect.CategoryPreflightRejected},
		{directconnect.ClassPairingScopeChanged, directconnect.StageBurned, false, directconnect.CategoryAdmissionBlocked},
		{directconnect.ClassLedgerIndeterminate, directconnect.StageBurned, false, directconnect.CategoryAdmissionBlocked},
		{directconnect.ClassCredentialUsed, directconnect.StageBurned, false, directconnect.CategoryAdmissionBlocked},
		{directconnect.ClassPairingRateLimited, directconnect.StageBurned, false, directconnect.CategoryAdmissionBlocked},
		{directconnect.ClassPairingCircuitOpen, directconnect.StageBurned, false, directconnect.CategoryAdmissionBlocked},
		{directconnect.ClassActivationFailed, directconnect.StageActivated, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassSecureHandshakeFailed, directconnect.StageHandshake, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassControlAuthentication, directconnect.StagePrepare, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassRendezvousProtocol, directconnect.StagePrepare, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassCarrierDomainViolation, directconnect.StagePrepare, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassRendezvousBudgetExceeded, directconnect.StagePrepare, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassSTUNSilent, directconnect.StageSTUN, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassSTUNProtocol, directconnect.StageSTUN, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassSTUNSourceMismatch, directconnect.StageSTUN, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassReadyRejected, directconnect.StageReady, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassPunchTimeout, directconnect.StagePunch, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassDirectPacketRejected, directconnect.StagePunch, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassVerificationFailed, directconnect.StageVerify, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassPeerCancelled, directconnect.StageReady, true, directconnect.CategoryCancelled},
		{directconnect.ClassAttemptExpired, directconnect.StagePunch, true, directconnect.CategoryAttemptFailed},
		{directconnect.ClassResourceBudgetExceeded, directconnect.StageSocket, true, directconnect.CategorySafetyTripped},
		{directconnect.ClassDrainFailed, directconnect.StageTerminal, true, directconnect.CategorySafetyTripped},
		{directconnect.ClassDirectAttemptFailed, directconnect.StagePreflight, false, directconnect.CategoryPreflightRejected},
	}
	payload, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	want, err := os.ReadFile("testdata/direct-error-classes.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(payload, want) {
		t.Fatalf("direct error class golden changed\ngot:\n%s\nwant:\n%s", payload, want)
	}

	privateCause := errors.New("dial 192.0.2.91:443 from private-host user-private path-private")
	for _, current := range entries {
		rpcErr := directConnectError(&directconnect.Failure{
			Class: current.Class, Stage: current.Stage, CredentialBurned: current.CredentialBurned,
			TerminalCategory: current.TerminalCategory, Cause: privateCause,
		})
		encoded, err := json.Marshal(rpcErr)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("192.0.2.91")) || bytes.Contains(encoded, []byte("private-host")) ||
			bytes.Contains(encoded, []byte("user-private")) || bytes.Contains(encoded, []byte("path-private")) {
			t.Fatalf("direct error %q leaked an internal cause: %s", current.Class, encoded)
		}
		assertDirectErrorData(t, rpcErr, current.Class, current.Stage, current.CredentialBurned, current.TerminalCategory)
	}
}

func TestDirectV2DeadlineDefaultsAndCanOnlyDecrease(t *testing.T) {
	handler := newTestHandler(t, &fakeAuthority{status: clearTrip()}, staticDiagnose{}, nil)
	handler.version.Store(2)
	direct, rpcErr := handler.deadline(testRequest(t, MethodConnectTest, validDirectV2Params(`{}`)))
	if rpcErr != nil || direct != 15*time.Second {
		t.Fatalf("direct default deadline = %s, %+v", direct, rpcErr)
	}
	loopback, rpcErr := handler.deadline(testRequest(t, MethodConnectTest,
		`{"auth_scope":"test_only","attempt":{"kind":"loopback_complete_bundle","complete_bundle":{}}}`))
	if rpcErr != nil || loopback != 0 {
		t.Fatalf("loopback default deadline = %s, %+v", loopback, rpcErr)
	}
	raised := strings.TrimSuffix(validDirectV2Params(`{}`), "}") + `,"deadline_ms":15001}`
	_, rpcErr = handler.deadline(testRequest(t, MethodConnectTest, raised))
	if rpcErr == nil || rpcErr.Data.Limit != 15000 {
		t.Fatalf("direct raised deadline = %+v", rpcErr)
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

type fakeConnectAuthority struct {
	fakeAuthority
	result  loopbackcarrier.Result
	err     error
	payload []byte
	ledger  governor.PairingLedgerStatus
	calls   int
}

type fakeDirectAuthority struct {
	fakeAuthority
	result directconnect.Result
	err    error
	config directconnect.Config
	calls  int
}

func (authority *fakeDirectAuthority) ConnectDirect(_ context.Context, config directconnect.Config) (directconnect.Result, error) {
	authority.calls++
	authority.config = config
	authority.config.Artifact = append([]byte(nil), config.Artifact...)
	if authority.err == nil && config.Progress != nil {
		for _, stage := range []string{
			directconnect.StagePresent, directconnect.StageBurned, directconnect.StageActivated,
			directconnect.StageHandshake, directconnect.StagePrepare, directconnect.StageSocket,
			directconnect.StageSTUN, directconnect.StageReady, directconnect.StageFire,
			directconnect.StagePunchSent, directconnect.StagePunch, directconnect.StageVerify,
			directconnect.StageTerminal,
		} {
			if err := config.Progress(stage, stage != directconnect.StageTerminal); err != nil {
				return directconnect.Result{}, errors.Join(directconnect.ErrProgressDelivery, err)
			}
		}
	}
	return authority.result, authority.err
}

func (authority *fakeConnectAuthority) ConnectTest(_ context.Context, payload []byte, _ string, progress loopbackcarrier.ProgressReporter) (loopbackcarrier.Result, error) {
	authority.calls++
	authority.payload = append(authority.payload[:0], payload...)
	if progress != nil {
		if err := progress(loopbackcarrier.ProgressStageSocketReady); err != nil {
			return loopbackcarrier.Result{}, err
		}
	}
	return authority.result, authority.err
}

func (authority *fakeConnectAuthority) PairingLedgerStatus() governor.PairingLedgerStatus {
	return authority.ledger
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

type stageFailingProgress struct{ stage string }

func (progress *stageFailingProgress) Report(stage string, _ bool) error {
	if stage == progress.stage {
		return errors.New("test progress sink failure")
	}
	return nil
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

func validDirectV2Params(artifact string) string {
	return `{"auth_scope":"test_only","attempt":{"kind":"direct_oob_artifact","oob_artifact":` + artifact +
		`},"rendezvous":{"endpoint":"192.0.2.10:443","deployment_tier":"self_hosted","tls":{"verification":"spki_sha256","spki_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},"stun_endpoint":"192.0.2.20:3478"}`
}

func assertDirectErrorData(t *testing.T, rpcErr *stdiojsonrpc.RPCError, class, stage string, burned bool, category string) {
	t.Helper()
	if rpcErr == nil || rpcErr.Data.Class != class || rpcErr.Data.Reason != class || rpcErr.Data.Retryable ||
		rpcErr.Data.Stage != stage || rpcErr.Data.CredentialBurned == nil || *rpcErr.Data.CredentialBurned != burned ||
		rpcErr.Data.TerminalCategory != category {
		t.Fatalf("direct error = %+v", rpcErr)
	}
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
