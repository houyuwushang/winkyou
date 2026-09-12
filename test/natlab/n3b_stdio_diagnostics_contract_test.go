//go:build linux && natlab

package natlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
	"winkyou/internal/v2/directconnect"
)

func n3bDiagnosticFrame(t testing.TB, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))), payload...)
}

// The existing required Linux matrix invokes this series explicitly; default
// builds (especially Windows) gain no N3b harness capability or exception.
func testN3BDiagnosticRequiredContracts(t *testing.T) {
	for round := 1; round <= 20; round++ {
		if !t.Run(fmt.Sprintf("round_%d", round), func(t *testing.T) {
			t.Run("stable_errors", TestN3BDiagnosticPreservesStableFailures)
			t.Run("privacy_bounds", TestN3BDiagnosticPrivacyFirstFailureAndBounds)
			t.Run("progress", TestN3BDiagnosticProgressAndSuccessAreIndependent)
			t.Run("serve", TestN3BDiagnosticServeFailurePrivacy)
			t.Run("child_output", TestN2DChildOutputDiagnosticIsBoundedAndPrivate)
			t.Run("wiring", TestN3BDiagnosticActualHarnessWiringMutations)
		}) {
			return
		}
	}
}

func TestN3BDiagnosticServeFailurePrivacy(t *testing.T) {
	for _, test := range []struct {
		err   error
		class string
	}{
		{nil, "none"}, {governor.ErrNamespaceUnsafe, "namespace"},
		{governor.ErrSafetyStateCorrupt, "safety"}, {governor.ErrPairingLedgerIndeterminate, "ledger"},
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{governor.ErrCancellationDrainTimeout, "drain"}, {errors.New("SYNTHETIC_PRIVATE"), "other"},
	} {
		if got := n3bServeErrorClass(test.err); got != test.class || n3bSafeServeClass(got) != got {
			t.Fatalf("serve failure classification=%s want=%s", got, test.class)
		}
	}
}

func TestN3BDiagnosticPreservesStableFailures(t *testing.T) {
	for _, class := range []string{directconnect.ClassRendezvousTLSFailed, directconnect.ClassRendezvousUnreachable,
		directconnect.ClassPresenceTimeout, directconnect.ClassControlAuthentication, directconnect.ClassSTUNSilent,
		directconnect.ClassPairingScopeChanged, directconnect.ClassResourceBudgetExceeded, stdiojsonrpc.ClassInternalError} {
		t.Run(class, func(t *testing.T) {
			burned := true
			rpc := stdiojsonrpc.NewRPCError(-32000, class, "SYNTHETIC_PRIVATE_MESSAGE", false)
			rpc.Data.Stage, rpc.Data.CredentialBurned = directconnect.StageSTUN, &burned
			payload := n3bDiagnosticFrame(t, map[string]any{"jsonrpc": "2.0", "id": 2, "error": rpc})
			diag := inspectN3BStdioOutput(payload)
			if !diag.RPCErrorSeen || diag.Class != class || diag.Stage != directconnect.StageSTUN || !diag.BurnedKnown || !diag.Burned {
				t.Fatalf("lost structured failure: %+v", diag)
			}
			encoded, _ := json.Marshal(diag)
			if bytes.Contains(encoded, []byte("SYNTHETIC_PRIVATE")) {
				t.Fatal("raw message reached witness")
			}
		})
	}
}

func TestN3BDiagnosticPrivacyFirstFailureAndBounds(t *testing.T) {
	private := "SYNTHETIC_PRIVATE_FIELD"
	rpc := stdiojsonrpc.NewRPCError(-32000, private, private, false)
	rpc.Data.Stage = private
	first := n3bDiagnosticFrame(t, map[string]any{"id": private, "error": rpc})
	second := n3bDiagnosticFrame(t, map[string]any{"id": 2, "error": stdiojsonrpc.NewRPCError(-32000, directconnect.ClassSTUNSilent, "", false)})
	diag := inspectN3BStdioOutput(append(first, second...))
	if diag.Class != "unknown" || diag.Stage != "unknown" || diag.Frames != 2 || diag.BurnedKnown {
		t.Fatalf("first error was replaced or leaked: %+v", diag)
	}
	encoded, _ := json.Marshal(diag)
	if bytes.Contains(encoded, []byte(private)) {
		t.Fatal("private field reached diagnostic")
	}
	if got := inspectN3BStdioOutput([]byte("Content-Length: 10\r\n\r\n{}")); got.ParseFailure != "framing" {
		t.Fatalf("half frame = %+v", got)
	}
	if got := inspectN3BStdioOutput(bytes.Repeat(second, 100)); got.Frames != 32 || got.ParseFailure != "frame_limit" {
		t.Fatalf("unbounded frame inspection: %+v", got)
	}
}

func TestN3BDiagnosticProgressAndSuccessAreIndependent(t *testing.T) {
	payload := n3bDiagnosticFrame(t, map[string]any{"id": 1, "result": map[string]any{}})
	payload = append(payload, n3bDiagnosticFrame(t, map[string]any{
		"method": stdiojsonrpc.ProgressNotificationMethod,
		"params": stdiojsonrpc.Progress{RequestID: json.RawMessage("2"), Stage: directconnect.StageSTUN},
	})...)
	payload = append(payload, n3bDiagnosticFrame(t, map[string]any{"id": 2, "result": directconnect.Result{
		Terminal: "success", Bidirectional: true, PromotedTerminal: true, CredentialBurned: true, FinishRecorded: true,
	}})...)
	diag := inspectN3BStdioOutput(payload)
	if diag.Frames != 3 || diag.ProgressCount != 1 || !diag.HandshakeSeen || !diag.ResultSeen ||
		diag.RPCErrorSeen || diag.LastProgress != directconnect.StageSTUN || diag.ParseFailure != "none" ||
		diag.Stages[0] != directconnect.StageSTUN || !diag.ResultSuccess || !diag.Bidirectional || !diag.Promoted || !diag.ResultBurned || !diag.FinishRecorded {
		t.Fatalf("lost output metadata: %+v", diag)
	}
	// Seeing a result frame is not acceptance of that result. The original
	// Linux parser and n2dSuccessTerminalContract remain mandatory separately.
}

func TestN3BDiagnosticActualHarnessWiringMutations(t *testing.T) {
	for _, file := range []struct {
		name     string
		required []string
	}{
		{"n3b_stdio_linux_test.go", []string{"diagnostic := inspectN3BStdioOutput(output.Bytes())", "result.StdioDiagnostic = &diagnostic",
			"n3bFailedCaseDiagnostics(t, topology, servers, initiator, responder)", "iteration <= 20", "if !t.Run(", "assertN2DSuccessResult(t, initiatorResult"}},
		{"n2d_endpoint_linux_test.go", []string{"process.command.Stdout = &process.output", "process.command.Stderr = &process.output",
			"process.output.clear()", "logN2DEndpointFailure(t, process)", "if waitErr != nil || !result.OK"}},
		{"n3b_failure_diagnostics_linux_test.go", []string{"logN2DEndpointFailure(t, left)", "logN2DEndpointFailure(t, right)",
			"n3bSafeClass(diag.Class)", "n3bSafeStage(diag.Stage)", "n3bSafeParseFailure(diag.ParseFailure)", "topology.assertNoLeaks()"}},
	} {
		payload, err := os.ReadFile(file.name)
		if os.IsNotExist(err) {
			// Required CI runs the compiled binary from the repository root;
			// ordinary go test runs from test/natlab. Neither is a host path.
			payload, err = os.ReadFile(filepath.Join("test", "natlab", file.name))
		}
		if err != nil {
			t.Fatal("harness source unavailable")
		}
		check := func(source string) bool {
			for _, required := range file.required {
				if !strings.Contains(source, required) {
					return false
				}
			}
			return true
		}
		if !check(string(payload)) {
			t.Fatalf("missing diagnostic wiring in %s", file.name)
		}
		for index, required := range file.required {
			t.Run(fmt.Sprintf("%s_%d", file.name, index), func(t *testing.T) {
				if check(strings.ReplaceAll(string(payload), required, "DIAGNOSTIC_MUTATION")) {
					t.Fatal("disconnected diagnostic accepted")
				}
			})
		}
	}
}

func TestN2DChildOutputDiagnosticIsBoundedAndPrivate(t *testing.T) {
	var diag n2dChildOutputDiagnostic
	for _, part := range []string{"SYNTHETIC_PRIVATE\nWARNING: DATA ", "RACE\npan", "ic: test timed ", "out\nfatal error:\n"} {
		if n, err := diag.Write([]byte(part)); err != nil || n != len(part) {
			t.Fatal("output sink changed child write semantics")
		}
	}
	if got := diag.snapshot(); got != [4]bool{true, true, true, true} {
		t.Fatalf("split runtime markers = %v", got)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _ = diag.Write([]byte(strings.Repeat("x", 1000)))
			_ = diag.snapshot()
		}()
	}
	workers.Wait()
	if len(diag.tail) > 64 {
		t.Fatal("unbounded raw output retention")
	}
	diag.clear()
	if len(diag.tail) != 0 || diag.snapshot() != [4]bool{true, true, true, true} {
		t.Fatal("clear lost fixed witness or retained raw bytes")
	}
}
