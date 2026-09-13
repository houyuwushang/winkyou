package natlab

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winkyou/internal/v2/directconnect/gateb"
)

type gateB3ResultDiagnostic struct {
	State, LastStage, ErrorStage, Class string
}

// Fixed vocabulary only, never endpoints, commands, paths or arbitrary errors.
func gateB3ResultStage(value string) string {
	if value == "" {
		return "none"
	}
	for _, known := range gateb.ProgressSequence {
		if value == known {
			return value
		}
	}
	return "unrecognized"
}

func gateB3ResultClass(value string) string {
	if value == "" {
		return "none"
	}
	for _, known := range append(append([]string(nil), gateb.StableFailureClasses...),
		gateb.ClassCredentialUsed, gateb.ClassAdmissionBlocked, gateb.ClassOOBStreamInvalid,
		gateb.ClassOOBPresenceTimeout, gateb.ClassOOBStreamClosed, gateb.ClassOOBProtocolViolation,
		gateb.ClassAttemptExpired, gateb.ClassResourceBudgetExceeded, gateb.ClassTransportLeaseUnavailable,
		gateb.ClassTransportHandoffFailed, gateb.ClassDataPlaneChallengeFailed, gateb.ClassDrainFailed, "internal_error") {
		if value == known {
			return value
		}
	}
	return "unrecognized"
}

func gateB3ReadDiagnosticFile(path string, limit int64) ([]byte, string) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, "missing"
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, "unavailable"
	}
	if info.Size() > limit {
		return nil, "oversize"
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "unavailable"
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, "unavailable"
	}
	if int64(len(data)) > limit {
		return nil, "oversize"
	}
	return data, "readable"
}

func readGateB3ResultDiagnostic(path string) gateB3ResultDiagnostic {
	out := gateB3ResultDiagnostic{LastStage: "unavailable", ErrorStage: "unavailable", Class: "unavailable"}
	if stage, state := gateB3ReadDiagnosticFile(path+".stage", 128); state == "readable" {
		out.LastStage = gateB3ResultStage(string(stage))
	} else {
		out.LastStage = state
	}
	data, state := gateB3ReadDiagnosticFile(path, 64*1024)
	out.State = state
	if state != "readable" {
		return out
	}
	var wire struct {
		ErrorStage string `json:"error_stage"`
		ErrorClass string `json:"error_class"`
	}
	if len(data) == 0 || data[0] != '{' || json.Unmarshal(data, &wire) != nil {
		out.State = "invalid"
		return out
	}
	out.ErrorStage, out.Class = gateB3ResultStage(wire.ErrorStage), gateB3ResultClass(wire.ErrorClass)
	return out
}

func TestGateB3LifetimeResultDiagnostic(t *testing.T) {
	for _, test := range []struct {
		name, stage, result, state, wantStage, wantClass string
	}{
		{"normal", "candidates", `{"error_stage":"candidates","error_class":"attempt_expired"}`, "readable", "candidates", "attempt_expired"},
		{"unknown", "PRIVATE_VALUE", `{"error_stage":"PRIVATE_VALUE","error_class":"PRIVATE_VALUE"}`, "readable", "unrecognized", "unrecognized"},
		{"partial", "verify", `{"error_class":`, "invalid", "verify", "unavailable"},
		{"null", "verify", `null`, "invalid", "verify", "unavailable"},
		{"oversize", "verify", strings.Repeat("x", 64*1024+1), "oversize", "verify", "unavailable"},
		{"stage-oversize", strings.Repeat("x", 129), `{}`, "readable", "oversize", "none"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.json")
			if err := os.WriteFile(path, []byte(test.result), 0o600); err != nil {
				t.Fatal("synthetic result write failed")
			}
			if err := os.WriteFile(path+".stage", []byte(test.stage), 0o600); err != nil {
				t.Fatal("synthetic stage write failed")
			}
			got := readGateB3ResultDiagnostic(path)
			if got.State != test.state || got.LastStage != test.wantStage || got.Class != test.wantClass ||
				strings.Contains(got.ErrorStage, "PRIVATE") {
				t.Fatal("result diagnostic lost availability or fixed-vocabulary redaction")
			}
		})
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if got := readGateB3ResultDiagnostic(missing); got.State != "missing" || got.LastStage != "missing" || got.Class != "unavailable" {
		t.Fatal("missing result became a valid terminal")
	}
}
