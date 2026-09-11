//go:build c1bproof

package natlab

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/gatecorchestrator"
)

// Only already-existing private harness files are read, once each. No polling,
// process inspection, ledger acquisition, or production callback is added. A
// missing/partial return file must not turn into a fabricated zero-residue claim.
func gateC1bCrashTerminalSnapshot(resultFile, stageFile string) string {
	var snapshot struct {
		ResultState, StageState, LastStage, MarkerState string
		MarkerMatches                                   bool
		Result                                          *gateC1bCrashTerminal
	}
	stage, state := readGateC1bDiagnosticFile(stageFile, 128)
	snapshot.StageState = state
	snapshot.LastStage = gateC1bDiagnosticLabel(string(stage), strings.Join(gatecorchestrator.ProductProgressSequence, " "))
	marker, state := readGateC1bDiagnosticFile(stageFile+".fault", 128)
	snapshot.MarkerState, snapshot.MarkerMatches = state, state == "ok" && string(marker) == "consumer-crash"
	data, state := readGateC1bDiagnosticFile(resultFile, 64*1024)
	snapshot.ResultState = state
	if state == "ok" {
		var result struct {
			OK           *bool
			Class, Stage string
			Product      *gatecorchestrator.Result
		}
		if json.Unmarshal(data, &result) != nil || result.OK == nil || result.Product == nil {
			snapshot.ResultState = "invalid"
		} else {
			product := result.Product
			wg := product.Witness.WireGuard
			snapshot.Result = &gateC1bCrashTerminal{
				Class: gateC1bDiagnosticLabel(result.Class, gateC1bDiagnosticClasses),
				Stage: gateC1bDiagnosticLabel(result.Stage, strings.Join(gatecorchestrator.ProductProgressSequence, " ")),
				OK:    *result.OK, Ready: product.DataPlaneReady, Burned: product.CredentialBurned, Finish: product.FinishRecorded,
				Candidates: product.Witness.GateB.Emissions.CandidatePackets, Winner: product.Witness.GateB.Emissions.WinnerPackets,
				SSHExited: product.Witness.SSH.Exited, SSHKilled: product.Witness.SSH.Killed, SSHDrained: product.Witness.SSH.Drained,
				CarrierEOF: product.Witness.GateB.CarrierWitness.EOF, CarrierDrained: product.Witness.GateB.CarrierWitness.Drained,
				WGState:  gateC1bDiagnosticLabel(string(wg.State), gateC1bDiagnosticGateStates),
				WGFinish: wg.FinishRecorded, WGDetached: wg.AttemptDetached, WGClosed: wg.Closed,
				ReadinessWrites: wg.ReadinessWrites, ReadinessReads: wg.ReadinessReads,
				CompletionWrites: wg.CompletionWrites, CompletionReads: wg.CompletionReads,
			}
			if wg.CompletionFailure != nil {
				failure := *wg.CompletionFailure
				failure.Point = gateC1bDiagnosticLabel(failure.Point, `session_precondition challenge_precondition before_confirmation
					receive_confirmation before_durable_finish durable_finish after_durable_finish send_confirmation before_detach detach activation`)
				failure.Cause = gateC1bDiagnosticLabel(failure.Cause, gateC1bDiagnosticContextLabels)
				failure.GateState = probeio.WireGuardGateState(gateC1bDiagnosticLabel(string(failure.GateState), gateC1bDiagnosticGateStates))
				for _, context := range []*probeio.CompletionContextWitness{&failure.Attempt, &failure.Session, &failure.Challenge} {
					context.State = gateC1bDiagnosticLabel(context.State, gateC1bDiagnosticContextLabels)
					context.Cause = gateC1bDiagnosticLabel(context.Cause, gateC1bDiagnosticContextLabels)
				}
				snapshot.Result.CompletionFailure = &failure
			}
		}
	}
	// The projected schema has no arbitrary text, maps, raw errors, or paths.
	encoded, _ := json.Marshal(snapshot)
	return string(encoded)
}

type gateC1bCrashTerminal struct {
	Class, Stage, WGState                                              string
	OK, Ready, Burned, Finish                                          bool
	Candidates, Winner                                                 int
	SSHExited, SSHKilled, SSHDrained, CarrierEOF, CarrierDrained       bool
	WGFinish, WGDetached, WGClosed                                     bool
	ReadinessWrites, ReadinessReads, CompletionWrites, CompletionReads int
	CompletionFailure                                                  *probeio.WireGuardCompletionFailure
}

const gateC1bDiagnosticClasses = `hard_nat_profile_unsupported hard_nat_evidence_insufficient hard_nat_evidence_drifted
	hard_nat_plan_mismatch insufficient_authorized_search_budget hard_nat_candidate_exhausted hard_nat_campaign_rate_limited
	hard_nat_campaign_circuit_open hard_nat_packet_rejected credential_used pairing_admission_blocked oob_stream_invalid
	oob_presence_timeout oob_stream_closed oob_protocol_violation attempt_expired resource_budget_exceeded transport_lease_unavailable
	transport_handoff_failed data_plane_challenge_failed drain_failed gate_c_request_invalid peer_address_not_authorized
	ssh_profile_invalid ssh_host_identity_rejected ssh_transport_unavailable ssh_child_terminated ssh_budget_exceeded
	wireguard_binding_failed post_handoff_validation_failed session_drain_failed session_liveness_timeout
	session_liveness_protocol_invalid session_liveness_budget_exceeded session_liveness_clock_invalid
	session_liveness_unavailable harness_setup_rejected
	harness_pipe_fault_setup_failed harness_pipe_fault_drain_failed`

const gateC1bDiagnosticGateStates = `standby challenge_capped challenge_drain challenge_passed finish_confirming finish_detached active closed`
const gateC1bDiagnosticContextLabels = `none active missing deadline_exceeded canceled lease_inactive lease_closed gate_limit gate_state other`

func gateC1bDiagnosticLabel(value, allowed string) string {
	if value == "" {
		return "none"
	}
	for _, label := range strings.Fields(allowed) {
		if value == label {
			return label
		}
	}
	return "unrecognized"
}

func readGateC1bDiagnosticFile(path string, limit int64) ([]byte, string) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, "missing"
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, "unreadable"
	}
	if info.Size() > limit {
		return nil, "oversize"
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "unreadable"
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, "unreadable"
	}
	if int64(len(data)) > limit {
		return nil, "oversize"
	}
	return data, "ok"
}

// Also invoked by the existing required Linux diagnostics entry. Running this
// test on Windows needs neither netns nor any socket or child process.
func TestGateC1bCrashTerminalDiagnostics(t *testing.T) {
	dir := t.TempDir()
	resultFile, stageFile := filepath.Join(dir, "result"), filepath.Join(dir, "stage")
	write := func(path, contents string) {
		t.Helper()
		if os.WriteFile(path, []byte(contents), 0o600) != nil {
			t.Fatal("synthetic diagnostic fixture write failed")
		}
	}
	check := func(want ...string) string {
		t.Helper()
		got := gateC1bCrashTerminalSnapshot(resultFile, stageFile)
		for _, field := range want {
			if !strings.Contains(got, field) {
				t.Fatalf("diagnostic field missing: %s in %s", field, got)
			}
		}
		return got
	}
	check(`"ResultState":"missing"`, `"Result":null`, `"StageState":"missing"`, `"MarkerMatches":false`)
	write(stageFile, "data_plane_challenge")
	for _, partial := range []string{`{"OK":false`, `null`, `{}`, `{"OK":false,"Product":null}`} {
		write(resultFile, partial)
		check(`"ResultState":"invalid"`, `"Result":null`, `"LastStage":"data_plane_challenge"`)
	}
	write(resultFile, `{"OK":false,"Class":"post_handoff_validation_failed","Stage":"data_plane_challenge",
		"Product":{"credential_burned":true,"finish_recorded":true,"witness":{"gate_b":{"emissions":{"candidate_packets":32,"winner_packets":1}},
		"wireguard":{"FinishRecorded":true,"CompletionFailure":{"Point":"after_durable_finish","Cause":"canceled","GateState":"finish_confirming",
		"Attempt":{"State":"active","Cause":"none","Bounded":true,"RemainingMillis":1000}}}}}}`)
	check(`"ResultState":"ok"`, `"Class":"post_handoff_validation_failed"`, `"Candidates":32`, `"Winner":1`,
		`"Finish":true`, `"WGFinish":true`, `"Point":"after_durable_finish"`, `"RemainingMillis":1000`, `"MarkerState":"missing"`)
	write(stageFile, "finish_recorded")
	write(stageFile+".fault", "consumer-crash")
	check(`"LastStage":"finish_recorded"`, `"MarkerMatches":true`)
	for _, class := range []string{"session_liveness_timeout", "session_liveness_protocol_invalid",
		"session_liveness_clock_invalid", "session_liveness_budget_exceeded", "session_liveness_unavailable"} {
		write(resultFile, `{"OK":false,"Class":"`+class+`","Stage":"terminal","Product":{}}`)
		check(`"ResultState":"ok"`, `"Class":"`+class+`"`, `"Stage":"terminal"`)
	}

	// Every text-bearing projected field is hostile, including nested contexts;
	// unknown result fields, identity fields and the marker are never echoed.
	secret := "synthetic-private-192.0.2.99-user-path-key"
	write(stageFile, secret)
	write(stageFile+".fault", secret)
	write(resultFile, strings.ReplaceAll(`{"OK":false,"Class":"PRIVATE","Stage":"PRIVATE","Unknown":"PRIVATE",
		"Product":{"session_end":"PRIVATE","witness":{"gate_b":{"profile":"PRIVATE"},"wireguard":{"State":"PRIVATE",
		"CompletionFailure":{"Point":"PRIVATE","Cause":"PRIVATE","GateState":"PRIVATE",
		"Attempt":{"State":"PRIVATE","Cause":"PRIVATE"},"Session":{"State":"PRIVATE","Cause":"PRIVATE"},"Challenge":{"State":"PRIVATE","Cause":"PRIVATE"}}}}}}`, "PRIVATE", secret))
	got := check(`"ResultState":"ok"`, `"Class":"unrecognized"`, `"Stage":"unrecognized"`, `"WGState":"unrecognized"`,
		`"LastStage":"unrecognized"`, `"MarkerMatches":false`)
	if strings.Contains(got, secret) || strings.Contains(got, dir) || strings.Count(got, "unrecognized") != 13 {
		t.Fatal("diagnostic snapshot leaked or failed to classify private text")
	}
	write(resultFile, strings.Repeat("x", 64*1024+1))
	write(stageFile, strings.Repeat("x", 129))
	write(stageFile+".fault", strings.Repeat("x", 129))
	check(`"ResultState":"oversize"`, `"Result":null`, `"StageState":"oversize"`, `"MarkerState":"oversize"`)
	if _, state := readGateC1bDiagnosticFile(dir, 128); state != "unreadable" {
		t.Fatal("diagnostic reader accepted a non-regular file")
	}
}
