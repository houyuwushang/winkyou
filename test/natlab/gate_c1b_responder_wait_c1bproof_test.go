//go:build c1bproof

package natlab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/sshassembly"
)

const (
	gateC1bResponderResultLimit = 5 * time.Second
	// Issue #130: the result file is a harness witness, not a product timer.
	// Sum the frozen session drain, carrier drain and SSH child exit bounds
	// (2s each), plus 4s for sshd reaping/file publication under runner load.
	// Non-liveness C1b proofs retain their original 5s wait.
	livenessResponderResultMargin = 4 * time.Second
	livenessResponderResultLimit  = gatecorchestrator.SessionDrainTimeout + oobcarrier.DrainTimeout +
		sshassembly.DrainTimeout + livenessResponderResultMargin
)

// wait may call testing.Fatal (runtime.Goexit). Its failure diagnostics and
// original residue gate must still run before the fixture cleanup callbacks.
// There is exactly one wait; failure never adds a retry or a grace period.
func gateC1bWaitResponderResult(liveness bool, wait func(time.Duration), failed func()) {
	returned := false
	defer func() {
		if !returned {
			failed()
		}
	}()
	limit := gateC1bResponderResultLimit
	if liveness {
		limit = livenessResponderResultLimit
	}
	wait(limit)
	returned = true
}

func TestGateC1bResponderWaitContract(t *testing.T) {
	if gateC1bResponderResultLimit != 5*time.Second || livenessResponderResultLimit != 10*time.Second ||
		gatecorchestrator.SessionDrainTimeout != 2*time.Second || oobcarrier.DrainTimeout != 2*time.Second ||
		sshassembly.DrainTimeout != 2*time.Second {
		t.Fatal("responder witness wait lost its frozen product-bound derivation")
	}
	for _, liveness := range []bool{false, true} {
		calls, failures := 0, 0
		gateC1bWaitResponderResult(liveness, func(limit time.Duration) {
			calls++
			want := gateC1bResponderResultLimit
			if liveness {
				want = livenessResponderResultLimit
			}
			if limit != want {
				t.Fatal("wrong responder witness wait")
			}
		}, func() { failures++ })
		if calls != 1 || failures != 0 {
			t.Fatal("successful witness wait retried or entered failure cleanup")
		}
	}
	// Deterministic Fatal-equivalent injection: no real sleep, process, socket,
	// or deliberately failing subtest. The parent reads only after worker join.
	finished := make(chan struct{})
	var events []string
	go func() {
		defer close(finished)
		gateC1bWaitResponderResult(true, func(time.Duration) {
			events = append(events, "wait")
			runtime.Goexit()
		}, func() {
			events = append(events, "bilateral-diagnostics", "residue-gate")
		})
		events = append(events, "unexpected-return")
	}()
	<-finished
	if len(events) != 3 || events[0] != "wait" || events[1] != "bilateral-diagnostics" || events[2] != "residue-gate" {
		t.Fatalf("Fatal bypassed diagnostic/residue guard: %v", events)
	}
}

// Exercise the real testing.Fatal/Run/Cleanup ordering in an expected-failure
// test process, without starting a product child or any network fixture.
func TestGateC1bResponderWaitFatalContract(t *testing.T) {
	const environment = "WINKYOU_RESPONDER_WAIT_FATAL_FIXTURE"
	if scenario := os.Getenv(environment); scenario != "" {
		t.Run("synthetic-fixture", func(t *testing.T) {
			t.Cleanup(func() { t.Log("wait_contract_fixture_cleanup") })
			gateC1bWaitResponderResult(true, func(time.Duration) {
				t.Fatal("wait_contract_original_red")
			}, func() {
				t.Log("wait_contract_bilateral_diagnostics")
				defer t.Log("wait_contract_residue_gate")
				t.Run("initiator-drain", func(t *testing.T) {
					t.Log("wait_contract_initiator_drain")
					if scenario == "drain-fatal" {
						t.Fatal("wait_contract_initiator_red")
					}
				})
				t.Run("sshd-drain", func(t *testing.T) {
					t.Log("wait_contract_sshd_drain")
					if scenario == "drain-fatal" {
						t.Fatal("wait_contract_sshd_red")
					}
				})
			})
			t.Fatal("wait_contract_unexpected_return")
		})
		return
	}
	for _, scenario := range []string{"drain-success", "drain-fatal"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGateC1bResponderWaitFatalContract$", "-test.v", "-test.count=1", "-test.timeout=5s")
			command.Env = append(os.Environ(), environment+"="+scenario)
			output, err := command.CombinedOutput()
			defer clear(output)
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatal("expected failed test process did not exit with its original RED")
			}
			text := string(output)
			previous := -1
			for _, marker := range []string{"wait_contract_original_red", "wait_contract_bilateral_diagnostics", "wait_contract_initiator_drain",
				"wait_contract_sshd_drain", "wait_contract_residue_gate", "wait_contract_fixture_cleanup"} {
				position := strings.Index(text, marker)
				if position <= previous || strings.Count(text, marker) != 1 {
					t.Fatal("real Fatal skipped, reordered or repeated a diagnostic/drain/residue witness")
				}
				previous = position
			}
			if strings.Contains(text, "wait_contract_unexpected_return") ||
				(scenario == "drain-fatal" && (!strings.Contains(text, "wait_contract_initiator_red") || !strings.Contains(text, "wait_contract_sshd_red"))) {
				t.Fatal("real Fatal was swallowed or bypassed a host failure")
			}
			t.Log("expected_failure=true original_error_retained=true bilateral_diagnostics=true host_drains=2 residue_gate=1 before_fixture_cleanup=true")
		})
	}
}
