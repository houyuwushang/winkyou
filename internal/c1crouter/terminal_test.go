//go:build fieldc1c

package c1crouter

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestTerminalResolutionPriority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    terminalInput
		class string
		rule  int
	}{
		{"issue171_worker_drain_backstop_success", terminalInput{Reported: true, WorkerClass: "c1c_router_drain_failed", Backstop: "success", ChildErr: true, ResidueZero: true}, "c1c_router_drain_failed", 5},
		{"backstop_ownership_not_downgraded", terminalInput{Reported: true, WorkerClass: "c1c_router_resource_limit", Backstop: "failed", BackstopErr: ErrOwnership}, "c1c_router_ownership_invalid", 1},
		{"backstop_drain_authoritative", terminalInput{Reported: true, WorkerClass: "cancelled", Backstop: "failed", BackstopErr: ErrDrain}, "c1c_router_drain_failed", 1},
		{"preflight_failure_retained", terminalInput{Reported: true, WorkerClass: "gate_c_request_invalid", Backstop: "success", ChildErr: true, ResidueZero: true}, "gate_c_request_invalid", 5},
		{"killed_worker_unreported", terminalInput{Backstop: "success", ChildErr: true, ResidueZero: true}, "c1c_router_io_failed", 2},
		{"clean_cancellation", terminalInput{Reported: true, WorkerClass: "cancelled", Clean: true, Backstop: "not_needed", ResidueZero: true}, "cancelled", 4},
		{"cancelled_nonzero_exit", terminalInput{Reported: true, WorkerClass: "cancelled", Clean: true, ChildErr: true, Backstop: "not_needed", ResidueZero: true}, "c1c_router_io_failed", 3},
		{"expired_without_clean_journal", terminalInput{Reported: true, WorkerClass: "expired", Backstop: "success", ResidueZero: true}, "c1c_router_io_failed", 3},
		{"peaceful_but_residual", terminalInput{Reported: true, WorkerClass: "cancelled", Clean: true, Backstop: "not_needed"}, "c1c_router_drain_failed", 6},
		{"worker_failure_not_overwritten_by_residue", terminalInput{Reported: true, WorkerClass: "c1c_router_query_failed", Backstop: "success"}, "c1c_router_query_failed", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveTerminalClass(tc.in)
			if got.TerminalClass != tc.class || got.Rule != tc.rule {
				t.Errorf("terminal class=%s rule=%d; want class=%s rule=%d", got.TerminalClass, got.Rule, tc.class, tc.rule)
			}
			assertTerminalInputs(t, tc.in, got)
		})
	}
}

func assertTerminalInputs(t *testing.T, in terminalInput, got terminalResolution) {
	t.Helper()
	worker, backstop := "", ""
	if in.Reported {
		worker = in.WorkerClass
	}
	if in.Backstop == "failed" {
		backstop = errorClass(in.BackstopErr)
	}
	if got.Schema != "winkyou-router-terminal-resolution/1" || got.WorkerReported != in.Reported ||
		got.WorkerClass != worker || got.CleanAtExit != in.Clean || got.ChildExitError != in.ChildErr ||
		got.Backstop != in.Backstop || got.BackstopClass != backstop {
		t.Fatal("terminal resolution lost an input witness")
	}
}

func TestTerminalResolutionExhaustive(t *testing.T) {
	classes := []string{"success", "cancelled", "expired", "gate_c_request_invalid", "c1c_router_resource_limit", "c1c_router_ownership_invalid", "c1c_router_drain_failed", "c1c_router_command_unavailable", "c1c_router_query_failed", "c1c_router_io_failed"}
	count := 0
	for _, reported := range []bool{false, true} {
		for _, worker := range classes {
			for _, clean := range []bool{false, true} {
				for _, childErr := range []bool{false, true} {
					for _, backstop := range []string{"not_needed", "success", "failed"} {
						for _, residueZero := range []bool{false, true} {
							count++
							in := terminalInput{Reported: reported, WorkerClass: worker, Clean: clean, ChildErr: childErr, Backstop: backstop, ResidueZero: residueZero}
							if backstop == "failed" {
								in.BackstopErr = ErrOwnership
							}
							t.Run(fmt.Sprintf("%03d", count), func(t *testing.T) {
								got := resolveTerminalClass(in)
								if _, err := (Summary{Stage: "terminal", Class: got.TerminalClass}).Encode(); err != nil {
									t.Fatal("terminal class is outside public whitelist")
								}
								if got.Rule < 1 || got.Rule > 6 {
									t.Fatalf("terminal rule=%d is outside 1..6", got.Rule)
								}
								if backstop == "failed" && got.TerminalClass != errorClass(in.BackstopErr) {
									t.Errorf("backstop failure downgraded: class=%s rule=%d", got.TerminalClass, got.Rule)
								}
								assertTerminalInputs(t, in, got)
							})
						}
					}
				}
			}
		}
	}
	if count != 480 {
		t.Fatalf("terminal combinations=%d; want 480", count)
	}
	t.Logf("TERMINAL_EXHAUSTIVE classes=%d combinations=%d", len(classes), count)
}

func TestTerminalResolutionPrivateShape(t *testing.T) {
	r := resolveTerminalClass(terminalInput{Reported: true, WorkerClass: "cancelled", Clean: true, Backstop: "not_needed", ResidueZero: true})
	got, err := json.Marshal(r)
	const want = `{"schema":"winkyou-router-terminal-resolution/1","worker_reported":true,"worker_class":"cancelled","clean_at_exit":true,"child_exit_error":false,"backstop_cleanup":"not_needed","backstop_class":"","terminal_class":"cancelled","rule":4}`
	if err != nil || string(got) != want {
		t.Fatal("private terminal resolution schema changed")
	}
}

func TestTerminalErrorClassMappingUnchanged(t *testing.T) {
	for _, err := range []error{ErrDrain, ErrOwnership, ErrResource, ErrQuery, ErrCommandUnavailable, ErrInvalid, errIO} {
		if got := errorClass(fmt.Errorf("synthetic wrapper: %w", err)); got != err.Error() {
			t.Fatal("wrapped error classification changed")
		}
	}
	if errorClass(nil) != "c1c_router_io_failed" || errorClass(errors.New("synthetic detail")) != "c1c_router_io_failed" ||
		errorClass(errors.Join(ErrOwnership, ErrDrain)) != "c1c_router_drain_failed" {
		t.Fatal("existing error precedence or fallback changed")
	}
}
