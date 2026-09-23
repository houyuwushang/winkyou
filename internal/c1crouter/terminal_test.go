//go:build fieldc1c

package c1crouter

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
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

func TestTerminalGuardianSingleResolverContract(t *testing.T) {
	source, err := os.ReadFile("command_linux.go")
	if err != nil {
		t.Fatal("guardian source unavailable")
	}
	if violations := terminalGuardianViolations(string(source)); len(violations) != 0 {
		t.Fatalf("terminal guardian contract: %v", violations)
	}
	mutants := []struct{ name, old, replacement string }{
		{"missing_resolver", "resolveTerminalClass(in)", "otherTerminalClass(in)"},
		{"second_resolver", "resolveTerminalClass(in)", "resolveTerminalClass(in)\n\t_ = resolveTerminalClass(in)"},
		{"io_literal", "summary.Class = r.TerminalClass", `summary.Class = "c1c_router_io_failed"`},
		{"drain_literal", "summary.Class = r.TerminalClass", `summary.Class = "c1c_router_drain_failed"`},
		{"no_private_resolution", `"terminal-resolution.json"`, `"other-result.json"`},
		{"write_failure_not_io", "// failure, irrespective of the private writer's underlying error class.\n\t\tsummary.Class = errorClass(errIO)", "// failure ignored\n\t\tsummary.Class = r.TerminalClass"},
	}
	normalized := strings.ReplaceAll(string(source), "\r\n", "\n")
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			changed := strings.Replace(normalized, mutant.old, mutant.replacement, 1)
			if changed == normalized {
				t.Fatal("terminal mutation did not change source")
			}
			if violations := terminalGuardianViolations(changed); len(violations) == 0 {
				t.Fatal("terminal mutation escaped contract")
			}
		})
	}
}

func terminalGuardianViolations(source string) []string {
	var violations []string
	if strings.Count(source, "resolveTerminalClass(") != 1 {
		violations = append(violations, "resolver occurrence count")
	}
	for _, forbidden := range []string{`"c1c_router_io_failed"`, `"c1c_router_drain_failed"`} {
		if strings.Contains(source, forbidden) {
			violations = append(violations, "inline terminal class")
		}
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "guardian.go", source, 0)
	if err != nil {
		return append(violations, "invalid guardian source")
	}
	resolvers, writes, writeFailures := 0, 0, 0
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "resolveTerminalClass" {
				resolvers++
			}
			if terminalResolutionWrite(call) {
				writes++
			}
		}
		if statement, ok := node.(*ast.IfStmt); ok {
			assignment, ok := statement.Init.(*ast.AssignStmt)
			if !ok || len(assignment.Rhs) != 1 {
				return true
			}
			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if !ok || !terminalResolutionWrite(call) {
				return true
			}
			condition, ok := statement.Cond.(*ast.BinaryExpr)
			if ok && condition.Op == token.NEQ && terminalIdentifier(condition.X, "e") && terminalIdentifier(condition.Y, "nil") &&
				terminalWriteFailureBody(statement.Body) && statement.Else == nil {
				writeFailures++
			}
		}
		return true
	})
	if resolvers != 1 || writes != 1 || writeFailures != 1 {
		violations = append(violations, "single resolver/private write/rule 7")
	}
	return violations
}

func terminalIdentifier(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}

func terminalWriteFailureBody(body *ast.BlockStmt) bool {
	if len(body.List) != 1 {
		return false
	}
	assignment, ok := body.List[0].(*ast.AssignStmt)
	if !ok || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
		return false
	}
	left, ok := assignment.Lhs[0].(*ast.SelectorExpr)
	if !ok || !terminalIdentifier(left.X, "summary") || left.Sel.Name != "Class" {
		return false
	}
	right, ok := assignment.Rhs[0].(*ast.CallExpr)
	return ok && terminalIdentifier(right.Fun, "errorClass") && len(right.Args) == 1 && terminalIdentifier(right.Args[0], "errIO")
}

func terminalResolutionWrite(call *ast.CallExpr) bool {
	name, ok := call.Fun.(*ast.Ident)
	if !ok || name.Name != "writePrivateJSON" || len(call.Args) != 3 {
		return false
	}
	literal, ok := call.Args[1].(*ast.BasicLit)
	return ok && literal.Value == `"terminal-resolution.json"`
}
