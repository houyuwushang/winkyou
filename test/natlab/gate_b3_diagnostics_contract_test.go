package natlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestGateB3LifetimeDiagnosticErrorPrivacy(t *testing.T) {
	for _, test := range []struct {
		name, class string
		err         error
	}{
		{"deadline", "context_deadline", context.DeadlineExceeded},
		{"cancel", "context_canceled", context.Canceled},
		{"io_deadline", "io_deadline", os.ErrDeadlineExceeded},
		{"closed", "closed", net.ErrClosed},
		{"bind", "address_in_use", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "bind", Err: syscall.EADDRINUSE}}},
		{"socket_option", "permission", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "setsockopt", Err: syscall.EPERM}}},
		{"write", "no_buffers", &net.OpError{Op: "write", Err: syscall.ENOBUFS}},
		{"wait_delay", "command_wait_delay", exec.ErrWaitDelay},
		{"missing_exit_state", "command_exit", &exec.ExitError{}},
		{"unknown", "other", errors.New("SYNTHETIC_PRIVATE_SENTINEL")},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Synthetic poison in every normally sensitive wrapper. Never
			// depend on error text, endpoint String or command arguments.
			err := errors.Join(test.err, &net.OpError{Op: "SYNTHETIC_PRIVATE_SENTINEL", Net: "SYNTHETIC_PRIVATE_SENTINEL",
				Source: gateB3PoisonAddress{}, Addr: gateB3PoisonAddress{},
				Err: &os.PathError{Op: "SYNTHETIC_PRIVATE_SENTINEL", Path: "SYNTHETIC_PRIVATE_SENTINEL", Err: gateB3PoisonError{}}})
			got := gateB3SafeError(err, context.Canceled)
			if got.Class != test.class || got.Context != "canceled" {
				t.Fatalf("sanitized class=%+v want=%s", got, test.class)
			}
			data, marshalErr := json.Marshal(got)
			if marshalErr != nil || strings.Contains(string(data), "SYNTHETIC_PRIVATE_SENTINEL") {
				t.Fatal("diagnostic leaked synthetic private material")
			}
		})
	}
	got := gateB3SafeError(&os.SyscallError{Syscall: "SYNTHETIC_PRIVATE_SENTINEL", Err: syscall.EINVAL}, nil)
	if got.Syscall != "other" || got.Class != "invalid_argument" {
		t.Fatalf("unknown operation not sanitized: %+v", got)
	}
}

type gateB3PoisonError struct{}

func (gateB3PoisonError) Error() string { panic("raw error formatting is forbidden") }

type gateB3PoisonAddress struct{}

func (gateB3PoisonAddress) Network() string { panic("address formatting is forbidden") }
func (gateB3PoisonAddress) String() string  { panic("address formatting is forbidden") }

func TestGateB3LifetimeDiagnosticExitHelper(t *testing.T) {
	if os.Getenv("WINKYOU_NAT_DIAGNOSTIC_EXIT_HELPER") != "1" {
		return
	}
	os.Exit(7)
}

func TestGateB3LifetimeDiagnosticCommandExit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestGateB3LifetimeDiagnosticExitHelper$")
	command.Env = append(os.Environ(), "WINKYOU_NAT_DIAGNOSTIC_EXIT_HELPER=1")
	got := gateB3SafeError(command.Run(), ctx.Err())
	if got.Class != "command_exit" || !got.ExitKnown || got.ExitCode != 7 || got.Context != "active" {
		t.Fatalf("command exit witness=%+v", got)
	}
}

func TestGateB3LifetimeDiagnosticFirstFailureSurvivesCleanup(t *testing.T) {
	origin := time.Now()
	diag := &gateB3NATDiagnostic{origin: origin}
	diag.queryStart()
	diag.queryEnd("", syscall.EACCES, nil)
	diag.mark(gateB3ObserverDone, origin.Add(50*time.Millisecond), syscall.EACCES, nil)
	diag.fail(gateB3PreferredReturn, context.DeadlineExceeded, context.DeadlineExceeded)
	diag.mark(gateB3RouterTerminal, origin.Add(2*time.Second), context.DeadlineExceeded, nil)
	diag.mark(gateB3RouterClose, origin.Add(3*time.Second), context.Canceled, context.Canceled)
	diag.fail(gateB3NamespaceFailure, syscall.EPIPE, context.Canceled)
	diag.mark(gateB3RouterTerminal, origin.Add(4*time.Second), nil, nil)
	diag.mark(gateB3RouterClose, origin.Add(4*time.Second), nil, nil)
	got := diag.snapshot()
	if got.Query.Error.Class != "permission" || got.Points[gateB3ObserverDone].AtNS != 50_000_000 ||
		got.FirstFailure.Phase != gateB3PreferredReturn || got.FirstFailure.Error.Class != "context_deadline" ||
		got.Points[gateB3RouterTerminal].Error.Class != "context_deadline" ||
		got.Points[gateB3RouterClose].Error.Class != "context_canceled" {
		t.Fatalf("first observations overwritten by terminal/cleanup: %+v", got)
	}
	got.Points[gateB3ObserverDone].AtNS = -1
	got.Query.Error.Class = "changed"
	if diag.snapshot().Points[gateB3ObserverDone].AtNS < 0 || diag.snapshot().Query.Error.Class != "permission" {
		t.Fatal("snapshot aliases live state")
	}
}

func TestGateB3LifetimeDiagnosticConcurrentSnapshot(t *testing.T) {
	diag := &gateB3NATDiagnostic{origin: time.Now()}
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				diag.mark(gateB3PreferredEnter, time.Now(), nil, nil)
				diag.queryStart()
				diag.queryEnd("zero", nil, nil)
				diag.fail(gateB3PreferredReturn, context.DeadlineExceeded, nil)
				_ = diag.snapshot()
			}
		}()
	}
	workers.Wait()
	got := diag.snapshot()
	if got.Query.Started != 1600 || got.Query.Completed != 1600 || got.Query.Zero != 1600 || !got.FirstFailure.Seen {
		t.Fatalf("bounded concurrent observations lost: %+v", got)
	}
	var absent *gateB3NATDiagnostic
	absent.mark(gateB3WriteBegin, time.Now(), nil, nil)
	absent.fail(gateB3WriteEnd, syscall.EPIPE, nil)
	absent.queryStart()
	absent.queryEnd("missing", nil, nil)
	if absent.snapshot() != (gateB3DiagnosticSnapshot{}) {
		t.Fatal("disabled diagnostics fabricated evidence")
	}
}

func TestGateB3LifetimeDiagnosticDenialPredicate(t *testing.T) {
	for _, test := range []struct{ text, outcome string }{
		{"", "missing"}, {"1 64 ACCEPT", "missing"}, {"1 DROP", "missing"},
		{"0 0 DROP", "zero"}, {"bad 0 DROP", "invalid"}, {"18446744073709551616 0 DROP", "invalid"},
		{"1 64 DROP", "positive"}, {"0 0 DROP\r\n2 128 DROP", "positive"},
		{"bad 0 DROP\n0 0 DROP", "invalid"}, {"bad 0 DROP\n1 64 DROP", "positive"},
	} {
		if got := gateB3DenialOutcome([]byte(test.text)); got != test.outcome {
			t.Errorf("DROP outcome=%s want=%s", got, test.outcome)
		}
	}
}

func TestGateB3LifetimeDiagnosticCleanupContinuesAfterEveryFailure(t *testing.T) {
	for failAt := range gateB3FailureCleanupStageCount {
		var checks [gateB3FailureCleanupStageCount]func() bool
		var visited []int
		for stage := range checks {
			checks[stage] = func() bool { visited = append(visited, stage); return stage != failAt }
		}
		result := gateB3RunFailureCleanup(checks)
		if len(visited) != len(checks) {
			t.Fatal("cleanup failure bypassed later evidence")
		}
		for stage, ok := range result {
			if visited[stage] != stage || ok != (stage != failAt) {
				t.Fatalf("cleanup observation/order changed at stage %d", stage)
			}
		}
	}
	if got := gateB3RunFailureCleanup([gateB3FailureCleanupStageCount]func() bool{}); got != ([gateB3FailureCleanupStageCount]bool{}) {
		t.Fatal("unavailable cleanup observations claimed PASS")
	}
}

// Read the actual tagged fixture, not a Windows clone. Mutations prove that
// adding standalone diagnostic tests cannot hide disconnected observation.
func TestGateB3LifetimeDiagnosticWiringMutations(t *testing.T) {
	for _, file := range []struct {
		name     string
		required []string
	}{
		{"gate_b3_netns_linux_test.go", []string{
			"logGateB3RouterPair(t, pair...)", "gateB3FailedCaseCleanup(t, topology, observer",
			"if t.Failed() && !residueComplete", "rightRouter, responderResult.UDPPackets+responderResult.DataPacketsWritten, leftRouter, rightRouter",
		}},
		{"gate_b3_mapping_lifetime_linux_test.go", []string{
			"diag.queryEnd(\"\", err, ctx.Err())", "diag.mark(gateB3ObserverDone",
			"diag.mark(gateB3PreferredDeadline", "plan.diagnostics[side].mark(gateB3PeerReady",
			"if outcome == \"positive\"", "ctx, cancel = context.WithTimeout(ctx, 2*time.Second)",
			"ctx, cancel := context.WithTimeout(plan.ctx, 2*time.Second)", "command.WaitDelay = 100 * time.Millisecond",
		}},
		{"gate_b2_nat_linux_test.go", []string{
			"gateB3Diagnostic.mark(gateB3RouterTerminal", "gateB3Diagnostic.mark(gateB3RouterClose",
			"diag.fail(gateB3PreferredReturn", "diag.fail(gateB3MappingBindEnd", "diag.fail(gateB3SocketOption", "diag.fail(gateB3WriteEnd",
		}},
	} {
		data, err := os.ReadFile(file.name)
		if err != nil {
			t.Fatal("tagged fixture source unavailable")
		}
		source := string(data)
		check := func(text string) bool {
			for _, required := range file.required {
				if !strings.Contains(text, required) {
					return false
				}
			}
			return true
		}
		if !check(source) {
			t.Fatalf("diagnostic wiring missing in %s", file.name)
		}
		for index, required := range file.required {
			t.Run(fmt.Sprintf("%s_%d", file.name, index), func(t *testing.T) {
				if check(strings.ReplaceAll(source, required, "DIAGNOSTIC_MUTATION")) {
					t.Fatal("disconnected observation escaped gate")
				}
			})
		}
	}
}

func TestGateB3LifetimeDiagnosticEveryFatalHasBothSnapshots(t *testing.T) {
	data, err := os.ReadFile("gate_b3_netns_linux_test.go")
	if err != nil {
		t.Fatal("tagged fixture source unavailable")
	}
	valid, offsets := gateB3OutboundFatalSnapshots(data)
	if !valid || len(offsets) != 3 {
		t.Fatal("every outbound Fatal must have a preceding bilateral snapshot")
	}
	for index, offset := range offsets {
		mutant := append([]byte(nil), data...)
		copy(mutant[offset:offset+len("logGateB3RouterPair")], "badGateB3RouterPair")
		if ok, _ := gateB3OutboundFatalSnapshots(mutant); ok {
			t.Fatalf("missing snapshot at Fatal %d escaped mutation gate", index)
		}
	}
}

func gateB3OutboundFatalSnapshots(source []byte) (bool, []int) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "fixture.go", source, 0)
	if err != nil {
		return false, nil
	}
	valid := true
	var offsets []int
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "waitGateB3RouterOutbound" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			block, ok := node.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for index, statement := range block.List {
				expression, ok := statement.(*ast.ExprStmt)
				if !ok {
					continue
				}
				call, ok := expression.X.(*ast.CallExpr)
				if !ok {
					continue
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (selector.Sel.Name != "Fatal" && selector.Sel.Name != "Fatalf") {
					continue
				}
				if index == 0 {
					valid = false
					continue
				}
				previous, ok := block.List[index-1].(*ast.ExprStmt)
				if !ok {
					valid = false
					continue
				}
				previousCall, ok := previous.X.(*ast.CallExpr)
				if !ok {
					valid = false
					continue
				}
				name, ok := previousCall.Fun.(*ast.Ident)
				if !ok || name.Name != "logGateB3RouterPair" || len(previousCall.Args) != 2 || !previousCall.Ellipsis.IsValid() {
					valid = false
					continue
				}
				pair, ok := previousCall.Args[1].(*ast.Ident)
				if !ok || pair.Name != "pair" {
					valid = false
					continue
				}
				offsets = append(offsets, set.Position(name.Pos()).Offset)
			}
			return true
		})
	}
	return valid && len(offsets) == 3, offsets
}
