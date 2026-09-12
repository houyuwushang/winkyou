//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGateB3LifetimeDiagnosticRealObserver(t *testing.T) {
	for _, mode := range []string{"positive", "query_error", "canceled_before_positive", "zero_missing_invalid_then_positive"} {
		t.Run(mode, func(t *testing.T) {
			origin := time.Now()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			base := newGateB3LateHitMappingPlan()
			base.hitOrdinal = 0
			plan := &gateB3OrderedEarlyMappingPlan{base: base, firstLeft: false,
				firstSent: make(chan struct{}), firstDenied: make(chan struct{}),
				ctx: ctx, cancel: cancel, done: make(chan struct{}), peerNamespace: "synthetic-namespace",
				diagnostics: [2]*gateB3NATDiagnostic{{origin: origin}, {origin: origin}}}
			queryEntered, queryRelease := make(chan struct{}), make(chan struct{})
			queries := 0
			commandValid := true
			go plan.observeInitialDenialWith(func(command *exec.Cmd) ([]byte, error) {
				commandValid = commandValid && reflect.DeepEqual(command.Args,
					[]string{"ip", "netns", "exec", "synthetic-namespace", "iptables", "-w", "1", "-nvxL", "WYM_INITIAL"}) &&
					command.WaitDelay == 100*time.Millisecond
				queries++
				if queries == 1 {
					close(queryEntered)
				}
				switch mode {
				case "query_error":
					return nil, syscall.EACCES
				case "canceled_before_positive":
					<-queryRelease
				case "zero_missing_invalid_then_positive":
					if queries < 4 {
						return []byte([]string{"0 0 DROP", "1 64 ACCEPT", "bad 0 DROP"}[queries-1]), nil
					}
				}
				return []byte("1 64 DROP"), nil
			})
			// An observer assertion failure must not strand its controlled
			// query. This is test cleanup, never a forwarding/release condition.
			defer func() {
				select {
				case <-queryRelease:
				default:
					close(queryRelease)
				}
				if !plan.stopObserver() {
					t.Error("test observer did not join")
				}
			}()
			waitCtx, waitCancel := context.WithCancel(ctx)
			defer waitCancel()
			leftDone, rightDone := make(chan error, 1), make(chan error, 1)
			go func() { _, err := plan.preferred(waitCtx, true, 50000); leftDone <- err }()
			go func() { _, err := plan.preferred(ctx, false, 60000); rightDone <- err }()
			if err := gateB3DiagnosticReceive(t, rightDone); err != nil {
				t.Fatal("first sender could not pass unchanged peer barrier")
			}
			plan.forwarded(false)
			select {
			case <-queryEntered:
			case <-time.After(time.Second):
				t.Fatal("query did not start after first send")
			}
			if mode == "canceled_before_positive" {
				waitCancel()
				if !errors.Is(gateB3DiagnosticReceive(t, leftDone), context.Canceled) {
					t.Fatal("waiting caller did not cancel")
				}
				close(queryRelease)
			}
			select {
			case <-plan.done:
			case <-time.After(time.Second):
				t.Fatal("query observer did not join")
			}
			if !commandValid {
				t.Fatal("diagnostic seam changed the frozen query command")
			}
			if mode == "query_error" {
				select {
				case <-plan.firstDenied:
					t.Fatal("query error released DROP gate")
				default:
				}
				waitCancel()
				if !errors.Is(gateB3DiagnosticReceive(t, leftDone), context.Canceled) {
					t.Fatal("query error changed original waiter cancellation")
				}
			} else if mode != "canceled_before_positive" {
				if err := gateB3DiagnosticReceive(t, leftDone); err != nil {
					t.Fatal("positive DROP did not release peer")
				}
			}
			left, right := plan.diagnostics[0].snapshot(), plan.diagnostics[1].snapshot()
			if right.Query.Started != uint64(queries) || right.Query.Completed != uint64(queries) || !right.Points[gateB3ObserverDone].Seen ||
				!left.Points[gateB3PeerReady].Seen || !left.Points[gateB3PreferredReturn].Seen ||
				right.Points[gateB3FirstSent].AtNS > right.Query.FirstStartNS || right.Query.LastStartNS > right.Query.LastEndNS ||
				left.Points[gateB3PreferredDeadline].AtNS-left.Points[gateB3PreferredEnter].AtNS > int64(2*time.Second) ||
				right.Points[gateB3DenialDeadline].AtNS-right.Points[gateB3DenialWait].AtNS > int64(2*time.Second) {
				t.Fatal("first synchronization phases/unchanged bounds not observed")
			}
			if mode == "query_error" && (right.Query.Error.Class != "permission" || right.Points[gateB3ObserverDone].Error.Class != "permission" ||
				left.Points[gateB3PreferredReturn].Error.Class != "context_canceled") {
				t.Fatal("query cause was replaced by waiter terminal")
			}
			if mode == "canceled_before_positive" && (left.Points[gateB3FirstDenied].AtNS < left.Points[gateB3PreferredReturn].AtNS ||
				left.Points[gateB3PreferredReturn].Error.Class != "context_canceled") {
				t.Fatal("late positive observation resurrected failed waiter")
			}
			if mode == "zero_missing_invalid_then_positive" && (right.Query.Zero != 1 || right.Query.Missing != 1 || right.Query.Invalid != 1 || right.Query.Positive != 1) {
				t.Fatal("non-positive observations were not distinguished")
			}
		})
	}
}

func gateB3DiagnosticReceive(t testing.TB, results <-chan error) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(time.Second):
		t.Fatal("diagnostic worker did not join")
		return context.DeadlineExceeded
	}
}

func TestGateB3LifetimeDiagnosticAbsentFirstSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	diag := &gateB3NATDiagnostic{origin: time.Now()}
	plan := &gateB3OrderedEarlyMappingPlan{ctx: ctx, cancel: cancel, firstSent: make(chan struct{}), done: make(chan struct{}),
		diagnostics: [2]*gateB3NATDiagnostic{nil, diag}}
	called := false
	go plan.observeInitialDenialWith(func(*exec.Cmd) ([]byte, error) { called = true; return nil, nil })
	if !plan.stopObserver() {
		t.Fatal("absent opener observer did not join")
	}
	got := diag.snapshot()
	if called || got.Query.Started != 0 || got.Points[gateB3ObserverDone].Error.Class != "context_canceled" {
		t.Fatal("absence started query or lost cancellation")
	}
}

type gateB3DiagnosticTB struct {
	testing.TB
	lines []string
}

func (*gateB3DiagnosticTB) Helper() {}
func (recorder *gateB3DiagnosticTB) Logf(format string, args ...any) {
	recorder.lines = append(recorder.lines, fmt.Sprintf(format, args...))
}
func (recorder *gateB3DiagnosticTB) Fatalf(string, ...any) {
	recorder.lines = append(recorder.lines, "FATAL")
	panic("expected fatal")
}

func TestGateB3LifetimeDiagnosticBothSidesBeforeFatal(t *testing.T) {
	left := &gateB2NATRouter{config: gateB2NATConfig{gateB3Diagnostic: &gateB3NATDiagnostic{origin: time.Now()}}}
	right := &gateB2NATRouter{config: gateB2NATConfig{gateB3Diagnostic: &gateB3NATDiagnostic{origin: time.Now()}}}
	left.outbound.Store(1)
	right.config.gateB3Diagnostic.fail(gateB3MappingBindEnd, syscall.EADDRINUSE, nil)
	recorder := &gateB3DiagnosticTB{}
	func() {
		defer func() {
			if recover() != "expected fatal" {
				t.Fatal("original outbound excess assertion did not fail")
			}
		}()
		waitGateB3RouterOutbound(recorder, left, 0, left, right)
	}()
	joined := strings.Join(recorder.lines, "\n")
	if !strings.Contains(joined, "DIAGNOSTIC side=0") || !strings.Contains(joined, "DIAGNOSTIC side=1") ||
		!strings.Contains(joined, "Class:address_in_use") || !strings.HasSuffix(joined, "FATAL") {
		t.Fatal("left Fatal hid peer root cause")
	}
}

func TestGateB3LifetimeDiagnosticRealCloseRetainsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	diag := &gateB3NATDiagnostic{origin: time.Now()}
	router := &gateB2NATRouter{ctx: ctx, cancel: cancel, done: make(chan error, 1), config: gateB2NATConfig{gateB3Diagnostic: diag}}
	err := errors.Join(errGateB2NATOutbound, syscall.ENOBUFS)
	diag.fail(gateB3WriteEnd, err, nil)
	router.done <- err
	if !errors.Is(router.Close(), syscall.ENOBUFS) || router.Close() != nil {
		t.Fatal("diagnostics changed existing Close return contract")
	}
	got := diag.snapshot()
	if got.FirstFailure.Phase != gateB3WriteEnd || got.FirstFailure.Error.Class != "no_buffers" ||
		!got.Points[gateB3RouterClose].Seen || got.Points[gateB3RouterClose].Error.Class != "no_buffers" {
		t.Fatal("second cleanup call erased original Close failure")
	}
}
