//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func lifetimeObserverTestTuple() gateB3LifetimeTuple {
	return gateB3LifetimeTuple{netip.MustParseAddrPort("192.0.2.1:50001"), netip.MustParseAddrPort("198.51.100.1:50002")}
}

func lifetimeObserverTestModel(t *testing.T, read func(context.Context, string, gateB3LifetimeTuple) (bool, error)) (*gateB3NATLifetime, chan time.Time) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	model := &gateB3NATLifetime{idle: 60 * time.Second, ctx: ctx, cancel: cancel,
		done: make(chan struct{}), flows: make(map[gateB3LifetimeTuple]gateB3LifetimeFlow)}
	key := lifetimeObserverTestTuple()
	model.track(key[0], key[1])
	ticks := make(chan time.Time)
	go model.observeTicks(ticks, read)
	t.Cleanup(func() {
		cancel()
		select {
		case <-model.done:
		case <-time.After(2 * time.Second):
			t.Error("fake observer did not drain")
		}
	})
	return model, ticks
}

func lifetimeObserverTestTick(t *testing.T, model *gateB3NATLifetime, ticks chan<- time.Time) {
	t.Helper()
	select {
	case ticks <- time.Now():
	case <-model.done:
		t.Fatal("a single sampling failure terminated the observer")
	case <-time.After(2 * time.Second):
		t.Fatal("fake observer did not accept its next tick")
	}
}

func TestGateB3LifetimeObserverTimeoutContinues(t *testing.T) {
	calls := 0 // only the observer worker accesses this counter
	model, ticks := lifetimeObserverTestModel(t, func(ctx context.Context, namespace string, key gateB3LifetimeTuple) (bool, error) {
		calls++
		return readGateB3LifetimeFlowWithRunner(ctx, namespace, key, func(command *exec.Cmd) ([]byte, error) {
			if calls == 1 {
				<-ctx.Done() // the real, unchanged one-second per-query deadline
				return nil, ctx.Err()
			}
			return []byte("udp synthetic exact-key result\n"), nil
		})
	})
	lifetimeObserverTestTick(t, model, ticks)
	lifetimeObserverTestTick(t, model, ticks)
	// No third query: the unbuffered next-tick handoff above proves the first
	// query completed. Wait for the second cache update, never for the kernel.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		model.mu.Lock()
		flow, failure := model.flows[lifetimeObserverTestTuple()], model.failure
		timedOut, errored := model.samplesTimedOut, model.samplesErrored
		model.mu.Unlock()
		if failure != nil {
			t.Fatal("timeout became a fixture failure")
		}
		if flow.samples == 1 {
			if !flow.present || flow.presentAt.IsZero() || !flow.goneAt.IsZero() || timedOut != 1 || errored != 0 {
				t.Fatal("timeout created an absence witness or lost the next positive sample")
			}
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("observer never recorded its next successful sample")
		}
	}
}

func TestGateB3LifetimeObserverMissingCommandFatal(t *testing.T) {
	model, ticks := lifetimeObserverTestModel(t, func(ctx context.Context, namespace string, key gateB3LifetimeTuple) (bool, error) {
		return readGateB3LifetimeFlowWithRunner(ctx, namespace, key, func(*exec.Cmd) ([]byte, error) {
			return nil, exec.ErrNotFound
		})
	})
	lifetimeObserverTestTick(t, model, ticks)
	select {
	case <-model.done:
	case <-time.After(2 * time.Second):
		t.Fatal("missing command did not stop the observer")
	}
	if err := model.close(); err == nil || !strings.Contains(err.Error(), "command unavailable") {
		t.Fatal("missing command lost its fatal classification")
	}
}

func TestGateB3LifetimeObserverTailBeforeFirstSample(t *testing.T) {
	key := lifetimeObserverTestTuple()
	model := &gateB3NATLifetime{idle: 60 * time.Second, flows: map[gateB3LifetimeTuple]gateB3LifetimeFlow{key: {}}}
	model.beforeWinner(key[0], key[1], time.Second, 1)
	if model.winner.samples != 0 || model.age.Milliseconds() != 1000 || model.refresh != 1 || model.sentAt.IsZero() {
		t.Fatal("tail fixture lost its exact age/outbound witness")
	}
	if !validGateB3StableObservation(model.winner, model.age, model.idle, model.refresh, model.sentAt) {
		t.Fatal("M-S rejected an unsampled tail winner with exact age/outbound witness")
	}
	for _, bad := range []struct {
		age     time.Duration
		refresh uint64
	}{
		{model.age, 0},
		{model.age, 2},
		{model.idle, 1},
	} {
		if validGateB3StableObservation(model.winner, bad.age, model.idle, bad.refresh, model.sentAt) {
			t.Fatal("unsampled disposition waived the age/outbound boundary")
		}
	}
}

func TestGateB3LifetimeObserverExpiryNeedsSecondObservation(t *testing.T) {
	sentAt := time.Now()
	positive := gateB3LifetimeFlow{presentAt: sentAt.Add(-31 * time.Second),
		sampledAt: sentAt.Add(-time.Second), present: true, samples: 1}
	if validGateB3ExpiryObservation(positive, sentAt) || validGateB3ExpiryObservation(gateB3LifetimeFlow{}, sentAt) {
		t.Fatal("M-E accepted a missing explicit negative observation")
	}
	negative := positive
	negative.goneAt, negative.sampledAt, negative.present, negative.samples = sentAt.Add(-time.Second), sentAt.Add(-time.Second), false, 2
	if !validGateB3ExpiryObservation(negative, sentAt) {
		t.Fatal("M-E rejected its unchanged positive-then-negative witness")
	}
}

func TestGateB3LifetimeObserverCanceledExitIsNotAbsence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	present, err := readGateB3LifetimeFlowWithRunner(ctx, "", lifetimeObserverTestTuple(), func(*exec.Cmd) ([]byte, error) {
		return []byte("conntrack v1: such conntrack doesn't exist"), &exec.ExitError{}
	})
	if present || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled ExitError was not classified as an interrupted sample")
	}
}

type lifetimeObserverExitError int

func (err lifetimeObserverExitError) Error() string { return "synthetic command exit" }
func (err lifetimeObserverExitError) ExitCode() int { return int(err) }

func TestGateB3LifetimeObserverQueryClassification(t *testing.T) {
	for _, test := range []struct {
		name, contextState, output string
		err                        error
		wantPresent                bool
		wantError                  error
		wantOtherError             bool
	}{
		{name: "one_positive", output: "udp synthetic exact-key result\n", wantPresent: true},
		{name: "explicit_negative", output: "conntrack v1: such conntrack doesn't exist", err: lifetimeObserverExitError(1)},
		{name: "wrong_exit_negative", output: "conntrack v1: such conntrack doesn't exist", err: lifetimeObserverExitError(2), wantOtherError: true},
		{name: "missing_version_prefix", output: "such conntrack doesn't exist", err: lifetimeObserverExitError(1), wantOtherError: true},
		{name: "partial_output_negative", output: "conntrack v1: such conntrack doesn't exist\nudp partial", err: lifetimeObserverExitError(1), wantOtherError: true},
		{name: "empty_success", wantOtherError: true},
		{name: "ambiguous_success", output: "udp synthetic\nudp synthetic\n", wantOtherError: true},
		{name: "missing_command", err: fmt.Errorf("PRIVATE_OBSERVER_DETAIL: %w", exec.ErrNotFound), wantError: errGateB3LifetimeCommandUnavailable},
		{name: "missing_command_and_deadline", contextState: "expired", err: exec.ErrNotFound, wantError: errGateB3LifetimeCommandUnavailable},
		{name: "prestart_deadline", contextState: "expired", err: context.DeadlineExceeded, wantError: context.DeadlineExceeded},
		{name: "killed_child_deadline", contextState: "expired", err: &exec.ExitError{}, wantError: context.DeadlineExceeded},
		{name: "deadline_with_negative", contextState: "expired", output: "conntrack v1: such conntrack doesn't exist", err: lifetimeObserverExitError(1), wantError: context.DeadlineExceeded},
		{name: "late_positive", contextState: "expired", output: "udp synthetic", wantError: context.DeadlineExceeded},
		{name: "parent_cancel", contextState: "canceled", err: &exec.ExitError{}, wantError: context.Canceled},
		{name: "wrapped_interruption", err: fmt.Errorf("interrupted: %w", context.Canceled), wantError: context.Canceled},
		{name: "other_start_failure", err: errors.New("PRIVATE_OBSERVER_DETAIL"), wantOtherError: true},
		{name: "other_exit", err: lifetimeObserverExitError(2), output: "PRIVATE_OBSERVER_DETAIL", wantOtherError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			switch test.contextState {
			case "expired":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			present, err := readGateB3LifetimeFlowWithRunner(ctx, "", lifetimeObserverTestTuple(), func(command *exec.Cmd) ([]byte, error) {
				if command.WaitDelay != 100*time.Millisecond || !strings.Contains(strings.Join(command.Args, " "), "conntrack -G -p udp") {
					t.Error("runner lost its bounded exact-key command")
				}
				return []byte(test.output), test.err
			})
			if present != test.wantPresent || test.wantError != nil && !errors.Is(err, test.wantError) ||
				test.wantOtherError && (err == nil || errors.Is(err, errGateB3LifetimeCommandUnavailable)) ||
				test.wantError == nil && !test.wantOtherError && err != nil {
				t.Fatal("query result classification differs from the frozen vector")
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE_OBSERVER_DETAIL") {
				t.Fatal("query error exposed unredacted command detail")
			}
		})
	}
}

func TestGateB3LifetimeObserverErrorStreak(t *testing.T) {
	for _, reset := range []error{nil, context.DeadlineExceeded, context.Canceled} {
		model := &gateB3NATLifetime{flows: make(map[gateB3LifetimeTuple]gateB3LifetimeFlow)}
		key, now := lifetimeObserverTestTuple(), time.Now()
		failure := errors.New("mapping lifetime reverse-flow read failed: exit=2")
		for n := 0; n < gateB3LifetimeMaxConsecutiveErrors-1; n++ {
			if !model.recordSample(key, false, failure, now) || model.failure != nil {
				t.Fatal("observer failed before eight consecutive query errors")
			}
		}
		if !model.recordSample(key, true, reset, now) || model.consecutiveErrors != 0 {
			t.Fatal("success/interruption did not break the nonzero-exit streak")
		}
		for n := 1; n <= gateB3LifetimeMaxConsecutiveErrors; n++ {
			if continued := model.recordSample(key, false, failure, now); continued != (n < gateB3LifetimeMaxConsecutiveErrors) {
				t.Fatal("observer consecutive-error cutoff differs")
			}
		}
		if model.failure == nil || model.samplesErrored != 15 || model.flows[key].samples != boolLifetimeInt(reset == nil) ||
			model.samplesTimedOut != boolLifetimeInt(reset != nil) || !model.flows[key].goneAt.IsZero() {
			t.Fatal("error streak lost exact counts or invented absence")
		}
	}
	// Exercise the actual loop's fatal branch, not just the counter helper.
	model, ticks := lifetimeObserverTestModel(t, func(context.Context, string, gateB3LifetimeTuple) (bool, error) {
		return false, errors.New("mapping lifetime reverse-flow read failed: exit=2")
	})
	for n := 0; n < gateB3LifetimeMaxConsecutiveErrors; n++ {
		lifetimeObserverTestTick(t, model, ticks)
	}
	select {
	case <-model.done:
	case <-time.After(2 * time.Second):
		t.Fatal("consecutive-error limit did not drain the worker")
	}
	if model.close() == nil || model.samplesErrored != 8 {
		t.Fatal("consecutive-error failure was not retained through drain")
	}
}

func TestGateB3LifetimeObserverFailedQueryNeverUpdatesEvidence(t *testing.T) {
	key, now := lifetimeObserverTestTuple(), time.Now()
	model := &gateB3NATLifetime{flows: make(map[gateB3LifetimeTuple]gateB3LifetimeFlow)}
	model.recordSample(key, true, nil, now.Add(-time.Second))
	positive := model.flows[key]
	for _, err := range []error{context.DeadlineExceeded, context.Canceled, errors.New("query failed")} {
		if !model.recordSample(key, false, err, now) || model.flows[key] != positive {
			t.Fatal("failed query changed the last successful presence evidence")
		}
		if validGateB3ExpiryObservation(model.flows[key], now) {
			t.Fatal("M-E mistook a failed query for confirmed disappearance")
		}
	}
	if model.samplesTimedOut != 2 || model.samplesErrored != 1 || model.failure != nil {
		t.Fatal("failed-query counters differ")
	}
}

func TestGateB3LifetimeObserverWinnerSnapshotImmutable(t *testing.T) {
	key, now := lifetimeObserverTestTuple(), time.Now()
	model := &gateB3NATLifetime{idle: 60 * time.Second, flows: make(map[gateB3LifetimeTuple]gateB3LifetimeFlow)}
	model.track(key[0], key[1])
	model.beforeWinner(key[0], key[1], time.Second, 1)
	model.recordSample(key, true, nil, now)
	model.recordSample(key, false, nil, now.Add(time.Second))
	if model.winner != (gateB3LifetimeFlow{}) || model.flows[key].samples != 2 ||
		validGateB3ExpiryObservation(model.winner, model.sentAt) {
		t.Fatal("after-winner sampling filled in the frozen pre-send evidence")
	}
	for _, flow := range []gateB3LifetimeFlow{
		{samples: 1, sampledAt: now}, // a completed negative, not unsampled
		{samples: 1, present: true, presentAt: now, sampledAt: now.Add(-2 * time.Second)},
		{samples: 2, present: true, presentAt: now, goneAt: now, sampledAt: now},
	} {
		if validGateB3StableObservation(flow, time.Second, time.Minute, 1, now) {
			t.Fatal("M-S unsampled exception waived sampled negative/stale/gone evidence")
		}
	}
	valid := gateB3LifetimeFlow{samples: 1, present: true, presentAt: now.Add(-time.Second), sampledAt: now.Add(-time.Second)}
	if !validGateB3StableObservation(valid, time.Second, time.Minute, 1, now) {
		t.Fatal("M-S rejected unchanged fresh sampled evidence")
	}
}

func boolLifetimeInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
