//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
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
		model.mu.Unlock()
		if failure != nil {
			t.Fatal("timeout became a fixture failure")
		}
		if flow.samples == 1 {
			if !flow.present || flow.presentAt.IsZero() || !flow.goneAt.IsZero() {
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
