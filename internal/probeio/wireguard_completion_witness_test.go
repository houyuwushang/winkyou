package probeio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestConsumerFinishedCompletionFailureWitness(t *testing.T) {
	for _, test := range []struct {
		name, point, cause, attempt, session string
		finished                             bool
	}{
		{"session_cancel", "after_durable_finish", "canceled", "active", "canceled", true},
		{"session_deadline", "after_durable_finish", "deadline_exceeded", "active", "deadline_exceeded", true},
		{"attempt_cancel", "after_durable_finish", "canceled", "canceled", "active", true},
		{"attempt_deadline", "after_durable_finish", "deadline_exceeded", "deadline_exceeded", "active", true},
		{"durable_error", "durable_finish", "other", "active", "active", false},
		{"lease_closed", "detach", "lease_inactive", "active", "active", true},
		{"private_cancel_cause", "after_durable_finish", "canceled", "active", "canceled", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			absolute := time.Duration(0)
			if test.name == "attempt_deadline" {
				absolute = time.Second
			}
			gate, _, lease, calls := completionPhaseFixture(t, WireGuardInitiator, false, absolute)
			lifetime := 8 * time.Second
			if test.name == "session_deadline" {
				lifetime = time.Second
			}
			base, stop := context.WithTimeout(context.Background(), lifetime)
			defer stop()
			ctx, cancel := context.WithCancelCause(base)
			defer cancel(nil)
			privateDetail := "synthetic-untrusted-error-do-not-export"
			err := gate.FinishAndActivate(ctx, func() error {
				switch test.name {
				case "session_cancel":
					cancel(nil)
				case "session_deadline":
					<-ctx.Done()
				case "attempt_cancel":
					gate.attemptCancel()
				case "attempt_deadline":
					<-gate.attemptCtx.Done()
				case "durable_error":
					return errors.New(privateDetail)
				case "lease_closed":
					return lease.Close()
				case "private_cancel_cause":
					cancel(errors.New(privateDetail))
				}
				return nil
			})
			w := gate.Witness()
			failure := w.CompletionFailure
			if err == nil || failure == nil || failure.Point != test.point || failure.Cause != test.cause ||
				failure.Attempt.State != test.attempt || failure.Session.State != test.session ||
				failure.GateState != wireGuardGateFinishConfirming || w.State != WireGuardGateClosed ||
				w.FinishRecorded != test.finished || w.AttemptDetached || !w.PeerFinishConfirmed ||
				calls.reads.Load() != 3 || calls.writes.Load() != 3 {
				t.Fatalf("failure witness mismatch: case=%s witness=%+v failure=%+v reads=%d writes=%d",
					test.name, w, failure, calls.reads.Load(), calls.writes.Load())
			}
			if !failure.Attempt.Bounded || !failure.Session.Bounded || !failure.Challenge.Bounded ||
				(test.attempt == "active" && failure.Attempt.RemainingMillis <= 0) ||
				(test.session == "deadline_exceeded" && failure.Session.RemainingMillis > 0) ||
				(test.attempt == "deadline_exceeded" && failure.Attempt.RemainingMillis > 0) {
				t.Fatal("deadline witness was lost or captured after cleanup")
			}
			if test.name == "private_cancel_cause" && failure.Session.Cause != "other" {
				t.Fatal("arbitrary context cause was not redacted")
			}
			encoded, err := json.Marshal(failure)
			if err != nil || bytes.Contains(encoded, []byte(privateDetail)) {
				t.Fatal("completion witness exposed an arbitrary error string")
			}
			original := *failure
			failure.Point = "caller-mutated-copy"
			failure.Attempt.State = "caller-mutated-copy"
			// A repeated call must not overwrite the first pre-cleanup evidence.
			_ = gate.FinishAndActivate(ctx, func() error { t.Error("repeated FINISH"); return nil })
			if *gate.Witness().CompletionFailure != original {
				t.Fatal("witness aliasing or cleanup overwrote the original failure")
			}
		})
	}
}

func TestConsumerFinishedSuccessfulWitnessRemainsAdditive(t *testing.T) {
	gate, _, _, _ := completionPhaseFixture(t, WireGuardInitiator, false, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := gate.FinishAndActivate(ctx, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	w := gate.Witness()
	encoded, err := json.Marshal(w)
	if err != nil || w.CompletionFailure != nil || bytes.Contains(encoded, []byte("CompletionFailure")) {
		t.Fatal("successful witness JSON changed")
	}
}
