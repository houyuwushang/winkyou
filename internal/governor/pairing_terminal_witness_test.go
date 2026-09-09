package governor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPairingTerminalWitnessExactLeaseAndOriginalFailure(t *testing.T) {
	for _, path := range []string{"consume", "postcheck", "already_finished"} {
		t.Run(path, func(t *testing.T) {
			env := newTestPairingGateEnvironment(t, "terminal-witness", OperationConnectTest)
			var terminalErr error
			if path == "postcheck" {
				gate := &PairingAdmissionGate{hooks: pairingAdmissionGateHooks{
					afterPostcheck: func() error { return context.Canceled },
				}}
				_, terminalErr = gate.Commit(context.Background(), env.attempt, env.request)
			} else {
				committed, err := NewPairingAdmissionGate().Commit(context.Background(), env.attempt, env.request)
				if err != nil {
					t.Fatal(err)
				}
				if path == "already_finished" {
					if err := committed.finish(PairingTerminalCancelled); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				authorization, err := committed.ConsumeForCarrier(ctx)
				if authorization != nil {
					t.Fatal("failed consume granted emission authority")
				}
				terminalErr = err
			}
			if path != "already_finished" && !errors.Is(terminalErr, context.Canceled) {
				t.Fatalf("original cancellation lost: %v", terminalErr)
			}
			if !PairingTerminalRecordedForAttempt(terminalErr, env.attempt) ||
				!PairingTerminalRecordedForAttempt(fmt.Errorf("wrapped: %w", terminalErr), env.attempt) {
				t.Fatal("durable failure did not attest to its original lease")
			}
			var marker *durablePairingTerminalError
			if !errors.As(terminalErr, &marker) || terminalErr.Error() != marker.cause.Error() {
				t.Fatal("witness changed public failure text")
			}
			assertPairingJournalSequence(t, env, 3)
			// Same identifiers and cost in another namespace are NOT the same
			// attempt instance. A saved witness cannot release a restart's lease.
			foreign := newTestPairingGateEnvironment(t, "terminal-witness", OperationConnectTest)
			for _, attempt := range []*AttemptLease{nil, new(AttemptLease), foreign.attempt} {
				if PairingTerminalRecordedForAttempt(terminalErr, attempt) {
					t.Fatal("foreign/zero lease accepted")
				}
			}
			for _, err := range []error{nil, context.Canceled, ErrCommittedAttemptInvalid, errors.New(terminalErr.Error()),
				&durablePairingTerminalError{cause: context.Canceled}} {
				if PairingTerminalRecordedForAttempt(err, env.attempt) {
					t.Fatal("unproven terminal accepted")
				}
			}
			select {
			case <-env.attempt.Done():
				t.Fatal("read-only witness released the attempt")
			default:
			}
			if err := env.attempt.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPairingTerminalWitnessRequiresSuccessfulFinishSync(t *testing.T) {
	for _, path := range []string{"consume", "postcheck"} {
		t.Run(path, func(t *testing.T) {
			env := newTestPairingGateEnvironment(t, "terminal-write-failure", OperationConnectTest)
			injected := errors.New("synthetic FINISH sync failure")
			env.ledger.hooks.afterAppendBeforeSync = func(record pairingJournalRecord) error {
				if record.Type == pairingRecordFinish {
					return injected
				}
				return nil
			}
			var terminalErr error
			if path == "postcheck" {
				gate := &PairingAdmissionGate{hooks: pairingAdmissionGateHooks{
					afterPostcheck: func() error { return context.Canceled },
				}}
				_, terminalErr = gate.Commit(context.Background(), env.attempt, env.request)
			} else {
				committed, err := NewPairingAdmissionGate().Commit(context.Background(), env.attempt, env.request)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				_, terminalErr = committed.ConsumeForCarrier(ctx)
			}
			if !errors.Is(terminalErr, injected) || PairingTerminalRecordedForAttempt(terminalErr, env.attempt) {
				t.Fatalf("failed sync granted a terminal witness: %v", terminalErr)
			}
			select {
			case <-env.attempt.Done():
				t.Fatal("failed FINISH released attempt")
			default:
			}
		})
	}
}

func TestPairingTerminalWitnessWaitsForFinishCompletion(t *testing.T) {
	env := newTestPairingGateEnvironment(t, "terminal-slow-finish", OperationConnectTest)
	entered, release := make(chan struct{}), make(chan struct{})
	env.ledger.hooks.afterSync = func(record pairingJournalRecord) error {
		if record.Type == pairingRecordFinish {
			close(entered)
			<-release
		}
		return nil
	}
	committed, err := NewPairingAdmissionGate().Commit(context.Background(), env.attempt, env.request)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	go func() { _, err := committed.ConsumeForCarrier(ctx); results <- err }()
	timer := time.NewTimer(2*time.Second + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-entered:
	case <-timer.C:
		close(release)
		t.Fatal("FINISH did not reach barrier")
	}
	select {
	case <-results:
		close(release)
		t.Fatal("consume returned before FINISH completed")
	default:
	}
	select {
	case <-env.attempt.Done():
		close(release)
		t.Fatal("attempt released before FINISH completed")
	default:
	}
	close(release)
	select {
	case err := <-results:
		if !PairingTerminalRecordedForAttempt(err, env.attempt) {
			t.Fatal("completed FINISH lacked witness")
		}
	case <-timer.C:
		t.Fatal("consume did not drain after releasing FINISH barrier")
	}
	assertPairingJournalSequence(t, env, 3)
}
