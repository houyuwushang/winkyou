package governor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newLoopbackTerminationEnvironment(t *testing.T) *testPairingGateEnvironment {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Millisecond)
	ledger, _, path, owner := newTestPairingLedger(t, base, false)
	clock := &testPairingGateClock{value: base}
	ledger.now = clock.Now
	prepareTestSafetyTrip(t, filepath.Dir(path))
	owner.pairingLedger = ledger
	machine, err := New(owner, ProfilePhase1Machine, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = machine.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	peer, err := machine.AcquirePeer("two-phase-peer")
	if err != nil {
		t.Fatal(err)
	}
	request := testPairingRequest("two-phase", base, 3)
	cost := AttemptCost{Resources: Resources{Sockets: 1, Targets: 1, FiveTuples: 1, Packets: 3, PacketsPerSecond: 3}, Duration: 15 * time.Second, Heavyweight: true}
	request.Envelope = PairingEnvelopeFromAttemptCost(cost)
	attempt, err := peer.AcquireLoopbackAttempt(ctx, AttemptRequest{ID: request.AttemptID, Operation: OperationConnectTest, Cost: cost})
	if err != nil {
		t.Fatal(err)
	}
	return &testPairingGateEnvironment{ledger: ledger, clock: clock, path: path, owner: owner, governor: machine, attempt: attempt, request: request, context: ctx, cancel: cancel}
}

func commitLoopbackTermination(t *testing.T, env *testPairingGateEnvironment) (*CommittedAttempt, *CommittedCarrierAuthorization) {
	t.Helper()
	c, err := NewPairingAdmissionGate().Commit(env.context, env.attempt, env.request)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.ConsumeForCarrier(env.context)
	if err != nil {
		t.Fatal(err)
	}
	return c, a
}

func TestLoopbackTwoPhaseFinishOwnsReservationUntilSync(t *testing.T) {
	env := newLoopbackTerminationEnvironment(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var finishCalls atomic.Int32
	env.ledger.hooks.afterAppendBeforeSync = func(record pairingJournalRecord) error {
		if record.Type == pairingRecordFinish {
			finishCalls.Add(1)
			close(entered)
			<-release
		}
		return nil
	}
	committed, auth := commitLoopbackTermination(t, env)
	drain, err := env.attempt.RegisterDrain("synthetic-network")
	if err != nil {
		t.Fatal(err)
	}
	var hooks atomic.Int32
	if err := auth.RegisterLoopbackPreFinish(func() error { hooks.Add(1); return drain.Complete() }); err != nil {
		t.Fatal(err)
	}
	env.cancel()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("FINISH not reached after network drain")
	}
	snapshot := env.governor.Snapshot() // must not wait behind the blocked fsync
	if snapshot.ActiveAttempts != 1 || snapshot.Reserved != env.attempt.request.Cost.Resources || snapshot.SafetyTrip.BlocksActiveWork {
		t.Fatal("slow FINISH released admission or tripped")
	}
	if _, err := env.governor.AcquirePeer("forbidden-during-finish"); !errors.Is(err, ErrTerminalFinalizing) {
		t.Fatal("new peer not fenced")
	}
	if _, err := env.attempt.RegisterDrain("late-network"); !errors.Is(err, ErrLeaseClosed) {
		t.Fatal("late I/O drain accepted")
	}
	select {
	case <-env.attempt.Done():
		t.Fatal("attempt released before FINISH sync")
	default:
	}
	if owner, err := AcquirePreparedNamespace(filepath.Dir(env.path), ScopeMachine, "exclusion-witness"); err == nil {
		_ = owner.Close()
		t.Fatal("owner released before FINISH")
	}
	releaseOnce.Do(func() { close(release) })
	if err := auth.Finish(PairingTerminalCancelled); err != nil {
		t.Fatal(err)
	}
	if err := env.attempt.Close(); err != nil {
		t.Fatal(err)
	}
	if hooks.Load() != 1 || finishCalls.Load() != 1 {
		t.Fatal("hook or FINISH executed more than once")
	}
	select {
	case <-committed.writerDone:
	default:
		t.Fatal("writer not joined")
	}
	assertPairingJournalSequence(t, env, 3)
	ledger, err := readPairingLedgerSnapshot(env.path, env.clock.Now(), env.governor.ownerInfo.InstanceID, validateTestPairingLedgerFile)
	if err != nil || ledger.status.TwentyFourHourAdmissions != 1 || ledger.status.TwentyFourHourPackets != 3 {
		t.Fatal("terminal path refunded admission")
	}
	if env.governor.Snapshot().ActiveAttempts != 0 {
		t.Fatal("successful FINISH leaked reservation")
	}
}

func TestLoopbackTwoPhaseStalledFinishHasBoundedVerdictAndRetainsOwner(t *testing.T) {
	env := newLoopbackTerminationEnvironment(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	env.ledger.hooks.afterAppendBeforeSync = func(record pairingJournalRecord) error {
		if record.Type == pairingRecordFinish {
			close(entered)
			<-release
		}
		return nil
	}
	committed, auth := commitLoopbackTermination(t, env)
	hookErr := errors.New("synthetic revoke error before stalled FINISH")
	if err := auth.RegisterLoopbackPreFinish(func() error { return hookErr }); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	finished := make(chan error, 1)
	go func() { finished <- auth.Finish(PairingTerminalCancelled) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("FINISH not entered")
	}
	var finishErr error
	select {
	case finishErr = <-finished:
	case <-time.After(LoopbackFinalizationTimeout + 5*time.Second):
		t.Fatal("storage timeout failed to publish verdict")
	}
	if !errors.Is(finishErr, ErrTerminalFinalizationTimeout) || !errors.Is(finishErr, hookErr) || time.Since(started) < LoopbackFinalizationTimeout {
		t.Fatalf("incorrect timeout verdict: %v", finishErr)
	}
	if err := env.governor.Close(); !errors.Is(err, ErrTerminalFinalizationTimeout) {
		t.Fatal("Close did not preserve pending storage fault")
	}
	snapshot := env.governor.Snapshot()
	if snapshot.Closed || snapshot.ActiveAttempts != 1 || snapshot.Reserved != env.attempt.request.Cost.Resources || snapshot.SafetyTrip.BlocksActiveWork {
		t.Fatal("timeout faked closure or network trip")
	}
	if _, err := env.governor.AcquirePeer("forbidden-after-timeout"); !errors.Is(err, ErrTerminalFinalizationTimeout) {
		t.Fatal("timeout reopened admission")
	}
	select {
	case <-env.attempt.Done():
		t.Fatal("timeout released pending writer")
	default:
	}
	select {
	case <-committed.writerDone:
		t.Fatal("blocked writer reported done")
	default:
	}
	if owner, err := AcquirePreparedNamespace(filepath.Dir(env.path), ScopeMachine, "timeout-owner-witness"); err == nil {
		_ = owner.Close()
		t.Fatal("blocked writer lost OS exclusion")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-env.attempt.terminal.settled:
	case <-time.After(3 * time.Second):
		t.Fatal("late writer did not settle")
	}
	if _, err := env.governor.AcquirePeer("forbidden-after-late-success"); !errors.Is(err, ErrTerminalFinalizationTimeout) {
		t.Fatal("late success cleared fault")
	}
	if err := auth.Finish(PairingTerminalCancelled); !errors.Is(err, ErrTerminalFinalizationTimeout) {
		t.Fatal("late completion changed published verdict")
	}
	if env.governor.Snapshot().ActiveAttempts != 1 {
		t.Fatal("late success released quarantined charge")
	}
	_ = env.governor.Close() // now physically quiescent; error remains visible
	if !env.governor.Snapshot().Closed {
		t.Fatal("settled owner failed to close")
	}
	owner, err := AcquirePreparedNamespace(filepath.Dir(env.path), ScopeMachine, "settled-owner-witness")
	if err != nil {
		t.Fatal("settled owner leaked")
	}
	_ = owner.Close()
	t.Log("TWO_PHASE_TIMEOUT network_trip=false timeout=true late_success_clears_fault=false owner_retained_until_settled=true")
}

func TestLoopbackTwoPhaseFinishWriteFailureIsNotNetworkTrip(t *testing.T) {
	env := newLoopbackTerminationEnvironment(t)
	writeErr := errors.New("synthetic finish write failure")
	env.ledger.hooks.writeFrame = func(file *os.File, record pairingJournalRecord, frame []byte) (int, error) {
		if record.Type == pairingRecordFinish {
			return 0, writeErr
		}
		return file.Write(frame)
	}
	_, auth := commitLoopbackTermination(t, env)
	if err := auth.Finish(PairingTerminalCancelled); !errors.Is(err, writeErr) || !errors.Is(err, ErrTerminalFinalizationFailed) {
		t.Fatal("storage error lost its type")
	}
	<-env.attempt.terminal.settled
	if env.governor.Snapshot().SafetyTrip.BlocksActiveWork {
		t.Fatal("disk failure became network trip")
	}
	if _, err := env.governor.AcquirePeer("after-storage-failure"); !errors.Is(err, ErrTerminalFinalizationFailed) {
		t.Fatal("disk failure did not fence")
	}
	_ = env.governor.Close()
	ledger, err := readPairingLedgerSnapshot(env.path, env.clock.Now(), "", validateTestPairingLedgerFile)
	if err != nil || ledger.sequence != 2 || ledger.status.TwentyFourHourAdmissions != 1 || ledger.status.TwentyFourHourPackets != 3 {
		t.Fatal("failed FINISH changed durable BURN charge")
	}
}

func TestLoopbackTwoPhaseNetworkTimeoutStillPersistsTrip(t *testing.T) {
	env := newLoopbackTerminationEnvironment(t)
	_, auth := commitLoopbackTermination(t, env)
	drain, err := env.attempt.RegisterDrain("unresponsive-network-worker")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = drain.Complete() })
	started := time.Now()
	err = auth.Finish(PairingTerminalCancelled)
	if !errors.Is(err, ErrCancellationDrainTimeout) || errors.Is(err, ErrTerminalFinalizationTimeout) {
		t.Fatalf("wrong phase error: %v", err)
	}
	if time.Since(started) < 2*time.Second || env.governor.Snapshot().SafetyTrip.Record.Reason != SafetyTripCancellation {
		t.Fatal("original network tripwire disabled")
	}
	if owner, err := AcquirePreparedNamespace(filepath.Dir(env.path), ScopeMachine, "network-owner-witness"); err == nil {
		_ = owner.Close()
		t.Fatal("undrained network released owner")
	}
	_ = drain.Complete()
	<-env.attempt.terminal.settled
	_ = env.governor.Close()
	owner, err := AcquirePreparedNamespace(filepath.Dir(env.path), ScopeMachine, "network-trip-readback")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if status := owner.SafetyTripStatus(); status.Record.Reason != SafetyTripCancellation {
		t.Fatal("network timeout not persisted")
	}
}

func TestLoopbackTwoPhaseHookOnceExpiryAndAdmissionFailure(t *testing.T) {
	for _, stage := range []string{"expired-before-emission", "cancel-after-burn", "concurrent-finish"} {
		t.Run(stage, func(t *testing.T) {
			env := newLoopbackTerminationEnvironment(t)
			if stage == "cancel-after-burn" {
				gate := NewPairingAdmissionGate()
				gate.hooks.afterDurableAdmission = func() error { env.cancel(); return context.Canceled }
				if c, err := gate.Commit(env.context, env.attempt, env.request); c != nil || !errors.Is(err, context.Canceled) {
					t.Fatal("post-burn cancel accepted")
				}
				if err := env.attempt.Close(); err != nil {
					t.Fatal(err)
				}
				assertPairingJournalSequence(t, env, 3)
				return
			}
			_, auth := commitLoopbackTermination(t, env)
			var calls atomic.Int32
			hookErr := errors.New("synthetic hook error")
			if err := auth.RegisterLoopbackPreFinish(func() error { calls.Add(1); return hookErr }); err != nil {
				t.Fatal(err)
			}
			if err := auth.RegisterLoopbackPreFinish(func() error { return nil }); !errors.Is(err, ErrCommittedAttemptInvalid) {
				t.Fatal("second hook accepted")
			}
			if stage == "expired-before-emission" {
				env.clock.Set(env.request.ExpiresAt)
				if err := auth.BeforeFirstEmission(context.Background()); !errors.Is(err, ErrCommittedAttemptInvalid) {
					t.Fatal("expired credential emitted")
				}
			} else {
				var wait sync.WaitGroup
				for i := 0; i < 16; i++ {
					wait.Add(1)
					go func() {
						defer wait.Done()
						if err := auth.Finish(PairingTerminalCancelled); !errors.Is(err, hookErr) {
							t.Error("hook error lost")
						}
					}()
				}
				wait.Wait()
			}
			if calls.Load() != 1 {
				t.Fatal("hook not single-shot")
			}
			assertPairingJournalSequence(t, env, 3)
		})
	}
}

func TestLoopbackTwoPhaseCannotOptOrdinaryAuthorizationIn(t *testing.T) {
	env := newTestPairingGateEnvironment(t, "ordinary-hook", OperationConnectTest)
	_, auth := commitLoopbackTermination(t, env)
	if err := auth.RegisterLoopbackPreFinish(func() error { return nil }); !errors.Is(err, ErrCommittedAttemptInvalid) {
		t.Fatal("ordinary lifecycle gained loopback hook")
	}
	if err := auth.Finish(PairingTerminalCancelled); err != nil {
		t.Fatal(err)
	}
}
