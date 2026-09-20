package governor_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/loopbackcarrier"
)

// These test-only interfaces also allow the same regression to compile
// against the original implementation in a read-only source overlay. The
// baseline cannot opt in; the implemented real lease must use the new mode.
type prefinishLoopbackAcquirer interface {
	AcquireLoopbackAttempt(context.Context, governor.AttemptRequest) (*governor.AttemptLease, error)
}
type prefinishHookRegistrar interface {
	RegisterLoopbackPreFinish(func() error) error
}

func TestLoopbackPreFinishCredentialExpiry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	expires := now.Add(10 * time.Minute)
	namespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
		t.Fatal("namespace preparation failed")
	}
	machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "credential-prefinish")
	if err != nil {
		t.Fatal("governor acquisition failed")
	}
	defer machine.Close()
	setTime, err := governor.InstallLoopbackCredentialClock(machine, now)
	if err != nil {
		t.Fatal("credential clock setup failed")
	}
	journal, err := governor.ObserveCarrierAbsenceJournal(machine)
	if err != nil {
		t.Fatal("journal observer setup failed")
	}
	delay, err := governor.InjectLoopbackCarrierFinishDelay(machine, 2500*time.Millisecond)
	if err != nil {
		t.Fatal("FINISH delay setup failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	peer, err := machine.AcquirePeer("credential-prefinish-peer")
	if err != nil {
		t.Fatal("peer acquisition failed")
	}
	defer peer.Close()
	cost := loopbackcarrier.AttemptCost()
	request := governor.AttemptRequest{ID: processID(2), Operation: governor.OperationConnectTest, Cost: cost}
	var attempt *governor.AttemptLease
	if acquirer, ok := any(peer).(prefinishLoopbackAcquirer); ok {
		attempt, err = acquirer.AcquireLoopbackAttempt(ctx, request)
	} else {
		attempt, err = peer.AcquireAttempt(ctx, request)
	}
	if err != nil {
		t.Fatal("attempt acquisition failed")
	}
	defer attempt.Close()
	committed, err := governor.NewPairingAdmissionGate().Commit(ctx, attempt, governor.PairingAdmissionRequest{
		CredentialID: processID(3), AttemptID: request.ID, ContextDigest: strings.Repeat("03", 32), Scope: governor.ScopeMachine,
		ExpiresAt: expires, Envelope: governor.PairingEnvelopeFromAttemptCost(cost),
	})
	if err != nil {
		t.Fatal("commit failed")
	}
	authorization, err := committed.ConsumeForCarrier(ctx)
	if err != nil {
		t.Fatal("consume failed")
	}
	local, target := reserveLoopbackEndpoint(t), reserveLoopbackEndpoint(t)
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: local, AllowedTargetScope: probeio.AllowedTargetScopeLoopback})
	if err != nil {
		t.Fatal("factory setup failed")
	}
	controller, err := probeio.New(probeio.Config{Lease: attempt, Factory: factory, Generation: probeio.NewGeneration(1), ExpectedGeneration: 1, BuildVersion: "credential-prefinish"})
	if err != nil {
		t.Fatal("controller setup failed")
	}
	defer controller.Close()
	if registrar, ok := any(authorization).(prefinishHookRegistrar); ok {
		if err := registrar.RegisterLoopbackPreFinish(controller.RevokeForTerminal); err != nil {
			t.Fatal("hook registration failed")
		}
	}
	socket, err := controller.OpenProbeSocket(ctx)
	if err != nil {
		t.Fatal("socket setup failed")
	}
	if err := socket.RegisterTarget(target); err != nil {
		t.Fatal("target registration failed")
	}
	// The caller context remains live. Only the credential clock is advanced;
	// no 13s carrier context exists in this direct gate/controller fixture.
	started := time.Now()
	timer := time.NewTimer(13 * time.Second)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		t.Fatal("fixture hang guard fired")
	}
	setTime(expires)
	firstErr := authorization.BeforeFirstEmission(ctx)
	if !errors.Is(firstErr, governor.ErrPairingCredentialExpired) || ctx.Err() != nil {
		t.Error("not an actual credential-expiry invalidation")
	}
	_ = authorization.Finish(governor.PairingTerminalExpired)
	_ = controller.Close()
	_ = peer.Close()
	elapsed := time.Since(started)
	memory := machine.Snapshot()
	j, d := journal(), delay()
	closeErr := machine.Close()
	reopened, reopenErr := governor.AcquireLoopbackCarrierTestGovernor(namespace, "credential-readback")
	persisted := governor.SafetyTripStatus{}
	checked := false
	if reopenErr == nil {
		persisted, checked = reopened.Snapshot().SafetyTrip, true
		_ = reopened.Close()
	} else {
		var trip *governor.SafetyTripError
		if errors.As(reopenErr, &trip) {
			persisted, checked = trip.Status, true
		}
	}
	ledger, ledgerErr := governor.InspectLoopbackCarrierTestLedger(namespace, expires)
	unfinished, _, occupancyErr := governor.InspectLoopbackCarrierTestOccupancy(namespace, expires)
	rebound := t.Run("port-rebind", func(t *testing.T) { assertReusable(t, local) })
	t.Logf("R3_CREDENTIAL elapsed_ns=%d delay_ns=%d delay_calls=%d credential_expired=%t caller_clear=%t finish_reason=%s memory_state=%s memory_reason=%s persisted_checked=%t persisted_state=%s persisted_reason=%s attempts=%d peers=%d reserved_zero=%t admissions_24h=%d packets_24h=%d unfinished=%d port_rebound=%t",
		elapsed.Nanoseconds(), d.Ended.Sub(d.Started).Nanoseconds(), d.Calls, errors.Is(firstErr, governor.ErrPairingCredentialExpired), ctx.Err() == nil, j.FinishReason,
		memory.SafetyTrip.State, memory.SafetyTrip.Record.Reason, checked, persisted.State, persisted.Record.Reason, memory.ActiveAttempts, memory.ActivePeers,
		memory.Reserved == (governor.Resources{}), ledger.TwentyFourHourAdmissions, ledger.TwentyFourHourPackets, unfinished, rebound)
	if d.Calls != 1 || d.Ended.Sub(d.Started) < 2500*time.Millisecond || j.FinishReason != governor.PairingTerminalExpired || !checked || ledgerErr != nil || occupancyErr != nil ||
		memory.ActiveAttempts != 0 || memory.ActivePeers != 0 || memory.Reserved != (governor.Resources{}) || ledger.TwentyFourHourAdmissions != 1 || ledger.TwentyFourHourPackets != 3 || unfinished != 0 || !rebound {
		t.Error("credential terminal/accounting/residue witness failed")
	}
	if memory.SafetyTrip.BlocksActiveWork || persisted.BlocksActiveWork || closeErr != nil {
		t.Error("credential pre-finish path tripped after physical drain")
	}
}
