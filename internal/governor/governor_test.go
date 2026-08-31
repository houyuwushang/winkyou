package governor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testAttempt(id string) AttemptRequest {
	return AttemptRequest{
		ID:        id,
		Operation: OperationConnectTest,
		Cost: AttemptCost{
			Resources: Resources{
				Sockets:          1,
				Targets:          1,
				PacketsPerSecond: 1,
				Packets:          4,
				FiveTuples:       1,
			},
			Duration: time.Second,
		},
	}
}

func newTestGovernor(t *testing.T, profile Profile, limits *Limits) *Governor {
	t.Helper()
	scope, err := profile.Scope()
	if err != nil {
		t.Fatalf("profile scope: %v", err)
	}
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, scope, "test-build")
	if err != nil {
		t.Fatalf("acquire test owner: %v", err)
	}
	var governor *Governor
	if profile == ProfilePhase1UserAcknowledged {
		restricted, restrictedErr := NewRestrictedUserGovernor(owner, limits)
		err = restrictedErr
		if restricted != nil {
			governor = restricted.governor
		}
	} else {
		governor, err = New(owner, profile, limits)
	}
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new governor: %v", err)
	}
	t.Cleanup(func() {
		if err := governor.Close(); err != nil {
			t.Errorf("close governor: %v", err)
		}
	})
	return governor
}

func prepareTestSafetyTrip(t *testing.T, namespace string) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(namespace, safetyTripFilename), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create test safety trip file: %v", err)
	}
	if err := initializeSafetyTripFile(file, time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)); err != nil {
		_ = file.Close()
		t.Fatalf("initialize test safety trip file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close test safety trip file: %v", err)
	}
}

func TestGovernorReservesAndReleasesHierarchy(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-a")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-a"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}

	snapshot := governor.Snapshot()
	if snapshot.ActivePeers != 1 || snapshot.ActiveAttempts != 1 {
		t.Fatalf("active peers/attempts = %d/%d, want 1/1", snapshot.ActivePeers, snapshot.ActiveAttempts)
	}
	if snapshot.Reserved != testAttempt("unused").Cost.Resources {
		t.Fatalf("reserved = %+v, want %+v", snapshot.Reserved, testAttempt("unused").Cost.Resources)
	}
	if snapshot.Owner.PID == 0 || snapshot.Scope != ScopeMachine {
		t.Fatalf("owner snapshot = %+v, want machine owner diagnostics", snapshot.Owner)
	}

	if _, err := governor.AcquirePeer("peer-a"); !errors.Is(err, ErrDuplicatePeer) {
		t.Fatalf("duplicate peer error = %v, want ErrDuplicatePeer", err)
	}
	if _, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-b")); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("second peer attempt error = %v, want ErrLimitExceeded", err)
	}

	if err := attempt.Close(); err != nil {
		t.Fatalf("close attempt: %v", err)
	}
	select {
	case <-attempt.Done():
	default:
		t.Fatal("attempt Done was not closed")
	}
	snapshot = governor.Snapshot()
	if snapshot.ActiveAttempts != 0 || snapshot.Reserved != (Resources{}) {
		t.Fatalf("after attempt close snapshot = %+v, want no attempt reservations", snapshot)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("close peer: %v", err)
	}
	if snapshot := governor.Snapshot(); snapshot.ActivePeers != 0 {
		t.Fatalf("active peers after close = %d, want 0", snapshot.ActivePeers)
	}
}

func TestAttemptLeaseTripBindsPeerAndAttemptIdentity(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-bound")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-bound"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}

	status, err := attempt.Trip(SafetyTripEvent{
		Reason:    SafetyTripHardLimit,
		Detail:    "probeio test",
		PeerID:    "spoofed-peer",
		AttemptID: "spoofed-attempt",
	})
	if err != nil {
		t.Fatalf("trip attempt: %v", err)
	}
	if status.State != SafetyTripTripped {
		t.Fatalf("trip state = %q, want %q", status.State, SafetyTripTripped)
	}
	if status.Record.PeerID != "peer-bound" || status.Record.AttemptID != "attempt-bound" {
		t.Fatalf("trip identity = %q/%q, want peer-bound/attempt-bound", status.Record.PeerID, status.Record.AttemptID)
	}
	select {
	case <-attempt.Done():
	case <-time.After(time.Second):
		t.Fatal("trip did not close attempt lease")
	}
}

func TestAttemptTripWaitsForRegisteredDrain(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-trip-drain")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-trip-drain"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	drain, err := attempt.RegisterDrain("trip-drain")
	if err != nil {
		t.Fatalf("register drain: %v", err)
	}

	if _, err := attempt.Trip(SafetyTripEvent{Reason: SafetyTripHardLimit, Detail: "trip drain proof"}); err != nil {
		t.Fatalf("trip attempt: %v", err)
	}
	select {
	case <-attempt.Stopping():
	default:
		t.Fatal("trip did not synchronously signal stopping")
	}
	select {
	case <-attempt.Done():
		t.Fatal("trip released attempt before drain completion")
	default:
	}
	if snapshot := governor.Snapshot(); snapshot.ActiveAttempts != 1 {
		t.Fatalf("active attempts while trip drains = %d, want 1", snapshot.ActiveAttempts)
	}

	if err := drain.Complete(); err != nil {
		t.Fatalf("complete drain: %v", err)
	}
	select {
	case <-attempt.Done():
	case <-time.After(time.Second):
		t.Fatal("trip did not release attempt after drain completion")
	}
}

func TestClosedAttemptLeaseCannotTripGovernor(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-closed")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-closed"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("close attempt: %v", err)
	}

	status, err := attempt.Trip(SafetyTripEvent{
		Reason: SafetyTripHardLimit,
		Detail: "must be rejected",
	})
	if !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("trip error = %v, want ErrLeaseClosed", err)
	}
	if status.BlocksActiveWork {
		t.Fatalf("closed attempt changed safety status: %+v", status)
	}
	if snapshot := governor.Snapshot(); snapshot.SafetyTrip.BlocksActiveWork {
		t.Fatalf("governor tripped from closed capability: %+v", snapshot.SafetyTrip)
	}
}

func TestAttemptCloseWaitsForRegisteredDrain(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-drain")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-drain"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	drain, err := attempt.RegisterDrain("probeio-controller")
	if err != nil {
		t.Fatalf("register drain: %v", err)
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- attempt.Close() }()
	select {
	case <-attempt.Stopping():
	case <-time.After(time.Second):
		t.Fatal("attempt did not enter stopping state")
	}
	select {
	case err := <-closeResult:
		t.Fatalf("attempt close returned before drain completion: %v", err)
	default:
	}
	repeatCloseResult := make(chan error, 1)
	go func() { repeatCloseResult <- attempt.Close() }()
	select {
	case err := <-repeatCloseResult:
		t.Fatalf("concurrent attempt close returned before drain completion: %v", err)
	default:
	}
	if snapshot := governor.Snapshot(); snapshot.ActiveAttempts != 1 {
		t.Fatalf("active attempts while draining = %d, want 1", snapshot.ActiveAttempts)
	}
	if _, err := attempt.Trip(SafetyTripEvent{Reason: SafetyTripHardLimit, Detail: "stale stopping capability"}); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("stopping attempt trip error = %v, want ErrLeaseClosed", err)
	}

	if err := drain.Complete(); err != nil {
		t.Fatalf("complete drain: %v", err)
	}
	if err := drain.Complete(); err != nil {
		t.Fatalf("repeat drain completion: %v", err)
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("attempt close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("attempt close did not finish after drain completion")
	}
	select {
	case err := <-repeatCloseResult:
		if err != nil {
			t.Fatalf("concurrent attempt close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent attempt close did not finish after drain completion")
	}
	select {
	case <-attempt.Done():
	default:
		t.Fatal("attempt Done did not close after drain completion")
	}
	if snapshot := governor.Snapshot(); snapshot.ActiveAttempts != 0 || snapshot.Reserved != (Resources{}) {
		t.Fatalf("snapshot after drain = %+v, want released attempt", snapshot)
	}
	if _, err := attempt.RegisterDrain("late-drain"); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("late drain error = %v, want ErrLeaseClosed", err)
	}
}

func TestAttemptDrainRegistrationsAreBounded(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-bounded-drains")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-bounded-drains"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}

	drains := make([]DrainHandle, 0, maxAttemptDrainRegistrations)
	for index := 0; index < maxAttemptDrainRegistrations; index++ {
		drain, err := attempt.RegisterDrain(fmt.Sprintf("drain-%d", index))
		if err != nil {
			t.Fatalf("register drain %d: %v", index, err)
		}
		drains = append(drains, drain)
	}
	if _, err := attempt.RegisterDrain("one-too-many"); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("extra drain error = %v, want ErrLimitExceeded", err)
	}
	for index, drain := range drains {
		if err := drain.Complete(); err != nil {
			t.Fatalf("complete drain %d: %v", index, err)
		}
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("close attempt: %v", err)
	}
}

func TestAttemptExclusiveClaimIsOneShotForLeaseLifetime(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-exclusive-claim")
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-exclusive-claim"))
	if err != nil {
		t.Fatal(err)
	}
	if err := attempt.ClaimExclusive("n2-rendezvous-carrier"); err != nil {
		t.Fatal(err)
	}
	drain, err := attempt.RegisterDrain("n2-rendezvous-carrier")
	if err != nil {
		t.Fatal(err)
	}
	if err := drain.Complete(); err != nil {
		t.Fatal(err)
	}
	if err := attempt.ClaimExclusive("n2-rendezvous-carrier"); !errors.Is(err, ErrExclusiveClaimUsed) {
		t.Fatalf("reused exclusive claim = %v, want ErrExclusiveClaimUsed", err)
	}
	if err := attempt.ClaimExclusive("different-adapter"); err != nil {
		t.Fatalf("independent claim = %v", err)
	}
	if err := attempt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := attempt.ClaimExclusive("after-close"); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("claim after close = %v, want ErrLeaseClosed", err)
	}
}

func TestAttemptCancellationDrainTimeoutTripsMachine(t *testing.T) {
	hard, err := HardLimits(ProfilePhase1Machine)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	hard.CancellationDrainTimeout = 20 * time.Millisecond
	governor := newTestGovernor(t, ProfilePhase1Machine, &hard)
	peer, err := governor.AcquirePeer("peer-timeout")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-timeout"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	drain, err := attempt.RegisterDrain("stuck-worker")
	if err != nil {
		t.Fatalf("register drain: %v", err)
	}

	err = attempt.Close()
	if !errors.Is(err, ErrCancellationDrainTimeout) {
		t.Fatalf("close error = %v, want ErrCancellationDrainTimeout", err)
	}
	status := governor.Snapshot().SafetyTrip
	if status.State != SafetyTripTripped || status.Record.Reason != SafetyTripCancellation {
		t.Fatalf("safety trip = %+v, want cancellation timeout", status)
	}
	if status.Record.PeerID != "peer-timeout" || status.Record.AttemptID != "attempt-timeout" {
		t.Fatalf("trip identity = %q/%q", status.Record.PeerID, status.Record.AttemptID)
	}
	if err := attempt.Close(); !errors.Is(err, ErrCancellationDrainTimeout) {
		t.Fatalf("repeat close error = %v, want ErrCancellationDrainTimeout", err)
	}
	select {
	case <-attempt.Done():
	default:
		t.Fatal("timed-out attempt was not forcibly revoked")
	}
	if err := drain.Complete(); err != nil {
		t.Fatalf("late drain completion: %v", err)
	}
}

func TestGovernorCloseHoldsMachineOwnerUntilDrainsFinish(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "drain-owner")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	governor, err := New(owner, ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new governor: %v", err)
	}
	peer, err := governor.AcquirePeer("peer-owner")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-owner"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	drain, err := attempt.RegisterDrain("owner-drain")
	if err != nil {
		t.Fatalf("register drain: %v", err)
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- governor.Close() }()
	select {
	case <-attempt.Stopping():
	case <-time.After(time.Second):
		t.Fatal("governor close did not signal attempt stopping")
	}
	contender, contenderErr := AcquirePreparedNamespace(namespace, ScopeMachine, "contender")
	if contender != nil {
		_ = contender.Close()
		t.Fatal("contender acquired namespace while drain was pending")
	}
	if !errors.Is(contenderErr, ErrOwnerHeld) {
		t.Fatalf("contender error = %v, want ErrOwnerHeld", contenderErr)
	}
	if err := drain.Complete(); err != nil {
		t.Fatalf("complete drain: %v", err)
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("close governor: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("governor close did not finish after drain completion")
	}

	reacquired, err := AcquirePreparedNamespace(namespace, ScopeMachine, "after-drain")
	if err != nil {
		t.Fatalf("reacquire namespace: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatalf("close reacquired owner: %v", err)
	}
}

func TestGovernorCloseTimeoutTripsBeforeReleasingMachineOwner(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	hard, err := HardLimits(ProfilePhase1Machine)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	hard.CancellationDrainTimeout = 20 * time.Millisecond
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "timeout-owner")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	governor, err := New(owner, ProfilePhase1Machine, &hard)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new governor: %v", err)
	}
	peer, err := governor.AcquirePeer("peer-timeout-owner")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-timeout-owner"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	if _, err := attempt.RegisterDrain("stuck-owner-drain"); err != nil {
		t.Fatalf("register drain: %v", err)
	}

	if err := governor.Close(); !errors.Is(err, ErrCancellationDrainTimeout) {
		t.Fatalf("close error = %v, want ErrCancellationDrainTimeout", err)
	}
	restartedOwner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "restart-build")
	if err != nil {
		t.Fatalf("reacquire owner after timeout: %v", err)
	}
	defer func() { _ = restartedOwner.Close() }()
	if _, err := New(restartedOwner, ProfilePhase1Machine, nil); !errors.Is(err, ErrSafetyTripped) {
		t.Fatalf("new governor after timeout error = %v, want ErrSafetyTripped", err)
	}
}

func TestGovernorConfigurationCanLowerButNotRaiseHardLimits(t *testing.T) {
	hard, err := HardLimits(ProfilePhase1Machine)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	raised := hard
	raised.Aggregate.Sockets++

	owner, err := AcquirePreparedNamespace(t.TempDir(), ScopeMachine, "test-build")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := New(owner, ProfilePhase1Machine, &raised); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("raised limits error = %v, want ErrLimitExceeded", err)
	}
	raisedDrain := hard
	raisedDrain.CancellationDrainTimeout += time.Second
	if _, err := New(owner, ProfilePhase1Machine, &raisedDrain); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("raised drain timeout error = %v, want ErrLimitExceeded", err)
	}

	lowered := hard
	lowered.MaxActivePeers = 1
	governor := newTestGovernor(t, ProfilePhase1Machine, &lowered)
	if _, err := governor.AcquirePeer("peer-a"); err != nil {
		t.Fatalf("acquire first peer: %v", err)
	}
	if _, err := governor.AcquirePeer("peer-b"); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("second peer error = %v, want ErrLimitExceeded", err)
	}
}

func TestManualTraversalProfileIsExactAndIsolated(t *testing.T) {
	limits, err := HardLimits(ProfilePhase1ManualTraversal)
	if err != nil {
		t.Fatal(err)
	}
	want := Resources{Sockets: 128, Targets: 516, FiveTuples: 523, Packets: 526, PacketsPerSecond: 64}
	if limits.Aggregate != want || limits.PerAttempt != want || limits.MaxActivePeers != 1 ||
		limits.MaxActiveAttempts != 1 || limits.MaxAttemptsPerPeer != 1 || limits.MaxHeavyweightAttempts != 1 ||
		limits.MaxAttemptDuration != 22*time.Second || limits.CancellationDrainTimeout != 2*time.Second {
		t.Fatalf("manual traversal limits = %+v", limits)
	}
	if scope, err := ProfilePhase1ManualTraversal.Scope(); err != nil || scope != ScopeMachine {
		t.Fatalf("manual scope = %q/%v", scope, err)
	}
	for _, operation := range []Operation{OperationPrediction, OperationBirthday} {
		if !ProfilePhase1ManualTraversal.Allows(operation) {
			t.Errorf("manual traversal rejected %s", operation)
		}
	}
	if ProfilePhase1ManualTraversal.Allows(OperationConnectTest) || ProfilePhase1Machine.Allows(OperationPrediction) ||
		ProfilePhase1UserAcknowledged.Allows(OperationBirthday) {
		t.Fatal("manual traversal authority leaked into an existing profile or operation")
	}
}

func TestHardNATCampaignProfileIsExactAndCannotBorrow(t *testing.T) {
	limits, err := HardLimits(ProfilePhase1HardNATCampaign)
	if err != nil {
		t.Fatal(err)
	}
	want := Resources{Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512}
	if limits.Aggregate != want || limits.PerAttempt != want || limits.MaxActivePeers != 1 ||
		limits.MaxActiveAttempts != 1 || limits.MaxAttemptsPerPeer != 1 || limits.MaxHeavyweightAttempts != 1 ||
		limits.MaxAttemptDuration != 47*time.Second || limits.CancellationDrainTimeout != 2*time.Second {
		t.Fatalf("hard NAT campaign limits = %+v", limits)
	}
	if scope, err := ProfilePhase1HardNATCampaign.Scope(); err != nil || scope != ScopeMachine {
		t.Fatalf("hard campaign scope = %q/%v", scope, err)
	}
	if !ProfilePhase1HardNATCampaign.Allows(OperationBirthday) ||
		ProfilePhase1HardNATCampaign.Allows(OperationPrediction) ||
		ProfilePhase1HardNATCampaign.Allows(OperationConnectTest) {
		t.Fatal("hard campaign operation authority drifted")
	}
	manual, err := HardLimits(ProfilePhase1ManualTraversal)
	if err != nil {
		t.Fatal(err)
	}
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "hard-campaign-no-borrow")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := New(owner, ProfilePhase1HardNATCampaign, &manual); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("hard campaign borrowed manual limits: %v", err)
	}
}

func TestHardNATCampaignSecondAttemptPersistsTrip(t *testing.T) {
	machine := newTestGovernor(t, ProfilePhase1HardNATCampaign, nil)
	peer, err := machine.AcquirePeer("hard-campaign-peer")
	if err != nil {
		t.Fatal(err)
	}
	request := AttemptRequest{
		ID: "hard-campaign-first", Operation: OperationBirthday,
		Cost: AttemptCost{
			Resources: Resources{Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512},
			Duration:  47 * time.Second, Heavyweight: true,
		},
	}
	first, err := peer.AcquireAttempt(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.ID = "hard-campaign-second"
	if second, err := peer.AcquireAttempt(context.Background(), request); second != nil || !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("second campaign attempt=%v/%v", second, err)
	}
	status := machine.Snapshot().SafetyTrip
	if !status.BlocksActiveWork || status.Record.Reason != SafetyTripHardLimit || status.Record.AttemptID != request.ID {
		t.Fatalf("hard campaign second-attempt trip=%+v", status)
	}
	select {
	case <-first.Stopping():
	case <-time.After(time.Second):
		t.Fatal("hard campaign hard-limit trip did not revoke the first attempt")
	}
}

func TestManualTraversalSecondHeavyweightAttemptPersistsTrip(t *testing.T) {
	machine := newTestGovernor(t, ProfilePhase1ManualTraversal, nil)
	peer, err := machine.AcquirePeer("manual-peer")
	if err != nil {
		t.Fatal(err)
	}
	request := AttemptRequest{
		ID: "manual-first", Operation: OperationBirthday,
		Cost: AttemptCost{
			Resources: Resources{Sockets: 128, Targets: 516, FiveTuples: 523, Packets: 526, PacketsPerSecond: 64},
			Duration:  22 * time.Second, Heavyweight: true,
		},
	}
	first, err := peer.AcquireAttempt(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.ID = "manual-second"
	if second, err := peer.AcquireAttempt(context.Background(), request); second != nil || !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("second heavyweight=%v/%v", second, err)
	}
	status := machine.Snapshot().SafetyTrip
	if !status.BlocksActiveWork || status.Record.Reason != SafetyTripHardLimit || status.Record.AttemptID != request.ID {
		t.Fatalf("manual hard-limit trip=%+v", status)
	}
	select {
	case <-first.Stopping():
	case <-time.After(time.Second):
		t.Fatal("manual hard-limit trip did not revoke the first attempt")
	}
}

func TestUserAcknowledgedProfileRejectsPrivilegedOperations(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1UserAcknowledged, nil)
	peer, err := governor.AcquirePeer("peer-a")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}

	for _, operation := range []Operation{
		OperationNodeRuntime,
		OperationRecovery,
		OperationPortMapping,
		OperationPrediction,
		OperationBirthday,
	} {
		request := testAttempt("attempt-" + string(operation))
		request.Operation = operation
		if _, err := peer.AcquireAttempt(context.Background(), request); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("operation %s error = %v, want ErrNotAllowed", operation, err)
		}
	}

	heavy := testAttempt("attempt-heavy")
	heavy.Cost.Heavyweight = true
	if _, err := peer.AcquireAttempt(context.Background(), heavy); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("heavyweight user attempt error = %v, want ErrLimitExceeded", err)
	}

	oversized := testAttempt("attempt-oversized")
	oversized.Cost.Resources.Sockets = 5
	if _, err := peer.AcquireAttempt(context.Background(), oversized); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("oversized user attempt error = %v, want ErrLimitExceeded", err)
	}
}

func TestAttemptCancellationReleasesReservation(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	peer, err := governor.AcquirePeer("peer-a")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	attempt, err := peer.AcquireAttempt(ctx, testAttempt("attempt-a"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	cancel()

	select {
	case <-attempt.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("attempt was not released after cancellation")
	}
	if snapshot := governor.Snapshot(); snapshot.ActiveAttempts != 0 || snapshot.Reserved != (Resources{}) {
		t.Fatalf("snapshot after cancellation = %+v, want no attempt reservations", snapshot)
	}
	if _, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-b")); err != nil {
		t.Fatalf("reacquire after cancellation: %v", err)
	}
}

func TestHeavyweightLimitIsAtomicUnderConcurrency(t *testing.T) {
	governor := newTestGovernor(t, ProfilePhase1Machine, nil)
	const contenders = 16
	peers := make([]*PeerLease, 0, contenders)
	for index := 0; index < contenders; index++ {
		peer, err := governor.AcquirePeer(fmt.Sprintf("peer-%02d", index))
		if err != nil {
			t.Fatalf("acquire peer %d: %v", index, err)
		}
		peers = append(peers, peer)
	}

	start := make(chan struct{})
	results := make(chan *AttemptLease, contenders)
	var wait sync.WaitGroup
	for index, peer := range peers {
		wait.Add(1)
		go func(index int, peer *PeerLease) {
			defer wait.Done()
			<-start
			request := testAttempt(fmt.Sprintf("attempt-%02d", index))
			request.Cost.Heavyweight = true
			attempt, err := peer.AcquireAttempt(context.Background(), request)
			if err == nil {
				results <- attempt
				return
			}
			if !errors.Is(err, ErrLimitExceeded) {
				t.Errorf("contender %d error = %v, want ErrLimitExceeded", index, err)
			}
		}(index, peer)
	}
	close(start)
	wait.Wait()
	close(results)

	var acquired []*AttemptLease
	for attempt := range results {
		acquired = append(acquired, attempt)
	}
	if len(acquired) != 1 {
		t.Fatalf("heavyweight attempts acquired = %d, want 1", len(acquired))
	}
	snapshot := governor.Snapshot()
	if snapshot.HeavyweightAttempts != 1 || snapshot.ActiveAttempts != 1 {
		t.Fatalf("heavyweight snapshot = %+v, want one active heavyweight attempt", snapshot)
	}
	if err := acquired[0].Close(); err != nil {
		t.Fatalf("close heavyweight attempt: %v", err)
	}
}

func TestGovernorCloseReleasesChildrenAndNamespace(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "first-build")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	governor, err := New(owner, ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new governor: %v", err)
	}
	peer, err := governor.AcquirePeer("peer-a")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-a"))
	if err != nil {
		t.Fatalf("acquire attempt: %v", err)
	}
	if err := governor.Close(); err != nil {
		t.Fatalf("close governor: %v", err)
	}
	select {
	case <-attempt.Done():
	default:
		t.Fatal("governor close did not close child attempt")
	}
	if _, err := peer.AcquireAttempt(context.Background(), testAttempt("attempt-b")); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("closed peer acquire error = %v, want ErrLeaseClosed", err)
	}

	reacquired, err := AcquirePreparedNamespace(namespace, ScopeMachine, "second-build")
	if err != nil {
		t.Fatalf("reacquire released namespace: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatalf("close reacquired owner: %v", err)
	}
}

func TestGovernorPreventsPrematureOwnerClose(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeMachine, "first-build")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	governor, err := New(owner, ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new governor: %v", err)
	}
	if err := owner.Close(); !errors.Is(err, ErrOwnerInUse) {
		t.Fatalf("close claimed owner error = %v, want ErrOwnerInUse", err)
	}
	contender, err := AcquirePreparedNamespace(namespace, ScopeMachine, "contender-build")
	if contender != nil {
		_ = contender.Close()
	}
	if !errors.Is(err, ErrOwnerHeld) {
		t.Fatalf("contender error = %v, want ErrOwnerHeld", err)
	}
	if err := governor.Close(); err != nil {
		t.Fatalf("close governor: %v", err)
	}
}

func TestGovernorRejectsMismatchedOwnerScope(t *testing.T) {
	owner, err := AcquirePreparedNamespace(t.TempDir(), ScopeUserAcknowledged, "test-build")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := New(owner, ProfilePhase1Machine, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mismatched scope error = %v, want ErrInvalidRequest", err)
	}
}
