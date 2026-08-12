package governor

import (
	"context"
	"errors"
	"fmt"
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
	owner, err := AcquirePreparedNamespace(t.TempDir(), scope, "test-build")
	if err != nil {
		t.Fatalf("acquire test owner: %v", err)
	}
	governor, err := New(owner, profile, limits)
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
