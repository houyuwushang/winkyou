package governor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newRestrictedTestGovernor(t *testing.T) *RestrictedUserGovernor {
	t.Helper()
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeUserAcknowledged, "restricted-test")
	if err != nil {
		t.Fatalf("acquire user owner: %v", err)
	}
	restricted, err := NewRestrictedUserGovernor(owner, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new restricted governor: %v", err)
	}
	t.Cleanup(func() {
		if err := restricted.Close(); err != nil {
			t.Errorf("close restricted governor: %v", err)
		}
	})
	return restricted
}

func TestGenericGovernorCannotConstructUserAcknowledgedProfile(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeUserAcknowledged, "generic-rejected")
	if err != nil {
		t.Fatalf("acquire user owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := New(owner, ProfilePhase1UserAcknowledged, nil); !errors.Is(err, ErrRestrictedScopeRequired) {
		t.Fatalf("generic constructor error = %v, want ErrRestrictedScopeRequired", err)
	}
}

func TestRestrictedUserGovernorExposesOnlyReviewedAttemptKinds(t *testing.T) {
	restricted := newRestrictedTestGovernor(t)
	snapshot := restricted.Snapshot()
	if snapshot.Profile != ProfilePhase1UserAcknowledged || snapshot.Scope != ScopeUserAcknowledged {
		t.Fatalf("restricted identity = %s/%s", snapshot.Profile, snapshot.Scope)
	}
	if snapshot.Limits.MaxActivePeers != 1 || snapshot.Limits.MaxActiveAttempts != 1 || snapshot.Limits.MaxHeavyweightAttempts != 0 {
		t.Fatalf("restricted hard limits = %+v", snapshot.Limits)
	}

	peer, err := restricted.AcquirePeer("diagnose-peer")
	if err != nil {
		t.Fatalf("acquire peer: %v", err)
	}
	if _, err := restricted.AcquirePeer("second-peer"); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("second peer error = %v, want ErrLimitExceeded", err)
	}
	request := RestrictedAttemptRequest{
		ID: "diagnose-attempt",
		Resources: Resources{
			Sockets:          1,
			Targets:          1,
			PacketsPerSecond: 1,
			Packets:          1,
			FiveTuples:       1,
		},
		Duration: time.Second,
	}
	attempt, err := peer.AcquireDiagnosticAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("acquire diagnostic attempt: %v", err)
	}
	if got := attempt.Request(); got.Operation != OperationDiagnose || got.Cost.Heavyweight {
		t.Fatalf("diagnostic request = %+v", got)
	}
	if err := attempt.Close(); err != nil {
		t.Fatalf("close diagnostic attempt: %v", err)
	}

	request.ID = "connect-test-attempt"
	connect, err := peer.AcquireConnectTestAttempt(context.Background(), request)
	if err != nil {
		t.Fatalf("acquire connect-test attempt: %v", err)
	}
	if got := connect.Request(); got.Operation != OperationConnectTest || got.Cost.Heavyweight {
		t.Fatalf("connect-test request = %+v", got)
	}
	if err := connect.Close(); err != nil {
		t.Fatalf("close connect-test attempt: %v", err)
	}
}

func TestRestrictedUserGovernorCannotRaiseCompiledLimits(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	owner, err := AcquirePreparedNamespace(namespace, ScopeUserAcknowledged, "raised-rejected")
	if err != nil {
		t.Fatalf("acquire user owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	hard, err := HardLimits(ProfilePhase1UserAcknowledged)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	hard.Aggregate.Packets++
	if _, err := NewRestrictedUserGovernor(owner, &hard); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("raised limit error = %v, want ErrLimitExceeded", err)
	}
}

func TestRestrictedUserOwnerStillSerializesProcesses(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	first, err := AcquirePreparedNamespace(namespace, ScopeUserAcknowledged, "first-user")
	if err != nil {
		t.Fatalf("acquire first owner: %v", err)
	}
	defer func() { _ = first.Close() }()
	second, err := AcquirePreparedNamespace(namespace, ScopeUserAcknowledged, "second-user")
	if second != nil {
		_ = second.Close()
	}
	if !errors.Is(err, ErrOwnerHeld) {
		t.Fatalf("second owner error = %v, want ErrOwnerHeld", err)
	}
}

func TestCanonicalRestrictedAcquisitionRejectsReadyMachineBeforeUserSetup(t *testing.T) {
	prepareCalls := 0
	restricted, err := acquireRestrictedUserGovernor("ready-machine", restrictedUserDependencies{
		inspectMachine: func() NamespaceStatus {
			return NamespaceStatus{Scope: ScopeMachine, State: NamespaceReady, Ready: true, Path: "machine-safety"}
		},
		prepareUser: func() (NamespaceStatus, error) {
			prepareCalls++
			return NamespaceStatus{}, nil
		},
		acquireOwner: AcquirePreparedNamespace,
	})
	if restricted != nil {
		_ = restricted.Close()
		t.Fatal("ready machine returned a restricted authority")
	}
	if !errors.Is(err, ErrUserScopeNotNeeded) || prepareCalls != 0 {
		t.Fatalf("ready machine result error=%v prepare_calls=%d", err, prepareCalls)
	}
}

func TestCanonicalRestrictedAcquisitionClosesOnMachineInstallRace(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	inspectCalls := 0
	restricted, err := acquireRestrictedUserGovernor("machine-race", restrictedUserDependencies{
		inspectMachine: func() NamespaceStatus {
			inspectCalls++
			if inspectCalls == 1 {
				return NamespaceStatus{Scope: ScopeMachine, State: NamespaceMissing}
			}
			return NamespaceStatus{Scope: ScopeMachine, State: NamespaceReady, Ready: true, Path: "machine-safety"}
		},
		prepareUser: func() (NamespaceStatus, error) {
			return NamespaceStatus{Scope: ScopeUserAcknowledged, State: NamespaceReady, Ready: true, Path: namespace}, nil
		},
		acquireOwner: AcquirePreparedNamespace,
	})
	if restricted != nil {
		_ = restricted.Close()
		t.Fatal("machine install race returned a restricted authority")
	}
	if !errors.Is(err, ErrUserScopeNotNeeded) || inspectCalls != 2 {
		t.Fatalf("machine race result error=%v inspect_calls=%d", err, inspectCalls)
	}
	reacquired, err := AcquirePreparedNamespace(namespace, ScopeUserAcknowledged, "after-race")
	if err != nil {
		t.Fatalf("reacquire user namespace after rejected race: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatalf("close reacquired owner: %v", err)
	}
}

func TestCanonicalRestrictedAcquisitionReturnsBoundedUserAuthority(t *testing.T) {
	namespace := t.TempDir()
	prepareTestSafetyTrip(t, namespace)
	inspectCalls := 0
	restricted, err := acquireRestrictedUserGovernor("canonical-user", restrictedUserDependencies{
		inspectMachine: func() NamespaceStatus {
			inspectCalls++
			return NamespaceStatus{Scope: ScopeMachine, State: NamespaceMissing}
		},
		prepareUser: func() (NamespaceStatus, error) {
			return NamespaceStatus{Scope: ScopeUserAcknowledged, State: NamespaceReady, Ready: true, Path: namespace}, nil
		},
		acquireOwner: AcquirePreparedNamespace,
	})
	if err != nil {
		t.Fatalf("acquire canonical user authority: %v", err)
	}
	if inspectCalls != 2 {
		t.Fatalf("machine readiness inspections = %d, want 2", inspectCalls)
	}
	snapshot := restricted.Snapshot()
	if snapshot.Scope != ScopeUserAcknowledged || snapshot.Profile != ProfilePhase1UserAcknowledged || snapshot.Limits.MaxHeavyweightAttempts != 0 {
		t.Fatalf("canonical restricted snapshot = %+v", snapshot)
	}
	if err := restricted.Close(); err != nil {
		t.Fatalf("close canonical user authority: %v", err)
	}
}
