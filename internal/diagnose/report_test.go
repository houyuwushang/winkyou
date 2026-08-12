package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
)

type fakeRestrictedUserAuthority struct {
	snapshot   governor.Snapshot
	closeErr   error
	closeCalls int
}

func (authority *fakeRestrictedUserAuthority) Snapshot() governor.Snapshot {
	return authority.snapshot
}

func (authority *fakeRestrictedUserAuthority) Close() error {
	authority.closeCalls++
	return authority.closeErr
}

func readyInspector() Inspector {
	return Inspector{
		Now: func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.FixedZone("test", 8*60*60)) },
		Namespace: func() governor.NamespaceStatus {
			return governor.NamespaceStatus{Scope: governor.ScopeMachine, State: governor.NamespaceReady, Ready: true}
		},
		Owner: func() governor.OwnerStatus {
			return governor.OwnerStatus{Scope: governor.ScopeMachine, State: governor.OwnerIdle}
		},
		SafetyTrip: func() governor.SafetyTripStatus {
			return governor.SafetyTripStatus{State: governor.SafetyTripClear}
		},
		Configuration: func(string) ConfigStatus {
			return ConfigStatus{State: ConfigReady, Source: "defaults_and_environment"}
		},
		Interfaces: func() InterfaceStatus {
			return InterfaceStatus{State: InterfacesReady, Count: 1, UpCount: 1}
		},
		DefaultRoute: func(context.Context) DefaultRouteStatus {
			return DefaultRouteStatus{State: RoutePresent, Family: "ipv4", Interface: "Ethernet"}
		},
		Platform:     Platform{OS: "test-os", Arch: "test-arch"},
		BuildVersion: "test-build",
	}
}

func TestMissingMachineScopeStillCompletesEveryPassiveSection(t *testing.T) {
	inspector := readyInspector()
	calls := make(map[string]int)
	inspector.Namespace = func() governor.NamespaceStatus {
		calls["namespace"]++
		return governor.NamespaceStatus{Scope: governor.ScopeMachine, State: governor.NamespaceMissing, RequiresElevation: true}
	}
	baseOwner := inspector.Owner
	inspector.Owner = func() governor.OwnerStatus { calls["owner"]++; return baseOwner() }
	baseSafety := inspector.SafetyTrip
	inspector.SafetyTrip = func() governor.SafetyTripStatus { calls["safety"]++; return baseSafety() }
	baseConfiguration := inspector.Configuration
	inspector.Configuration = func(path string) ConfigStatus { calls["configuration"]++; return baseConfiguration(path) }
	baseInterfaces := inspector.Interfaces
	inspector.Interfaces = func() InterfaceStatus { calls["interfaces"]++; return baseInterfaces() }
	baseRoute := inspector.DefaultRoute
	inspector.DefaultRoute = func(ctx context.Context) DefaultRouteStatus { calls["route"]++; return baseRoute(ctx) }

	report := inspector.Run(context.Background(), Options{})
	for _, section := range []string{"namespace", "owner", "safety", "configuration", "interfaces", "route"} {
		if calls[section] != 1 {
			t.Fatalf("%s calls = %d, want 1", section, calls[section])
		}
	}
	if report.ActiveProbe.State != "active_probe_blocked" || report.ActiveProbe.Reason != "machine_scope_not_ready" {
		t.Fatalf("active probe = %+v", report.ActiveProbe)
	}
	if report.ActiveProbe.Action != "wink setup-machine-scope" {
		t.Fatalf("repair action = %q", report.ActiveProbe.Action)
	}
	if report.NetworkActivityStarted {
		t.Fatal("passive report claimed network activity")
	}
	if report.GeneratedAt.Location() != time.UTC || report.GeneratedAt.Hour() != 4 {
		t.Fatalf("generated_at = %v, want normalized UTC", report.GeneratedAt)
	}
}

func TestReadyMachineStillBlocksUnreviewedActiveProbe(t *testing.T) {
	report := readyInspector().Run(context.Background(), Options{})
	if report.SchemaVersion != SchemaVersion || report.Mode != "passive_only" || report.Redaction != "partial" {
		t.Fatalf("report identity = %q/%q/%q", report.SchemaVersion, report.Mode, report.Redaction)
	}
	if report.ActiveProbe.Reason != "passive_only_slice" {
		t.Fatalf("active probe = %+v", report.ActiveProbe)
	}
}

func TestOwnerAndSafetyTripBlockReasonsAreExplicit(t *testing.T) {
	t.Run("owner", func(t *testing.T) {
		inspector := readyInspector()
		owner := governor.OwnerInfo{PID: 42, InstanceID: "instance", BuildVersion: "held-build", Scope: governor.ScopeMachine}
		inspector.Owner = func() governor.OwnerStatus {
			return governor.OwnerStatus{Scope: governor.ScopeMachine, State: governor.OwnerHeld, Held: true, Owner: &owner, MetadataAvailable: true}
		}
		report := inspector.Run(context.Background(), Options{})
		if report.ActiveProbe.Reason != "machine_governor_owned" || report.ActiveProbe.Detail == "" {
			t.Fatalf("active probe = %+v", report.ActiveProbe)
		}
	})

	t.Run("safety trip", func(t *testing.T) {
		inspector := readyInspector()
		inspector.SafetyTrip = func() governor.SafetyTripStatus {
			return governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true}
		}
		report := inspector.Run(context.Background(), Options{})
		if report.ActiveProbe.Reason != "machine_safety_trip" || report.ActiveProbe.Action != "wink safety status" {
			t.Fatalf("active probe = %+v", report.ActiveProbe)
		}
	})
}

func TestMissingCollectorsFailClosedInsideReport(t *testing.T) {
	report := (Inspector{}).Run(context.Background(), Options{})
	if report.Namespace.State != governor.NamespaceUnavailable || report.Owner.State != governor.OwnerUnavailable {
		t.Fatalf("governor sections = %+v/%+v", report.Namespace, report.Owner)
	}
	if !report.SafetyTrip.BlocksActiveWork || report.ActiveProbe.State != "active_probe_blocked" {
		t.Fatalf("fail-closed report = %+v", report)
	}
}

func TestUserAcknowledgedScopeIsExplicitRestrictedAndStillPassive(t *testing.T) {
	inspector := readyInspector()
	inspector.Namespace = func() governor.NamespaceStatus {
		return governor.NamespaceStatus{Scope: governor.ScopeMachine, State: governor.NamespaceMissing, RequiresElevation: true}
	}
	inspector.UserNamespace = func() governor.NamespaceStatus {
		return governor.NamespaceStatus{Scope: governor.ScopeUserAcknowledged, State: governor.NamespaceReady, Ready: true, Path: "user-safety"}
	}
	inspector.UserOwner = func() governor.OwnerStatus {
		return governor.OwnerStatus{Scope: governor.ScopeUserAcknowledged, State: governor.OwnerIdle}
	}
	inspector.UserSafetyTrip = func() governor.SafetyTripStatus {
		return governor.SafetyTripStatus{State: governor.SafetyTripClear}
	}
	hard, err := governor.HardLimits(governor.ProfilePhase1UserAcknowledged)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	authority := &fakeRestrictedUserAuthority{snapshot: governor.Snapshot{
		Profile: governor.ProfilePhase1UserAcknowledged,
		Scope:   governor.ScopeUserAcknowledged,
		Limits:  hard,
	}}
	var acquiredBuild string
	inspector.AcquireUser = func(buildVersion string) (RestrictedUserAuthority, error) {
		acquiredBuild = buildVersion
		return authority, nil
	}

	report := inspector.Run(context.Background(), Options{GovernorScope: governor.ScopeUserAcknowledged})
	if report.Mode != "user_acknowledged_passive_only" || report.GovernorScope != governor.ScopeUserAcknowledged {
		t.Fatalf("report identity = %q/%q", report.Mode, report.GovernorScope)
	}
	if acquiredBuild != "test-build" || authority.closeCalls != 1 {
		t.Fatalf("authority lifecycle build=%q close_calls=%d", acquiredBuild, authority.closeCalls)
	}
	boundary := report.UserAcknowledged
	if boundary == nil || !boundary.ExplicitAcknowledgement || boundary.MachineWide || boundary.PersistentDefault || !boundary.Acquired || !boundary.PolicyVerified || !boundary.Released {
		t.Fatalf("user boundary = %+v", boundary)
	}
	if len(boundary.AllowedOperations) != 2 || boundary.HardLimits.MaxActivePeers != 1 || boundary.HardLimits.MaxHeavyweightAttempts != 0 {
		t.Fatalf("compiled user policy = %+v", boundary)
	}
	if report.MachineNamespace == nil || report.MachineNamespace.State != governor.NamespaceMissing {
		t.Fatalf("machine namespace evidence = %+v", report.MachineNamespace)
	}
	if report.ActiveProbe.Reason != "user_acknowledged_passive_only" || report.NetworkActivityStarted {
		t.Fatalf("passive boundary = %+v network_started=%t", report.ActiveProbe, report.NetworkActivityStarted)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	jsonText := string(encoded)
	if !strings.Contains(jsonText, `"max_attempt_duration_ms":15000`) || strings.Contains(jsonText, `"MaxActivePeers"`) {
		t.Fatalf("report did not preserve DTO/domain separation: %s", jsonText)
	}
}

func TestReadyMachineScopeRejectsLowerUserAuthority(t *testing.T) {
	inspector := readyInspector()
	inspector.UserNamespace = func() governor.NamespaceStatus {
		return governor.NamespaceStatus{Scope: governor.ScopeUserAcknowledged, State: governor.NamespaceMissing}
	}
	inspector.UserOwner = func() governor.OwnerStatus {
		return governor.OwnerStatus{Scope: governor.ScopeUserAcknowledged, State: governor.OwnerUnavailable}
	}
	inspector.UserSafetyTrip = func() governor.SafetyTripStatus {
		return governor.SafetyTripStatus{State: governor.SafetyTripUnavailable, BlocksActiveWork: true}
	}
	inspector.AcquireUser = func(string) (RestrictedUserAuthority, error) {
		return nil, governor.ErrUserScopeNotNeeded
	}
	report := inspector.Run(context.Background(), Options{GovernorScope: governor.ScopeUserAcknowledged})
	if report.ActiveProbe.Reason != "user_acknowledged_scope_not_needed" {
		t.Fatalf("active probe = %+v", report.ActiveProbe)
	}
	if report.UserAcknowledged == nil || report.UserAcknowledged.Acquired {
		t.Fatalf("user boundary = %+v", report.UserAcknowledged)
	}
}

func TestUserAcknowledgedAcquisitionFailureRemainsPassiveAndExplicit(t *testing.T) {
	inspector := readyInspector()
	inspector.Namespace = func() governor.NamespaceStatus {
		return governor.NamespaceStatus{Scope: governor.ScopeMachine, State: governor.NamespaceMissing, RequiresElevation: true}
	}
	inspector.UserNamespace = func() governor.NamespaceStatus {
		return governor.NamespaceStatus{Scope: governor.ScopeUserAcknowledged, State: governor.NamespaceUnsafe, Detail: "permission drift"}
	}
	inspector.UserOwner = func() governor.OwnerStatus {
		return governor.OwnerStatus{Scope: governor.ScopeUserAcknowledged, State: governor.OwnerUnavailable}
	}
	inspector.UserSafetyTrip = func() governor.SafetyTripStatus {
		return governor.SafetyTripStatus{State: governor.SafetyTripUnavailable, BlocksActiveWork: true}
	}
	inspector.AcquireUser = func(string) (RestrictedUserAuthority, error) {
		return nil, errors.New("permission drift")
	}

	report := inspector.Run(context.Background(), Options{GovernorScope: governor.ScopeUserAcknowledged})
	if report.UserAcknowledged == nil || report.UserAcknowledged.Acquired || report.UserAcknowledged.Released {
		t.Fatalf("failed boundary = %+v", report.UserAcknowledged)
	}
	if report.ActiveProbe.Reason != "user_acknowledged_scope_unavailable" || report.ActiveProbe.Detail != "permission drift" {
		t.Fatalf("active probe = %+v", report.ActiveProbe)
	}
	if report.NetworkActivityStarted {
		t.Fatal("failed acquisition started network activity")
	}
}

func TestMachineDefaultNeverAcquiresUserAuthority(t *testing.T) {
	inspector := readyInspector()
	inspector.AcquireUser = func(string) (RestrictedUserAuthority, error) {
		t.Fatal("machine default called user authority")
		return nil, nil
	}
	report := inspector.Run(context.Background(), Options{})
	if report.GovernorScope != governor.ScopeMachine || report.UserAcknowledged != nil || report.MachineNamespace != nil {
		t.Fatalf("machine default boundary = %+v", report)
	}
}
