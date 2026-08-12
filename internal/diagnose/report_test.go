package diagnose

import (
	"context"
	"testing"
	"time"

	"winkyou/internal/governor"
)

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
