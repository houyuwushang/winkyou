package solver

import "testing"

func TestPathRoleAndDependencyHelpers(t *testing.T) {
	direct := PathSummary{ConnectionType: "direct"}
	if !IsDirectPath(direct) {
		t.Fatal("IsDirectPath(direct) = false, want true")
	}
	if IsRelayPath(direct) {
		t.Fatal("IsRelayPath(direct) = true, want false")
	}
	if !HasDependency(direct, PathDependencyNone) {
		t.Fatal("HasDependency(direct, none) = false, want true for empty dependencies")
	}

	protected := PathSummary{Role: PathRoleProtectedDirect}
	if !IsDirectPath(protected) {
		t.Fatal("IsDirectPath(protected role) = false, want true")
	}

	relay := PathSummary{
		ConnectionType: "direct",
		Dependencies: []PathDependency{{
			Kind:   PathDependencyRelay,
			NodeID: "relay-1",
			Reason: "turn_candidate",
		}},
	}
	if !IsRelayPath(relay) {
		t.Fatal("IsRelayPath(relay dependency) = false, want true")
	}
	if !HasDependency(relay, PathDependencyRelay) {
		t.Fatal("HasDependency(relay, relay) = false, want true")
	}
	if HasDependency(relay, PathDependencyCoordinator) {
		t.Fatal("HasDependency(relay, coordinator) = true, want false")
	}
}

func TestClonePathSummary(t *testing.T) {
	original := PathSummary{
		PathID:         "path/a",
		ConnectionType: "direct",
		Role:           PathRoleProtectedDirect,
		Details:        map[string]string{"strategy": "legacy_ice_udp"},
		Metrics:        map[string]string{"rtt_ms": "12"},
		Dependencies: []PathDependency{{
			Kind:   PathDependencyPeer,
			NodeID: "node-b",
			Reason: "bootstrap_hint",
		}},
	}

	clone := ClonePathSummary(original)
	clone.Details["strategy"] = "changed"
	clone.Metrics["rtt_ms"] = "99"
	clone.Dependencies[0].NodeID = "node-c"

	if original.Details["strategy"] != "legacy_ice_udp" {
		t.Fatalf("original Details mutated: %q", original.Details["strategy"])
	}
	if original.Metrics["rtt_ms"] != "12" {
		t.Fatalf("original Metrics mutated: %q", original.Metrics["rtt_ms"])
	}
	if original.Dependencies[0].NodeID != "node-b" {
		t.Fatalf("original Dependencies mutated: %q", original.Dependencies[0].NodeID)
	}
}
