package legacyice

import (
	"testing"

	"winkyou/pkg/solver"
)

func TestPathPolicyMetadata(t *testing.T) {
	directRole, directDeps := pathPolicyMetadata("direct")
	if directRole != solver.PathRoleProtectedDirect {
		t.Fatalf("direct role = %q, want %q", directRole, solver.PathRoleProtectedDirect)
	}
	if len(directDeps) != 0 {
		t.Fatalf("direct dependencies = %#v, want none", directDeps)
	}

	relayRole, relayDeps := pathPolicyMetadata("relay")
	if relayRole != solver.PathRolePrimaryCandidate {
		t.Fatalf("relay role = %q, want %q", relayRole, solver.PathRolePrimaryCandidate)
	}
	if len(relayDeps) != 1 || relayDeps[0].Kind != solver.PathDependencyRelay {
		t.Fatalf("relay dependencies = %#v, want relay dependency", relayDeps)
	}
	if relayDeps[0].Reason != "turn_or_relay_candidate" {
		t.Fatalf("relay dependency reason = %q, want turn_or_relay_candidate", relayDeps[0].Reason)
	}
}
