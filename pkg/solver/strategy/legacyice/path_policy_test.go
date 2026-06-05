package legacyice

import (
	"net"
	"testing"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

func TestPathPolicyMetadata(t *testing.T) {
	directRole, directDeps := pathPolicyMetadata("direct", candidatePair("117.48.146.2", "1.1.1.1"))
	if directRole != solver.PathRoleProtectedDirect {
		t.Fatalf("direct role = %q, want %q", directRole, solver.PathRoleProtectedDirect)
	}
	if len(directDeps) != 0 {
		t.Fatalf("direct dependencies = %#v, want none", directDeps)
	}

	relayRole, relayDeps := pathPolicyMetadata("relay", nil)
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

func TestPathPolicyMetadataMarksOverlayCandidatesAsDependent(t *testing.T) {
	role, deps := pathPolicyMetadata("direct", candidatePair("117.48.146.2", "100.102.17.35"))
	if role == solver.PathRoleProtectedDirect {
		t.Fatalf("direct role = %q, want non-protected role for overlay candidate", role)
	}
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("direct role = %q, want %q", role, solver.PathRolePrimaryCandidate)
	}
	if len(deps) != 1 || deps[0].Kind != solver.PathDependencyUnknown {
		t.Fatalf("dependencies = %#v, want unknown dependency", deps)
	}
	if deps[0].Reason != "remote_cgnat_or_overlay_candidate" {
		t.Fatalf("dependency reason = %q, want remote_cgnat_or_overlay_candidate", deps[0].Reason)
	}
}

func TestPathPolicyMetadataMarksPrivateCandidatesAsDependent(t *testing.T) {
	role, deps := pathPolicyMetadata("direct", candidatePair("10.6.22.2", "117.48.146.2"))
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("direct role = %q, want %q", role, solver.PathRolePrimaryCandidate)
	}
	if len(deps) != 1 || deps[0].Reason != "local_private_candidate" {
		t.Fatalf("dependencies = %#v, want local private dependency", deps)
	}
}

func candidatePair(localIP, remoteIP string) *nat.CandidatePair {
	return &nat.CandidatePair{
		Local: &nat.Candidate{
			Type:    nat.CandidateTypeSrflx,
			Address: &net.UDPAddr{IP: net.ParseIP(localIP), Port: 10000},
		},
		Remote: &nat.Candidate{
			Type:    nat.CandidateTypePrflx,
			Address: &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: 20000},
		},
	}
}
