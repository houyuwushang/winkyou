package legacyice

import (
	"net"
	"testing"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

func TestPathPolicyMetadata(t *testing.T) {
	directRole, directDeps := pathPolicyMetadata("direct", candidatePair("117.48.146.2", "1.1.1.1"), modeDirectPrefer, nil, nil)
	if directRole != solver.PathRoleProtectedDirect {
		t.Fatalf("direct role = %q, want %q", directRole, solver.PathRoleProtectedDirect)
	}
	if len(directDeps) != 0 {
		t.Fatalf("direct dependencies = %#v, want none", directDeps)
	}

	relayRole, relayDeps := pathPolicyMetadata("relay", nil, modeDirectPrefer, nil, nil)
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
	role, deps := pathPolicyMetadata("direct", candidatePair("117.48.146.2", "100.102.17.35"), modeDirectPrefer, nil, nil)
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
	role, deps := pathPolicyMetadata("direct", candidatePair("10.6.22.2", "117.48.146.2"), modeDirectPrefer, nil, nil)
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("direct role = %q, want %q", role, solver.PathRolePrimaryCandidate)
	}
	if len(deps) != 1 || deps[0].Reason != "local_private_candidate" {
		t.Fatalf("dependencies = %#v, want local private dependency", deps)
	}
}

func TestPathPolicyMetadataAllowsSrflxBaseLocalHostForPublicDirect(t *testing.T) {
	role, deps := pathPolicyMetadata("direct", candidatePairWithTypes(nat.CandidateTypeHost, "192.168.1.20", nat.CandidateTypeSrflx, "117.48.146.2"), modePublicDirect, map[string]struct{}{"192.168.1.20": {}}, nil)
	if role != solver.PathRoleProtectedDirect {
		t.Fatalf("public direct role = %q, want %q", role, solver.PathRoleProtectedDirect)
	}
	if len(deps) != 0 {
		t.Fatalf("public direct dependencies = %#v, want none", deps)
	}
}

func TestPathPolicyMetadataKeepsUnadvertisedPrivateLocalDependentForPublicDirect(t *testing.T) {
	role, deps := pathPolicyMetadata("direct", candidatePairWithTypes(nat.CandidateTypeHost, "192.168.1.20", nat.CandidateTypeSrflx, "117.48.146.2"), modePublicDirect, nil, nil)
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("public direct private role = %q, want %q", role, solver.PathRolePrimaryCandidate)
	}
	if len(deps) != 1 || deps[0].Reason != "local_private_candidate" {
		t.Fatalf("public direct private deps = %#v, want local_private_candidate", deps)
	}
}

func TestPathPolicyMetadataKeepsOverlayLocalDependentForPublicDirect(t *testing.T) {
	role, deps := pathPolicyMetadata("direct", candidatePairWithTypes(nat.CandidateTypeHost, "100.102.17.35", nat.CandidateTypeSrflx, "117.48.146.2"), modePublicDirect, map[string]struct{}{"100.102.17.35": {}}, nil)
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("public direct overlay role = %q, want %q", role, solver.PathRolePrimaryCandidate)
	}
	if len(deps) != 1 || deps[0].Reason != "local_cgnat_or_overlay_candidate" {
		t.Fatalf("public direct overlay deps = %#v, want local_cgnat_or_overlay_candidate", deps)
	}
}

func TestPathPolicyMetadataAllowsTrustedCIDRForPublicDirect(t *testing.T) {
	trusted := []string{"100.64.0.0/10"}
	role, deps := pathPolicyMetadata("direct", candidatePairWithTypes(nat.CandidateTypeHost, "100.102.17.35", nat.CandidateTypePrflx, "100.102.17.36"), modePublicDirect, nil, trusted)
	if role != solver.PathRoleProtectedDirect {
		t.Fatalf("trusted public direct role = %q, want %q", role, solver.PathRoleProtectedDirect)
	}
	if len(deps) != 0 {
		t.Fatalf("trusted public direct dependencies = %#v, want none", deps)
	}
}

func TestPathPolicyMetadataKeepsRemotePrivateDependentForPublicDirect(t *testing.T) {
	role, deps := pathPolicyMetadata("direct", candidatePairWithTypes(nat.CandidateTypeHost, "192.168.1.20", nat.CandidateTypeHost, "10.0.0.50"), modePublicDirect, map[string]struct{}{"192.168.1.20": {}}, nil)
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("public direct remote private role = %q, want %q", role, solver.PathRolePrimaryCandidate)
	}
	if len(deps) != 1 || deps[0].Reason != "remote_private_candidate" {
		t.Fatalf("public direct remote private deps = %#v, want remote_private_candidate", deps)
	}
}

func candidatePair(localIP, remoteIP string) *nat.CandidatePair {
	return candidatePairWithTypes(nat.CandidateTypeSrflx, localIP, nat.CandidateTypePrflx, remoteIP)
}

func candidatePairWithTypes(localType nat.CandidateType, localIP string, remoteType nat.CandidateType, remoteIP string) *nat.CandidatePair {
	return &nat.CandidatePair{
		Local: &nat.Candidate{
			Type:    localType,
			Address: &net.UDPAddr{IP: net.ParseIP(localIP), Port: 10000},
		},
		Remote: &nat.Candidate{
			Type:    remoteType,
			Address: &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: 20000},
		},
	}
}
