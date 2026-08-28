package hardnatplan

import "testing"

func TestCompactSourceCommitmentRoundTrip(t *testing.T) {
	tests := []struct {
		profile  Profile
		resource ResourceClass
		role     Role
		mapping  MappingBehavior
		ports    []uint16
	}{
		{ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, MappingAPDM, sequentialPorts(50000, 8, 1)},
		{ProfileAsymmetricBirthday, ResourceAsymmetric, RoleMappingSet, MappingAPDM, apparentlyRandomPorts()},
		{ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, MappingEIM, apparentlyRandomPorts()},
	}
	for _, test := range tests {
		graph := syntheticEvidence(test.mapping, FilteringAPDF, test.ports)
		commitment, err := BuildLocalCommitment(LocalCommitmentInput{
			Profile: test.profile, ResourceClass: test.resource,
			Context:  AttemptContext{AttemptDigest: graph.AttemptDigest, Generation: graph.Generation, Role: test.role},
			Evidence: graph, Validation: trustedValidation(graph), Budget: generousBudget(),
		})
		if err != nil {
			t.Fatalf("build %s/%s: %v", test.profile, test.role, err)
		}
		compact, err := CompactSourceInputFor(commitment)
		if err != nil {
			t.Fatalf("compact %s/%s: %v", test.profile, test.role, err)
		}
		rebuilt, err := ReconstructLocalCommitment(compact)
		if err != nil || rebuilt.SourceDigest != commitment.SourceDigest {
			t.Fatalf("rebuild %s/%s digest=%x want=%x err=%v", test.profile, test.role, rebuilt.SourceDigest, commitment.SourceDigest, err)
		}
	}
}

func TestCompactSourceCannotSupplyCostOrCandidates(t *testing.T) {
	input := CompactSourceInput{
		Profile: ProfilePredictiveEdm, ResourceClass: ResourcePredictive, Role: RoleInitiator,
		AttemptDigest: syntheticDigest("attempt"), Generation: 1,
		PredictedPorts: sequentialPorts(50000, PredictiveWindowPorts, 1),
		EvidenceDigest: syntheticDigest("evidence"), ValidationDigest: syntheticDigest("validation"),
		ModelCoverage: "synthetic",
	}
	input.PredictedPorts[0] = 0
	if _, err := ReconstructLocalCommitment(input); err == nil {
		t.Fatal("invalid source schedule was reconstructed")
	}
}
