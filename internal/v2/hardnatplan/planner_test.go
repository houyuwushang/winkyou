package hardnatplan

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

type countingKeySource struct {
	calls int
	key   [32]byte
}

func (source *countingKeySource) DerivePlannerKey(PlannerKeyContext) ([32]byte, error) {
	source.calls++
	return source.key, nil
}

func TestBilateralPlannerFreezesThreeProfileShapes(t *testing.T) {
	t.Run("predictive", func(t *testing.T) {
		plan := buildPlanForRole(t, ProfilePredictiveEdm, ResourcePredictive, RoleInitiator,
			syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1)))
		if len(plan.Candidates) != 32 || plan.Cost != (Cost{Sockets: 8, Targets: 64, FiveTuples: 64, Packets: 64, PacketsPerSecond: 32, ActiveMillis: 13_000}) ||
			!plan.Executable || plan.Probability.Primary.FloorPartsPerTrillion != ProbabilityScale {
			t.Fatalf("predictive plan = %+v", plan)
		}
		assertCandidateShape(t, plan, 8, 1, 65535)
		for _, candidate := range plan.Candidates {
			if candidate.ExpectedSourcePort == 0 {
				t.Fatal("predictive plan omitted committed source port")
			}
		}
	})

	t.Run("asymmetric both fixed roles", func(t *testing.T) {
		mappingGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
		targetGraph := syntheticEvidence(MappingEIM, FilteringAPDF, apparentlyRandomPorts())
		mappingCommitment, err := BuildLocalCommitment(localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleMappingSet, mappingGraph))
		if err != nil {
			t.Fatal(err)
		}
		targetCommitment, err := BuildLocalCommitment(localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, targetGraph))
		if err != nil {
			t.Fatal(err)
		}
		wantEndpoint := AddressPort{Address: targetGraph.Allocation[0].MappedAddress, Port: targetGraph.Allocation[0].MappedPort}
		if targetCommitment.ReceiveEndpoint != wantEndpoint {
			t.Fatalf("target receive endpoint = %+v, want witnessed %+v", targetCommitment.ReceiveEndpoint, wantEndpoint)
		}
		pair, err := BuildBilateralPlan(BilateralPlannerInput{First: targetCommitment, Second: mappingCommitment, KeySource: keySource("asymmetric-pair")})
		if err != nil {
			t.Fatal(err)
		}
		mapping, _ := pair.PlanForRole(RoleMappingSet)
		target, _ := pair.PlanForRole(RoleTargetSet)
		wantCost := Cost{Sockets: 128, Targets: 512, FiveTuples: 512, Packets: 512, PacketsPerSecond: 64, ActiveMillis: 13_000}
		if len(mapping.Candidates) != 128 || len(target.Candidates) != 512 || mapping.Cost != wantCost || target.Cost != wantCost ||
			mapping.CostDigest != target.CostDigest || mapping.Probability.Primary.FloorPartsPerTrillion < minimumAsymmetricPPTrillion {
			t.Fatalf("asymmetric mapping/target = %d/%d costs=%+v/%+v", len(mapping.Candidates), len(target.Candidates), mapping.Cost, target.Cost)
		}
		assertCandidateShape(t, mapping, 128, 1, 65535)
		assertCandidateShape(t, target, 1, 1, 65535)
		for _, candidate := range mapping.Candidates {
			if candidate.TargetPort != targetCommitment.ReceiveEndpoint.Port {
				t.Fatalf("mapping-set target = %d, want peer commitment %d", candidate.TargetPort, targetCommitment.ReceiveEndpoint.Port)
			}
		}
	})

	t.Run("hard profiles remain plan-only", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
		hard16 := buildPlanForRole(t, ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph)
		if len(hard16.Candidates) != DynamicPortCount || hard16.Executable || hard16.Universe.Min != DynamicPortMin || hard16.Universe.Max != DynamicPortMax ||
			hard16.Cost.Sockets != 16 || hard16.Cost.Targets != 16_400 || hard16.Cost.Packets != 16_432 ||
			hard16.Probability.FullRangeBaseline.FloorPartsPerTrillion < minimumHard16FullPPTrillion {
			t.Fatalf("hard16 = candidates=%d executable=%t universe=%+v cost=%+v", len(hard16.Candidates), hard16.Executable, hard16.Universe, hard16.Cost)
		}
		assertCandidateShape(t, hard16, 16, DynamicPortMin, DynamicPortMax)

		hard32 := buildPlanForRole(t, ProfileHardBirthday, ResourceHard32KCandidate, RoleResponder, graph)
		if len(hard32.Candidates) != 32_768 || hard32.Executable || hard32.Cost.Sockets != 32 ||
			hard32.Probability.FullRangeBaseline.FloorPartsPerTrillion < minimumHard32FullPPTrillion {
			t.Fatalf("hard32 = candidates=%d executable=%t cost=%+v", len(hard32.Candidates), hard32.Executable, hard32.Cost)
		}
		assertCandidateShape(t, hard32, 32, DynamicPortMin, DynamicPortMax)
	})
}

func TestPredictiveBilateralScheduleTargetsPeerCommitment(t *testing.T) {
	leftGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	rightGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(60000, 8, 1))
	left, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, leftGraph))
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleResponder, rightGraph))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := BuildBilateralPlan(BilateralPlannerInput{First: left, Second: right, KeySource: keySource("different-windows")})
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := BuildBilateralPlan(BilateralPlannerInput{First: right, Second: left, KeySource: keySource("different-windows")})
	if err != nil || reversed.JointDigest != pair.JointDigest || reversed.Commitment() != pair.Commitment() {
		t.Fatalf("input order changed canonical bilateral plan: %+v/%v", reversed.Commitment(), err)
	}
	leftPlan, _ := pair.PlanForRole(RoleInitiator)
	rightPlan, _ := pair.PlanForRole(RoleResponder)
	leftSources := sourcePortSet(left.SourceSlots)
	rightSources := sourcePortSet(right.SourceSlots)
	for _, candidate := range leftPlan.Candidates {
		if _, ok := leftSources[candidate.ExpectedSourcePort]; !ok {
			t.Fatalf("left source %d was not locally committed", candidate.ExpectedSourcePort)
		}
		if _, ok := rightSources[candidate.TargetPort]; !ok {
			t.Fatalf("left target %d was not committed by right", candidate.TargetPort)
		}
	}
	for _, candidate := range rightPlan.Candidates {
		if _, ok := rightSources[candidate.ExpectedSourcePort]; !ok {
			t.Fatalf("right source %d was not locally committed", candidate.ExpectedSourcePort)
		}
		if _, ok := leftSources[candidate.TargetPort]; !ok {
			t.Fatalf("right target %d was not committed by left", candidate.TargetPort)
		}
	}
	if leftPlan.PlanDigest == rightPlan.PlanDigest || leftPlan.EvidenceDigest == rightPlan.EvidenceDigest {
		t.Fatal("distinct directional evidence/plans were incorrectly collapsed")
	}
	commitment := pair.Commitment()
	if err := VerifyJointCommitment(commitment, commitment); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecutablePlanAgainstCommitment(leftPlan, left, commitment); err != nil {
		t.Fatalf("verify executable predictive plan: %v", err)
	}
	mutated := commitment
	mutated.Directions[1].Triple.Plan[0]++
	if err := VerifyJointCommitment(commitment, mutated); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("joint mismatch error = %v", err)
	}
}

func TestBilateralPlannerIsDeterministicRoleSeparatedAndOwned(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	initiator, err := BuildLocalCommitment(localCommitmentInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph))
	if err != nil {
		t.Fatal(err)
	}
	responder, err := BuildLocalCommitment(localCommitmentInput(ProfileHardBirthday, ResourceHard16KLab, RoleResponder, graph))
	if err != nil {
		t.Fatal(err)
	}
	input := BilateralPlannerInput{First: initiator, Second: responder, KeySource: keySource("hard-determinism")}
	first, err := BuildBilateralPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildBilateralPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.JointDigest != second.JointDigest || first.Commitment() != second.Commitment() || !slices.Equal(first.Plans[0].Candidates, second.Plans[0].Candidates) {
		t.Fatal("same bilateral inputs were not deterministic")
	}
	if slices.Equal(first.Plans[0].Candidates[:16], first.Plans[1].Candidates[:16]) {
		t.Fatal("role-separated domain produced the same directional plan")
	}
	joint := first.Commitment()
	for _, check := range []struct {
		plan   Plan
		source LocalSourceCommitment
	}{
		{first.Plans[0], initiator},
		{first.Plans[1], responder},
	} {
		if err := VerifyPlanAgainstCommitment(check.plan, check.source, joint); err != nil {
			t.Fatalf("verify generated plan: %v", err)
		}
	}
	if err := VerifyExecutablePlanAgainstCommitment(first.Plans[0], initiator, joint); !errors.Is(err, ErrUnsupportedProfile) {
		t.Fatalf("plan-only hard resource execution error = %v", err)
	}
	clone := first.Plans[0].Clone()
	clone.Candidates[0].TargetPort = 0
	if first.Plans[0].Candidates[0].TargetPort == 0 {
		t.Fatal("Plan.Clone shares candidate ownership")
	}
	executableMutation := first.Plans[0].Clone()
	executableMutation.Executable = true
	if err := VerifyPlanAgainstCommitment(executableMutation, initiator, joint); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("executable mutation error = %v", err)
	}
}

func TestPlanAndSourceDigestsBindScheduleFields(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	commitment, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph))
	if err != nil {
		t.Fatal(err)
	}
	for index, mutate := range []func(*LocalSourceCommitment){
		func(value *LocalSourceCommitment) { value.Role = RoleResponder },
		func(value *LocalSourceCommitment) { value.SourceSlots[0].SocketSlot++ },
		func(value *LocalSourceCommitment) { value.SourceSlots[0].Ordinal++ },
		func(value *LocalSourceCommitment) { value.SourceSlots[0].ExpectedPublicSourcePort++ },
	} {
		mutated := commitment.Clone()
		mutate(&mutated)
		if digestSourceCommitment(mutated) == commitment.SourceDigest {
			t.Errorf("source mutation %d did not change digest", index)
		}
	}

	plan := buildPlanForRole(t, ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph)
	baseline := plan.PlanDigest
	for index, mutate := range []func(*Plan){
		func(value *Plan) { value.Role = RoleResponder },
		func(value *Plan) { value.Candidates[0].Role = RoleResponder },
		func(value *Plan) { value.Candidates[0].SocketSlot++ },
		func(value *Plan) { value.Candidates[0].Ordinal++ },
		func(value *Plan) { value.Candidates[0].ExpectedSourcePort++ },
		func(value *Plan) { value.Candidates[0].TargetPort++ },
		func(value *Plan) { value.Executable = !value.Executable },
	} {
		mutated := plan.Clone()
		mutate(&mutated)
		if digestPlan(mutated, graph.AttemptDigest) == baseline {
			t.Errorf("plan mutation %d did not change digest", index)
		}
	}
}

func TestBilateralPlannerRejectsNonCanonicalProbabilityBeforeKey(t *testing.T) {
	leftGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	rightGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(60000, 8, 1))
	left, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, leftGraph))
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleResponder, rightGraph))
	if err != nil {
		t.Fatal(err)
	}
	left.Probability.Model = "forged-model"
	left.Probability.Universe = "forged-universe"
	left.SourceDigest = digestSourceCommitment(left)
	source := &countingKeySource{key: syntheticDigest("must-not-be-called")}
	if _, err := BuildBilateralPlan(BilateralPlannerInput{First: left, Second: right, KeySource: source}); !errors.Is(err, ErrPlanMismatch) || source.calls != 0 {
		t.Fatalf("forged probability error/key-calls = %v/%d", err, source.calls)
	}
}

func TestPlannerFreezesCostBeforeSourceOrCandidateGeneration(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	for _, mutate := range []func(*Cost){
		func(cost *Cost) { cost.Sockets = 15 },
		func(cost *Cost) { cost.Targets = 16_399 },
		func(cost *Cost) { cost.FiveTuples = 16_399 },
		func(cost *Cost) { cost.Packets = 16_431 },
		func(cost *Cost) { cost.PacketsPerSecond = 511 },
		func(cost *Cost) { cost.ActiveMillis = 44_999 },
	} {
		input := localCommitmentInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph)
		mutate(&input.Budget)
		commitment, err := BuildLocalCommitment(input)
		if !errors.Is(err, ErrInsufficientBudget) || len(commitment.SourceSlots) != 0 || commitment.Cost.Packets != 16_432 || allZero(commitment.CostDigest[:]) {
			t.Fatalf("budget failure commitment/error = %+v/%v", commitment, err)
		}
	}

	valid, err := BuildLocalCommitment(localCommitmentInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := BuildLocalCommitment(localCommitmentInput(ProfileHardBirthday, ResourceHard16KLab, RoleResponder, graph))
	if err != nil {
		t.Fatal(err)
	}
	valid.SourceSlots[0].SocketSlot++
	source := &countingKeySource{key: syntheticDigest("must-not-be-called")}
	if _, err := BuildBilateralPlan(BilateralPlannerInput{First: valid, Second: peer, KeySource: source}); !errors.Is(err, ErrPlanMismatch) || source.calls != 0 {
		t.Fatalf("tampered commitment error/key-calls = %v/%d", err, source.calls)
	}
}

func TestPlannerRejectsEvidenceOrProfileWithoutFallback(t *testing.T) {
	tests := []LocalCommitmentInput{
		localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())),
		localCommitmentInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))),
		localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())),
	}
	for index, input := range tests {
		commitment, err := BuildLocalCommitment(input)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(commitment.SourceSlots) != 0 {
			t.Errorf("case %d commitment/error = %+v/%v", index, commitment, err)
		}
	}
}

func TestRemoteIntentRejectsCandidateAndBudgetControl(t *testing.T) {
	valid, err := json.Marshal(map[string]string{
		"profile": string(ProfileHardBirthday), "resource_class": string(ResourceHard16KLab), "role": string(RoleInitiator), "generation": "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ParseRemoteIntent(valid)
	if err != nil || intent.Profile != ProfileHardBirthday || intent.ResourceClass != ResourceHard16KLab {
		t.Fatalf("valid intent = %+v/%v", intent, err)
	}
	for _, member := range []string{"candidate_list", "candidate_span", "packet_count", "socket_count", "packets_per_second", "target_ports"} {
		payload := []byte(`{"profile":"hard_birthday_campaign/1","resource_class":"hard_16k_lab/1","role":"initiator","generation":"1","` + member + `":[]}`)
		if _, err := ParseRemoteIntent(payload); !errors.Is(err, ErrRemoteControlField) {
			t.Errorf("member %s error = %v", member, err)
		}
	}
	duplicate := []byte(`{"profile":"hard_birthday_campaign/1","profile":"hard_birthday_campaign/1","resource_class":"hard_16k_lab/1","role":"initiator","generation":"1"}`)
	if _, err := ParseRemoteIntent(duplicate); !errors.Is(err, ErrRemoteControlField) {
		t.Fatalf("duplicate error = %v", err)
	}
}

func sourcePortSet(slots []SourceSlot) map[uint16]struct{} {
	result := make(map[uint16]struct{}, len(slots))
	for _, slot := range slots {
		result[slot.ExpectedPublicSourcePort] = struct{}{}
	}
	return result
}

func assertCandidateShape(t *testing.T, plan Plan, sockets int, minimum, maximum uint16) {
	t.Helper()
	seen := make(map[[2]uint32]struct{}, len(plan.Candidates))
	perSocket := make(map[uint16]int)
	for ordinal, candidate := range plan.Candidates {
		if candidate.Ordinal != uint32(ordinal) || candidate.Role != plan.Role || candidate.TargetPort == 0 ||
			candidate.TargetPort < minimum || candidate.TargetPort > maximum || int(candidate.SocketSlot) >= sockets {
			t.Fatalf("invalid candidate %d: %+v", ordinal, candidate)
		}
		key := [2]uint32{uint32(candidate.SocketSlot), uint32(candidate.TargetPort)}
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate tuple at %d: %+v", ordinal, candidate)
		}
		seen[key] = struct{}{}
		perSocket[candidate.SocketSlot]++
	}
	if len(perSocket) != sockets {
		t.Fatalf("used sockets = %d, want %d", len(perSocket), sockets)
	}
}
