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

func TestPlannerFreezesThreeProfileShapes(t *testing.T) {
	t.Run("predictive", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		plan, err := BuildPlan(planInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph))
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Candidates) != 32 || plan.Cost != (Cost{Sockets: 8, Targets: 64, FiveTuples: 64, Packets: 64, PacketsPerSecond: 32, ActiveMillis: 13_000}) ||
			!plan.Executable || plan.Probability.Primary.FloorPartsPerTrillion != ProbabilityScale {
			t.Fatalf("predictive plan = %+v", plan)
		}
		assertCandidateShape(t, plan, 8, 1, 65535)
	})

	t.Run("asymmetric both fixed roles", func(t *testing.T) {
		mappingGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
		mapping, err := BuildPlan(planInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleMappingSet, mappingGraph))
		if err != nil {
			t.Fatal(err)
		}
		targetGraph := syntheticEvidence(MappingEIM, FilteringAPDF, apparentlyRandomPorts())
		target, err := BuildPlan(planInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, targetGraph))
		if err != nil {
			t.Fatal(err)
		}
		wantCost := Cost{Sockets: 128, Targets: 512, FiveTuples: 512, Packets: 512, PacketsPerSecond: 64, ActiveMillis: 13_000}
		if len(mapping.Candidates) != 128 || len(target.Candidates) != 512 || mapping.Cost != wantCost || target.Cost != wantCost ||
			mapping.CostDigest != target.CostDigest || mapping.Probability.Primary.FloorPartsPerTrillion < minimumAsymmetricPPTrillion {
			t.Fatalf("asymmetric mapping/target = %d/%d costs=%+v/%+v probability=%+v", len(mapping.Candidates), len(target.Candidates), mapping.Cost, target.Cost, target.Probability)
		}
		assertCandidateShape(t, mapping, 128, 1, 65535)
		assertCandidateShape(t, target, 1, 1, 65535)
		for _, candidate := range mapping.Candidates {
			if candidate.TargetPort != 55000 {
				t.Fatalf("mapping-set target port = %d, want fixed authenticated port", candidate.TargetPort)
			}
		}
	})

	t.Run("hard 16k lab", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
		plan, err := BuildPlan(planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph))
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Candidates) != DynamicPortCount || plan.Executable || plan.Universe.Min != DynamicPortMin || plan.Universe.Max != DynamicPortMax ||
			plan.Cost.Sockets != 16 || plan.Cost.Targets != 16_400 || plan.Cost.Packets != 16_432 ||
			plan.Probability.Primary.FloorPartsPerTrillion < 632_000_000_000 || plan.Probability.FullRangeBaseline.FloorPartsPerTrillion < minimumHard16FullPPTrillion {
			t.Fatalf("hard16 plan = candidates=%d executable=%t universe=%+v cost=%+v probability=%+v", len(plan.Candidates), plan.Executable, plan.Universe, plan.Cost, plan.Probability)
		}
		assertCandidateShape(t, plan, 16, DynamicPortMin, DynamicPortMax)
	})

	t.Run("hard 32k comparison only", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
		plan, err := BuildPlan(planInput(ProfileHardBirthday, ResourceHard32KCandidate, RoleResponder, graph))
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Candidates) != 32_768 || plan.Executable || plan.Cost.Sockets != 32 || plan.Probability.FullRangeBaseline.FloorPartsPerTrillion < minimumHard32FullPPTrillion {
			t.Fatalf("hard32 plan = candidates=%d executable=%t cost=%+v probability=%+v", len(plan.Candidates), plan.Executable, plan.Cost, plan.Probability)
		}
		assertCandidateShape(t, plan, 32, DynamicPortMin, DynamicPortMax)
	})
}

func TestPlannerIsDeterministicRoleSeparatedAndOwned(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	initiatorInput := planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph)
	first, err := BuildPlan(initiatorInput)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(initiatorInput)
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanDigest != second.PlanDigest || first.CostDigest != second.CostDigest || !slices.Equal(first.Candidates, second.Candidates) {
		t.Fatal("same planner inputs were not deterministic")
	}
	responder, err := BuildPlan(planInput(ProfileHardBirthday, ResourceHard16KLab, RoleResponder, graph))
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanDigest == responder.PlanDigest || slices.Equal(first.Candidates[:16], responder.Candidates[:16]) {
		t.Fatal("role-separated domain produced the same plan")
	}
	clone := first.Clone()
	clone.Candidates[0].TargetPort = 0
	if first.Candidates[0].TargetPort == clone.Candidates[0].TargetPort {
		t.Fatal("Plan.Clone shares candidate ownership")
	}
	if err := VerifyDigestTriple(first.Digests(), second.Digests()); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDigestTriple(first.Digests(), responder.Digests()); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("mismatch error = %v", err)
	}
}

func TestPlanDigestBindsRoleSlotOrdinalAndTargetPort(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	plan, err := BuildPlan(planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph))
	if err != nil {
		t.Fatal(err)
	}
	baseline := plan.PlanDigest
	mutations := []func(*Plan){
		func(value *Plan) { value.Role = RoleResponder },
		func(value *Plan) { value.Candidates[0].Role = RoleResponder },
		func(value *Plan) { value.Candidates[0].SocketSlot++ },
		func(value *Plan) { value.Candidates[0].Ordinal++ },
		func(value *Plan) { value.Candidates[0].TargetPort++ },
	}
	for index, mutate := range mutations {
		mutated := plan.Clone()
		mutate(&mutated)
		if got := digestPlan(mutated, graph.AttemptDigest); got == baseline {
			t.Errorf("mutation %d did not change plan digest", index)
		}
	}
}

func TestPlannerFreezesCostBeforeCandidateGeneration(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	input := planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph)
	source := &countingKeySource{key: syntheticDigest("must-not-be-called")}
	input.KeySource = source
	input.Budget.Packets = 16_431
	plan, err := BuildPlan(input)
	if !errors.Is(err, ErrInsufficientBudget) || len(plan.Candidates) != 0 || source.calls != 0 || plan.Cost.Packets != 16_432 || allZero(plan.CostDigest[:]) {
		t.Fatalf("budget failure plan/error/key-calls = %+v/%v/%d", plan, err, source.calls)
	}

	for _, mutate := range []func(*Cost){
		func(cost *Cost) { cost.Sockets = 15 }, func(cost *Cost) { cost.Targets = 16_399 },
		func(cost *Cost) { cost.FiveTuples = 16_399 }, func(cost *Cost) { cost.PacketsPerSecond = 511 },
		func(cost *Cost) { cost.ActiveMillis = 44_999 },
	} {
		input := planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph)
		source := &countingKeySource{key: syntheticDigest("not-called")}
		input.KeySource = source
		mutate(&input.Budget)
		plan, err := BuildPlan(input)
		if !errors.Is(err, ErrInsufficientBudget) || len(plan.Candidates) != 0 || source.calls != 0 {
			t.Fatalf("dimension mutation plan/error/key-calls = %d/%v/%d", len(plan.Candidates), err, source.calls)
		}
	}
}

func TestPlannerRejectsEvidenceOrProfileWithoutFallback(t *testing.T) {
	tests := []PlannerInput{
		planInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())),
		planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))),
		planInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())),
	}
	for index, input := range tests {
		plan, err := BuildPlan(input)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(plan.Candidates) != 0 {
			t.Errorf("case %d plan/error = %+v/%v", index, plan, err)
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
