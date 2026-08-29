package hardnatplan

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	planEncodingLabel   = "winkyou-hardnat-plan-v3\x00"
	costEncodingLabel   = "winkyou-hardnat-cost-v1\x00"
	sourceEncodingLabel = "winkyou-hardnat-source-commitment-v1\x00"
	jointEncodingLabel  = "winkyou-hardnat-joint-plan-v1\x00"
	prpEncodingLabel    = "winkyou-hardnat-prp-v1\x00"

	minimumAsymmetricPPTrillion = uint64(632_000_000_000)
	minimumHard16FullPPTrillion = uint64(60_000_000_000)
	minimumHard32FullPPTrillion = uint64(221_000_000_000)
)

type planShape struct {
	cost       Cost
	universe   Universe
	candidates uint32
	executable bool
}

type hardProbabilityCacheKey struct {
	profile    Profile
	resource   ResourceClass
	universe   Universe
	candidates uint32
}

type hardProbabilityCacheValue struct {
	once   sync.Once
	report ProbabilityReport
	err    error
}

// The hard profiles have exactly one compile-time shape each. Probability is
// immutable for that shape and expensive enough that independently verifying
// both commitments must not repeatedly spend the active attempt envelope on
// identical high-precision arithmetic. The cache remains bounded to the two
// accepted hard resources; caller-specific evidence coverage is restored on
// the returned value and never stored.
var hardProbabilityCache sync.Map

// BuildLocalCommitment validates one side's trusted evidence and freezes its
// own predicted source schedule. It never guesses or consumes the peer's
// schedule. Cost admission precedes source-slot allocation.
func BuildLocalCommitment(input LocalCommitmentInput) (LocalSourceCommitment, error) {
	commitment := LocalSourceCommitment{
		Profile: input.Profile, ResourceClass: input.ResourceClass, Role: input.Context.Role,
		AttemptDigest: input.Context.AttemptDigest, Generation: input.Context.Generation,
	}
	if input.Context.Generation == 0 || allZero(input.Context.AttemptDigest[:]) ||
		input.Context.AttemptDigest != input.Evidence.AttemptDigest || input.Context.Generation != input.Evidence.Generation {
		return commitment, ErrInvalidEvidence
	}
	if err := validateRole(input.Profile, input.Context.Role); err != nil {
		return commitment, err
	}

	model, err := InferStateModel(input.Evidence, input.Validation)
	commitment.EvidenceDigest = model.EvidenceDigest
	commitment.ValidationDigest = model.ValidationDigest
	if err != nil {
		return commitment, err
	}
	if err := validateModelForProfile(input.Profile, input.Context.Role, model); err != nil {
		return commitment, err
	}
	receiveEndpoint := AddressPort{}
	if input.Profile == ProfileAsymmetricBirthday && input.Context.Role == RoleTargetSet {
		receiveEndpoint = model.ReusableEndpoint
	}
	if err := validateReceiveEndpoint(input.Profile, input.Context.Role, receiveEndpoint); err != nil {
		return commitment, err
	}
	shape, err := shapeFor(input.Profile, input.ResourceClass, input.Context.Role, model)
	if err != nil {
		return commitment, err
	}
	commitment.Cost = shape.cost
	commitment.Universe = shape.universe
	commitment.Executable = shape.executable
	commitment.ReceiveEndpoint = receiveEndpoint
	commitment.CostDigest = digestCost(input.Profile, input.ResourceClass, shape.cost)
	commitment.Probability, err = probabilityFor(input.Profile, input.ResourceClass, model, shape)
	if err != nil {
		return commitment, err
	}
	if !probabilityAdmitted(input.ResourceClass, commitment.Probability) || !input.Budget.admits(shape.cost) {
		return commitment, ErrInsufficientBudget
	}
	commitment.SourceSlots, err = sourceSlotsFor(input.ResourceClass, input.Context.Role, model, receiveEndpoint)
	if err != nil {
		return commitment, err
	}
	commitment.SourceDigest = digestSourceCommitment(commitment)
	return commitment, nil
}

// BuildBilateralPlan combines two independently validated source commitments.
// Direction A targets B's committed source schedule and direction B targets
// A's schedule. The two directional digest triples are intentionally distinct
// and are bound by one canonical joint digest.
func BuildBilateralPlan(input BilateralPlannerInput) (BilateralPlan, error) {
	var bilateral BilateralPlan
	first, second, err := canonicalCommitments(input.First, input.Second)
	if err != nil {
		return bilateral, err
	}
	if err := validateLocalCommitment(first); err != nil {
		return bilateral, err
	}
	if err := validateLocalCommitment(second); err != nil {
		return bilateral, err
	}
	if input.KeySource == nil {
		return bilateral, ErrInvalidPlannerKey
	}
	key, err := input.KeySource.DerivePlannerKey(PlannerKeyContext{
		AttemptDigest: first.AttemptDigest, Generation: first.Generation, Profile: first.Profile, ResourceClass: first.ResourceClass,
		FirstEvidenceDigest: first.EvidenceDigest, SecondEvidenceDigest: second.EvidenceDigest,
	})
	if err != nil || allZero(key[:]) {
		clear(key[:])
		return bilateral, ErrInvalidPlannerKey
	}
	defer clear(key[:])

	commitments := [2]LocalSourceCommitment{first, second}
	for index := range commitments {
		local := commitments[index]
		peer := commitments[1-index]
		candidates, candidateErr := buildDirectionalCandidates(local, peer, key)
		if candidateErr != nil {
			return BilateralPlan{}, candidateErr
		}
		shape, shapeErr := shapeForCommitment(local)
		if shapeErr != nil || uint32(len(candidates)) != shape.candidates {
			clearCandidates(candidates)
			if shapeErr != nil {
				return BilateralPlan{}, shapeErr
			}
			return BilateralPlan{}, fmt.Errorf("%w: candidate shape mismatch", ErrUnsupportedProfile)
		}
		plan := Plan{
			Profile: local.Profile, ResourceClass: local.ResourceClass, Role: local.Role, Generation: local.Generation,
			Universe: local.Universe, Cost: local.Cost, Candidates: candidates, Probability: local.Probability,
			EvidenceDigest: local.EvidenceDigest, CostDigest: local.CostDigest, Executable: local.Executable,
		}
		plan.PlanDigest = digestPlan(plan, local.AttemptDigest)
		bilateral.Plans[index] = plan
		bilateral.SourceDigests[index] = local.SourceDigest
	}
	bilateral.Profile = first.Profile
	bilateral.ResourceClass = first.ResourceClass
	bilateral.AttemptDigest = first.AttemptDigest
	bilateral.Generation = first.Generation
	commitment := bilateral.Commitment()
	bilateral.JointDigest = digestJointCommitment(commitment)
	return bilateral, nil
}

func validateModelForProfile(profile Profile, role Role, model StateModel) error {
	if !model.PublicAddressStable || model.SuccessfulSamples < MinSuccessfulAllocationSamples ||
		model.ObserverAddressCount < 2 || !model.HasAlternatePort {
		return ErrEvidenceInsufficient
	}
	switch profile {
	case ProfilePredictiveEdm:
		if !model.Mapping.endpointDependent() ||
			(model.Allocation != AllocationSequentialUniform && model.Allocation != AllocationMonotonicNonuniform) ||
			len(model.PredictedSourcePorts) != PredictiveWindowPorts {
			return ErrEvidenceInsufficient
		}
	case ProfileAsymmetricBirthday:
		if role == RoleMappingSet && !model.Mapping.endpointDependent() {
			return ErrEvidenceInsufficient
		}
		if role == RoleTargetSet && (model.Mapping != MappingEIM || !model.ReusableEndpoint.Valid()) {
			return ErrEvidenceInsufficient
		}
	case ProfileHardBirthday:
		if !model.Mapping.endpointDependent() || model.Allocation != AllocationApparentlyRandom {
			return ErrEvidenceInsufficient
		}
	default:
		return ErrUnsupportedProfile
	}
	return nil
}

func validateReceiveEndpoint(profile Profile, role Role, endpoint AddressPort) error {
	required := profile == ProfileAsymmetricBirthday && role == RoleTargetSet
	if required && !endpoint.Valid() {
		return ErrInvalidEvidence
	}
	if !required && endpoint != (AddressPort{}) {
		return ErrInvalidEvidence
	}
	return nil
}

func shapeFor(profile Profile, resource ResourceClass, role Role, model StateModel) (planShape, error) {
	switch {
	case profile == ProfilePredictiveEdm && resource == ResourcePredictive:
		return planShape{
			cost:       Cost{Sockets: 8, Targets: 64, FiveTuples: 64, Packets: 64, PacketsPerSecond: 32, ActiveMillis: 13_000},
			universe:   Universe{Name: "peer-source-schedule/1", Count: uint32(len(model.PredictedSourcePorts))},
			candidates: uint32(len(model.PredictedSourcePorts)), executable: true,
		}, nil
	case profile == ProfileAsymmetricBirthday && resource == ResourceAsymmetric:
		count := uint32(512)
		if role == RoleMappingSet {
			count = 128
		}
		return planShape{
			cost:       Cost{Sockets: 128, Targets: 512, FiveTuples: 512, Packets: 512, PacketsPerSecond: 64, ActiveMillis: 13_000},
			universe:   Universe{Name: "nonzero-udp-ports/1", Min: 1, Max: 65535},
			candidates: count, executable: true,
		}, nil
	case profile == ProfileHardBirthday && resource == ResourceHard16KLab:
		return planShape{
			cost:     Cost{Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512, ActiveMillis: 45_000},
			universe: Universe{Name: "iana-dynamic-private-49152-65535/1", Min: DynamicPortMin, Max: DynamicPortMax},
			// Gate B3 acceptance atomically makes this exact, compiled plan
			// executable. Executable is part of PlanDigest, so older B1 builds
			// fail joint commitment rather than negotiating or falling back.
			candidates: DynamicPortCount, executable: true,
		}, nil
	case profile == ProfileHardBirthday && resource == ResourceHard32KCandidate:
		return planShape{
			cost:       Cost{Sockets: 32, Targets: 32_768, FiveTuples: 32_768, Packets: 32_768, PacketsPerSecond: 512, ActiveMillis: 45_000},
			universe:   Universe{Name: "iana-dynamic-private-49152-65535/two-socket-rounds/1", Min: DynamicPortMin, Max: DynamicPortMax, Count: 32_768},
			candidates: 32_768, executable: false,
		}, nil
	default:
		return planShape{}, ErrUnsupportedProfile
	}
}

func shapeForCommitment(commitment LocalSourceCommitment) (planShape, error) {
	model := StateModel{}
	if commitment.ResourceClass == ResourcePredictive {
		model.PredictedSourcePorts = make([]uint16, len(commitment.SourceSlots))
	}
	return shapeFor(commitment.Profile, commitment.ResourceClass, commitment.Role, model)
}

func probabilityForCommitment(commitment LocalSourceCommitment, shape planShape) (ProbabilityReport, error) {
	model := StateModel{Coverage: commitment.Probability.ModelCoverage}
	if commitment.ResourceClass == ResourcePredictive {
		model.PredictedSourcePorts = make([]uint16, len(commitment.SourceSlots))
	}
	return probabilityFor(commitment.Profile, commitment.ResourceClass, model, shape)
}

func probabilityFor(profile Profile, resource ResourceClass, model StateModel, shape planShape) (ProbabilityReport, error) {
	if resource == ResourceHard16KLab || resource == ResourceHard32KCandidate {
		return probabilityForHardShape(profile, resource, model.Coverage, shape)
	}
	report := ProbabilityReport{Conditional: true, ModelCoverage: model.Coverage}
	switch resource {
	case ResourcePredictive:
		report.Model = string(ProfilePredictiveEdm)
		report.Universe = shape.universe.Name
		report.Assumptions = "both committed source schedules remain valid for the directional attempt"
		primary, err := CollisionProbabilityWithoutReplacement(uint64(len(model.PredictedSourcePorts)), uint64(len(model.PredictedSourcePorts)), 1)
		if err != nil {
			return report, err
		}
		report.Primary, report.FullRangeBaseline = primary, primary
	case ResourceAsymmetric:
		report.Model = string(ProfileAsymmetricBirthday)
		report.Universe = shape.universe.Name
		report.Assumptions = "EDM mappings are uniform without replacement and the opposite mapping is reusable"
		primary, err := CollisionProbabilityWithoutReplacement(65535, 128, 512)
		if err != nil {
			return report, err
		}
		report.Primary, report.FullRangeBaseline = primary, primary
	default:
		return report, ErrUnsupportedProfile
	}
	approximation, err := PoissonApproximation(report.Primary.Universe, report.Primary.LeftDraws, report.Primary.RightDraws)
	if err != nil {
		return report, err
	}
	delta, err := ApproximationDelta(report.Primary, approximation)
	if err != nil {
		return report, err
	}
	report.PoissonApproximation, report.ApproximationDelta = approximation, delta
	return report, nil
}

func probabilityForHardShape(profile Profile, resource ResourceClass, coverage string, shape planShape) (ProbabilityReport, error) {
	key := hardProbabilityCacheKey{profile: profile, resource: resource, universe: shape.universe, candidates: shape.candidates}
	entryValue, _ := hardProbabilityCache.LoadOrStore(key, &hardProbabilityCacheValue{})
	entry := entryValue.(*hardProbabilityCacheValue)
	entry.once.Do(func() {
		report := ProbabilityReport{
			Model:         string(ProfileHardBirthday),
			Universe:      shape.universe.Name,
			Assumptions:   "public mappings remain uniformly inside the compiled 49152-65535 model universe",
			Conditional:   true,
			ModelCoverage: "",
		}
		q := uint64(shape.candidates)
		fullUniverse, err := checkedProduct(65535, 65535)
		if err == nil {
			var conditionalUniverse uint64
			conditionalUniverse, err = checkedProduct(DynamicPortCount, DynamicPortCount)
			if err == nil {
				report.Primary, err = CollisionProbabilityWithoutReplacement(conditionalUniverse, q, q)
			}
		}
		if err == nil {
			report.FullRangeBaseline, err = CollisionProbabilityWithoutReplacement(fullUniverse, q, q)
		}
		if err == nil {
			report.PoissonApproximation, err = PoissonApproximation(report.Primary.Universe, report.Primary.LeftDraws, report.Primary.RightDraws)
		}
		if err == nil {
			report.ApproximationDelta, err = ApproximationDelta(report.Primary, report.PoissonApproximation)
		}
		entry.report, entry.err = report, err
	})
	report := entry.report
	report.ModelCoverage = coverage
	return report, entry.err
}

func probabilityAdmitted(resource ResourceClass, report ProbabilityReport) bool {
	switch resource {
	case ResourcePredictive:
		return report.Primary.FloorPartsPerTrillion == ProbabilityScale
	case ResourceAsymmetric:
		return report.Primary.FloorPartsPerTrillion >= minimumAsymmetricPPTrillion
	case ResourceHard16KLab:
		return report.FullRangeBaseline.FloorPartsPerTrillion >= minimumHard16FullPPTrillion
	case ResourceHard32KCandidate:
		return report.FullRangeBaseline.FloorPartsPerTrillion >= minimumHard32FullPPTrillion
	default:
		return false
	}
}

func sourceSlotsFor(resource ResourceClass, role Role, model StateModel, endpoint AddressPort) ([]SourceSlot, error) {
	switch resource {
	case ResourcePredictive:
		result := make([]SourceSlot, len(model.PredictedSourcePorts))
		for ordinal, port := range model.PredictedSourcePorts {
			if port == 0 {
				return nil, ErrEvidenceInsufficient
			}
			result[ordinal] = SourceSlot{SocketSlot: uint16(ordinal % 8), Ordinal: uint32(ordinal), ExpectedPublicSourcePort: port}
		}
		return result, nil
	case ResourceAsymmetric:
		if role == RoleMappingSet {
			result := make([]SourceSlot, 128)
			for ordinal := range result {
				result[ordinal] = SourceSlot{SocketSlot: uint16(ordinal), Ordinal: uint32(ordinal)}
			}
			return result, nil
		}
		if role == RoleTargetSet && endpoint.Valid() {
			return []SourceSlot{{
				SocketSlot: model.ReusableEndpointSlot, Ordinal: 0, ExpectedPublicSourcePort: endpoint.Port,
			}}, nil
		}
	case ResourceHard16KLab:
		result := make([]SourceSlot, 16)
		for index := range result {
			result[index] = SourceSlot{SocketSlot: uint16(index), Ordinal: uint32(index)}
		}
		return result, nil
	case ResourceHard32KCandidate:
		result := make([]SourceSlot, 32)
		for index := range result {
			result[index] = SourceSlot{SocketSlot: uint16(index), Ordinal: uint32(index)}
		}
		return result, nil
	}
	return nil, ErrUnsupportedProfile
}

func canonicalCommitments(left, right LocalSourceCommitment) (LocalSourceCommitment, LocalSourceCommitment, error) {
	if left.Profile != right.Profile || left.ResourceClass != right.ResourceClass || left.AttemptDigest != right.AttemptDigest ||
		left.Generation != right.Generation || left.Generation == 0 || allZero(left.AttemptDigest[:]) {
		return LocalSourceCommitment{}, LocalSourceCommitment{}, ErrPlanMismatch
	}
	var firstRole, secondRole Role
	switch left.Profile {
	case ProfilePredictiveEdm, ProfileHardBirthday:
		firstRole, secondRole = RoleInitiator, RoleResponder
	case ProfileAsymmetricBirthday:
		firstRole, secondRole = RoleMappingSet, RoleTargetSet
	default:
		return LocalSourceCommitment{}, LocalSourceCommitment{}, ErrUnsupportedProfile
	}
	if left.Role == firstRole && right.Role == secondRole {
		return left.Clone(), right.Clone(), nil
	}
	if right.Role == firstRole && left.Role == secondRole {
		return right.Clone(), left.Clone(), nil
	}
	return LocalSourceCommitment{}, LocalSourceCommitment{}, ErrPlanMismatch
}

func validateLocalCommitment(commitment LocalSourceCommitment) error {
	if err := validateRole(commitment.Profile, commitment.Role); err != nil {
		return err
	}
	if err := validateReceiveEndpoint(commitment.Profile, commitment.Role, commitment.ReceiveEndpoint); err != nil {
		return err
	}
	shape, err := shapeForCommitment(commitment)
	if err != nil {
		return err
	}
	probability, err := probabilityForCommitment(commitment, shape)
	if err != nil {
		return err
	}
	if commitment.Cost != shape.cost || commitment.Universe != shape.universe || commitment.Executable != shape.executable ||
		commitment.CostDigest != digestCost(commitment.Profile, commitment.ResourceClass, commitment.Cost) ||
		allZero(commitment.EvidenceDigest[:]) || allZero(commitment.ValidationDigest[:]) ||
		commitment.SourceDigest != digestSourceCommitment(commitment) || commitment.Probability != probability ||
		!probabilityAdmitted(commitment.ResourceClass, commitment.Probability) {
		return ErrPlanMismatch
	}
	if err := validateSourceSlots(commitment); err != nil {
		return err
	}
	return nil
}

// VerifyPlanAgainstCommitment recomputes every local plan binding. The joint
// commitment is expected to have arrived over the authenticated Gate B
// control channel.
func VerifyPlanAgainstCommitment(plan Plan, source LocalSourceCommitment, joint JointPlanCommitment) error {
	if err := validateLocalCommitment(source); err != nil {
		return err
	}
	if !validJointCommitmentShape(joint) || joint.JointDigest != digestJointCommitment(joint) {
		return ErrPlanMismatch
	}
	if joint.Profile != source.Profile || joint.ResourceClass != source.ResourceClass ||
		joint.AttemptDigest != source.AttemptDigest || joint.Generation != source.Generation {
		return ErrPlanMismatch
	}
	if plan.Profile != source.Profile || plan.ResourceClass != source.ResourceClass || plan.Role != source.Role ||
		plan.Generation != source.Generation || plan.Universe != source.Universe || plan.Cost != source.Cost ||
		plan.Probability != source.Probability || plan.EvidenceDigest != source.EvidenceDigest ||
		plan.CostDigest != source.CostDigest || plan.Executable != source.Executable ||
		plan.PlanDigest != digestPlan(plan, source.AttemptDigest) {
		return ErrPlanMismatch
	}
	shape, err := shapeForCommitment(source)
	if err != nil {
		return err
	}
	if err := validatePlanCandidates(plan, source, shape); err != nil {
		return err
	}
	for _, direction := range joint.Directions {
		if direction.Role == plan.Role && direction.SourceDigest == source.SourceDigest && direction.Triple == plan.Digests() {
			return nil
		}
	}
	return ErrPlanMismatch
}

// VerifyExecutablePlanAgainstCommitment is the mandatory pre-I/O check for a
// later executor. Plan-only resource classes cannot pass it.
func VerifyExecutablePlanAgainstCommitment(plan Plan, source LocalSourceCommitment, joint JointPlanCommitment) error {
	if err := VerifyPlanAgainstCommitment(plan, source, joint); err != nil {
		return err
	}
	if !plan.Executable {
		return ErrUnsupportedProfile
	}
	return nil
}

func validatePlanCandidates(plan Plan, source LocalSourceCommitment, shape planShape) error {
	if uint32(len(plan.Candidates)) != shape.candidates {
		return ErrPlanMismatch
	}
	seen := make(map[[2]uint32]struct{}, len(plan.Candidates))
	for index, candidate := range plan.Candidates {
		if candidate.Role != plan.Role || candidate.Ordinal != uint32(index) || candidate.TargetPort == 0 ||
			uint32(candidate.SocketSlot) >= shape.cost.Sockets {
			return ErrPlanMismatch
		}
		key := [2]uint32{uint32(candidate.SocketSlot), uint32(candidate.TargetPort)}
		if _, duplicate := seen[key]; duplicate {
			return ErrPlanMismatch
		}
		seen[key] = struct{}{}
		switch source.ResourceClass {
		case ResourcePredictive:
			if index >= len(source.SourceSlots) || candidate.SocketSlot != source.SourceSlots[index].SocketSlot ||
				candidate.ExpectedSourcePort != source.SourceSlots[index].ExpectedPublicSourcePort {
				return ErrPlanMismatch
			}
		case ResourceAsymmetric:
			if source.Role == RoleMappingSet && candidate.ExpectedSourcePort != 0 {
				return ErrPlanMismatch
			}
			if source.Role == RoleTargetSet && (candidate.SocketSlot != source.SourceSlots[0].SocketSlot ||
				candidate.ExpectedSourcePort != source.ReceiveEndpoint.Port) {
				return ErrPlanMismatch
			}
		case ResourceHard16KLab, ResourceHard32KCandidate:
			if candidate.ExpectedSourcePort != 0 {
				return ErrPlanMismatch
			}
		default:
			return ErrUnsupportedProfile
		}
	}
	return nil
}

func validateSourceSlots(commitment LocalSourceCommitment) error {
	want := 0
	switch commitment.ResourceClass {
	case ResourcePredictive:
		want = PredictiveWindowPorts
	case ResourceAsymmetric:
		want = 128
		if commitment.Role == RoleTargetSet {
			want = 1
		}
	case ResourceHard16KLab:
		want = 16
	case ResourceHard32KCandidate:
		want = 32
	default:
		return ErrUnsupportedProfile
	}
	if len(commitment.SourceSlots) != want {
		return ErrPlanMismatch
	}
	seenPorts := make(map[uint16]struct{}, len(commitment.SourceSlots))
	for index, slot := range commitment.SourceSlots {
		if slot.Ordinal != uint32(index) {
			return ErrPlanMismatch
		}
		switch commitment.ResourceClass {
		case ResourcePredictive:
			if slot.SocketSlot != uint16(index%8) || slot.ExpectedPublicSourcePort == 0 {
				return ErrPlanMismatch
			}
			if _, duplicate := seenPorts[slot.ExpectedPublicSourcePort]; duplicate {
				return ErrPlanMismatch
			}
			seenPorts[slot.ExpectedPublicSourcePort] = struct{}{}
		case ResourceAsymmetric:
			if commitment.Role == RoleMappingSet && (slot.SocketSlot != uint16(index) || slot.ExpectedPublicSourcePort != 0) {
				return ErrPlanMismatch
			}
			if commitment.Role == RoleTargetSet && slot.ExpectedPublicSourcePort != commitment.ReceiveEndpoint.Port {
				return ErrPlanMismatch
			}
			if commitment.Role == RoleTargetSet && uint32(slot.SocketSlot) >= commitment.Cost.Sockets {
				return ErrPlanMismatch
			}
		case ResourceHard16KLab, ResourceHard32KCandidate:
			if slot.SocketSlot != uint16(index) || slot.ExpectedPublicSourcePort != 0 {
				return ErrPlanMismatch
			}
		}
	}
	return nil
}

func buildDirectionalCandidates(local, peer LocalSourceCommitment, key [32]byte) ([]Candidate, error) {
	switch local.ResourceClass {
	case ResourcePredictive:
		permutation := make([]uint16, len(peer.SourceSlots))
		for index := range permutation {
			permutation[index] = uint16(index)
		}
		shuffleUint16(key, "predictive-bilateral-pairing\x00initiator\x00responder", permutation)
		if local.Role == RoleResponder {
			inverse := make([]uint16, len(permutation))
			for index, target := range permutation {
				inverse[target] = uint16(index)
			}
			clear(permutation)
			permutation = inverse
		}
		result := make([]Candidate, len(local.SourceSlots))
		for ordinal, slot := range local.SourceSlots {
			result[ordinal] = Candidate{
				Role: local.Role, SocketSlot: slot.SocketSlot, Ordinal: uint32(ordinal), ExpectedSourcePort: slot.ExpectedPublicSourcePort,
				TargetPort: peer.SourceSlots[permutation[ordinal]].ExpectedPublicSourcePort,
			}
		}
		clear(permutation)
		return result, nil
	case ResourceAsymmetric:
		if local.Role == RoleMappingSet {
			if !peer.ReceiveEndpoint.Valid() {
				return nil, ErrPlanMismatch
			}
			slots := make([]uint16, len(local.SourceSlots))
			for index, slot := range local.SourceSlots {
				slots[index] = slot.SocketSlot
			}
			shuffleUint16(key, string(local.Role)+"\x00mapping-slots", slots)
			result := make([]Candidate, len(slots))
			for ordinal, slot := range slots {
				result[ordinal] = Candidate{Role: local.Role, SocketSlot: slot, Ordinal: uint32(ordinal), TargetPort: peer.ReceiveEndpoint.Port}
			}
			clear(slots)
			return result, nil
		}
		ports := portRange(1, 65535)
		shuffleUint16(key, string(local.Role)+"\x00target-ports", ports)
		ports = ports[:512]
		result := make([]Candidate, len(ports))
		for ordinal, port := range ports {
			result[ordinal] = Candidate{
				Role: local.Role, SocketSlot: local.SourceSlots[0].SocketSlot, Ordinal: uint32(ordinal),
				ExpectedSourcePort: local.ReceiveEndpoint.Port, TargetPort: port,
			}
		}
		clear(ports)
		return result, nil
	case ResourceHard16KLab:
		ports := portRange(DynamicPortMin, DynamicPortMax)
		shuffleUint16(key, string(local.Role)+"\x00hard-16k", ports)
		result := make([]Candidate, len(ports))
		for ordinal, port := range ports {
			result[ordinal] = Candidate{Role: local.Role, SocketSlot: uint16(ordinal / 1024), Ordinal: uint32(ordinal), TargetPort: port}
		}
		clear(ports)
		return result, nil
	case ResourceHard32KCandidate:
		ports := portRange(DynamicPortMin, DynamicPortMax)
		shuffleUint16(key, string(local.Role)+"\x00hard-32k", ports)
		result := make([]Candidate, 0, 32_768)
		for round := 0; round < 2; round++ {
			for index, port := range ports {
				ordinal := round*len(ports) + index
				result = append(result, Candidate{Role: local.Role, SocketSlot: uint16(ordinal / 1024), Ordinal: uint32(ordinal), TargetPort: port})
			}
		}
		clear(ports)
		return result, nil
	default:
		return nil, ErrUnsupportedProfile
	}
}

func portRange(minimum, maximum uint16) []uint16 {
	result := make([]uint16, int(maximum)-int(minimum)+1)
	for index := range result {
		result[index] = uint16(int(minimum) + index)
	}
	return result
}

// shuffleUint16 is a keyed Fisher-Yates permutation. Each draw uses
// HMAC-SHA256(label || domain || i || rejection-counter); rejection sampling
// removes modulo bias and freezes a cross-language PRP construction.
func shuffleUint16(key [32]byte, domain string, values []uint16) {
	for index := len(values) - 1; index > 0; index-- {
		selected := prfIndex(key, domain, uint32(index), uint64(index+1))
		values[index], values[selected] = values[selected], values[index]
	}
}

func prfIndex(key [32]byte, domain string, ordinal uint32, bound uint64) int {
	threshold := -bound % bound
	for counter := uint32(0); ; counter++ {
		mac := hmac.New(sha256.New, key[:])
		mac.Write([]byte(prpEncodingLabel))
		var encoded bytes.Buffer
		appendString(&encoded, domain)
		appendUint32(&encoded, ordinal)
		appendUint32(&encoded, counter)
		mac.Write(encoded.Bytes())
		digest := mac.Sum(nil)
		value := binary.BigEndian.Uint64(digest[:8])
		clear(digest)
		if value >= threshold {
			return int(value % bound)
		}
	}
}

func digestCost(profile Profile, resource ResourceClass, cost Cost) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString(costEncodingLabel)
	appendString(&encoded, string(profile))
	appendString(&encoded, string(resource))
	appendUint32(&encoded, cost.Sockets)
	appendUint32(&encoded, cost.Targets)
	appendUint32(&encoded, cost.FiveTuples)
	appendUint32(&encoded, cost.Packets)
	appendUint32(&encoded, cost.PacketsPerSecond)
	appendUint32(&encoded, cost.ActiveMillis)
	return sha256.Sum256(encoded.Bytes())
}

func digestSourceCommitment(commitment LocalSourceCommitment) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString(sourceEncodingLabel)
	appendString(&encoded, string(commitment.Profile))
	appendString(&encoded, string(commitment.ResourceClass))
	appendString(&encoded, string(commitment.Role))
	encoded.Write(commitment.AttemptDigest[:])
	appendUint64(&encoded, commitment.Generation)
	appendString(&encoded, commitment.Universe.Name)
	appendUint16(&encoded, commitment.Universe.Min)
	appendUint16(&encoded, commitment.Universe.Max)
	appendUint32(&encoded, commitment.Universe.Count)
	appendAddress(&encoded, commitment.ReceiveEndpoint.Address)
	appendUint16(&encoded, commitment.ReceiveEndpoint.Port)
	encoded.Write(commitment.EvidenceDigest[:])
	encoded.Write(commitment.ValidationDigest[:])
	encoded.Write(commitment.CostDigest[:])
	appendProbabilityReport(&encoded, commitment.Probability)
	if commitment.Executable {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	appendUint32(&encoded, uint32(len(commitment.SourceSlots)))
	for _, slot := range commitment.SourceSlots {
		appendUint16(&encoded, slot.SocketSlot)
		appendUint32(&encoded, slot.Ordinal)
		appendUint16(&encoded, slot.ExpectedPublicSourcePort)
	}
	return sha256.Sum256(encoded.Bytes())
}

func digestPlan(plan Plan, attemptDigest [32]byte) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString(planEncodingLabel)
	appendString(&encoded, string(plan.Profile))
	appendString(&encoded, string(plan.ResourceClass))
	appendString(&encoded, string(plan.Role))
	encoded.Write(attemptDigest[:])
	appendUint64(&encoded, plan.Generation)
	appendString(&encoded, plan.Universe.Name)
	appendUint16(&encoded, plan.Universe.Min)
	appendUint16(&encoded, plan.Universe.Max)
	appendUint32(&encoded, plan.Universe.Count)
	encoded.Write(plan.EvidenceDigest[:])
	encoded.Write(plan.CostDigest[:])
	appendProbabilityReport(&encoded, plan.Probability)
	if plan.Executable {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	appendUint32(&encoded, uint32(len(plan.Candidates)))
	for _, candidate := range plan.Candidates {
		appendString(&encoded, string(candidate.Role))
		appendUint16(&encoded, candidate.SocketSlot)
		appendUint32(&encoded, candidate.Ordinal)
		appendUint16(&encoded, candidate.ExpectedSourcePort)
		appendUint16(&encoded, candidate.TargetPort)
	}
	return sha256.Sum256(encoded.Bytes())
}

func appendProbabilityReport(encoded *bytes.Buffer, report ProbabilityReport) {
	appendString(encoded, report.Model)
	appendString(encoded, report.Universe)
	appendString(encoded, report.Assumptions)
	if report.Conditional {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	appendString(encoded, report.ModelCoverage)
	appendProbability(encoded, report.Primary)
	appendProbability(encoded, report.FullRangeBaseline)
	appendString(encoded, report.PoissonApproximation)
	appendString(encoded, report.ApproximationDelta)
}

func appendProbability(encoded *bytes.Buffer, probability Probability) {
	appendUint64(encoded, probability.Universe)
	appendUint64(encoded, probability.LeftDraws)
	appendUint64(encoded, probability.RightDraws)
	appendUint64(encoded, uint64(probability.PrecisionBits))
	appendString(encoded, probability.LowerDecimal)
	appendString(encoded, probability.UpperDecimal)
	appendUint64(encoded, probability.FloorPartsPerTrillion)
	appendString(encoded, probability.ExactRational)
}

func digestJointCommitment(commitment JointPlanCommitment) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString(jointEncodingLabel)
	appendString(&encoded, string(commitment.Profile))
	appendString(&encoded, string(commitment.ResourceClass))
	encoded.Write(commitment.AttemptDigest[:])
	appendUint64(&encoded, commitment.Generation)
	for _, direction := range commitment.Directions {
		appendString(&encoded, string(direction.Role))
		encoded.Write(direction.SourceDigest[:])
		encoded.Write(direction.Triple.Plan[:])
		encoded.Write(direction.Triple.Cost[:])
		encoded.Write(direction.Triple.Evidence[:])
	}
	return sha256.Sum256(encoded.Bytes())
}

func clearCandidates(candidates []Candidate) {
	for index := range candidates {
		candidates[index] = Candidate{}
	}
}
