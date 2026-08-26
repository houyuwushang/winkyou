package hardnatplan

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	planEncodingLabel = "winkyou-hardnat-plan-v1\x00"
	costEncodingLabel = "winkyou-hardnat-cost-v1\x00"
	prpEncodingLabel  = "winkyou-hardnat-prp-v1\x00"

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

// BuildPlan performs the Gate B1 pipeline without I/O. Cost is selected and
// digested before a planner key is requested or a candidate slice is created.
// Any evidence, budget, key, profile, or role failure therefore returns zero
// candidates.
func BuildPlan(input PlannerInput) (Plan, error) {
	plan := Plan{Profile: input.Profile, ResourceClass: input.ResourceClass, Role: input.Context.Role, Generation: input.Context.Generation}
	if input.Context.Generation == 0 || allZero(input.Context.AttemptDigest[:]) || input.Context.AttemptDigest != input.Evidence.AttemptDigest ||
		input.Context.Generation != input.Evidence.Generation {
		return plan, ErrInvalidEvidence
	}
	if err := validateRole(input.Profile, input.Context.Role); err != nil {
		return plan, err
	}

	model, err := InferStateModel(input.Evidence)
	plan.EvidenceDigest = model.EvidenceDigest
	if err != nil {
		return plan, err
	}
	if err := validateModelForProfile(input.Profile, input.Context.Role, model); err != nil {
		return plan, err
	}

	shape, err := shapeFor(input.Profile, input.ResourceClass, input.Context.Role, model)
	if err != nil {
		return plan, err
	}
	plan.Cost = shape.cost
	plan.Universe = shape.universe
	plan.Executable = shape.executable
	plan.CostDigest = digestCost(input.Profile, input.ResourceClass, shape.cost)
	plan.Probability, err = probabilityFor(input.Profile, input.ResourceClass, model, shape)
	if err != nil {
		return plan, err
	}
	if !probabilityAdmitted(input.ResourceClass, plan.Probability) {
		return plan, ErrInsufficientBudget
	}
	// The complete frozen cost is admitted before calling the key source or
	// allocating the candidate slice.
	if !input.Budget.admits(shape.cost) {
		return plan, ErrInsufficientBudget
	}
	if input.KeySource == nil {
		return plan, ErrInvalidPlannerKey
	}
	key, err := input.KeySource.DerivePlannerKey(PlannerKeyContext{
		AttemptDigest: input.Context.AttemptDigest, EvidenceDigest: model.EvidenceDigest,
		Generation: input.Context.Generation, Profile: input.Profile, ResourceClass: input.ResourceClass, Role: input.Context.Role,
	})
	if err != nil || allZero(key[:]) {
		clear(key[:])
		return plan, ErrInvalidPlannerKey
	}
	defer clear(key[:])

	candidates, err := buildCandidates(input.Context, input.ResourceClass, model, key)
	if err != nil {
		return plan, err
	}
	if uint32(len(candidates)) != shape.candidates {
		clearCandidates(candidates)
		return plan, fmt.Errorf("%w: candidate shape mismatch", ErrUnsupportedProfile)
	}
	plan.Candidates = candidates
	plan.PlanDigest = digestPlan(plan, input.Context.AttemptDigest)
	return plan, nil
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
			len(model.CandidateWindow) == 0 || len(model.CandidateWindow) > PredictiveWindowPorts {
			return ErrEvidenceInsufficient
		}
	case ProfileAsymmetricBirthday:
		if role == RoleMappingSet && !model.Mapping.endpointDependent() {
			return ErrEvidenceInsufficient
		}
		if role == RoleTargetSet && model.Mapping != MappingEIM {
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

func shapeFor(profile Profile, resource ResourceClass, role Role, model StateModel) (planShape, error) {
	switch {
	case profile == ProfilePredictiveEdm && resource == ResourcePredictive:
		return planShape{
			cost:       Cost{Sockets: 8, Targets: 64, FiveTuples: 64, Packets: 64, PacketsPerSecond: 32, ActiveMillis: 13_000},
			universe:   Universe{Name: "evidence-ranked-window/1", Count: uint32(len(model.CandidateWindow))},
			candidates: uint32(len(model.CandidateWindow)), executable: true,
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
			cost:       Cost{Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512, ActiveMillis: 45_000},
			universe:   Universe{Name: "iana-dynamic-private-49152-65535/1", Min: DynamicPortMin, Max: DynamicPortMax},
			candidates: DynamicPortCount, executable: false,
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

func probabilityFor(profile Profile, resource ResourceClass, model StateModel, shape planShape) (ProbabilityReport, error) {
	report := ProbabilityReport{Conditional: true, ModelCoverage: model.Coverage}
	switch resource {
	case ResourcePredictive:
		report.Model = string(ProfilePredictiveEdm)
		report.Universe = shape.universe.Name
		report.Assumptions = "next allocation remains inside the evidence-derived 32-port window"
		primary, err := CollisionProbabilityWithoutReplacement(uint64(len(model.CandidateWindow)), uint64(len(model.CandidateWindow)), 1)
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
	case ResourceHard16KLab, ResourceHard32KCandidate:
		q := uint64(shape.candidates)
		fullUniverse, err := checkedProduct(65535, 65535)
		if err != nil {
			return report, err
		}
		conditionalUniverse, err := checkedProduct(DynamicPortCount, DynamicPortCount)
		if err != nil {
			return report, err
		}
		primary, err := CollisionProbabilityWithoutReplacement(conditionalUniverse, q, q)
		if err != nil {
			return report, err
		}
		baseline, err := CollisionProbabilityWithoutReplacement(fullUniverse, q, q)
		if err != nil {
			return report, err
		}
		report.Model = string(ProfileHardBirthday)
		report.Universe = shape.universe.Name
		report.Assumptions = "public mappings remain uniformly inside the compiled 49152-65535 model universe"
		report.Primary, report.FullRangeBaseline = primary, baseline
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

func buildCandidates(context AttemptContext, resource ResourceClass, model StateModel, key [32]byte) ([]Candidate, error) {
	switch resource {
	case ResourcePredictive:
		ports := append([]uint16(nil), model.CandidateWindow...)
		shuffleUint16(key, string(context.Role)+"\x00predictive-window", ports)
		result := make([]Candidate, len(ports))
		for ordinal, port := range ports {
			result[ordinal] = Candidate{Role: context.Role, SocketSlot: uint16(ordinal % 8), Ordinal: uint32(ordinal), TargetPort: port}
		}
		clear(ports)
		return result, nil
	case ResourceAsymmetric:
		if context.Role == RoleMappingSet {
			if context.FixedPeerPort == 0 {
				return nil, ErrInvalidEvidence
			}
			slots := make([]uint16, 128)
			for index := range slots {
				slots[index] = uint16(index)
			}
			shuffleUint16(key, string(context.Role)+"\x00mapping-slots", slots)
			result := make([]Candidate, len(slots))
			for ordinal, slot := range slots {
				result[ordinal] = Candidate{Role: context.Role, SocketSlot: slot, Ordinal: uint32(ordinal), TargetPort: context.FixedPeerPort}
			}
			clear(slots)
			return result, nil
		}
		ports := portRange(1, 65535)
		shuffleUint16(key, string(context.Role)+"\x00target-ports", ports)
		ports = ports[:512]
		result := make([]Candidate, len(ports))
		for ordinal, port := range ports {
			result[ordinal] = Candidate{Role: context.Role, SocketSlot: 0, Ordinal: uint32(ordinal), TargetPort: port}
		}
		clear(ports)
		return result, nil
	case ResourceHard16KLab:
		ports := portRange(DynamicPortMin, DynamicPortMax)
		shuffleUint16(key, string(context.Role)+"\x00hard-16k", ports)
		result := make([]Candidate, len(ports))
		for ordinal, port := range ports {
			result[ordinal] = Candidate{Role: context.Role, SocketSlot: uint16(ordinal / 1024), Ordinal: uint32(ordinal), TargetPort: port}
		}
		clear(ports)
		return result, nil
	case ResourceHard32KCandidate:
		ports := portRange(DynamicPortMin, DynamicPortMax)
		shuffleUint16(key, string(context.Role)+"\x00hard-32k", ports)
		result := make([]Candidate, 0, 32_768)
		for round := 0; round < 2; round++ {
			for index, port := range ports {
				ordinal := round*len(ports) + index
				result = append(result, Candidate{Role: context.Role, SocketSlot: uint16(ordinal / 1024), Ordinal: uint32(ordinal), TargetPort: port})
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
	appendUint32(&encoded, plan.Universe.Size())
	encoded.Write(plan.EvidenceDigest[:])
	encoded.Write(plan.CostDigest[:])
	appendString(&encoded, plan.Probability.Model)
	appendString(&encoded, plan.Probability.Universe)
	appendString(&encoded, plan.Probability.Assumptions)
	if plan.Probability.Conditional {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	appendString(&encoded, plan.Probability.ModelCoverage)
	appendString(&encoded, plan.Probability.Primary.LowerDecimal)
	appendString(&encoded, plan.Probability.Primary.UpperDecimal)
	appendUint32(&encoded, uint32(len(plan.Candidates)))
	for _, candidate := range plan.Candidates {
		appendString(&encoded, string(candidate.Role))
		appendUint16(&encoded, candidate.SocketSlot)
		appendUint32(&encoded, candidate.Ordinal)
		appendUint16(&encoded, candidate.TargetPort)
	}
	return sha256.Sum256(encoded.Bytes())
}

func clearCandidates(candidates []Candidate) {
	for index := range candidates {
		candidates[index] = Candidate{}
	}
}
