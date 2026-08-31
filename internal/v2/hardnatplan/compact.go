package hardnatplan

import "fmt"

const MaxModelCoverageBytes = 256

// CompactSourceInput is the minimum authenticated wire material from which a
// peer can independently reconstruct a frozen LocalSourceCommitment. It omits
// deterministic slots, costs, universes and probability fields so a remote
// endpoint cannot supply those execution-control values.
type CompactSourceInput struct {
	Profile           Profile
	ResourceClass     ResourceClass
	Role              Role
	AttemptDigest     [32]byte
	Generation        uint64
	PredictedPorts    []uint16
	ReceiveEndpoint   AddressPort
	ReceiveSocketSlot uint16
	EvidenceDigest    [32]byte
	ValidationDigest  [32]byte
	ModelCoverage     string
}

func ReconstructLocalCommitment(input CompactSourceInput) (LocalSourceCommitment, error) {
	commitment := LocalSourceCommitment{
		Profile: input.Profile, ResourceClass: input.ResourceClass, Role: input.Role,
		AttemptDigest: input.AttemptDigest, Generation: input.Generation,
		ReceiveEndpoint: input.ReceiveEndpoint, EvidenceDigest: input.EvidenceDigest,
		ValidationDigest: input.ValidationDigest,
	}
	if input.Generation == 0 || allZero(input.AttemptDigest[:]) || allZero(input.EvidenceDigest[:]) ||
		allZero(input.ValidationDigest[:]) || len(input.ModelCoverage) == 0 || len(input.ModelCoverage) > MaxModelCoverageBytes {
		return commitment, ErrPlanMismatch
	}
	if err := validateRole(input.Profile, input.Role); err != nil {
		return commitment, err
	}
	model := StateModel{Coverage: input.ModelCoverage}
	switch input.ResourceClass {
	case ResourcePredictive:
		if input.Profile != ProfilePredictiveEdm || len(input.PredictedPorts) != PredictiveWindowPorts ||
			input.ReceiveEndpoint != (AddressPort{}) || input.ReceiveSocketSlot != 0 {
			return commitment, ErrPlanMismatch
		}
		model.PredictedSourcePorts = append([]uint16(nil), input.PredictedPorts...)
	case ResourceAsymmetric:
		if input.Profile != ProfileAsymmetricBirthday || len(input.PredictedPorts) != 0 {
			return commitment, ErrPlanMismatch
		}
		if input.Role == RoleTargetSet {
			if !input.ReceiveEndpoint.Valid() {
				return commitment, ErrPlanMismatch
			}
			model.ReusableEndpoint = input.ReceiveEndpoint
			model.ReusableEndpointSlot = input.ReceiveSocketSlot
		} else if input.ReceiveEndpoint != (AddressPort{}) || input.ReceiveSocketSlot != 0 {
			return commitment, ErrPlanMismatch
		}
	case ResourceHard16KLab:
		if input.Profile != ProfileHardBirthday || len(input.PredictedPorts) != 0 ||
			input.ReceiveEndpoint != (AddressPort{}) || input.ReceiveSocketSlot != 0 {
			return commitment, ErrPlanMismatch
		}
	default:
		return commitment, ErrUnsupportedProfile
	}
	shape, err := shapeFor(input.Profile, input.ResourceClass, input.Role, model)
	if err != nil || !shape.executable {
		return commitment, ErrUnsupportedProfile
	}
	commitment.Cost = shape.cost
	commitment.Universe = shape.universe
	commitment.Executable = shape.executable
	commitment.CostDigest = digestCost(input.Profile, input.ResourceClass, shape.cost)
	commitment.Probability, err = probabilityFor(input.Profile, input.ResourceClass, model, shape)
	if err != nil || !probabilityAdmitted(input.ResourceClass, commitment.Probability) {
		return LocalSourceCommitment{}, fmt.Errorf("%w: canonical probability", ErrPlanMismatch)
	}
	commitment.SourceSlots, err = sourceSlotsFor(input.ResourceClass, input.Role, model, input.ReceiveEndpoint)
	if err != nil {
		return LocalSourceCommitment{}, err
	}
	commitment.SourceDigest = digestSourceCommitment(commitment)
	if err := validateLocalCommitment(commitment); err != nil {
		return LocalSourceCommitment{}, err
	}
	return commitment, nil
}

// CompactSourceInputFor returns only the bounded non-deterministic source
// fields required by ReconstructLocalCommitment.
func CompactSourceInputFor(commitment LocalSourceCommitment) (CompactSourceInput, error) {
	if err := validateLocalCommitment(commitment); err != nil {
		return CompactSourceInput{}, err
	}
	input := CompactSourceInput{
		Profile: commitment.Profile, ResourceClass: commitment.ResourceClass, Role: commitment.Role,
		AttemptDigest: commitment.AttemptDigest, Generation: commitment.Generation,
		ReceiveEndpoint: commitment.ReceiveEndpoint, EvidenceDigest: commitment.EvidenceDigest,
		ValidationDigest: commitment.ValidationDigest, ModelCoverage: commitment.Probability.ModelCoverage,
	}
	if commitment.ResourceClass == ResourcePredictive {
		input.PredictedPorts = make([]uint16, len(commitment.SourceSlots))
		for index, slot := range commitment.SourceSlots {
			input.PredictedPorts[index] = slot.ExpectedPublicSourcePort
		}
	}
	if commitment.ResourceClass == ResourceAsymmetric && commitment.Role == RoleTargetSet {
		input.ReceiveSocketSlot = commitment.SourceSlots[0].SocketSlot
	}
	return input, nil
}
