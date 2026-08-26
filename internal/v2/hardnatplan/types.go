package hardnatplan

import (
	"errors"
	"fmt"
)

const (
	MinSuccessfulAllocationSamples = 8
	PredictiveWindowPorts          = 32
	MaxMonotonicDelta              = 32
	// MaxMonotonicDeltaSpread is the independently reviewable low-dispersion
	// threshold: max(delta)-min(delta) must not exceed four ports.
	MaxMonotonicDeltaSpread = 4

	DynamicPortMin   = 49152
	DynamicPortMax   = 65535
	DynamicPortCount = DynamicPortMax - DynamicPortMin + 1

	ProbabilityPrecisionBits = 512
	ProbabilityScale         = uint64(1_000_000_000_000)
)

var (
	ErrInvalidEvidence          = errors.New("hard_nat_evidence_invalid")
	ErrEvidenceInsufficient     = errors.New("hard_nat_evidence_insufficient")
	ErrUnsupportedEvidence      = errors.New("unsupported_evidence")
	ErrUnsupportedProfile       = errors.New("hard_nat_profile_unsupported")
	ErrInsufficientBudget       = errors.New("insufficient_authorized_search_budget")
	ErrInvalidPlannerKey        = errors.New("hard_nat_planner_key_invalid")
	ErrRemoteControlField       = errors.New("hard_nat_remote_control_field_rejected")
	ErrPlanMismatch             = errors.New("hard_nat_plan_mismatch")
	ErrInvalidProbabilityInput  = errors.New("hard_nat_probability_invalid")
	ErrProbabilityInputOverflow = errors.New("hard_nat_probability_overflow")
)

type MappingBehavior string

const (
	MappingUnknown MappingBehavior = "mapping_unknown"
	MappingEIM     MappingBehavior = "eim"
	MappingADM     MappingBehavior = "adm"
	MappingAPDM    MappingBehavior = "apdm"
)

func (behavior MappingBehavior) valid() bool {
	return behavior == MappingEIM || behavior == MappingADM || behavior == MappingAPDM
}

func (behavior MappingBehavior) endpointDependent() bool {
	return behavior == MappingADM || behavior == MappingAPDM
}

type FilteringBehavior string

const (
	FilteringUnknown FilteringBehavior = "filtering_unknown"
	FilteringEIF     FilteringBehavior = "eif"
	FilteringADF     FilteringBehavior = "adf"
	FilteringAPDF    FilteringBehavior = "apdf"
)

func (behavior FilteringBehavior) valid() bool {
	return behavior == FilteringEIF || behavior == FilteringADF || behavior == FilteringAPDF
}

type AllocationBehavior string

const (
	AllocationSequentialUniform   AllocationBehavior = "sequential_uniform"
	AllocationMonotonicNonuniform AllocationBehavior = "monotonic_nonuniform"
	AllocationApparentlyRandom    AllocationBehavior = "apparently_random"
	AllocationInsufficientData    AllocationBehavior = "insufficient_data"
)

type EvidenceSource string

const (
	SourceAuthorizedGateway EvidenceSource = "authorized_gateway"
	SourceRFC5780           EvidenceSource = "rfc5780"
	SourcePeerReflector     EvidenceSource = "peer_reflector"
	SourceLocalTomography   EvidenceSource = "local_tomography"
)

func (source EvidenceSource) strength() int {
	switch source {
	case SourceAuthorizedGateway:
		return 4
	case SourceRFC5780:
		return 3
	case SourcePeerReflector:
		return 2
	case SourceLocalTomography:
		return 1
	default:
		return 0
	}
}

type EvidenceOrigin string

const (
	OriginLocalTransaction EvidenceOrigin = "local_transaction"
	OriginRemoteReport     EvidenceOrigin = "remote_report"
)

type AddressFamily uint8

const (
	AddressFamilyIPv4 AddressFamily = 4
	AddressFamilyIPv6 AddressFamily = 6
)

// Address is an inert canonical address value. IPv4 occupies Bytes[0:4] and
// requires Bytes[4:16] to be zero; IPv6 occupies all sixteen bytes.
type Address struct {
	Family AddressFamily
	Bytes  [16]byte
}

func Address4(value [4]byte) Address {
	var address Address
	address.Family = AddressFamilyIPv4
	copy(address.Bytes[:4], value[:])
	return address
}

func Address6(value [16]byte) Address {
	return Address{Family: AddressFamilyIPv6, Bytes: value}
}

func (address Address) Valid() bool {
	switch address.Family {
	case AddressFamilyIPv4:
		for _, value := range address.Bytes[4:] {
			if value != 0 {
				return false
			}
		}
		return address.Bytes[0]|address.Bytes[1]|address.Bytes[2]|address.Bytes[3] != 0
	case AddressFamilyIPv6:
		var any byte
		for _, value := range address.Bytes {
			any |= value
		}
		return any != 0
	default:
		return false
	}
}

func (address Address) canonicalBytes() []byte {
	length := 16
	if address.Family == AddressFamilyIPv4 {
		length = 4
	}
	result := make([]byte, 1+length)
	result[0] = byte(address.Family)
	copy(result[1:], address.Bytes[:length])
	return result
}

type AddressPort struct {
	Address Address
	Port    uint16
}

func (endpoint AddressPort) Valid() bool {
	return endpoint.Address.Valid() && endpoint.Port != 0
}

type EvidenceMeta struct {
	Source          EvidenceSource
	Origin          EvidenceOrigin
	ObserverAddress Address
	ObserverPort    uint16
	TransactionID   [12]byte
	AttemptDigest   [32]byte
	Generation      uint64
	ObservedAtMilli int64
}

type MappingEvidence struct {
	Meta     EvidenceMeta
	Behavior MappingBehavior
}

type FilteringEvidence struct {
	Meta     EvidenceMeta
	Behavior FilteringBehavior
}

type IPPoolingEvidence struct {
	Meta       EvidenceMeta
	Stable     bool
	PoolDigest [32]byte
}

type AllocationSample struct {
	Meta          EvidenceMeta
	SocketSlot    uint16
	Ordinal       uint32
	MappedAddress Address
	MappedPort    uint16
	Success       bool
}

type EvidenceGraph struct {
	AttemptDigest        [32]byte
	MachineScopeDigest   [32]byte
	PeerDigest           [32]byte
	ObservationSetDigest [32]byte
	SocketOwnerDigest    [32]byte
	Generation           uint64
	StartedAtMilli       int64
	FinishedAtMilli      int64
	ExpiresAtMilli       int64
	Mapping              []MappingEvidence
	Filtering            []FilteringEvidence
	IPPooling            []IPPoolingEvidence
	Allocation           []AllocationSample
}

type StateModel struct {
	Mapping              MappingBehavior
	MappingSource        EvidenceSource
	Filtering            FilteringBehavior
	FilteringSource      EvidenceSource
	Allocation           AllocationBehavior
	PublicAddressStable  bool
	SuccessfulSamples    int
	FailedSamples        int
	ObserverAddressCount int
	HasAlternatePort     bool
	MinimumDelta         uint16
	MaximumDelta         uint16
	PredictedNextPort    uint16
	ResidualUniverse     uint32
	AllocationLimitation string
	CandidateWindow      []uint16
	EvidenceDigest       [32]byte
	RawEvidenceDigest    [32]byte
	ExpiresAtMilli       int64
	Conditional          bool
	Coverage             string
}

func (model StateModel) Clone() StateModel {
	model.CandidateWindow = append([]uint16(nil), model.CandidateWindow...)
	return model
}

type Profile string

const (
	ProfilePredictiveEdm      Profile = "predictive_edm/1"
	ProfileAsymmetricBirthday Profile = "asymmetric_birthday/1"
	ProfileHardBirthday       Profile = "hard_birthday_campaign/1"
)

type ResourceClass string

const (
	ResourcePredictive       ResourceClass = "predictive_32/1"
	ResourceAsymmetric       ResourceClass = "asymmetric_128x512/1"
	ResourceHard16KLab       ResourceClass = "hard_16k_lab/1"
	ResourceHard32KCandidate ResourceClass = "hard_32k_candidate/1"
)

type Role string

const (
	RoleInitiator  Role = "initiator"
	RoleResponder  Role = "responder"
	RoleMappingSet Role = "mapping_set_role"
	RoleTargetSet  Role = "target_set_role"
)

type Cost struct {
	Sockets          uint32 `json:"sockets"`
	Targets          uint32 `json:"targets"`
	FiveTuples       uint32 `json:"five_tuples"`
	Packets          uint32 `json:"packets"`
	PacketsPerSecond uint32 `json:"packets_per_second"`
	ActiveMillis     uint32 `json:"active_millis"`
}

func (budget Cost) admits(cost Cost) bool {
	return budget.Sockets >= cost.Sockets && budget.Targets >= cost.Targets &&
		budget.FiveTuples >= cost.FiveTuples && budget.Packets >= cost.Packets &&
		budget.PacketsPerSecond >= cost.PacketsPerSecond && budget.ActiveMillis >= cost.ActiveMillis
}

type Candidate struct {
	Role       Role   `json:"role"`
	SocketSlot uint16 `json:"socket_slot"`
	Ordinal    uint32 `json:"ordinal"`
	TargetPort uint16 `json:"target_port"`
}

type Universe struct {
	Name  string `json:"name"`
	Min   uint16 `json:"min"`
	Max   uint16 `json:"max"`
	Count uint32 `json:"count,omitempty"`
}

func (universe Universe) Size() uint32 {
	if universe.Count != 0 {
		return universe.Count
	}
	if universe.Min == 0 || universe.Max < universe.Min {
		return 0
	}
	return uint32(universe.Max) - uint32(universe.Min) + 1
}

type ProbabilityReport struct {
	Model                string      `json:"model"`
	Universe             string      `json:"universe"`
	Assumptions          string      `json:"assumptions"`
	Conditional          bool        `json:"conditional"`
	ModelCoverage        string      `json:"model_coverage"`
	Primary              Probability `json:"primary"`
	FullRangeBaseline    Probability `json:"full_range_baseline"`
	PoissonApproximation string      `json:"poisson_approximation"`
	ApproximationDelta   string      `json:"approximation_delta"`
}

type Plan struct {
	Profile        Profile
	ResourceClass  ResourceClass
	Role           Role
	Generation     uint64
	Universe       Universe
	Cost           Cost
	Candidates     []Candidate
	Probability    ProbabilityReport
	EvidenceDigest [32]byte
	CostDigest     [32]byte
	PlanDigest     [32]byte
	Executable     bool
}

func (plan Plan) Clone() Plan {
	plan.Candidates = append([]Candidate(nil), plan.Candidates...)
	return plan
}

type DigestTriple struct {
	Plan     [32]byte
	Cost     [32]byte
	Evidence [32]byte
}

func (plan Plan) Digests() DigestTriple {
	return DigestTriple{Plan: plan.PlanDigest, Cost: plan.CostDigest, Evidence: plan.EvidenceDigest}
}

func VerifyDigestTriple(local, remote DigestTriple) error {
	if local != remote {
		return ErrPlanMismatch
	}
	return nil
}

type AttemptContext struct {
	AttemptDigest [32]byte
	Generation    uint64
	Role          Role
	FixedPeerPort uint16
}

type PlannerKeyContext struct {
	AttemptDigest  [32]byte
	EvidenceDigest [32]byte
	Generation     uint64
	Profile        Profile
	ResourceClass  ResourceClass
	Role           Role
}

// PlannerKeySource is the only planner-key boundary reserved for Gate B2. A
// B2 Noise session will derive this key; B1 has no handshake dependency.
type PlannerKeySource interface {
	DerivePlannerKey(PlannerKeyContext) ([32]byte, error)
}

type PlannerInput struct {
	Profile       Profile
	ResourceClass ResourceClass
	Context       AttemptContext
	Evidence      EvidenceGraph
	Budget        Cost
	KeySource     PlannerKeySource
}

func validateRole(profile Profile, role Role) error {
	switch profile {
	case ProfilePredictiveEdm, ProfileHardBirthday:
		if role == RoleInitiator || role == RoleResponder {
			return nil
		}
	case ProfileAsymmetricBirthday:
		if role == RoleMappingSet || role == RoleTargetSet {
			return nil
		}
	}
	return fmt.Errorf("%w: role %q is invalid for profile %q", ErrUnsupportedProfile, role, profile)
}
