package hardnatplan

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

type goldenCandidate struct {
	Role       Role   `json:"role"`
	SocketSlot uint16 `json:"socket_slot"`
	Ordinal    uint32 `json:"ordinal"`
	TargetPort uint16 `json:"target_port"`
}

type goldenProbabilityRow struct {
	Name                  string `json:"name"`
	Universe              uint64 `json:"universe"`
	Left                  uint64 `json:"left"`
	Right                 uint64 `json:"right"`
	Lower                 string `json:"lower"`
	Upper                 string `json:"upper"`
	FloorPartsPerTrillion uint64 `json:"floor_parts_per_trillion"`
	PoissonApproximation  string `json:"poisson_approximation"`
	ApproximationDelta    string `json:"approximation_delta"`
}

type goldenProbabilityError struct {
	Name       string `json:"name"`
	Universe   uint64 `json:"universe"`
	Left       uint64 `json:"left"`
	Right      uint64 `json:"right"`
	ErrorClass string `json:"error_class"`
}

type goldenEvidenceBindings struct {
	AttemptHex        string `json:"attempt_hex"`
	MachineScopeHex   string `json:"machine_scope_hex"`
	PeerHex           string `json:"peer_hex"`
	ObservationSetHex string `json:"observation_set_hex"`
	SocketOwnerHex    string `json:"socket_owner_hex"`
}

type goldenStateModel struct {
	Mapping              MappingBehavior    `json:"mapping"`
	MappingSource        EvidenceSource     `json:"mapping_source"`
	Filtering            FilteringBehavior  `json:"filtering"`
	FilteringSource      EvidenceSource     `json:"filtering_source"`
	Allocation           AllocationBehavior `json:"allocation"`
	PublicAddressStable  bool               `json:"public_address_stable"`
	SuccessfulSamples    int                `json:"successful_samples"`
	FailedSamples        int                `json:"failed_samples"`
	ObserverAddressCount int                `json:"observer_address_count"`
	HasAlternatePort     bool               `json:"has_alternate_port"`
	MinimumDelta         uint16             `json:"minimum_delta"`
	MaximumDelta         uint16             `json:"maximum_delta"`
	PredictedNextPort    uint16             `json:"predicted_next_port"`
	ResidualUniverse     uint32             `json:"residual_universe"`
	AllocationLimitation string             `json:"allocation_limitation"`
	CandidateWindow      []uint16           `json:"candidate_window"`
	EvidenceDigestHex    string             `json:"evidence_digest_hex"`
	RawEvidenceDigestHex string             `json:"raw_evidence_digest_hex"`
	ExpiresAtMilli       int64              `json:"expires_at_milli"`
	Conditional          bool               `json:"conditional"`
	Coverage             string             `json:"coverage"`
}

type hardNATGolden struct {
	Schema                   string                   `json:"schema"`
	ByteOrder                string                   `json:"byte_order"`
	PRPLabelHex              string                   `json:"prp_label_hex"`
	PlannerKeyHex            string                   `json:"planner_key_hex"`
	Profile                  Profile                  `json:"profile"`
	ResourceClass            ResourceClass            `json:"resource_class"`
	Role                     Role                     `json:"role"`
	EvidenceBindings         goldenEvidenceBindings   `json:"evidence_bindings"`
	StateModel               goldenStateModel         `json:"state_model"`
	Universe                 Universe                 `json:"universe"`
	Cost                     Cost                     `json:"cost"`
	FirstCandidates          []goldenCandidate        `json:"first_16_candidates"`
	LastCandidates           []goldenCandidate        `json:"last_16_candidates"`
	EvidenceDigestHex        string                   `json:"evidence_digest_hex"`
	CostDigestHex            string                   `json:"cost_digest_hex"`
	PlanDigestHex            string                   `json:"plan_digest_hex"`
	Probability              ProbabilityReport        `json:"probability"`
	ProbabilityRows          []goldenProbabilityRow   `json:"probability_rows"`
	ProbabilityErrors        []goldenProbabilityError `json:"probability_errors"`
	ChangeRequestHex         string                   `json:"change_request_hex"`
	BehaviorSuccessHex       string                   `json:"behavior_success_hex"`
	MinimumAllocationSamples int                      `json:"minimum_allocation_samples"`
	MonotonicDeltaMaximum    int                      `json:"monotonic_delta_maximum"`
	MonotonicDeltaSpread     int                      `json:"monotonic_delta_spread"`
}

func TestHardNATCrossLanguageGoldenIsByteStable(t *testing.T) {
	payload, err := os.ReadFile("testdata/hardnatplan.synthetic.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.ReplaceAll(string(payload), "\r\n", "\n"))
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var golden hardNATGolden
	if err := decoder.Decode(&golden); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("golden has trailing JSON: %v", err)
	}
	actual := buildHardNATGolden(t)
	if !reflect.DeepEqual(actual, golden) {
		actualPayload, _ := json.MarshalIndent(actual, "", "  ")
		goldenPayload, _ := json.MarshalIndent(golden, "", "  ")
		t.Fatalf("Gate B1 golden changed\nactual:\n%s\ngolden:\n%s", actualPayload, goldenPayload)
	}
}

func buildHardNATGolden(t *testing.T) hardNATGolden {
	t.Helper()
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	model, err := InferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	input := planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph)
	key := syntheticDigest("planner-key:" + string(ProfileHardBirthday) + ":" + string(RoleInitiator))
	input.KeySource = fixedKeySource{key: key}
	plan, err := BuildPlan(input)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]goldenCandidate, 16)
	last := make([]goldenCandidate, 16)
	for index := 0; index < 16; index++ {
		first[index] = goldenCandidate(plan.Candidates[index])
		last[index] = goldenCandidate(plan.Candidates[len(plan.Candidates)-16+index])
	}

	full, _ := checkedProduct(65535, 65535)
	conditional, _ := checkedProduct(DynamicPortCount, DynamicPortCount)
	rows := []struct {
		name        string
		universe    uint64
		left, right uint64
	}{
		{name: "boundary_zero_draw", universe: 65535, left: 0, right: 65535},
		{name: "boundary_one", universe: 1, left: 1, right: 1},
		{name: "boundary_65535", universe: 65535, left: 65535, right: 1},
		{name: "asymmetric_128x512", universe: 65535, left: 128, right: 512},
		{name: "hard_512", universe: full, left: 512, right: 512},
		{name: "hard_2048", universe: full, left: 2048, right: 2048},
		{name: "hard_8192", universe: full, left: 8192, right: 8192},
		{name: "hard_16384", universe: full, left: 16384, right: 16384},
		{name: "hard_32768", universe: full, left: 32768, right: 32768},
		{name: "hard_49152", universe: full, left: 49152, right: 49152},
		{name: "hard_65535", universe: full, left: 65535, right: 65535},
		{name: "conditional_16k", universe: conditional, left: 16384, right: 16384},
		{name: "conditional_32k", universe: conditional, left: 32768, right: 32768},
	}
	probabilityRows := make([]goldenProbabilityRow, 0, len(rows))
	for _, row := range rows {
		probability, err := CollisionProbabilityWithoutReplacement(row.universe, row.left, row.right)
		if err != nil {
			t.Fatal(err)
		}
		approximation, err := PoissonApproximation(row.universe, row.left, row.right)
		if err != nil {
			t.Fatal(err)
		}
		delta, err := ApproximationDelta(probability, approximation)
		if err != nil {
			t.Fatal(err)
		}
		probabilityRows = append(probabilityRows, goldenProbabilityRow{
			Name: row.name, Universe: row.universe, Left: row.left, Right: row.right,
			Lower: probability.LowerDecimal, Upper: probability.UpperDecimal, FloorPartsPerTrillion: probability.FloorPartsPerTrillion,
			PoissonApproximation: approximation, ApproximationDelta: delta,
		})
	}

	transaction := syntheticTransaction()
	changeRequest, err := BuildBehaviorBindingRequest(transaction, ChangeRequest{ChangeIP: true, ChangePort: true})
	if err != nil {
		t.Fatal(err)
	}
	behaviorSuccess, err := BuildBehaviorBindingSuccess(transaction, BehaviorAttributes{
		Mapped:         AddressPort{Address: syntheticAddress(100).Address(), Port: 50000},
		ResponseOrigin: AddressPort{Address: syntheticAddress(10).Address(), Port: 3478},
		OtherAddress:   AddressPort{Address: syntheticAddress(11).Address(), Port: 3479},
		HasMapped:      true, HasResponseOrigin: true, HasOtherAddress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return hardNATGolden{
		Schema: "winkyou-hardnatplan-golden/1", ByteOrder: "big-endian", PRPLabelHex: hex.EncodeToString([]byte(prpEncodingLabel)),
		PlannerKeyHex: hex.EncodeToString(key[:]), Profile: plan.Profile, ResourceClass: plan.ResourceClass, Role: plan.Role,
		EvidenceBindings: goldenEvidenceBindings{
			AttemptHex: hex.EncodeToString(graph.AttemptDigest[:]), MachineScopeHex: hex.EncodeToString(graph.MachineScopeDigest[:]),
			PeerHex: hex.EncodeToString(graph.PeerDigest[:]), ObservationSetHex: hex.EncodeToString(graph.ObservationSetDigest[:]),
			SocketOwnerHex: hex.EncodeToString(graph.SocketOwnerDigest[:]),
		},
		StateModel: goldenStateModel{
			Mapping: model.Mapping, MappingSource: model.MappingSource, Filtering: model.Filtering, FilteringSource: model.FilteringSource,
			Allocation: model.Allocation, PublicAddressStable: model.PublicAddressStable, SuccessfulSamples: model.SuccessfulSamples,
			FailedSamples: model.FailedSamples, ObserverAddressCount: model.ObserverAddressCount, HasAlternatePort: model.HasAlternatePort,
			MinimumDelta: model.MinimumDelta, MaximumDelta: model.MaximumDelta, PredictedNextPort: model.PredictedNextPort,
			ResidualUniverse: model.ResidualUniverse, AllocationLimitation: model.AllocationLimitation,
			CandidateWindow: append([]uint16{}, model.CandidateWindow...), EvidenceDigestHex: hex.EncodeToString(model.EvidenceDigest[:]),
			RawEvidenceDigestHex: hex.EncodeToString(model.RawEvidenceDigest[:]), ExpiresAtMilli: model.ExpiresAtMilli,
			Conditional: model.Conditional, Coverage: model.Coverage,
		},
		Universe: plan.Universe, Cost: plan.Cost, FirstCandidates: first, LastCandidates: last,
		EvidenceDigestHex: hex.EncodeToString(plan.EvidenceDigest[:]), CostDigestHex: hex.EncodeToString(plan.CostDigest[:]), PlanDigestHex: hex.EncodeToString(plan.PlanDigest[:]),
		Probability: plan.Probability, ProbabilityRows: probabilityRows,
		ProbabilityErrors: []goldenProbabilityError{
			{Name: "zero_universe", Universe: 0, Left: 0, Right: 0, ErrorClass: ErrInvalidProbabilityInput.Error()},
			{Name: "sum_overflow", Universe: ^uint64(0), Left: ^uint64(0), Right: 1, ErrorClass: ErrProbabilityInputOverflow.Error()},
		},
		ChangeRequestHex: hex.EncodeToString(changeRequest), BehaviorSuccessHex: hex.EncodeToString(behaviorSuccess),
		MinimumAllocationSamples: MinSuccessfulAllocationSamples, MonotonicDeltaMaximum: MaxMonotonicDelta, MonotonicDeltaSpread: MaxMonotonicDeltaSpread,
	}
}
