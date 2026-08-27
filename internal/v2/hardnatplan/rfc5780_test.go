package hardnatplan

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func TestRFC5780ChangeRequestCodecGolden(t *testing.T) {
	transaction := syntheticTransaction()
	packet, err := BuildBehaviorBindingRequest(transaction, ChangeRequest{ChangeIP: true, ChangePort: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "000100082112a4420102030405060708090a0b0c0003000400000006"
	if got := hex.EncodeToString(packet); got != want {
		t.Fatalf("CHANGE-REQUEST bytes = %s, want %s", got, want)
	}
	parsedTransaction, change, err := ParseBehaviorBindingRequest(packet)
	if err != nil || parsedTransaction != transaction || !change.ChangeIP || !change.ChangePort {
		t.Fatalf("parsed request = %x/%+v/%v", parsedTransaction, change, err)
	}
}

func TestRFC5780ResponseOriginOtherAddressCodecRoundTrip(t *testing.T) {
	transaction := syntheticTransaction()
	want := BehaviorAttributes{
		Mapped:         AddressPort{Address: syntheticAddress(100).Address(), Port: 50000},
		ResponseOrigin: AddressPort{Address: syntheticAddress(10).Address(), Port: 3478},
		OtherAddress:   AddressPort{Address: syntheticAddress(11).Address(), Port: 3479},
		HasMapped:      true, HasResponseOrigin: true, HasOtherAddress: true,
	}
	packet, err := BuildBehaviorBindingSuccess(transaction, want)
	if err != nil {
		t.Fatal(err)
	}
	attributeTypes := make(map[uint16]bool)
	if err := walkAttributes(packet, func(attributeType uint16, _ []byte) error {
		attributeTypes[attributeType] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !attributeTypes[0x0001] || !attributeTypes[AttributeXORMappedAddress] {
		t.Fatalf("RFC 5780 response attributes = %v, require MAPPED-ADDRESS and XOR-MAPPED-ADDRESS", attributeTypes)
	}
	parsed, err := ParseBehaviorBindingSuccess(packet, transaction)
	if err != nil || parsed != want {
		t.Fatalf("parsed response = %+v/%v, want %+v", parsed, err, want)
	}
	t.Logf("RFC5780 success hex=%s", hex.EncodeToString(packet))

	// Unknown comprehension-optional attributes are ignored after framing.
	packet = appendAttribute(packet, 0x8022, []byte("ok"))
	if parsed, err := ParseBehaviorBindingSuccess(packet, transaction); err != nil || parsed != want {
		t.Fatalf("optional attribute response = %+v/%v", parsed, err)
	}
	packet = appendAttribute(packet[:len(packet)-8], 0x000f, []byte{0, 0, 0, 0})
	if _, err := ParseBehaviorBindingSuccess(packet, transaction); !errors.Is(err, ErrUnsupportedEvidence) {
		t.Fatalf("required attribute error = %v", err)
	}
}

func TestRFC5780RequiresConsistentMappedAndXORMappedAddress(t *testing.T) {
	transaction := syntheticTransaction()
	packet, err := BuildBehaviorBindingSuccess(transaction, BehaviorAttributes{
		Mapped: AddressPort{Address: syntheticAddress(100).Address(), Port: 50000}, HasMapped: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutMapped := append([]byte(nil), packet[:stunHeaderBytes]...)
	withoutMapped = append(withoutMapped, packet[stunHeaderBytes+12:]...)
	binary.BigEndian.PutUint16(withoutMapped[2:4], uint16(len(withoutMapped)-stunHeaderBytes))
	if _, err := ParseBehaviorBindingSuccess(withoutMapped, transaction); !errors.Is(err, ErrUnsupportedEvidence) {
		t.Fatalf("missing MAPPED-ADDRESS error = %v", err)
	}

	inconsistent := append([]byte(nil), packet...)
	// The second 12-byte attribute is XOR-MAPPED-ADDRESS; changing its encoded
	// port preserves framing while making the two mapped forms disagree.
	inconsistent[stunHeaderBytes+12+6] ^= 0x01
	if _, err := ParseBehaviorBindingSuccess(inconsistent, transaction); !errors.Is(err, ErrRFC5780Message) {
		t.Fatalf("inconsistent mapped attributes error = %v", err)
	}
}

func TestRFC5780StateMachineSeparatesMappingAndFiltering(t *testing.T) {
	mappings := []MappingBehavior{MappingEIM, MappingADM, MappingAPDM}
	filterings := []FilteringBehavior{FilteringEIF, FilteringADF, FilteringAPDF}
	for _, mapping := range mappings {
		for _, filtering := range filterings {
			machine := NewRFC5780Machine()
			observations := discoveryStateObservations(mapping, filtering)
			for index, step := range orderedRFC5780Steps {
				var err error
				machine, err = machine.Advance(step, observations[index])
				if err != nil {
					t.Fatalf("%s/%s step %s: %v", mapping, filtering, step, err)
				}
			}
			gotMapping, gotFiltering, err := machine.Result()
			if err != nil || gotMapping != mapping || gotFiltering != filtering {
				t.Errorf("%s/%s result = %s/%s/%v", mapping, filtering, gotMapping, gotFiltering, err)
			}
		}
	}
}

func TestRFC5780TranscriptDerivesBehaviorAndReusableEndpoint(t *testing.T) {
	graph := syntheticEvidence(MappingEIM, FilteringAPDF, apparentlyRandomPorts())
	model, err := inferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	wantEndpoint := AddressPort{Address: graph.Allocation[0].MappedAddress, Port: graph.Allocation[0].MappedPort}
	if model.Mapping != MappingEIM || model.Filtering != FilteringAPDF || model.ReusableEndpoint != wantEndpoint {
		t.Fatalf("derived behavior/endpoint = %s/%s/%+v, want %s/%s/%+v",
			model.Mapping, model.Filtering, model.ReusableEndpoint, MappingEIM, FilteringAPDF, wantEndpoint)
	}

	t.Run("self-asserted RFC classification", func(t *testing.T) {
		forged := graph
		forged.Mapping = append([]MappingEvidence(nil), graph.Mapping...)
		forged.Mapping = append(forged.Mapping, MappingEvidence{
			Meta:     evidenceMeta(forged, 240, SourceRFC5780, OriginLocalTransaction, syntheticAddress(10).Address(), 3478),
			Behavior: MappingAPDM,
		})
		if _, err := InferStateModel(forged, trustedValidation(forged)); !errors.Is(err, ErrInvalidEvidence) {
			t.Fatalf("self-asserted classification error = %v", err)
		}
	})

	t.Run("actual response source mismatch", func(t *testing.T) {
		tampered := graph
		tampered.RFC5780 = []RFC5780Transcript{graph.RFC5780[0].Clone()}
		tampered.RFC5780[0].Exchanges[0].ResponseSource.Port++
		if _, err := InferStateModel(tampered, trustedValidation(graph)); !errors.Is(err, ErrUnsupportedEvidence) {
			t.Fatalf("response-source mismatch error = %v", err)
		}
	})

	t.Run("unwitnessed endpoint", func(t *testing.T) {
		tampered := graph
		tampered.Allocation = append([]AllocationSample(nil), graph.Allocation...)
		tampered.Allocation[0].MappedPort++
		if _, err := InferStateModel(tampered, trustedValidation(tampered)); !errors.Is(err, ErrEvidenceInsufficient) {
			t.Fatalf("unwitnessed endpoint error = %v", err)
		}
	})

	t.Run("nonzero witnessed socket slot", func(t *testing.T) {
		nonzero := graph
		nonzero.RFC5780 = []RFC5780Transcript{graph.RFC5780[0].Clone()}
		nonzero.RFC5780[0].SocketSlot = 7
		nonzero.Allocation = append([]AllocationSample(nil), graph.Allocation...)
		nonzero.Allocation[0].SocketSlot = 7
		nonzero.Allocation[0].Meta.SocketSlot = 7
		input := localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, nonzero)
		commitment, err := BuildLocalCommitment(input)
		if err != nil {
			t.Fatal(err)
		}
		if len(commitment.SourceSlots) != 1 || commitment.SourceSlots[0].SocketSlot != 7 {
			t.Fatalf("nonzero witnessed source slots = %+v", commitment.SourceSlots)
		}
		mappingGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
		mappingCommitment, buildErr := BuildLocalCommitment(
			localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleMappingSet, mappingGraph),
		)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		pair, buildErr := BuildBilateralPlan(BilateralPlannerInput{
			First: mappingCommitment, Second: commitment, KeySource: keySource("nonzero-eim-slot"),
		})
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		plan, ok := pair.PlanForRole(RoleTargetSet)
		if !ok || len(plan.Candidates) == 0 || plan.Candidates[0].SocketSlot != 7 {
			t.Fatalf("nonzero witnessed target plan = %+v", plan)
		}
		if verifyErr := VerifyPlanAgainstCommitment(plan, commitment, pair.Commitment()); verifyErr != nil {
			t.Fatalf("verify nonzero witnessed plan: %v", verifyErr)
		}
	})
}

func TestRFC5780MissingCapabilityAndWrongOrderFailClosed(t *testing.T) {
	machine := NewRFC5780Machine()
	if _, err := machine.Advance(StepOtherAddress, DiscoveryObservation{}); !errors.Is(err, ErrRFC5780Order) {
		t.Fatalf("wrong-order error = %v", err)
	}
	observations := discoveryStateObservations(MappingEIM, FilteringAPDF)
	missingOther := observations[0]
	missingOther.Attributes.OtherAddress = AddressPort{}
	missingOther.Attributes.HasOtherAddress = false
	if _, err := machine.Advance(StepPrimary, missingOther); !errors.Is(err, ErrUnsupportedEvidence) {
		t.Fatalf("missing capability error = %v", err)
	}

	for name, other := range map[string]AddressPort{
		"same address": {Address: syntheticAddress(10).Address(), Port: 3479},
		"same port":    {Address: syntheticAddress(11).Address(), Port: 3478},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := observations[0]
			invalid.Attributes.OtherAddress = other
			invalid.Attributes.HasOtherAddress = true
			if _, err := NewRFC5780Machine().Advance(StepPrimary, invalid); !errors.Is(err, ErrUnsupportedEvidence) {
				t.Fatalf("invalid OTHER-ADDRESS topology error = %v", err)
			}
		})
	}

	advanced, err := NewRFC5780Machine().Advance(StepPrimary, observations[0])
	if err != nil {
		t.Fatal(err)
	}
	wrongSame := observations[1]
	wrongSame.RequestDestination.Port++
	if _, err := advanced.Advance(StepSameAddressOtherPort, wrongSame); !errors.Is(err, ErrUnsupportedEvidence) {
		t.Fatalf("wrong A1:P2 identity error = %v", err)
	}
	advanced, err = advanced.Advance(StepSameAddressOtherPort, observations[1])
	if err != nil {
		t.Fatal(err)
	}
	wrongOther := observations[2]
	wrongOther.ResponseSource.Port++
	if _, err := advanced.Advance(StepOtherAddress, wrongOther); !errors.Is(err, ErrUnsupportedEvidence) {
		t.Fatalf("wrong A2:P1 identity error = %v", err)
	}
}

func TestRFC5780CodecRejectsMalformedVectors(t *testing.T) {
	transaction := syntheticTransaction()
	valid, err := BuildBehaviorBindingRequest(transaction, ChangeRequest{ChangePort: true})
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		valid[:19],
		append([]byte(nil), valid...),
		append([]byte(nil), valid...),
		append([]byte(nil), valid...),
	}
	tests[1][4] ^= 0xff
	tests[2][3]++
	tests[3][27] = 0x08
	for index, packet := range tests {
		if _, _, err := ParseBehaviorBindingRequest(packet); err == nil {
			t.Errorf("malformed vector %d accepted", index)
		}
	}
}

func discoveryMappingObservations(mapping MappingBehavior) (BehaviorAttributes, BehaviorAttributes, BehaviorAttributes) {
	origin := AddressPort{Address: syntheticAddress(10).Address(), Port: 3478}
	sameOrigin := AddressPort{Address: origin.Address, Port: 3479}
	otherAddress := AddressPort{Address: syntheticAddress(11).Address(), Port: 3479}
	otherOrigin := AddressPort{Address: otherAddress.Address, Port: origin.Port}
	mappedA := AddressPort{Address: syntheticAddress(100).Address(), Port: 50000}
	mappedB := mappedA
	mappedC := mappedA
	switch mapping {
	case MappingADM:
		mappedC.Port = 50001
	case MappingAPDM:
		mappedB.Port = 50001
		mappedC.Port = 50002
	}
	primary := BehaviorAttributes{Mapped: mappedA, ResponseOrigin: origin, OtherAddress: otherAddress, HasMapped: true, HasResponseOrigin: true, HasOtherAddress: true}
	same := BehaviorAttributes{Mapped: mappedB, ResponseOrigin: sameOrigin, HasMapped: true, HasResponseOrigin: true}
	other := BehaviorAttributes{Mapped: mappedC, ResponseOrigin: otherOrigin, HasMapped: true, HasResponseOrigin: true}
	return primary, same, other
}

func discoveryStateObservations(mapping MappingBehavior, filtering FilteringBehavior) [RFC5780ExchangeCount]DiscoveryObservation {
	primary, same, other := discoveryMappingObservations(mapping)
	observations := [RFC5780ExchangeCount]DiscoveryObservation{
		{Received: true, Attributes: primary, RequestDestination: primary.ResponseOrigin, ResponseSource: primary.ResponseOrigin},
		{Received: true, Attributes: same, RequestDestination: same.ResponseOrigin, ResponseSource: same.ResponseOrigin},
		{Received: true, Attributes: other, RequestDestination: other.ResponseOrigin, ResponseSource: other.ResponseOrigin},
		{RequestDestination: primary.ResponseOrigin},
		{RequestDestination: primary.ResponseOrigin},
	}
	for index := range observations {
		observations[index].TransactionID = TransactionID{0: byte(index + 1), 11: byte(0xa0 + index)}
	}
	if filtering == FilteringEIF {
		observations[3].Received = true
		observations[3].ResponseSource = primary.OtherAddress
		observations[3].Attributes = BehaviorAttributes{HasResponseOrigin: true, ResponseOrigin: primary.OtherAddress}
	}
	if filtering == FilteringADF {
		origin := AddressPort{Address: primary.ResponseOrigin.Address, Port: primary.OtherAddress.Port}
		observations[4].Received = true
		observations[4].ResponseSource = origin
		observations[4].Attributes = BehaviorAttributes{HasResponseOrigin: true, ResponseOrigin: origin}
	}
	return observations
}

func syntheticTransaction() TransactionID {
	return TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
}

func appendAttribute(packet []byte, attributeType uint16, value []byte) []byte {
	padded := (len(value) + 3) &^ 3
	attribute := make([]byte, 4+padded)
	binary.BigEndian.PutUint16(attribute[0:2], attributeType)
	binary.BigEndian.PutUint16(attribute[2:4], uint16(len(value)))
	copy(attribute[4:], value)
	result := append(append([]byte(nil), packet...), attribute...)
	binary.BigEndian.PutUint16(result[2:4], uint16(len(result)-stunHeaderBytes))
	return result
}
