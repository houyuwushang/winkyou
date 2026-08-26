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

func TestRFC5780StateMachineSeparatesMappingAndFiltering(t *testing.T) {
	mappings := []MappingBehavior{MappingEIM, MappingADM, MappingAPDM}
	filterings := []FilteringBehavior{FilteringEIF, FilteringADF, FilteringAPDF}
	for _, mapping := range mappings {
		for _, filtering := range filterings {
			machine := NewRFC5780Machine()
			primary, sameAddress, otherAddress := discoveryMappingObservations(mapping)
			var err error
			machine, err = machine.Advance(StepPrimary, DiscoveryObservation{Received: true, Attributes: primary})
			if err != nil {
				t.Fatalf("%s/%s primary: %v", mapping, filtering, err)
			}
			machine, err = machine.Advance(StepSameAddressOtherPort, DiscoveryObservation{Received: true, Attributes: sameAddress})
			if err != nil {
				t.Fatalf("%s/%s same address: %v", mapping, filtering, err)
			}
			machine, err = machine.Advance(StepOtherAddress, DiscoveryObservation{Received: true, Attributes: otherAddress})
			if err != nil {
				t.Fatalf("%s/%s other address: %v", mapping, filtering, err)
			}
			changeIP := DiscoveryObservation{}
			if filtering == FilteringEIF {
				changeIP = DiscoveryObservation{Received: true, Attributes: BehaviorAttributes{HasResponseOrigin: true, ResponseOrigin: primary.OtherAddress}}
			}
			machine, err = machine.Advance(StepChangeIPPort, changeIP)
			if err != nil {
				t.Fatalf("%s/%s change IP: %v", mapping, filtering, err)
			}
			changePort := DiscoveryObservation{}
			if filtering == FilteringADF {
				changePort = DiscoveryObservation{Received: true, Attributes: BehaviorAttributes{
					HasResponseOrigin: true,
					ResponseOrigin:    AddressPort{Address: primary.ResponseOrigin.Address, Port: primary.ResponseOrigin.Port + 1},
				}}
			}
			machine, err = machine.Advance(StepChangePort, changePort)
			if err != nil {
				t.Fatalf("%s/%s change port: %v", mapping, filtering, err)
			}
			gotMapping, gotFiltering, err := machine.Result()
			if err != nil || gotMapping != mapping || gotFiltering != filtering {
				t.Errorf("%s/%s result = %s/%s/%v", mapping, filtering, gotMapping, gotFiltering, err)
			}
		}
	}
}

func TestRFC5780MissingCapabilityAndWrongOrderFailClosed(t *testing.T) {
	machine := NewRFC5780Machine()
	if _, err := machine.Advance(StepOtherAddress, DiscoveryObservation{}); !errors.Is(err, ErrRFC5780Order) {
		t.Fatalf("wrong-order error = %v", err)
	}
	primary := BehaviorAttributes{
		Mapped: AddressPort{Address: syntheticAddress(100).Address(), Port: 50000}, HasMapped: true,
		ResponseOrigin: AddressPort{Address: syntheticAddress(10).Address(), Port: 3478}, HasResponseOrigin: true,
		// OTHER-ADDRESS deliberately absent.
	}
	if _, err := machine.Advance(StepPrimary, DiscoveryObservation{Received: true, Attributes: primary}); !errors.Is(err, ErrUnsupportedEvidence) {
		t.Fatalf("missing capability error = %v", err)
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
	otherOrigin := AddressPort{Address: syntheticAddress(11).Address(), Port: 3479}
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
	primary := BehaviorAttributes{Mapped: mappedA, ResponseOrigin: origin, OtherAddress: otherOrigin, HasMapped: true, HasResponseOrigin: true, HasOtherAddress: true}
	same := BehaviorAttributes{Mapped: mappedB, ResponseOrigin: sameOrigin, HasMapped: true, HasResponseOrigin: true}
	other := BehaviorAttributes{Mapped: mappedC, ResponseOrigin: otherOrigin, HasMapped: true, HasResponseOrigin: true}
	return primary, same, other
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
