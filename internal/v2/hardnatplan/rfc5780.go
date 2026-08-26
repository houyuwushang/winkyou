package hardnatplan

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	stunBindingRequest      uint16 = 0x0001
	stunBindingSuccess      uint16 = 0x0101
	stunMagicCookie         uint32 = 0x2112a442
	stunHeaderBytes                = 20
	maxBehaviorMessageBytes        = 1024

	AttributeChangeRequest    uint16 = 0x0003
	AttributeMappedAddress    uint16 = 0x0001
	AttributeXORMappedAddress uint16 = 0x0020
	AttributeResponseOrigin   uint16 = 0x802b
	AttributeOtherAddress     uint16 = 0x802c
)

var (
	ErrRFC5780Message = errors.New("hardnatplan: invalid RFC 5780 message")
	ErrRFC5780Order   = errors.New("hardnatplan: invalid RFC 5780 state order")
)

type TransactionID [12]byte

type ChangeRequest struct {
	ChangeIP   bool
	ChangePort bool
}

type BehaviorAttributes struct {
	Mapped            AddressPort
	ResponseOrigin    AddressPort
	OtherAddress      AddressPort
	HasMapped         bool
	HasResponseOrigin bool
	HasOtherAddress   bool
}

// BuildBehaviorBindingRequest creates only a Binding Request and optional
// CHANGE-REQUEST attribute. It is a byte codec and performs no I/O.
func BuildBehaviorBindingRequest(transaction TransactionID, change ChangeRequest) ([]byte, error) {
	if allZero(transaction[:]) {
		return nil, ErrRFC5780Message
	}
	length := 0
	if change.ChangeIP || change.ChangePort {
		length = 8
	}
	packet := make([]byte, stunHeaderBytes+length)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], transaction[:])
	if length != 0 {
		binary.BigEndian.PutUint16(packet[20:22], AttributeChangeRequest)
		binary.BigEndian.PutUint16(packet[22:24], 4)
		var flags uint32
		if change.ChangeIP {
			flags |= 0x04
		}
		if change.ChangePort {
			flags |= 0x02
		}
		binary.BigEndian.PutUint32(packet[24:28], flags)
	}
	return packet, nil
}

// ParseBehaviorBindingRequest validates the RFC 5780 request subset and
// returns its transaction and CHANGE-REQUEST flags.
func ParseBehaviorBindingRequest(packet []byte) (TransactionID, ChangeRequest, error) {
	var transaction TransactionID
	var change ChangeRequest
	if err := validateSTUNHeader(packet, stunBindingRequest); err != nil {
		return transaction, change, err
	}
	copy(transaction[:], packet[8:20])
	foundChange := false
	err := walkAttributes(packet, func(attributeType uint16, value []byte) error {
		switch attributeType {
		case AttributeChangeRequest:
			if foundChange || len(value) != 4 {
				return ErrRFC5780Message
			}
			flags := binary.BigEndian.Uint32(value)
			if flags & ^uint32(0x06) != 0 {
				return ErrRFC5780Message
			}
			change = ChangeRequest{ChangeIP: flags&0x04 != 0, ChangePort: flags&0x02 != 0}
			foundChange = true
			return nil
		default:
			if attributeType < 0x8000 {
				return ErrUnsupportedEvidence
			}
			return nil
		}
	})
	return transaction, change, err
}

// ParseBehaviorBindingSuccess extracts the mapped endpoint plus RFC 5780
// RESPONSE-ORIGIN and OTHER-ADDRESS capabilities.
func ParseBehaviorBindingSuccess(packet []byte, expected TransactionID) (BehaviorAttributes, error) {
	var result BehaviorAttributes
	if err := validateSTUNHeader(packet, stunBindingSuccess); err != nil {
		return result, err
	}
	if !bytes.Equal(packet[8:20], expected[:]) {
		return result, ErrRFC5780Message
	}
	var mappedAddress, xorMappedAddress AddressPort
	hasMappedAddress, hasXORMappedAddress := false, false
	err := walkAttributes(packet, func(attributeType uint16, value []byte) error {
		var endpoint AddressPort
		var err error
		switch attributeType {
		case AttributeMappedAddress:
			if hasMappedAddress {
				return ErrRFC5780Message
			}
			mappedAddress, err = decodeSTUNAddress(value, expected, false)
			if err == nil {
				hasMappedAddress = true
			}
			return err
		case AttributeXORMappedAddress:
			if hasXORMappedAddress {
				return ErrRFC5780Message
			}
			xorMappedAddress, err = decodeSTUNAddress(value, expected, true)
			if err == nil {
				hasXORMappedAddress = true
			}
			return err
		case AttributeResponseOrigin:
			if result.HasResponseOrigin {
				return ErrRFC5780Message
			}
			endpoint, err = decodeSTUNAddress(value, expected, false)
			if err == nil {
				result.ResponseOrigin, result.HasResponseOrigin = endpoint, true
			}
			return err
		case AttributeOtherAddress:
			if result.HasOtherAddress {
				return ErrRFC5780Message
			}
			endpoint, err = decodeSTUNAddress(value, expected, false)
			if err == nil {
				result.OtherAddress, result.HasOtherAddress = endpoint, true
			}
			return err
		default:
			if attributeType < 0x8000 {
				return ErrUnsupportedEvidence
			}
			return nil
		}
	})
	if err != nil {
		return result, err
	}
	if !hasMappedAddress || !hasXORMappedAddress {
		return result, ErrUnsupportedEvidence
	}
	if mappedAddress != xorMappedAddress {
		return result, ErrRFC5780Message
	}
	result.Mapped, result.HasMapped = mappedAddress, true
	return result, nil
}

// BuildBehaviorBindingSuccess constructs a synthetic response vector. It is
// intentionally a pure codec helper, not a server or responder.
func BuildBehaviorBindingSuccess(transaction TransactionID, attributes BehaviorAttributes) ([]byte, error) {
	if allZero(transaction[:]) || !attributes.HasMapped || !attributes.Mapped.Valid() {
		return nil, ErrRFC5780Message
	}
	var encoded [][]byte
	mapped, err := encodeSTUNAddress(AttributeMappedAddress, attributes.Mapped, transaction, false)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, mapped)
	xorMapped, err := encodeSTUNAddress(AttributeXORMappedAddress, attributes.Mapped, transaction, true)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, xorMapped)
	if attributes.HasResponseOrigin {
		value, err := encodeSTUNAddress(AttributeResponseOrigin, attributes.ResponseOrigin, transaction, false)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, value)
	}
	if attributes.HasOtherAddress {
		value, err := encodeSTUNAddress(AttributeOtherAddress, attributes.OtherAddress, transaction, false)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, value)
	}
	length := 0
	for _, attribute := range encoded {
		length += len(attribute)
	}
	packet := make([]byte, stunHeaderBytes, stunHeaderBytes+length)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], transaction[:])
	for _, attribute := range encoded {
		packet = append(packet, attribute...)
		clear(attribute)
	}
	return packet, nil
}

func validateSTUNHeader(packet []byte, expectedType uint16) error {
	if len(packet) < stunHeaderBytes || len(packet) > maxBehaviorMessageBytes || binary.BigEndian.Uint16(packet[0:2]) != expectedType ||
		binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return ErrRFC5780Message
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if length%4 != 0 || length != len(packet)-stunHeaderBytes {
		return ErrRFC5780Message
	}
	return nil
}

func walkAttributes(packet []byte, visit func(uint16, []byte) error) error {
	for offset := stunHeaderBytes; offset < len(packet); {
		if len(packet)-offset < 4 {
			return ErrRFC5780Message
		}
		attributeType := binary.BigEndian.Uint16(packet[offset : offset+2])
		length := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		start := offset + 4
		end := start + length
		paddedEnd := start + ((length + 3) &^ 3)
		if end < start || paddedEnd < end || paddedEnd > len(packet) {
			return ErrRFC5780Message
		}
		for _, padding := range packet[end:paddedEnd] {
			if padding != 0 {
				return ErrRFC5780Message
			}
		}
		if err := visit(attributeType, packet[start:end]); err != nil {
			return err
		}
		offset = paddedEnd
	}
	return nil
}

func encodeSTUNAddress(attributeType uint16, endpoint AddressPort, transaction TransactionID, xor bool) ([]byte, error) {
	if !endpoint.Valid() {
		return nil, ErrRFC5780Message
	}
	length := 20
	if endpoint.Address.Family == AddressFamilyIPv4 {
		length = 8
	}
	attribute := make([]byte, 4+length)
	binary.BigEndian.PutUint16(attribute[0:2], attributeType)
	binary.BigEndian.PutUint16(attribute[2:4], uint16(length))
	attribute[5] = 0x01
	if endpoint.Address.Family == AddressFamilyIPv6 {
		attribute[5] = 0x02
	}
	port := endpoint.Port
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	binary.BigEndian.PutUint16(attribute[6:8], port)
	addressLength := 16
	if endpoint.Address.Family == AddressFamilyIPv4 {
		addressLength = 4
	}
	copy(attribute[8:8+addressLength], endpoint.Address.Bytes[:addressLength])
	if xor {
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:], transaction[:])
		for index := 0; index < addressLength; index++ {
			attribute[8+index] ^= mask[index]
		}
	}
	return attribute, nil
}

func decodeSTUNAddress(value []byte, transaction TransactionID, xor bool) (AddressPort, error) {
	var endpoint AddressPort
	if len(value) < 8 || value[0] != 0 {
		return endpoint, ErrRFC5780Message
	}
	port := binary.BigEndian.Uint16(value[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	if port == 0 {
		return endpoint, ErrRFC5780Message
	}
	switch value[1] {
	case 0x01:
		if len(value) != 8 {
			return endpoint, ErrRFC5780Message
		}
		var raw [4]byte
		copy(raw[:], value[4:8])
		if xor {
			var cookie [4]byte
			binary.BigEndian.PutUint32(cookie[:], stunMagicCookie)
			for index := range raw {
				raw[index] ^= cookie[index]
			}
		}
		endpoint.Address = Address4(raw)
	case 0x02:
		if len(value) != 20 {
			return endpoint, ErrRFC5780Message
		}
		var raw [16]byte
		copy(raw[:], value[4:20])
		if xor {
			var mask [16]byte
			binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
			copy(mask[4:], transaction[:])
			for index := range raw {
				raw[index] ^= mask[index]
			}
		}
		endpoint.Address = Address6(raw)
	default:
		return endpoint, ErrRFC5780Message
	}
	endpoint.Port = port
	if !endpoint.Valid() {
		return AddressPort{}, ErrRFC5780Message
	}
	return endpoint, nil
}

type DiscoveryStep string

const (
	StepPrimary              DiscoveryStep = "primary"
	StepSameAddressOtherPort DiscoveryStep = "same_address_other_port"
	StepOtherAddress         DiscoveryStep = "other_address"
	StepChangeIPPort         DiscoveryStep = "change_ip_port"
	StepChangePort           DiscoveryStep = "change_port"
)

type DiscoveryState uint8

const (
	DiscoveryAwaitPrimary DiscoveryState = iota
	DiscoveryAwaitSameAddressOtherPort
	DiscoveryAwaitOtherAddress
	DiscoveryAwaitChangeIPPort
	DiscoveryAwaitChangePort
	DiscoveryComplete
)

type DiscoveryObservation struct {
	Received   bool
	Attributes BehaviorAttributes
}

type RFC5780Machine struct {
	state        DiscoveryState
	primary      BehaviorAttributes
	sameAddress  BehaviorAttributes
	otherAddress BehaviorAttributes
	changeIPPort bool
	changePort   bool
}

func NewRFC5780Machine() RFC5780Machine {
	return RFC5780Machine{state: DiscoveryAwaitPrimary}
}

func (machine RFC5780Machine) State() DiscoveryState { return machine.state }

// Advance returns a new value; callers cannot mutate an accepted prior state.
func (machine RFC5780Machine) Advance(step DiscoveryStep, observation DiscoveryObservation) (RFC5780Machine, error) {
	expected := map[DiscoveryState]DiscoveryStep{
		DiscoveryAwaitPrimary: StepPrimary, DiscoveryAwaitSameAddressOtherPort: StepSameAddressOtherPort,
		DiscoveryAwaitOtherAddress: StepOtherAddress, DiscoveryAwaitChangeIPPort: StepChangeIPPort,
		DiscoveryAwaitChangePort: StepChangePort,
	}[machine.state]
	if step != expected {
		return machine, ErrRFC5780Order
	}
	switch machine.state {
	case DiscoveryAwaitPrimary:
		attributes := observation.Attributes
		if !observation.Received || !attributes.HasMapped || !attributes.HasResponseOrigin || !attributes.HasOtherAddress ||
			!attributes.Mapped.Valid() || !attributes.ResponseOrigin.Valid() || !attributes.OtherAddress.Valid() ||
			attributes.ResponseOrigin.Address == attributes.OtherAddress.Address || attributes.ResponseOrigin.Port == attributes.OtherAddress.Port {
			return machine, ErrUnsupportedEvidence
		}
		machine.primary = attributes
		machine.state = DiscoveryAwaitSameAddressOtherPort
	case DiscoveryAwaitSameAddressOtherPort:
		attributes := observation.Attributes
		if !observation.Received || !attributes.HasMapped || !attributes.HasResponseOrigin || !attributes.Mapped.Valid() ||
			attributes.ResponseOrigin.Address != machine.primary.ResponseOrigin.Address ||
			attributes.ResponseOrigin.Port != machine.primary.OtherAddress.Port {
			return machine, ErrUnsupportedEvidence
		}
		machine.sameAddress = attributes
		machine.state = DiscoveryAwaitOtherAddress
	case DiscoveryAwaitOtherAddress:
		attributes := observation.Attributes
		if !observation.Received || !attributes.HasMapped || !attributes.HasResponseOrigin || !attributes.Mapped.Valid() ||
			attributes.ResponseOrigin.Address != machine.primary.OtherAddress.Address ||
			attributes.ResponseOrigin.Port != machine.primary.ResponseOrigin.Port {
			return machine, ErrUnsupportedEvidence
		}
		machine.otherAddress = attributes
		machine.state = DiscoveryAwaitChangeIPPort
	case DiscoveryAwaitChangeIPPort:
		if observation.Received {
			if !observation.Attributes.HasResponseOrigin || observation.Attributes.ResponseOrigin != machine.primary.OtherAddress {
				return machine, ErrUnsupportedEvidence
			}
			machine.changeIPPort = true
		}
		machine.state = DiscoveryAwaitChangePort
	case DiscoveryAwaitChangePort:
		if observation.Received {
			origin := observation.Attributes.ResponseOrigin
			if !observation.Attributes.HasResponseOrigin || origin.Address != machine.primary.ResponseOrigin.Address ||
				origin.Port != machine.primary.OtherAddress.Port {
				return machine, ErrUnsupportedEvidence
			}
			machine.changePort = true
		}
		machine.state = DiscoveryComplete
	default:
		return machine, ErrRFC5780Order
	}
	return machine, nil
}

func (machine RFC5780Machine) Result() (MappingBehavior, FilteringBehavior, error) {
	if machine.state != DiscoveryComplete {
		return MappingUnknown, FilteringUnknown, ErrRFC5780Order
	}
	mapping := MappingAPDM
	if machine.primary.Mapped == machine.sameAddress.Mapped && machine.primary.Mapped == machine.otherAddress.Mapped {
		mapping = MappingEIM
	} else if machine.primary.Mapped == machine.sameAddress.Mapped && machine.primary.Mapped != machine.otherAddress.Mapped {
		mapping = MappingADM
	}
	filtering := FilteringAPDF
	if machine.changeIPPort {
		filtering = FilteringEIF
	} else if machine.changePort {
		filtering = FilteringADF
	}
	return mapping, filtering, nil
}
