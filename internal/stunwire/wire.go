package stunwire

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	BindingRequestType        uint16 = 0x0001
	BindingSuccessType        uint16 = 0x0101
	AttributeXORMappedAddress uint16 = 0x0020
	MagicCookie               uint32 = 0x2112a442
	HeaderBytes                      = 20
	MaxRequestBytes                  = 1500
)

var (
	ErrMessageTooLarge          = errors.New("stunwire: message exceeds the hard limit")
	ErrTruncatedMessage         = errors.New("stunwire: truncated message")
	ErrUnexpectedMessage        = errors.New("stunwire: unexpected STUN message type")
	ErrMagicCookieMismatch      = errors.New("stunwire: magic cookie mismatch")
	ErrAttributeLength          = errors.New("stunwire: invalid attribute length or padding")
	ErrUnknownRequiredAttribute = errors.New("stunwire: unknown comprehension-required attribute")
	ErrInvalidMappedEndpoint    = errors.New("stunwire: invalid mapped endpoint")
)

// TransactionID is the RFC 8489 96-bit transaction identifier.
type TransactionID [12]byte

// ParseBindingRequest validates the complete minimal request profile used by
// wink-stund. Comprehension-optional attributes are ignored after their
// framing is validated. Every comprehension-required attribute is rejected:
// this unauthenticated response-only profile implements none of them.
func ParseBindingRequest(packet []byte) (TransactionID, error) {
	var transaction TransactionID
	if len(packet) > MaxRequestBytes {
		return transaction, ErrMessageTooLarge
	}
	if len(packet) < HeaderBytes {
		return transaction, ErrTruncatedMessage
	}
	if binary.BigEndian.Uint16(packet[0:2]) != BindingRequestType {
		return transaction, ErrUnexpectedMessage
	}
	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if messageLength%4 != 0 || messageLength != len(packet)-HeaderBytes {
		return transaction, ErrAttributeLength
	}
	if binary.BigEndian.Uint32(packet[4:8]) != MagicCookie {
		return transaction, ErrMagicCookieMismatch
	}

	for offset := HeaderBytes; offset < len(packet); {
		if len(packet)-offset < 4 {
			return transaction, ErrAttributeLength
		}
		attributeType := binary.BigEndian.Uint16(packet[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		valueStart := offset + 4
		valueEnd := valueStart + attributeLength
		paddedLength := (attributeLength + 3) &^ 3
		paddedEnd := valueStart + paddedLength
		if valueEnd < valueStart || paddedEnd < valueEnd || paddedEnd > len(packet) {
			return transaction, ErrAttributeLength
		}
		if attributeType < 0x8000 {
			return transaction, ErrUnknownRequiredAttribute
		}
		offset = paddedEnd
	}

	copy(transaction[:], packet[8:20])
	return transaction, nil
}

// BindingSuccess constructs one fixed-shape success response containing only
// XOR-MAPPED-ADDRESS. The result is 32 bytes for IPv4 and 44 bytes for IPv6.
func BindingSuccess(transaction TransactionID, mapped netip.AddrPort) ([]byte, error) {
	if !mapped.IsValid() || mapped.Port() == 0 || mapped.Addr().IsUnspecified() || mapped.Addr().IsMulticast() || mapped.Addr().Zone() != "" {
		return nil, ErrInvalidMappedEndpoint
	}
	address := mapped.Addr().Unmap()
	valueLength := 20
	family := byte(0x02)
	if address.Is4() {
		valueLength = 8
		family = 0x01
	}

	response := make([]byte, HeaderBytes+4+valueLength)
	binary.BigEndian.PutUint16(response[0:2], BindingSuccessType)
	binary.BigEndian.PutUint16(response[2:4], uint16(4+valueLength))
	binary.BigEndian.PutUint32(response[4:8], MagicCookie)
	copy(response[8:20], transaction[:])
	binary.BigEndian.PutUint16(response[20:22], AttributeXORMappedAddress)
	binary.BigEndian.PutUint16(response[22:24], uint16(valueLength))
	response[25] = family
	binary.BigEndian.PutUint16(response[26:28], mapped.Port()^uint16(MagicCookie>>16))

	if address.Is4() {
		bytes4 := address.As4()
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], MagicCookie)
		for index := range bytes4 {
			response[28+index] = bytes4[index] ^ cookie[index]
		}
		return response, nil
	}

	bytes16 := address.As16()
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], MagicCookie)
	copy(mask[4:], transaction[:])
	for index := range bytes16 {
		response[28+index] = bytes16[index] ^ mask[index]
	}
	return response, nil
}
