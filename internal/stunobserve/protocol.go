package stunobserve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"winkyou/internal/stunwire"
)

const (
	bindingRequestType  = stunwire.BindingRequestType
	bindingSuccessType  = stunwire.BindingSuccessType
	stunMagicCookie     = stunwire.MagicCookie
	stunHeaderBytes     = stunwire.HeaderBytes
	maxSTUNMessageBytes = 1024

	attributeMappedAddress    uint16 = 0x0001
	attributeMessageIntegrity uint16 = 0x0008
	attributeXORMappedAddress        = stunwire.AttributeXORMappedAddress
)

var (
	ErrMessageTooLarge          = errors.New("stunobserve: message exceeds the hard limit")
	ErrTruncatedMessage         = errors.New("stunobserve: truncated message")
	ErrUnexpectedMessage        = errors.New("stunobserve: unexpected STUN message type")
	ErrMagicCookieMismatch      = errors.New("stunobserve: magic cookie mismatch")
	ErrTransactionMismatch      = errors.New("stunobserve: transaction ID mismatch")
	ErrAttributeLength          = errors.New("stunobserve: invalid attribute length or padding")
	ErrUnknownRequiredAttribute = errors.New("stunobserve: unknown comprehension-required attribute")
	ErrUnsupportedAttribute     = errors.New("stunobserve: attribute is outside the minimal observation profile")
	ErrMappedAddressMissing     = errors.New("stunobserve: mapped address is missing")
	ErrMappedAddressInvalid     = errors.New("stunobserve: mapped address is invalid")
)

type transactionID = stunwire.TransactionID

func newBindingRequest(random io.Reader) ([]byte, transactionID, error) {
	var transaction transactionID
	if random == nil {
		return nil, transaction, fmt.Errorf("stunobserve: random source is unavailable")
	}
	if _, err := io.ReadFull(random, transaction[:]); err != nil {
		return nil, transaction, fmt.Errorf("stunobserve: generate transaction ID: %w", err)
	}
	packet := make([]byte, stunHeaderBytes)
	binary.BigEndian.PutUint16(packet[0:2], bindingRequestType)
	binary.BigEndian.PutUint16(packet[2:4], 0)
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], transaction[:])
	return packet, transaction, nil
}

func parseBindingSuccess(packet []byte, expected transactionID) (netip.AddrPort, string, error) {
	if len(packet) > maxSTUNMessageBytes {
		return netip.AddrPort{}, "", ErrMessageTooLarge
	}
	if len(packet) < stunHeaderBytes {
		return netip.AddrPort{}, "", ErrTruncatedMessage
	}
	if binary.BigEndian.Uint16(packet[0:2]) != bindingSuccessType {
		return netip.AddrPort{}, "", ErrUnexpectedMessage
	}
	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if messageLength%4 != 0 || messageLength != len(packet)-stunHeaderBytes {
		return netip.AddrPort{}, "", ErrAttributeLength
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return netip.AddrPort{}, "", ErrMagicCookieMismatch
	}
	var actual transactionID
	copy(actual[:], packet[8:20])
	if actual != expected {
		return netip.AddrPort{}, "", ErrTransactionMismatch
	}

	var mapped netip.AddrPort
	var xorMapped netip.AddrPort
	for offset := stunHeaderBytes; offset < len(packet); {
		if len(packet)-offset < 4 {
			return netip.AddrPort{}, "", ErrAttributeLength
		}
		attributeType := binary.BigEndian.Uint16(packet[offset : offset+2])
		attributeLength := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		valueStart := offset + 4
		valueEnd := valueStart + attributeLength
		paddedLength := (attributeLength + 3) &^ 3
		paddedEnd := valueStart + paddedLength
		if valueEnd < valueStart || paddedEnd < valueEnd || paddedEnd > len(packet) {
			return netip.AddrPort{}, "", ErrAttributeLength
		}

		switch attributeType {
		case attributeXORMappedAddress:
			if !xorMapped.IsValid() {
				address, err := parseMappedAddress(packet[valueStart:valueEnd], expected, true)
				if err != nil {
					return netip.AddrPort{}, "", err
				}
				xorMapped = address
			}
		case attributeMappedAddress:
			if !mapped.IsValid() {
				address, err := parseMappedAddress(packet[valueStart:valueEnd], expected, false)
				if err != nil {
					return netip.AddrPort{}, "", err
				}
				mapped = address
			}
		case attributeMessageIntegrity:
			return netip.AddrPort{}, "", ErrUnsupportedAttribute
		default:
			if attributeType < 0x8000 {
				return netip.AddrPort{}, "", ErrUnknownRequiredAttribute
			}
		}
		offset = paddedEnd
	}
	if xorMapped.IsValid() {
		return xorMapped, "xor_mapped_address", nil
	}
	if mapped.IsValid() {
		return mapped, "mapped_address", nil
	}
	return netip.AddrPort{}, "", ErrMappedAddressMissing
}

func parseMappedAddress(value []byte, transaction transactionID, xor bool) (netip.AddrPort, error) {
	if len(value) < 4 || value[0] != 0 {
		return netip.AddrPort{}, ErrMappedAddressInvalid
	}
	port := binary.BigEndian.Uint16(value[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	if port == 0 {
		return netip.AddrPort{}, ErrMappedAddressInvalid
	}

	var address netip.Addr
	switch value[1] {
	case 0x01:
		if len(value) != 8 {
			return netip.AddrPort{}, ErrMappedAddressInvalid
		}
		var bytes4 [4]byte
		copy(bytes4[:], value[4:8])
		if xor {
			cookie := [4]byte{}
			binary.BigEndian.PutUint32(cookie[:], stunMagicCookie)
			for i := range bytes4 {
				bytes4[i] ^= cookie[i]
			}
		}
		address = netip.AddrFrom4(bytes4)
	case 0x02:
		if len(value) != 20 {
			return netip.AddrPort{}, ErrMappedAddressInvalid
		}
		var bytes16 [16]byte
		copy(bytes16[:], value[4:20])
		if xor {
			var mask [16]byte
			binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
			copy(mask[4:], transaction[:])
			for i := range bytes16 {
				bytes16[i] ^= mask[i]
			}
		}
		address = netip.AddrFrom16(bytes16)
	default:
		return netip.AddrPort{}, ErrMappedAddressInvalid
	}
	if !address.IsValid() || address.IsUnspecified() {
		return netip.AddrPort{}, ErrMappedAddressInvalid
	}
	return netip.AddrPortFrom(address.Unmap(), port), nil
}
