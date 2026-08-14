package stunobserve

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestBindingRequestUsesExactTransactionAndCookie(t *testing.T) {
	random := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	packet, transaction, err := newBindingRequest(bytes.NewReader(random))
	if err != nil {
		t.Fatalf("new binding request: %v", err)
	}
	if len(packet) != stunHeaderBytes || binary.BigEndian.Uint16(packet[0:2]) != bindingRequestType {
		t.Fatalf("request header = %x", packet)
	}
	if binary.BigEndian.Uint16(packet[2:4]) != 0 || binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		t.Fatalf("request length/cookie = %x", packet[:8])
	}
	if !bytes.Equal(packet[8:20], random) || !bytes.Equal(transaction[:], random) {
		t.Fatalf("transaction = %x, packet = %x", transaction, packet[8:20])
	}
}

func TestBindingRequestRejectsShortRandomInput(t *testing.T) {
	_, _, err := newBindingRequest(bytes.NewReader(make([]byte, len(transactionID{})-1)))
	if err == nil {
		t.Fatal("short random input unexpectedly succeeded")
	}
}

func TestParseBindingSuccessPrefersXORAndToleratesOptionalAttributes(t *testing.T) {
	transaction := transactionID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	fallback := netip.MustParseAddrPort("192.0.2.10:40000")
	preferred := netip.MustParseAddrPort("198.51.100.20:41000")
	packet := bindingSuccess(
		transaction,
		stunAttribute(0x8022, []byte("abc"), []byte{0x7f}),
		stunAttribute(attributeMappedAddress, mappedAddressValue(fallback, transaction, false), nil),
		stunAttribute(attributeXORMappedAddress, mappedAddressValue(preferred, transaction, true), nil),
	)

	got, kind, err := parseBindingSuccess(packet, transaction)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if got != preferred || kind != "xor_mapped_address" {
		t.Fatalf("mapped = %v via %q, want %v via xor", got, kind, preferred)
	}
}

func TestParseBindingSuccessFallsBackToMappedIPv6(t *testing.T) {
	transaction := transactionID{11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	want := netip.MustParseAddrPort("[2001:db8::7]:42000")
	packet := bindingSuccess(
		transaction,
		stunAttribute(attributeMappedAddress, mappedAddressValue(want, transaction, false), nil),
	)
	got, kind, err := parseBindingSuccess(packet, transaction)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if got != want || kind != "mapped_address" {
		t.Fatalf("mapped = %v via %q, want %v via mapped", got, kind, want)
	}
}

func TestParseBindingSuccessRejectsMalformedOrOutOfScopeInput(t *testing.T) {
	transaction := transactionID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	mapped := netip.MustParseAddrPort("192.0.2.20:43000")
	validAttribute := stunAttribute(attributeXORMappedAddress, mappedAddressValue(mapped, transaction, true), nil)
	valid := bindingSuccess(transaction, validAttribute)

	tests := []struct {
		name   string
		packet []byte
		want   error
	}{
		{name: "truncated header", packet: valid[:stunHeaderBytes-1], want: ErrTruncatedMessage},
		{name: "hard size", packet: make([]byte, maxSTUNMessageBytes+1), want: ErrMessageTooLarge},
		{name: "wrong type", packet: mutateCopy(valid, func(packet []byte) { binary.BigEndian.PutUint16(packet[0:2], bindingRequestType) }), want: ErrUnexpectedMessage},
		{name: "wrong cookie", packet: mutateCopy(valid, func(packet []byte) { binary.BigEndian.PutUint32(packet[4:8], 0) }), want: ErrMagicCookieMismatch},
		{name: "wrong transaction", packet: mutateCopy(valid, func(packet []byte) { packet[8] ^= 0xff }), want: ErrTransactionMismatch},
		{name: "declared length mismatch", packet: mutateCopy(valid, func(packet []byte) { binary.BigEndian.PutUint16(packet[2:4], 4) }), want: ErrAttributeLength},
		{name: "truncated attribute value", packet: valid[:len(valid)-1], want: ErrAttributeLength},
		{name: "unknown required", packet: bindingSuccess(transaction, stunAttribute(0x0002, nil, nil)), want: ErrUnknownRequiredAttribute},
		{name: "message integrity out of scope", packet: bindingSuccess(transaction, stunAttribute(attributeMessageIntegrity, make([]byte, 20), nil)), want: ErrUnsupportedAttribute},
		{name: "missing mapping", packet: bindingSuccess(transaction, stunAttribute(0x8022, []byte("ok"), []byte{0, 0})), want: ErrMappedAddressMissing},
		{name: "invalid family", packet: bindingSuccess(transaction, stunAttribute(attributeMappedAddress, []byte{0, 3, 0, 1, 0, 0, 0, 0}, nil)), want: ErrMappedAddressInvalid},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseBindingSuccess(test.packet, transaction)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseBindingSuccessUsesFirstDuplicateMapping(t *testing.T) {
	transaction := transactionID{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	first := netip.MustParseAddrPort("192.0.2.30:44000")
	second := netip.MustParseAddrPort("198.51.100.30:45000")
	packet := bindingSuccess(
		transaction,
		stunAttribute(attributeXORMappedAddress, mappedAddressValue(first, transaction, true), nil),
		stunAttribute(attributeXORMappedAddress, mappedAddressValue(second, transaction, true), nil),
	)
	got, _, err := parseBindingSuccess(packet, transaction)
	if err != nil {
		t.Fatalf("parse duplicate: %v", err)
	}
	if got != first {
		t.Fatalf("mapped = %v, want first occurrence %v", got, first)
	}
}

func bindingSuccess(transaction transactionID, attributes ...[]byte) []byte {
	length := 0
	for _, attribute := range attributes {
		length += len(attribute)
	}
	packet := make([]byte, stunHeaderBytes, stunHeaderBytes+length)
	binary.BigEndian.PutUint16(packet[0:2], bindingSuccessType)
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], transaction[:])
	for _, attribute := range attributes {
		packet = append(packet, attribute...)
	}
	return packet
}

func stunAttribute(attributeType uint16, value, padding []byte) []byte {
	paddedLength := (len(value) + 3) &^ 3
	attribute := make([]byte, 4+paddedLength)
	binary.BigEndian.PutUint16(attribute[0:2], attributeType)
	binary.BigEndian.PutUint16(attribute[2:4], uint16(len(value)))
	copy(attribute[4:], value)
	copy(attribute[4+len(value):], padding)
	return attribute
}

func mappedAddressValue(endpoint netip.AddrPort, transaction transactionID, xor bool) []byte {
	address := endpoint.Addr().Unmap()
	length := 8
	family := byte(0x01)
	if address.Is6() {
		length = 20
		family = 0x02
	}
	value := make([]byte, length)
	value[1] = family
	port := endpoint.Port()
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	binary.BigEndian.PutUint16(value[2:4], port)
	if address.Is4() {
		bytes4 := address.As4()
		copy(value[4:8], bytes4[:])
		if xor {
			cookie := make([]byte, 4)
			binary.BigEndian.PutUint32(cookie, stunMagicCookie)
			for i := 0; i < 4; i++ {
				value[4+i] ^= cookie[i]
			}
		}
		return value
	}
	bytes16 := address.As16()
	copy(value[4:20], bytes16[:])
	if xor {
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[:4], stunMagicCookie)
		copy(mask[4:], transaction[:])
		for i := 0; i < 16; i++ {
			value[4+i] ^= mask[i]
		}
	}
	return value
}

func mutateCopy(source []byte, mutate func([]byte)) []byte {
	result := append([]byte(nil), source...)
	mutate(result)
	return result
}
