package stunwire

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
)

func TestParseBindingRequestRejectsMalformedMatrix(t *testing.T) {
	transaction := TransactionID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	valid := bindingRequest(transaction)
	tests := []struct {
		name   string
		packet []byte
		want   error
	}{
		{name: "short", packet: valid[:HeaderBytes-1], want: ErrTruncatedMessage},
		{name: "too large", packet: make([]byte, MaxRequestBytes+1), want: ErrMessageTooLarge},
		{name: "wrong type", packet: mutate(valid, func(packet []byte) { binary.BigEndian.PutUint16(packet[0:2], BindingSuccessType) }), want: ErrUnexpectedMessage},
		{name: "wrong cookie", packet: mutate(valid, func(packet []byte) { binary.BigEndian.PutUint32(packet[4:8], 0) }), want: ErrMagicCookieMismatch},
		{name: "declared length mismatch", packet: mutate(valid, func(packet []byte) { binary.BigEndian.PutUint16(packet[2:4], 4) }), want: ErrAttributeLength},
		{name: "truncated attribute header", packet: withRawBody(valid, []byte{0x80, 0x22}), want: ErrAttributeLength},
		{name: "truncated attribute value", packet: withRawBody(valid, []byte{0x80, 0x22, 0x00, 0x04, 0x01, 0x02, 0x03}), want: ErrAttributeLength},
		{name: "unknown required", packet: withAttribute(valid, 0x0002, nil), want: ErrUnknownRequiredAttribute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseBindingRequest(test.packet); !errors.Is(err, test.want) {
				t.Fatalf("ParseBindingRequest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseBindingRequestAcceptsOptionalAttributeAndReturnsTransaction(t *testing.T) {
	want := TransactionID{11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	request := withAttribute(bindingRequest(want), 0x8022, []byte("abc"))
	got, err := ParseBindingRequest(request)
	if err != nil {
		t.Fatalf("ParseBindingRequest() error = %v", err)
	}
	if got != want {
		t.Fatalf("transaction = %x, want %x", got, want)
	}
}

func TestBindingSuccessMatchesIPv4AndIPv6XORVectors(t *testing.T) {
	tests := []struct {
		name        string
		transaction TransactionID
		mapped      netip.AddrPort
		wantHex     string
	}{
		{
			name:        "RFC 5769 IPv4 mapping",
			transaction: TransactionID{0x63, 0xc7, 0x11, 0x7e, 0x07, 0x14, 0x27, 0x8f, 0x5d, 0x30, 0x49, 0xf5},
			mapped:      netip.MustParseAddrPort("192.0.2.1:32853"),
			wantHex:     "0101000c2112a44263c7117e0714278f5d3049f5002000080001a147e112a643",
		},
		{
			name:        "synthetic IPv6 mapping",
			transaction: TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			mapped:      netip.MustParseAddrPort("[2001:db8::1]:54321"),
			wantHex:     "010100182112a4420102030405060708090a0b0c002000140002f5230113a9fa0102030405060708090a0b0d",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := BindingSuccess(test.transaction, test.mapped)
			if err != nil {
				t.Fatalf("BindingSuccess() error = %v", err)
			}
			if got := hex.EncodeToString(response); got != test.wantHex {
				t.Fatalf("response = %s, want %s", got, test.wantHex)
			}
		})
	}
}

func TestBindingSuccessRejectsInvalidMappedEndpoint(t *testing.T) {
	for _, endpoint := range []netip.AddrPort{
		netip.MustParseAddrPort("0.0.0.0:3478"),
		netip.MustParseAddrPort("224.0.0.1:3478"),
		netip.MustParseAddrPort("192.0.2.1:0"),
	} {
		if _, err := BindingSuccess(TransactionID{}, endpoint); !errors.Is(err, ErrInvalidMappedEndpoint) {
			t.Errorf("BindingSuccess(%s) error = %v, want ErrInvalidMappedEndpoint", endpoint, err)
		}
	}
}

func bindingRequest(transaction TransactionID) []byte {
	packet := make([]byte, HeaderBytes)
	binary.BigEndian.PutUint16(packet[0:2], BindingRequestType)
	binary.BigEndian.PutUint32(packet[4:8], MagicCookie)
	copy(packet[8:20], transaction[:])
	return packet
}

func withAttribute(header []byte, attributeType uint16, value []byte) []byte {
	paddedLength := (len(value) + 3) &^ 3
	body := make([]byte, 4+paddedLength)
	binary.BigEndian.PutUint16(body[0:2], attributeType)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(value)))
	copy(body[4:], value)
	return withRawBody(header, body)
}

func withRawBody(header, body []byte) []byte {
	packet := append(append([]byte(nil), header[:HeaderBytes]...), body...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(body)))
	return packet
}

func mutate(source []byte, edit func([]byte)) []byte {
	result := append([]byte(nil), source...)
	edit(result)
	return result
}
