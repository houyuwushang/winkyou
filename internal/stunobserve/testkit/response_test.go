package testkit

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"winkyou/internal/stunwire"
)

func TestBindingSuccessBuildsIPv4AndIPv6XORMappedResponses(t *testing.T) {
	request := make([]byte, stunwire.HeaderBytes)
	binary.BigEndian.PutUint16(request[0:2], stunwire.BindingRequestType)
	binary.BigEndian.PutUint32(request[4:8], stunwire.MagicCookie)
	for index := 8; index < 20; index++ {
		request[index] = byte(index)
	}
	for _, mapped := range []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.8:42000"),
		netip.MustParseAddrPort("[2001:db8::8]:43000"),
	} {
		response, err := BindingSuccess(request, mapped)
		if err != nil {
			t.Fatalf("response for %s: %v", mapped, err)
		}
		if binary.BigEndian.Uint16(response[0:2]) != stunwire.BindingSuccessType || binary.BigEndian.Uint32(response[4:8]) != stunwire.MagicCookie || string(response[8:20]) != string(request[8:20]) {
			t.Fatalf("invalid response header for %s: %x", mapped, response)
		}
		wantValueLength := 8
		if mapped.Addr().Is6() {
			wantValueLength = 20
		}
		if len(response) != stunwire.HeaderBytes+4+wantValueLength || int(binary.BigEndian.Uint16(response[2:4])) != 4+wantValueLength {
			t.Fatalf("response length for %s = %d/%d", mapped, len(response), binary.BigEndian.Uint16(response[2:4]))
		}
	}
}

func TestBindingSuccessRejectsMalformedInputs(t *testing.T) {
	valid := make([]byte, stunwire.HeaderBytes)
	binary.BigEndian.PutUint16(valid[0:2], stunwire.BindingRequestType)
	binary.BigEndian.PutUint32(valid[4:8], stunwire.MagicCookie)
	tests := [][]byte{
		nil,
		append([]byte(nil), valid[:stunwire.HeaderBytes-1]...),
		func() []byte { packet := append([]byte(nil), valid...); packet[0] = 1; return packet }(),
		func() []byte { packet := append([]byte(nil), valid...); packet[4] = 0; return packet }(),
		func() []byte {
			packet := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(packet[2:4], 4)
			return packet
		}(),
	}
	for index, request := range tests {
		if _, err := BindingSuccess(request, netip.MustParseAddrPort("192.0.2.1:3478")); err == nil {
			t.Fatalf("malformed request %d accepted", index)
		}
	}
	if _, err := BindingSuccess(valid, netip.MustParseAddrPort("0.0.0.0:3478")); err == nil {
		t.Fatal("unspecified mapped endpoint accepted")
	}
}
