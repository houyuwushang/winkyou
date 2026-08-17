package stunobserve

import (
	"bytes"
	"net/netip"
	"testing"

	"winkyou/internal/stunobserve/testkit"
)

func TestTestkitBindingSuccessRoundTripsThroughProductionParser(t *testing.T) {
	request, transaction, err := newBindingRequest(bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}))
	if err != nil {
		t.Fatalf("binding request: %v", err)
	}
	for _, mapped := range []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.8:42000"),
		netip.MustParseAddrPort("[2001:db8::8]:43000"),
	} {
		response, err := testkit.BindingSuccess(request, mapped)
		if err != nil {
			t.Fatalf("test response for %s: %v", mapped, err)
		}
		actual, attribute, err := parseBindingSuccess(response, transaction)
		if err != nil {
			t.Fatalf("parse response for %s: %v", mapped, err)
		}
		if actual != mapped || attribute != "xor_mapped_address" {
			t.Fatalf("parsed response = %s/%s, want %s/xor_mapped_address", actual, attribute, mapped)
		}
	}
}
