package diagnose

import (
	"net"
	"reflect"
	"testing"
)

type testAddress string

func (address testAddress) Network() string { return "test" }
func (address testAddress) String() string  { return string(address) }

func TestAddressClassesRedactRawAddresses(t *testing.T) {
	addresses := []net.Addr{
		testAddress("127.0.0.1/8"),
		testAddress("192.168.1.20/24"),
		testAddress("100.64.1.2/10"),
		testAddress("8.8.8.8/32"),
		testAddress("::1/128"),
		testAddress("fd00::1/64"),
		testAddress("fe80::1%Ethernet/64"),
		testAddress("2001:4860:4860::8888/128"),
	}
	want := []string{
		"ipv4_global",
		"ipv4_loopback",
		"ipv4_private",
		"ipv4_shared",
		"ipv6_global",
		"ipv6_link_local",
		"ipv6_loopback",
		"ipv6_unique_local",
	}
	got := addressClasses(addresses)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("address classes = %v, want %v", got, want)
	}
	for _, class := range got {
		for _, address := range addresses {
			if class == address.String() {
				t.Fatalf("raw address leaked as class: %q", class)
			}
		}
	}
}

func TestMalformedAddressIsOnlyReportedAsUnparsed(t *testing.T) {
	if got := classifyAddress("private-hostname"); got != "unparsed" {
		t.Fatalf("class = %q, want unparsed", got)
	}
}
