package stunserver

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestDefaultStatsNeverContainClientAddress(t *testing.T) {
	counters := newCounters(false)
	counters.received.Add(1)
	counters.responseFrom(netip.MustParseAddr("192.0.2.129"))
	payload, err := json.Marshal(counters.snapshot())
	if err != nil {
		t.Fatalf("marshal stats: %v", err)
	}
	for _, forbidden := range []string{"192.0.2.129", "192.0.2.0/24", "response_prefixes"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("default stats contain %q: %s", forbidden, payload)
		}
	}
}

func TestExplicitPrefixStatsUseOnlyIPv4Slash24AndIPv6Slash48(t *testing.T) {
	counters := newCounters(true)
	for _, address := range []netip.Addr{
		netip.MustParseAddr("192.0.2.129"),
		netip.MustParseAddr("192.0.2.200"),
		netip.MustParseAddr("2001:db8:abcd:1234::5"),
	} {
		counters.responseFrom(address)
	}
	stats := counters.snapshot()
	if stats.ResponsePrefixes["192.0.2.0/24"] != 2 || stats.ResponsePrefixes["2001:db8:abcd::/48"] != 1 {
		t.Fatalf("prefix stats = %#v", stats.ResponsePrefixes)
	}
	payload, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("marshal stats: %v", err)
	}
	for _, forbidden := range []string{"192.0.2.129", "192.0.2.200", "2001:db8:abcd:1234::5"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("prefix stats contain full address %q: %s", forbidden, payload)
		}
	}
}

func TestPrefixStatsTableIsBounded(t *testing.T) {
	counters := newCounters(true)
	for index := 0; index < MaxLoggedPrefixes+1; index++ {
		address := netip.AddrFrom4([4]byte{198, byte(18 + index/256), byte(index % 256), 1})
		counters.responseFrom(address)
	}
	stats := counters.snapshot()
	if len(stats.ResponsePrefixes) != MaxLoggedPrefixes || stats.PrefixesOmitted != 1 {
		t.Fatalf("bounded prefix stats = entries %d omitted %d", len(stats.ResponsePrefixes), stats.PrefixesOmitted)
	}
}
