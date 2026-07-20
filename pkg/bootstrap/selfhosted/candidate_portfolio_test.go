package selfhosted

import (
	"reflect"
	"strconv"
	"testing"
	"time"

	"winkyou/pkg/recoverycard"
)

func TestBuildCandidatePortfolioStableOrderingAndGrouping(t *testing.T) {
	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	endpoints := []recoverycard.Endpoint{
		portfolioTestEndpoint("9.9.9.9:9000", base.Add(5*time.Hour), base.Add(3*time.Hour), recoverycard.PortPatternPreserving, 1, "nine"),
		portfolioTestEndpoint("8.8.8.8:8001", base.Add(5*time.Hour), base.Add(3*time.Hour), recoverycard.PortPatternPreserving, 1, "eight-one"),
		portfolioTestEndpoint("1.1.1.1:1000", base.Add(5*time.Hour), base.Add(4*time.Hour), recoverycard.PortPatternRandom, 1, "one"),
		portfolioTestEndpoint("4.4.4.4:4000", base.Add(6*time.Hour), base.Add(time.Hour), recoverycard.PortPatternRandom, 1, "four"),
		portfolioTestEndpoint("8.8.8.8:8000", base.Add(5*time.Hour), base.Add(3*time.Hour), recoverycard.PortPatternPreserving, 1, "eight-zero"),
	}
	shuffled := []recoverycard.Endpoint{endpoints[2], endpoints[4], endpoints[0], endpoints[3], endpoints[1]}

	first := buildCandidatePortfolio(recoverycard.Peer{Endpoints: endpoints}, false)
	second := buildCandidatePortfolio(recoverycard.Peer{Endpoints: shuffled}, false)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("portfolio depends on endpoint input order:\nfirst:  %#v\nsecond: %#v", first, second)
	}
	if first.UsableEndpointCount != 5 || first.FilteredEndpointCount != 0 || first.DuplicateEndpointCount != 0 || first.TotalGroupCount != 4 {
		t.Fatalf("unexpected portfolio counts: %#v", first)
	}
	if got, want := portfolioGroupIDs(first), []string{"4.4.4.4", "1.1.1.1", "8.8.8.8", "9.9.9.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("group order = %v, want %v", got, want)
	}
	eight := first.Groups[2]
	if eight.ID != eight.IP.String() || eight.TotalAnchorCount != 2 || len(eight.Anchors) != 2 {
		t.Fatalf("unexpected same-IP group: %#v", eight)
	}
	if got, want := []uint16{eight.Anchors[0].AddrPort.Port(), eight.Anchors[1].AddrPort.Port()}, []uint16{8000, 8001}; !reflect.DeepEqual(got, want) {
		t.Fatalf("same-IP anchor ports = %v, want %v", got, want)
	}
}

func TestBuildCandidatePortfolioRanksNATPredictability(t *testing.T) {
	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	peer := recoverycard.Peer{Endpoints: []recoverycard.Endpoint{
		portfolioTestEndpoint("1.1.1.1:1000", base, base, recoverycard.PortPatternUnknown, 1, "unknown"),
		portfolioTestEndpoint("4.4.4.4:1000", base, base, recoverycard.PortPatternRandom, 1, "random"),
		portfolioTestEndpoint("9.9.9.9:1000", base, base, recoverycard.PortPatternSequential, 1, "sequential"),
		portfolioTestEndpoint("8.8.8.8:1000", base, base, recoverycard.PortPatternPreserving, 1, "preserving"),
	}}

	portfolio := buildCandidatePortfolio(peer, false)
	if got, want := portfolioGroupIDs(portfolio), []string{"8.8.8.8", "9.9.9.9", "1.1.1.1", "4.4.4.4"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("NAT predictability order = %v, want %v", got, want)
	}
}

func TestBuildCandidatePortfolioFiltersAndDeduplicates(t *testing.T) {
	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	peer := recoverycard.Peer{Endpoints: []recoverycard.Endpoint{
		portfolioTestEndpoint("8.8.8.8:1000", base.Add(time.Hour), base, recoverycard.PortPatternUnknown, 0, "older"),
		portfolioTestEndpoint("8.8.8.8:1000", base.Add(3*time.Hour), base.Add(2*time.Hour), recoverycard.PortPatternUnknown, 0, "newer"),
		portfolioTestEndpoint("[::ffff:8.8.8.8]:1000", base.Add(2*time.Hour), base.Add(time.Hour), recoverycard.PortPatternUnknown, 0, "mapped"),
		portfolioTestEndpoint("10.0.0.1:2000", base, base, recoverycard.PortPatternUnknown, 0, "private"),
		portfolioTestEndpoint("127.0.0.1:3000", base, base, recoverycard.PortPatternUnknown, 0, "loopback"),
		portfolioTestEndpoint("[2001:4860:4860::8888]:4000", base, base, recoverycard.PortPatternUnknown, 0, "ipv6"),
		portfolioTestEndpoint("not-an-endpoint", base, base, recoverycard.PortPatternUnknown, 0, "malformed"),
		portfolioTestEndpoint("0.0.0.0:5000", base, base, recoverycard.PortPatternUnknown, 0, "unspecified"),
		portfolioTestEndpoint("224.0.0.1:6000", base, base, recoverycard.PortPatternUnknown, 0, "multicast"),
	}}

	strict := buildCandidatePortfolio(peer, false)
	if strict.UsableEndpointCount != 1 || strict.FilteredEndpointCount != 6 || strict.DuplicateEndpointCount != 2 || strict.TotalGroupCount != 1 {
		t.Fatalf("unexpected strict counts: %#v", strict)
	}
	anchor := strict.Groups[0].Anchors[0]
	if anchor.Endpoint.Source != "newer" || anchor.AddrPort.String() != "8.8.8.8:1000" {
		t.Fatalf("dedup retained wrong anchor: %#v", anchor)
	}

	relaxed := buildCandidatePortfolio(peer, true)
	if relaxed.UsableEndpointCount != 3 || relaxed.FilteredEndpointCount != 4 || relaxed.DuplicateEndpointCount != 2 || relaxed.TotalGroupCount != 3 {
		t.Fatalf("unexpected relaxed counts: %#v", relaxed)
	}
	if got, want := portfolioGroupIDs(relaxed), []string{"8.8.8.8", "10.0.0.1", "127.0.0.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("relaxed groups = %v, want %v", got, want)
	}
}

func TestBuildCandidatePortfolioBudgetsGroupsAndAnchors(t *testing.T) {
	base := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	endpoints := make([]recoverycard.Endpoint, 0, 11)
	for i := 0; i < 6; i++ {
		endpoints = append(endpoints, portfolioTestEndpoint(
			"11.0.0.1:"+strconv.Itoa(1000+i),
			base.Add(time.Duration(200-i)*time.Minute),
			base.Add(time.Duration(100-i)*time.Minute),
			recoverycard.PortPatternPreserving, 1, "multi",
		))
	}
	for i := 0; i < 5; i++ {
		endpoints = append(endpoints, portfolioTestEndpoint(
			strconv.Itoa(12+i)+".0.0.1:2000",
			base.Add(time.Duration(90-i)*time.Minute),
			base.Add(time.Duration(80-i)*time.Minute),
			recoverycard.PortPatternUnknown, 0, "single",
		))
	}

	portfolio := buildCandidatePortfolio(recoverycard.Peer{Endpoints: endpoints}, false)
	if portfolio.UsableEndpointCount != 11 || portfolio.TotalGroupCount != 6 {
		t.Fatalf("unexpected pre-budget counts: %#v", portfolio)
	}
	if len(portfolio.Groups) != maxCandidateGroups {
		t.Fatalf("retained groups = %d, want %d", len(portfolio.Groups), maxCandidateGroups)
	}
	if got, want := portfolioGroupIDs(portfolio), []string{"11.0.0.1", "12.0.0.1", "13.0.0.1", "14.0.0.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retained group IDs = %v, want %v", got, want)
	}
	first := portfolio.Groups[0]
	if first.TotalAnchorCount != 6 || len(first.Anchors) != maxCandidateAnchorsPerGroup {
		t.Fatalf("first group budget = total %d retained %d", first.TotalAnchorCount, len(first.Anchors))
	}
	if got, want := []uint16{
		first.Anchors[0].AddrPort.Port(), first.Anchors[1].AddrPort.Port(),
		first.Anchors[2].AddrPort.Port(), first.Anchors[3].AddrPort.Port(),
	}, []uint16{1000, 1001, 1002, 1003}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retained anchor ports = %v, want %v", got, want)
	}
}

func portfolioTestEndpoint(addr string, succeededAt, observedAt time.Time, pattern recoverycard.PortPattern, confidence float64, source string) recoverycard.Endpoint {
	return recoverycard.Endpoint{
		AddrPort:   addr,
		ObservedAt: observedAt,
		Source:     source,
		NAT: recoverycard.NATModel{
			Pattern: pattern, Confidence: confidence, ObservedAt: observedAt,
		},
		LastSuccessAt: succeededAt,
	}
}

func portfolioGroupIDs(portfolio candidatePortfolio) []string {
	result := make([]string, len(portfolio.Groups))
	for i := range portfolio.Groups {
		result[i] = portfolio.Groups[i].ID
	}
	return result
}
