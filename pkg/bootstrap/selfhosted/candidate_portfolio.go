package selfhosted

import (
	"math"
	"net/netip"
	"sort"

	"winkyou/pkg/recoverycard"
)

const (
	maxCandidateGroups          = 4
	maxCandidateAnchorsPerGroup = 4
)

// candidatePortfolio is a bounded, deterministic view of one peer's endpoint
// history. Counts describe the portfolio before its group and anchor budgets
// are applied, so callers can distinguish a small history from truncation.
type candidatePortfolio struct {
	Groups                 []candidateGroup
	UsableEndpointCount    int
	FilteredEndpointCount  int
	DuplicateEndpointCount int
	TotalGroupCount        int
}

// candidateGroup collects historical endpoint anchors that share one
// canonical IPv4 address. ID is stable across endpoint-port changes and is
// suitable for recovery status and rotation state.
type candidateGroup struct {
	ID               string
	IP               netip.Addr
	Anchors          []candidateAnchor
	TotalAnchorCount int
}

// candidateAnchor keeps both forms consumed by the current punch setup: the
// endpoint carries NAT prediction evidence, while AddrPort is parsed and
// canonicalized for target-port selection.
type candidateAnchor struct {
	Endpoint recoverycard.Endpoint
	AddrPort netip.AddrPort
}

// buildCandidatePortfolio filters, de-duplicates, ranks, groups, and bounds a
// peer's cached endpoint history. It deliberately accepts a Peer rather than a
// full Card because portfolio construction is independent for every peer.
func buildCandidatePortfolio(peer recoverycard.Peer, allowNonPublic bool) candidatePortfolio {
	portfolio := candidatePortfolio{}
	anchors := make([]candidateAnchor, 0, len(peer.Endpoints))
	for _, endpoint := range peer.Endpoints {
		address, ok := candidateAddrPort(endpoint.AddrPort, allowNonPublic)
		if !ok {
			portfolio.FilteredEndpointCount++
			continue
		}
		anchors = append(anchors, candidateAnchor{Endpoint: endpoint, AddrPort: address})
	}

	// Sort before de-duplication so the strongest metadata wins even when an
	// unvalidated or migrated card contains the same endpoint more than once.
	sort.Slice(anchors, func(i, j int) bool { return candidateAnchorLess(anchors[i], anchors[j]) })
	unique := anchors[:0]
	seen := make(map[netip.AddrPort]struct{}, len(anchors))
	for _, anchor := range anchors {
		if _, duplicate := seen[anchor.AddrPort]; duplicate {
			portfolio.DuplicateEndpointCount++
			continue
		}
		seen[anchor.AddrPort] = struct{}{}
		unique = append(unique, anchor)
	}
	portfolio.UsableEndpointCount = len(unique)

	// Since unique is globally ranked, each group's first appearance ranks the
	// group and appending preserves the same ordering for its anchors.
	groups := make([]candidateGroup, 0, len(unique))
	groupIndex := make(map[string]int, len(unique))
	for _, anchor := range unique {
		ip := anchor.AddrPort.Addr()
		id := ip.String()
		index, exists := groupIndex[id]
		if !exists {
			index = len(groups)
			groupIndex[id] = index
			groups = append(groups, candidateGroup{ID: id, IP: ip})
		}
		groups[index].Anchors = append(groups[index].Anchors, anchor)
	}
	portfolio.TotalGroupCount = len(groups)

	groupLimit := min(len(groups), maxCandidateGroups)
	portfolio.Groups = make([]candidateGroup, 0, groupLimit)
	for i := 0; i < groupLimit; i++ {
		group := groups[i]
		group.TotalAnchorCount = len(group.Anchors)
		anchorLimit := min(len(group.Anchors), maxCandidateAnchorsPerGroup)
		group.Anchors = append([]candidateAnchor(nil), group.Anchors[:anchorLimit]...)
		portfolio.Groups = append(portfolio.Groups, group)
	}
	return portfolio
}

func candidateAddrPort(raw string, allowNonPublic bool) (netip.AddrPort, bool) {
	address, err := netip.ParseAddrPort(raw)
	if err != nil || address.Port() == 0 {
		return netip.AddrPort{}, false
	}
	ip := address.Addr().Unmap()
	if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.AddrPort{}, false
	}
	if !allowNonPublic && !isPublicIPv4(ip) {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, address.Port()), true
}

func candidateAnchorLess(left, right candidateAnchor) bool {
	if !left.Endpoint.LastSuccessAt.Equal(right.Endpoint.LastSuccessAt) {
		return left.Endpoint.LastSuccessAt.After(right.Endpoint.LastSuccessAt)
	}
	if !left.Endpoint.ObservedAt.Equal(right.Endpoint.ObservedAt) {
		return left.Endpoint.ObservedAt.After(right.Endpoint.ObservedAt)
	}
	leftRank, rightRank := candidateNATRank(left.Endpoint.NAT.Pattern), candidateNATRank(right.Endpoint.NAT.Pattern)
	if leftRank != rightRank {
		return leftRank < rightRank
	}
	leftConfidence, rightConfidence := candidateNATConfidence(left.Endpoint.NAT.Confidence), candidateNATConfidence(right.Endpoint.NAT.Confidence)
	if leftConfidence != rightConfidence {
		return leftConfidence > rightConfidence
	}
	if comparison := left.AddrPort.Addr().Compare(right.AddrPort.Addr()); comparison != 0 {
		return comparison < 0
	}
	if left.AddrPort.Port() != right.AddrPort.Port() {
		return left.AddrPort.Port() < right.AddrPort.Port()
	}

	// The remaining comparisons only choose deterministically between duplicate
	// address records carrying otherwise equivalent ranking evidence.
	if !left.Endpoint.NAT.ObservedAt.Equal(right.Endpoint.NAT.ObservedAt) {
		return left.Endpoint.NAT.ObservedAt.After(right.Endpoint.NAT.ObservedAt)
	}
	if left.Endpoint.NAT.Delta != right.Endpoint.NAT.Delta {
		return left.Endpoint.NAT.Delta < right.Endpoint.NAT.Delta
	}
	if left.Endpoint.Source != right.Endpoint.Source {
		return left.Endpoint.Source < right.Endpoint.Source
	}
	if left.Endpoint.AddrPort != right.Endpoint.AddrPort {
		return left.Endpoint.AddrPort < right.Endpoint.AddrPort
	}
	return false
}

func candidateNATRank(pattern recoverycard.PortPattern) int {
	switch pattern {
	case recoverycard.PortPatternPreserving:
		return 0
	case recoverycard.PortPatternSequential:
		return 1
	case recoverycard.PortPatternUnknown:
		return 2
	case recoverycard.PortPatternRandom:
		return 3
	default:
		return 4
	}
}

func candidateNATConfidence(confidence float64) float64 {
	if math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 1 {
		return -1
	}
	return confidence
}
