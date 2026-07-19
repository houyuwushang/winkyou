package puncher

import (
	"math/rand"

	"winkyou/pkg/nat"
)

// PredictiveTargets returns the peer ports to punch when the peer's NAT port
// allocation is predictable (sequential/preserving). observedPort is the peer's
// most recently observed mapped port (e.g. from a fresh STUN probe exchanged via
// signaling) and span is how many mappings ahead to project. Returns nil when
// the report is not predictable, signaling the caller to fall back to
// BirthdayTargets.
func PredictiveTargets(report nat.PortAllocationReport, observedPort, span int) []int {
	return report.PredictMappedPorts(observedPort, span)
}

// BirthdayTargets returns up to n distinct random ports in [lo,hi] to spray at a
// peer whose port is unpredictable. r makes the selection deterministic for
// tests; callers pass a seeded source.
func BirthdayTargets(r *rand.Rand, n, lo, hi int) []int {
	if lo < 1 {
		lo = 1
	}
	if hi > 65535 {
		hi = 65535
	}
	if hi < lo || n <= 0 {
		return nil
	}
	span := hi - lo + 1
	if n > span {
		n = span
	}
	seen := make(map[int]struct{}, n)
	out := make([]int, 0, n)
	for attempts := 0; len(out) < n && attempts < n*8; attempts++ {
		p := lo + r.Intn(span)
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
