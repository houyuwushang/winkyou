package client

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
)

const (
	observationEndpointHintRecentLimit = 128
	observationEndpointHintMaxAge      = 10 * time.Minute
	observationEndpointHintMaxHints    = 8
)

func (e *engine) observationPublicEndpointHints() []string {
	if e == nil || !e.cfg.NAT.AutoPublicEndpointHints || e.observationStore == nil {
		return nil
	}
	observations := e.observationStore.Recent(observationEndpointHintRecentLimit)
	if len(observations) == 0 {
		return nil
	}
	allowedCIDRs := mergeStrategyTrustedCIDRs(e.cfg.NAT.CandidateCIDRInclude, e.cfg.NAT.DirectTrustedCIDRs, e.cfg.NAT.PublicDirectTrustedCIDRs)
	now := time.Now()
	seen := make(map[string]struct{})
	hints := make([]string, 0, observationEndpointHintMaxHints)
	for i := len(observations) - 1; i >= 0 && len(hints) < observationEndpointHintMaxHints; i-- {
		obs := observations[i]
		if !observationCanSeedPublicEndpointHint(obs, now) {
			continue
		}
		for _, sample := range splitObservationCandidateSamples(obs.Details["candidate_kept_samples"]) {
			hint := endpointHintFromObservationSample(sample, allowedCIDRs)
			if hint == "" {
				continue
			}
			if _, ok := seen[hint]; ok {
				continue
			}
			seen[hint] = struct{}{}
			hints = append(hints, hint)
			if len(hints) >= observationEndpointHintMaxHints {
				break
			}
		}
	}
	return hints
}

func observationCanSeedPublicEndpointHint(obs solver.Observation, now time.Time) bool {
	if obs.Strategy != legacyice.StrategyName || obs.Event != "candidate_gathered" {
		return false
	}
	if !strings.HasPrefix(strings.TrimSpace(obs.PlanID), "legacyice/public_direct") {
		return false
	}
	if obs.Details["mode"] != "public_direct" || obs.Details["candidate_side"] != "local" {
		return false
	}
	if obs.Timestamp.IsZero() || now.IsZero() {
		return true
	}
	age := now.Sub(obs.Timestamp)
	return age >= 0 && age <= observationEndpointHintMaxAge
}

func splitObservationCandidateSamples(raw string) []string {
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func endpointHintFromObservationSample(sample string, allowedCIDRs []string) string {
	kind, rest, ok := strings.Cut(strings.TrimSpace(sample), ":")
	if !ok || kind != nat.CandidateTypeSrflx.String() {
		return ""
	}
	publicPart, localPart, hasLocal := strings.Cut(rest, "<-")
	publicAddr, err := netip.ParseAddrPort(publicPart)
	if err != nil || !publicAddr.Addr().Is4() || publicAddr.Port() == 0 {
		return ""
	}
	publicIP := net.IP(publicAddr.Addr().AsSlice())
	if !endpointHintHistoryAddrAllowed(publicIP, allowedCIDRs) {
		return ""
	}
	if !hasLocal {
		return publicAddr.String()
	}
	localAddr, err := netip.ParseAddrPort(localPart)
	if err != nil || !localAddr.Addr().Is4() || localAddr.Port() == 0 {
		return publicAddr.String()
	}
	localIP := net.IP(localAddr.Addr().AsSlice())
	if !endpointHintHistoryLocalBaseAllowed(localIP, allowedCIDRs) {
		return publicAddr.String()
	}
	return publicAddr.String() + "/" + localAddr.String()
}

func endpointHintHistoryAddrAllowed(ip net.IP, allowedCIDRs []string) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if endpointHintHistoryIPInCIDRs(ip, allowedCIDRs) {
		return true
	}
	if ip.IsPrivate() {
		return false
	}
	return !endpointHintHistoryIPInCIDR(ip, "100.64.0.0/10") && !endpointHintHistoryIPInCIDR(ip, "198.18.0.0/15")
}

func endpointHintHistoryLocalBaseAllowed(ip net.IP, allowedCIDRs []string) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if endpointHintHistoryIPInCIDRs(ip, allowedCIDRs) {
		return true
	}
	return !endpointHintHistoryIPInCIDR(ip, "100.64.0.0/10") && !endpointHintHistoryIPInCIDR(ip, "198.18.0.0/15")
}

func endpointHintHistoryIPInCIDRs(ip net.IP, cidrs []string) bool {
	for _, cidr := range cidrs {
		if endpointHintHistoryIPInCIDR(ip, cidr) {
			return true
		}
	}
	return false
}

func endpointHintHistoryIPInCIDR(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	return err == nil && network.Contains(ip)
}
