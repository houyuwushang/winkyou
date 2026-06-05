package nat

import (
	"fmt"
	"net"
	"strings"
)

func buildCandidateInterfaceFilter(cfg ICEConfig) func(string) bool {
	include := normalizeNameSet(cfg.CandidateInterfaceInclude)
	exclude := normalizeNameSet(cfg.CandidateInterfaceExclude)
	autoExcludeVirtual := cfg.PublicDirectCandidate
	if len(include) == 0 && len(exclude) == 0 && !autoExcludeVirtual {
		return nil
	}
	return func(name string) bool {
		normalized := strings.ToLower(strings.TrimSpace(name))
		if _, ok := exclude[normalized]; ok {
			return false
		}
		if len(include) > 0 {
			_, ok := include[normalized]
			return ok
		}
		if autoExcludeVirtual && isLikelyVirtualCandidateInterface(normalized) {
			return false
		}
		return true
	}
}

func isLikelyVirtualCandidateInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, token := range []string{
		"natpierce",
		"tailscale",
		"zerotier",
		"hamachi",
		"wireguard",
		"wintun",
		"wink",
		"docker",
		"vethernet",
		"virtualbox",
		"vmware",
		"loopback",
	} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func buildCandidateIPFilter(cfg ICEConfig) (func(net.IP) bool, error) {
	include, err := parseCIDRList("candidate_cidr_include", cfg.CandidateCIDRInclude)
	if err != nil {
		return nil, err
	}
	exclude, err := parseCIDRList("candidate_cidr_exclude", cfg.CandidateCIDRExclude)
	if err != nil {
		return nil, err
	}
	if len(include) == 0 && len(exclude) == 0 {
		return nil, nil
	}
	return func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		if ipInAny(ip, exclude) {
			return false
		}
		if len(include) > 0 {
			return ipInAny(ip, include)
		}
		return true
	}, nil
}

func normalizeNameSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	return out
}

func parseCIDRList(field string, values []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(values))
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		_, prefix, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("nat: invalid %s[%d]: %q", field, i, value)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func ipInAny(ip net.IP, prefixes []*net.IPNet) bool {
	for _, prefix := range prefixes {
		if prefix != nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
