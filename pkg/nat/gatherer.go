package nat

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
)

// gatherHostCandidates enumerates local IPv4 addresses and returns
// host candidates. It skips loopback, down, and link-local interfaces,
// and deduplicates by IP.
func gatherHostCandidates() ([]Candidate, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("nat: list interfaces: %w", err)
	}

	seen := make(map[string]bool)
	var candidates []Candidate

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue // skip IPv6
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			key := ip.String()
			if seen[key] {
				continue
			}
			seen[key] = true

			c := Candidate{
				Type:       CandidateTypeHost,
				Address:    &net.UDPAddr{IP: ip, Port: 0},
				Priority:   hostPriority(ip),
				Foundation: hostFoundation(ip),
			}
			candidates = append(candidates, c)
		}
	}

	// Sort by priority descending for deterministic output.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Priority > candidates[j].Priority
	})

	return candidates, nil
}

// hostPriority computes a stable priority for a host candidate.
// RFC 8445: priority = (2^24 * type_pref) + (2^8 * local_pref) + (256 - component_id)
// type_pref for host = 126, component_id = 1 (RTP-like, single component).
func hostPriority(ip net.IP) uint32 {
	const typePref = 126
	const componentID = 1
	localPref := localPreference(ip)
	return (typePref << 24) | (localPref << 8) | (256 - componentID)
}

// srflxPriority computes a stable priority for a server-reflexive candidate.
// type_pref for srflx = 100.
func srflxPriority(ip net.IP) uint32 {
	const typePref = 100
	const componentID = 1
	localPref := localPreference(ip)
	return (typePref << 24) | (localPref << 8) | (256 - componentID)
}

// localPreference returns a 16-bit preference value derived from the IP.
// Private IPs get lower preference than routable IPs.
func localPreference(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	if ip4.IsPrivate() {
		return 65534
	}
	return 65535
}

// hostFoundation returns a stable foundation string for a host candidate.
// Foundation must be the same for candidates from the same base address
// and type, and different otherwise.
func hostFoundation(ip net.IP) string {
	h := sha256.Sum256([]byte("host:" + ip.String()))
	return fmt.Sprintf("h%x", h[:4])
}

// srflxFoundation returns a stable foundation string for a srflx candidate.
func srflxFoundation(baseIP net.IP, serverAddr string) string {
	h := sha256.Sum256([]byte("srflx:" + baseIP.String() + ":" + serverAddr))
	return fmt.Sprintf("s%x", h[:4])
}
