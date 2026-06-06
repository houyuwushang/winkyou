package tcpframed

import (
	"net"
	"strings"

	"winkyou/pkg/solver"
)

func tcpEndpointPathPolicy(addr net.Addr, trustedCIDRs []string) (solver.PathRole, []solver.PathDependency) {
	ip := ipFromAddr(addr)
	if ip == nil {
		return tcpEndpointDependency("explicit_tcp_address")
	}
	if ipInCIDRs(ip, trustedCIDRs) {
		return solver.PathRoleProtectedDirect, nil
	}
	if reason := nonPublicIPReason(ip); reason != "" {
		return tcpEndpointDependency("remote_" + reason)
	}
	return solver.PathRoleProtectedDirect, nil
}

func tcpEndpointDependency(reason string) (solver.PathRole, []solver.PathDependency) {
	return solver.PathRolePrimaryCandidate, []solver.PathDependency{{
		Kind:   solver.PathDependencyUnknown,
		Reason: reason,
	}}
}

func ipFromAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch typed := addr.(type) {
	case *net.TCPAddr:
		return typed.IP
	case *net.UDPAddr:
		return typed.IP
	case *net.IPAddr:
		return typed.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func ipInCIDRs(ip net.IP, cidrs []string) bool {
	if ip == nil || len(cidrs) == 0 {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func nonPublicIPReason(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "unspecified_candidate"
	case ip.IsLoopback():
		return "loopback_candidate"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link_local_candidate"
	case ip.IsMulticast():
		return "multicast_candidate"
	case ip.IsPrivate():
		return "private_candidate"
	case ipInCIDRs(ip, []string{"100.64.0.0/10"}):
		return "cgnat_or_overlay_candidate"
	case ipInCIDRs(ip, []string{"198.18.0.0/15"}):
		return "benchmark_or_overlay_candidate"
	default:
		return ""
	}
}
