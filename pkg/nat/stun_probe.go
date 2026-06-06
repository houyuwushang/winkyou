package nat

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// STUNProbeResult is the public outcome of a STUN binding probe.
type STUNProbeResult struct {
	LocalAddr  *net.UDPAddr
	MappedAddr *net.UDPAddr
	ServerAddr *net.UDPAddr
}

// STUNMappingProbe records how one STUN server sees a shared local UDP socket.
type STUNMappingProbe struct {
	Server     string
	LocalAddr  *net.UDPAddr
	MappedAddr *net.UDPAddr
	ServerAddr *net.UDPAddr
	Error      string
}

// STUNMappingReport summarizes multiple STUN probes sent from the same UDP
// socket. A symmetric result means at least two servers reported different
// mapped IPs or ports for the same local socket.
type STUNMappingReport struct {
	NATType NATType
	Probes  []STUNMappingProbe
}

// ProbeSTUN performs a single STUN binding probe against serverAddr.
func ProbeSTUN(ctx context.Context, serverAddr string) (*STUNProbeResult, error) {
	result, err := stunBind(ctx, serverAddr)
	if err != nil {
		return nil, err
	}
	return &STUNProbeResult{
		LocalAddr:  cloneUDPAddr(result.LocalAddr),
		MappedAddr: cloneUDPAddr(result.MappedAddr),
		ServerAddr: cloneUDPAddr(result.ServerAddr),
	}, nil
}

// ProbeSTUNMapping probes all servers from one UDP socket and classifies the
// observed mapping stability conservatively.
func ProbeSTUNMapping(ctx context.Context, servers []string) (STUNMappingReport, error) {
	report := STUNMappingReport{NATType: NATTypeUnknown}
	if len(servers) == 0 {
		return report, fmt.Errorf("nat: no STUN servers configured")
	}

	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return report, fmt.Errorf("nat: listen: %w", err)
	}
	defer conn.Close()

	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		probe := STUNMappingProbe{Server: server}
		host, port, err := parseSTUNAddr(server)
		if err != nil {
			probe.Error = err.Error()
			report.Probes = append(report.Probes, probe)
			continue
		}
		raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
		if err != nil {
			probe.Error = err.Error()
			report.Probes = append(report.Probes, probe)
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, stunDefaultTimeout)
		result, err := stunBindConn(probeCtx, conn, raddr)
		cancel()
		if err != nil {
			probe.Error = err.Error()
			report.Probes = append(report.Probes, probe)
			continue
		}
		probe.LocalAddr = cloneUDPAddr(result.LocalAddr)
		probe.MappedAddr = cloneUDPAddr(result.MappedAddr)
		probe.ServerAddr = cloneUDPAddr(result.ServerAddr)
		report.Probes = append(report.Probes, probe)
	}

	report.NATType = classifySTUNMapping(report.Probes)
	if successfulSTUNMappingProbeCount(report.Probes) == 0 {
		return report, fmt.Errorf("nat: all STUN probes failed")
	}
	return report, nil
}

func classifySTUNMapping(probes []STUNMappingProbe) NATType {
	var first *net.UDPAddr
	for _, probe := range probes {
		if probe.MappedAddr == nil {
			continue
		}
		if first == nil {
			first = probe.MappedAddr
			if isLocalAddress(first.IP) {
				return NATTypeNone
			}
			continue
		}
		if !probe.MappedAddr.IP.Equal(first.IP) || probe.MappedAddr.Port != first.Port {
			return NATTypeSymmetric
		}
	}
	return NATTypeUnknown
}

func successfulSTUNMappingProbeCount(probes []STUNMappingProbe) int {
	count := 0
	for _, probe := range probes {
		if probe.MappedAddr != nil {
			count++
		}
	}
	return count
}

// PublicEndpointHintsFromSTUNMapping formats usable public endpoint hints from
// a STUN mapping report. It is deliberately conservative: mapped addresses must
// be public IPv4 endpoints, and local bases are included only when they look
// like real underlay addresses instead of overlay or loopback interfaces.
func PublicEndpointHintsFromSTUNMapping(report STUNMappingReport) []string {
	return PublicEndpointHintsFromSTUNMappingWithTrustedCIDRs(report, nil)
}

// PublicEndpointHintsFromSTUNMappingWithTrustedCIDRs is like
// PublicEndpointHintsFromSTUNMapping, but allows explicitly trusted non-public
// underlay prefixes to appear in the mapped endpoint or local base.
func PublicEndpointHintsFromSTUNMappingWithTrustedCIDRs(report STUNMappingReport, trustedCIDRs []string) []string {
	return PublicEndpointHintsFromSTUNMappingWithAllowedCIDRs(report, trustedCIDRs)
}

// PublicEndpointHintsFromSTUNMappingWithAllowedCIDRs is like
// PublicEndpointHintsFromSTUNMapping, but allows explicitly configured
// non-public prefixes to appear in the mapped endpoint or local base.
func PublicEndpointHintsFromSTUNMappingWithAllowedCIDRs(report STUNMappingReport, allowedCIDRs []string) []string {
	trusted := parseEndpointHintTrustedCIDRs(allowedCIDRs)
	seen := make(map[string]struct{}, len(report.Probes))
	hints := make([]string, 0, len(report.Probes))
	for _, probe := range report.Probes {
		if probe.MappedAddr == nil || probe.MappedAddr.IP == nil || probe.MappedAddr.Port <= 0 {
			continue
		}
		if !usablePublicEndpointHintIP(probe.MappedAddr.IP, trusted) {
			continue
		}
		hint := probe.MappedAddr.String()
		if local := usablePublicEndpointHintLocalAddr(probe, trusted); local != nil {
			hint += "/" + local.String()
		}
		if _, ok := seen[hint]; ok {
			continue
		}
		seen[hint] = struct{}{}
		hints = append(hints, hint)
	}
	slices.Sort(hints)
	return hints
}

// PublicEndpointHintFromObservedEndpoint formats a peer-observed endpoint as a
// public endpoint hint when it passes the same conservative endpoint filter used
// for STUN-derived mappings.
func PublicEndpointHintFromObservedEndpoint(endpoint string, allowedCIDRs []string) string {
	addrPort, err := netip.ParseAddrPort(strings.TrimSpace(endpoint))
	if err != nil || !addrPort.Addr().Is4() || addrPort.Port() == 0 {
		return ""
	}
	ip := net.IP(addrPort.Addr().AsSlice())
	if !usablePublicEndpointHintIP(ip, parseEndpointHintTrustedCIDRs(allowedCIDRs)) {
		return ""
	}
	return addrPort.String()
}

func usablePublicEndpointHintLocalAddr(probe STUNMappingProbe, trusted []netip.Prefix) *net.UDPAddr {
	if usableEndpointHintLocalAddr(probe.LocalAddr, trusted) {
		return cloneUDPAddr(probe.LocalAddr)
	}
	if probe.LocalAddr == nil || probe.LocalAddr.Port <= 0 || probe.ServerAddr == nil {
		return nil
	}
	if probe.LocalAddr.IP != nil && !probe.LocalAddr.IP.IsUnspecified() {
		return nil
	}
	ip := localIPForUDPRoute(probe.ServerAddr)
	if !usableEndpointHintLocalIP(ip, trusted) {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: probe.LocalAddr.Port}
}

func usableEndpointHintLocalAddr(addr *net.UDPAddr, trusted []netip.Prefix) bool {
	return addr != nil && addr.Port > 0 && usableEndpointHintLocalIP(addr.IP, trusted)
}

func usablePublicEndpointHintIP(ip net.IP, trusted []netip.Prefix) bool {
	if ip == nil ||
		ip.To4() == nil ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() {
		return false
	}
	if ipInTrustedCIDRs(ip, trusted) {
		return true
	}
	return !ip.IsPrivate() &&
		!ipInCIDR(ip, "100.64.0.0/10") &&
		!ipInCIDR(ip, "198.18.0.0/15")
}

func usableEndpointHintLocalIP(ip net.IP, trusted []netip.Prefix) bool {
	if ip == nil ||
		ip.To4() == nil ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() {
		return false
	}
	if ipInTrustedCIDRs(ip, trusted) {
		return true
	}
	return !ipInCIDR(ip, "100.64.0.0/10") &&
		!ipInCIDR(ip, "198.18.0.0/15")
}

func parseEndpointHintTrustedCIDRs(values []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func ipInTrustedCIDRs(ip net.IP, trusted []netip.Prefix) bool {
	if ip == nil || len(trusted) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func localIPForUDPRoute(remote *net.UDPAddr) net.IP {
	if remote == nil {
		return nil
	}
	conn, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		return nil
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil
	}
	return append(net.IP(nil), local.IP...)
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}
