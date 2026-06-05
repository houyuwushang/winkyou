package nat

import (
	"context"
	"fmt"
	"net"
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
