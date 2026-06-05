package nat

import (
	"context"
	"net"
)

// STUNProbeResult is the public outcome of a STUN binding probe.
type STUNProbeResult struct {
	LocalAddr  *net.UDPAddr
	MappedAddr *net.UDPAddr
	ServerAddr *net.UDPAddr
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
