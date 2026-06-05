package nat

import (
	"context"
	"net"
	"time"
)

// natTraversalImpl is the real NATTraversal implementation.
// It performs actual STUN probes for NAT detection and candidate gathering.
type natTraversalImpl struct {
	cfg Config
}

// DetectNATType probes STUN servers to determine the NAT type.
//
// Conservative detection rules:
//   - No STUN servers or all probes fail -> NATTypeUnknown + error
//   - Mapped address matches a local routable address -> NATTypeNone
//   - Two STUN servers return different mapped IP or port -> NATTypeSymmetric
//   - Otherwise -> NATTypeUnknown (we don't guess cone subtypes yet)
func (n *natTraversalImpl) DetectNATType(ctx context.Context) (NATType, error) {
	report, err := ProbeSTUNMapping(ctx, n.cfg.STUNServers)
	if err != nil {
		return NATTypeUnknown, err
	}
	return report.NATType, nil
}

// DetectSTUNMapping probes STUN servers and returns the complete mapping report.
func (n *natTraversalImpl) DetectSTUNMapping(ctx context.Context) (STUNMappingReport, error) {
	return ProbeSTUNMapping(ctx, n.cfg.STUNServers)
}

// NewICEAgent creates a real pion/ice-backed ICE agent.
func (n *natTraversalImpl) NewICEAgent(cfg ICEConfig) (ICEAgent, error) {
	if cfg.GatherTimeout == 0 {
		cfg.GatherTimeout = 5 * time.Second
	}
	if cfg.CheckTimeout == 0 {
		cfg.CheckTimeout = 10 * time.Second
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 30 * time.Second
	}
	if len(cfg.STUNServers) == 0 {
		cfg.STUNServers = n.cfg.STUNServers
	}
	if len(cfg.TURNServers) == 0 {
		cfg.TURNServers = n.cfg.TURNServers
	}
	return newICEPionAgent(cfg)
}

// isLocalAddress checks whether ip matches any local interface address.
func isLocalAddress(ip net.IP) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
