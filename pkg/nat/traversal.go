package nat

import (
	"context"
	"fmt"
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
//   - No STUN servers or all probes fail → NATTypeUnknown + error
//   - Mapped address matches a local routable address → NATTypeNone
//   - Two STUN servers return different mapped IP or port → NATTypeSymmetric
//   - Otherwise → NATTypeUnknown (we don't guess cone subtypes yet)
func (n *natTraversalImpl) DetectNATType(ctx context.Context) (NATType, error) {
	if len(n.cfg.STUNServers) == 0 {
		return NATTypeUnknown, fmt.Errorf("nat: no STUN servers configured")
	}

	// Open a single UDP socket so all probes share the same local port.
	// This is required for comparing mapped addresses across servers.
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return NATTypeUnknown, fmt.Errorf("nat: listen: %w", err)
	}
	defer conn.Close()

	type probeResult struct {
		mapped *net.UDPAddr
		server string
		err    error
	}

	var results []probeResult
	for _, server := range n.cfg.STUNServers {
		host, port, err := parseSTUNAddr(server)
		if err != nil {
			results = append(results, probeResult{err: err, server: server})
			continue
		}

		raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
		if err != nil {
			results = append(results, probeResult{err: err, server: server})
			continue
		}

		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		res, err := stunBindConn(probeCtx, conn, raddr)
		cancel()

		if err != nil {
			results = append(results, probeResult{err: err, server: server})
			continue
		}
		results = append(results, probeResult{mapped: res.MappedAddr, server: server})
	}

	// Count successes.
	var successes []probeResult
	for _, r := range results {
		if r.err == nil {
			successes = append(successes, r)
		}
	}

	if len(successes) == 0 {
		return NATTypeUnknown, fmt.Errorf("nat: all STUN probes failed")
	}

	firstMapped := successes[0].mapped

	// Check if mapped address matches a local routable address → no NAT.
	if isLocalAddress(firstMapped.IP) {
		return NATTypeNone, nil
	}

	// If we have results from 2+ servers, compare mapped addresses.
	if len(successes) >= 2 {
		for _, s := range successes[1:] {
			if !s.mapped.IP.Equal(firstMapped.IP) || s.mapped.Port != firstMapped.Port {
				return NATTypeSymmetric, nil
			}
		}
	}

	// Can't distinguish cone subtypes with this simple approach.
	return NATTypeUnknown, nil
}

// NewICEAgent creates an ICE agent. The agent's GatherCandidates performs
// real host + srflx gathering; Connect/SetRemoteCandidates remain stubs.
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
	// Inherit STUN/TURN servers from parent config if not set on ICEConfig.
	if len(cfg.STUNServers) == 0 {
		cfg.STUNServers = n.cfg.STUNServers
	}
	if len(cfg.TURNServers) == 0 {
		cfg.TURNServers = n.cfg.TURNServers
	}
	return &iceAgentImpl{cfg: cfg}, nil
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

// iceAgentImpl has real GatherCandidates but stub Connect/SetRemoteCandidates.
type iceAgentImpl struct {
	cfg    ICEConfig
	closed bool
}

func (a *iceAgentImpl) GatherCandidates(ctx context.Context) ([]Candidate, error) {
	if a.closed {
		return nil, fmt.Errorf("nat: agent closed")
	}

	// 1. Gather host candidates.
	hosts, err := gatherHostCandidates()
	if err != nil {
		return nil, err
	}

	candidates := make([]Candidate, len(hosts))
	copy(candidates, hosts)

	// 2. Gather srflx candidates via STUN.
	if len(a.cfg.STUNServers) > 0 {
		srflx := gatherSrflxCandidates(ctx, a.cfg.STUNServers)
		candidates = append(candidates, srflx...)
	}

	return candidates, nil
}

func (a *iceAgentImpl) SetRemoteCandidates(candidates []Candidate) error {
	return ErrNotImplemented
}

func (a *iceAgentImpl) Connect(ctx context.Context) (net.Conn, *CandidatePair, error) {
	return nil, nil, ErrNotImplemented
}

func (a *iceAgentImpl) Close() error {
	a.closed = true
	return nil
}

// gatherSrflxCandidates probes each STUN server and returns srflx candidates.
// Failures are silently skipped — partial results are fine.
func gatherSrflxCandidates(ctx context.Context, servers []string) []Candidate {
	seen := make(map[string]bool)
	var candidates []Candidate

	for _, server := range servers {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		res, err := stunBind(probeCtx, server)
		cancel()
		if err != nil {
			continue
		}

		key := res.MappedAddr.String()
		if seen[key] {
			continue
		}
		seen[key] = true

		baseIP := net.IPv4zero
		if res.LocalAddr != nil {
			baseIP = res.LocalAddr.IP
		}

		c := Candidate{
			Type:       CandidateTypeSrflx,
			Address:    res.MappedAddr,
			Priority:   srflxPriority(res.MappedAddr.IP),
			Foundation: srflxFoundation(baseIP, server),
		}
		if res.LocalAddr != nil {
			c.RelatedAddr = res.LocalAddr
		}
		candidates = append(candidates, c)
	}

	return candidates
}
