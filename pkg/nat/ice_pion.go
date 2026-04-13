package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const iceProbePayload = "winkyou-ice-probe-v1"

type icePionAgent struct {
	cfg ICEConfig

	mu               sync.RWMutex
	closed           bool
	localCandidates  []Candidate
	remoteCandidates []Candidate
	selectedPair     *CandidatePair
	localConns       []*net.UDPConn
}

func newICEPionAgent(cfg ICEConfig) ICEAgent {
	return &icePionAgent{cfg: cfg}
}

func (a *icePionAgent) GatherCandidates(ctx context.Context) ([]Candidate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, fmt.Errorf("nat: agent closed")
	}

	for _, c := range a.localConns {
		_ = c.Close()
	}
	a.localConns = nil

	hosts, err := gatherHostCandidates()
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	for _, host := range hosts {
		if host.Address == nil || host.Address.IP == nil {
			continue
		}
		laddr := &net.UDPAddr{IP: append(net.IP(nil), host.Address.IP...), Port: 0}
		conn, err := net.ListenUDP("udp4", laddr)
		if err != nil {
			continue
		}
		bound := conn.LocalAddr().(*net.UDPAddr)
		host.Address = &net.UDPAddr{IP: append(net.IP(nil), bound.IP...), Port: bound.Port}
		a.localConns = append(a.localConns, conn)
		candidates = append(candidates, host)
	}

	if len(a.cfg.STUNServers) > 0 {
		candidates = append(candidates, gatherSrflxCandidates(ctx, a.cfg.STUNServers)...)
	}
	if len(a.cfg.TURNServers) > 0 {
		candidates = append(candidates, gatherRelayCandidates(a.cfg.TURNServers)...)
	}

	a.localCandidates = cloneCandidates(candidates)
	return cloneCandidates(candidates), nil
}

func (a *icePionAgent) SetRemoteCandidates(candidates []Candidate) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return fmt.Errorf("nat: agent closed")
	}
	if len(candidates) == 0 {
		return fmt.Errorf("nat: no remote candidates provided")
	}
	for i := range candidates {
		if candidates[i].Address == nil || candidates[i].Address.IP == nil {
			return fmt.Errorf("nat: remote candidate[%d] missing address", i)
		}
	}
	a.remoteCandidates = cloneCandidates(candidates)
	return nil
}

func (a *icePionAgent) Connect(ctx context.Context) (net.Conn, *CandidatePair, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, nil, fmt.Errorf("nat: agent closed")
	}
	if len(a.localCandidates) == 0 || len(a.localConns) == 0 {
		a.mu.Unlock()
		return nil, nil, fmt.Errorf("nat: local candidates not gathered")
	}
	if len(a.remoteCandidates) == 0 {
		a.mu.Unlock()
		return nil, nil, fmt.Errorf("nat: remote candidates not set")
	}
	localConns := append([]*net.UDPConn(nil), a.localConns...)
	remoteCandidates := cloneCandidates(a.remoteCandidates)
	a.mu.Unlock()

	connectTimeout := a.cfg.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 30 * time.Second
	}
	connCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	type success struct {
		conn      *net.UDPConn
		localAddr *net.UDPAddr
		remote    Candidate
	}
	successCh := make(chan success, 1)

	isRemote := func(addr *net.UDPAddr) (Candidate, bool) {
		for _, rc := range remoteCandidates {
			if rc.Address != nil && rc.Address.IP.Equal(addr.IP) && rc.Address.Port == addr.Port {
				return rc, true
			}
		}
		return Candidate{}, false
	}

	for _, udpConn := range localConns {
		c := udpConn
		go func() {
			buf := make([]byte, 256)
			for {
				_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, raddr, err := c.ReadFromUDP(buf)
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-connCtx.Done():
						return
					default:
						continue
					}
				}
				if err != nil {
					return
				}
				if string(buf[:n]) != iceProbePayload {
					continue
				}
				_ = c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
				_, _ = c.WriteToUDP([]byte(iceProbePayload), raddr)
				if remote, ok := isRemote(raddr); ok {
					localAddr := c.LocalAddr().(*net.UDPAddr)
					select {
					case successCh <- success{conn: c, localAddr: localAddr, remote: remote}:
					default:
					}
					return
				}
			}
		}()
	}

	sendTicker := time.NewTicker(100 * time.Millisecond)
	defer sendTicker.Stop()

	for {
		for _, rc := range remoteCandidates {
			if rc.Address == nil {
				continue
			}
			for _, lc := range localConns {
				_ = lc.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
				_, _ = lc.WriteToUDP([]byte(iceProbePayload), rc.Address)
			}
		}

		select {
		case <-connCtx.Done():
			return nil, nil, fmt.Errorf("nat: ice connect timeout: %w", connCtx.Err())
		case win := <-successCh:
			localCandidate := Candidate{Type: CandidateTypeHost, Address: &net.UDPAddr{IP: append(net.IP(nil), win.localAddr.IP...), Port: win.localAddr.Port}}
			pair := &CandidatePair{Local: &localCandidate, Remote: cloneCandidate(win.remote)}
			a.mu.Lock()
			a.selectedPair = &CandidatePair{Local: cloneCandidate(localCandidate), Remote: cloneCandidate(win.remote)}
			a.mu.Unlock()
			return &udpPairConn{conn: win.conn, remote: cloneUDPAddr(win.remote.Address)}, pair, nil
		case <-sendTicker.C:
		}
	}
}

func (a *icePionAgent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	for _, c := range a.localConns {
		_ = c.Close()
	}
	a.localConns = nil
	return nil
}

func (a *icePionAgent) GetSelectedPair() (*CandidatePair, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.selectedPair == nil {
		return nil, errors.New("nat: no selected pair")
	}
	return &CandidatePair{Local: cloneCandidate(*a.selectedPair.Local), Remote: cloneCandidate(*a.selectedPair.Remote)}, nil
}

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

func gatherRelayCandidates(turns []TURNServer) []Candidate {
	candidates := make([]Candidate, 0, len(turns))
	for _, ts := range turns {
		host, port, ok := parseTURNHostPort(ts.URL)
		if !ok {
			continue
		}
		candidates = append(candidates, Candidate{
			Type:       CandidateTypeRelay,
			Address:    &net.UDPAddr{IP: net.ParseIP(host), Port: port},
			Priority:   1,
			Foundation: "relay:" + host,
		})
	}
	return candidates
}

func parseTURNHostPort(raw string) (string, int, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "turn:")
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", 0, false
		}
		host, portStr, err := net.SplitHostPort(u.Host)
		if err != nil {
			return "", 0, false
		}
		port, err := parsePort(portStr)
		if err != nil {
			return "", 0, false
		}
		if net.ParseIP(host) == nil {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return "", 0, false
			}
			host = ips[0].String()
		}
		return host, port, true
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false
	}
	port, err := parsePort(portStr)
	if err != nil {
		return "", 0, false
	}
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return "", 0, false
		}
		host = ips[0].String()
	}
	return host, port, true
}

func parsePort(portStr string) (int, error) {
	var p int
	_, err := fmt.Sscanf(portStr, "%d", &p)
	if err != nil || p <= 0 || p > 65535 {
		return 0, fmt.Errorf("bad port")
	}
	return p, nil
}

func cloneCandidates(in []Candidate) []Candidate {
	out := make([]Candidate, 0, len(in))
	for _, c := range in {
		out = append(out, *cloneCandidate(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Priority > out[j].Priority })
	return out
}

func cloneCandidate(c Candidate) *Candidate {
	cc := &Candidate{Type: c.Type, Priority: c.Priority, Foundation: c.Foundation}
	if c.Address != nil {
		cc.Address = &net.UDPAddr{IP: append(net.IP(nil), c.Address.IP...), Port: c.Address.Port, Zone: c.Address.Zone}
	}
	if c.RelatedAddr != nil {
		cc.RelatedAddr = &net.UDPAddr{IP: append(net.IP(nil), c.RelatedAddr.IP...), Port: c.RelatedAddr.Port, Zone: c.RelatedAddr.Zone}
	}
	return cc
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

type udpPairConn struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
}

func (c *udpPairConn) Read(p []byte) (int, error) {
	for {
		n, raddr, err := c.conn.ReadFromUDP(p)
		if err != nil {
			return 0, err
		}
		if raddr.IP.Equal(c.remote.IP) && raddr.Port == c.remote.Port {
			return n, nil
		}
	}
}

func (c *udpPairConn) Write(p []byte) (int, error) {
	return c.conn.WriteToUDP(p, c.remote)
}

func (c *udpPairConn) Close() error { return c.conn.Close() }

func (c *udpPairConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *udpPairConn) RemoteAddr() net.Addr { return c.remote }
func (c *udpPairConn) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(t)
}
func (c *udpPairConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *udpPairConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
