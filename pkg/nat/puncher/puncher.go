package puncher

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Config controls one punch attempt against a single peer.
type Config struct {
	// RemoteIP is the peer's public IPv4 address.
	RemoteIP net.IP
	// TargetPorts are the peer ports to punch (from PredictiveTargets or
	// BirthdayTargets).
	TargetPorts []int
	// Session is a shared punch-traffic discriminator. It is not authentication:
	// callers that reuse a stable pair value must authenticate the resulting
	// socket separately with fresh challenge material.
	Session [8]byte
	// SocketCount is how many local source sockets to open (birthday-paradox
	// width). Defaults to 256.
	SocketCount int
	// Burst is how many probe packets to send per target per round. Defaults to 1.
	Burst int
	// RoundDelay is the pause between punch rounds. Defaults to 200ms.
	RoundDelay time.Duration
	// Method labels the punch strategy for diagnostics (e.g. "predictive").
	Method string
	// LocalPort, when > 0, binds a single source socket to this fixed local port
	// (SocketCount is ignored). A port-preserving peer uses it so its public
	// source port stays fixed and matches the target a symmetric peer punched,
	// which the symmetric peer's address-and-port-dependent NAT will accept.
	LocalPort int
	// BirthdayN, when > 0, makes each socket additionally spray BirthdayN FRESH
	// random ports in [BirthdayLo,BirthdayHi] every round. TargetPorts are still
	// sent first when present. That lets a restart attempt try the last observed
	// endpoint cheaply while retaining birthday coverage when the NAT allocated
	// a different port.
	BirthdayN  int
	BirthdayLo int
	BirthdayHi int
	// GracePeriod keeps all source sockets punching and acknowledging after the
	// first local hit so the peer can finish. Zero uses the production default.
	GracePeriod time.Duration
}

// Result is a verified bidirectional UDP path. Conn is the surviving source
// socket, left open for the caller to hand to the data plane; the caller owns
// it and must Close it.
type Result struct {
	Conn       *net.UDPConn
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr // peer's learned real post-NAT source address
	Method     string
}

const (
	defaultSocketCount = 256
	defaultRoundDelay  = 200 * time.Millisecond
	readPollInterval   = 200 * time.Millisecond
	maxPunchPacket     = 1500
	// gracePeriod keeps punching/acking after our own hit so the peer can finish
	// its handshake before we tear down the sockets it is still probing.
	gracePeriod = 3 * time.Second
)

// Punch opens SocketCount source sockets, punches RemoteIP:TargetPorts from each,
// learns the peer's real source from inbound probes (acking them), and returns
// the first socket that receives an ack, proving its probe reached the peer, i.e.
// a bidirectional path. It returns an error if no path is punched before ctx is
// done.
func Punch(ctx context.Context, cfg Config) (*Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("puncher: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("puncher: no path punched: %w", err)
	}
	if cfg.SocketCount <= 0 {
		cfg.SocketCount = defaultSocketCount
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.RoundDelay <= 0 {
		cfg.RoundDelay = defaultRoundDelay
	}
	if cfg.GracePeriod <= 0 {
		cfg.GracePeriod = gracePeriod
	}
	if len(cfg.TargetPorts) == 0 && cfg.BirthdayN <= 0 {
		return nil, fmt.Errorf("puncher: no target ports")
	}
	if cfg.RemoteIP == nil || cfg.RemoteIP.To4() == nil {
		return nil, fmt.Errorf("puncher: remote IP must be IPv4")
	}
	cfg.RemoteIP = append(net.IP(nil), cfg.RemoteIP.To4()...)
	cfg.TargetPorts = append([]int(nil), cfg.TargetPorts...)
	for _, port := range cfg.TargetPorts {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("puncher: target port %d is outside 1..65535", port)
		}
	}
	if cfg.LocalPort < 0 || cfg.LocalPort > 65535 {
		return nil, fmt.Errorf("puncher: local port %d is outside 1..65535", cfg.LocalPort)
	}
	if cfg.BirthdayN > 0 {
		if cfg.BirthdayLo <= 0 {
			cfg.BirthdayLo = 1024
		}
		if cfg.BirthdayHi <= 0 {
			cfg.BirthdayHi = 65535
		}
		if cfg.BirthdayLo > 65535 || cfg.BirthdayHi > 65535 || cfg.BirthdayHi < cfg.BirthdayLo {
			return nil, fmt.Errorf("puncher: birthday port range %d..%d is invalid", cfg.BirthdayLo, cfg.BirthdayHi)
		}
	}

	var sockets []*net.UDPConn
	if cfg.LocalPort > 0 {
		// Fixed local port: a single preserving-NAT socket whose public source
		// port stays constant so a symmetric peer's NAT accepts it.
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.LocalPort})
		if err != nil {
			return nil, fmt.Errorf("puncher: bind fixed local port %d: %w", cfg.LocalPort, err)
		}
		sockets = append(sockets, conn)
	} else {
		sockets = make([]*net.UDPConn, 0, cfg.SocketCount)
		for i := 0; i < cfg.SocketCount; i++ {
			if ctx.Err() != nil {
				break
			}
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				// Best-effort: stop opening more once the fd limit is hit.
				break
			}
			sockets = append(sockets, conn)
		}
	}
	if len(sockets) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("puncher: no path punched: %w", err)
		}
		return nil, fmt.Errorf("puncher: could not open any source socket")
	}
	if err := ctx.Err(); err != nil {
		for _, conn := range sockets {
			_ = conn.Close()
		}
		return nil, fmt.Errorf("puncher: no path punched: %w", err)
	}

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan *Result, len(sockets))
	var wg sync.WaitGroup
	for _, conn := range sockets {
		// A learned endpoint belongs to this exact source socket/NAT mapping.
		// Sharing it across sockets can make the two peers retain different
		// winning tuples after all losing sockets are closed.
		learned := &peerSet{m: make(map[string]*net.UDPAddr)}
		wg.Add(2)
		go func(c *net.UDPConn) { defer wg.Done(); punchReader(loopCtx, c, cfg, resultCh, learned) }(conn)
		go func(c *net.UDPConn) { defer wg.Done(); punchSender(loopCtx, c, cfg, learned) }(conn)
	}

	var result *Result
	select {
	case result = <-resultCh:
	case <-loopCtx.Done():
		select {
		case result = <-resultCh:
		default:
		}
	}

	if result != nil {
		// Keep the sockets punching/acking briefly so the peer can complete its
		// own handshake before teardown.
		select {
		case <-time.After(cfg.GracePeriod):
		case <-loopCtx.Done():
		}
	}

	cancel()
	wg.Wait()
	if result != nil {
		// punchReader uses short read deadlines to poll ctx. Do not leak the last
		// (normally already expired) deadline into the data-plane connection.
		_ = result.Conn.SetDeadline(time.Time{})
	}

	// Close every socket except the winning one, which is handed to the caller.
	for _, conn := range sockets {
		if result != nil && conn == result.Conn {
			continue
		}
		_ = conn.Close()
	}

	if result == nil {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("puncher: no path punched: %w", err)
		}
		return nil, fmt.Errorf("puncher: no path punched")
	}
	return result, nil
}

// punchReader receives on one socket: it acks inbound probes (learning the
// peer's real source and feeding it back to the senders) and reports a hit when
// it receives an ack.
func punchReader(ctx context.Context, conn *net.UDPConn, cfg Config, resultCh chan<- *Result, learned *peerSet) {
	buf := make([]byte, maxPunchPacket)
	reported := false
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(readPollInterval))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				continue // normal poll timeout; loop rechecks ctx
			}
			// Other error (e.g. ICMP port unreachable): back off to avoid a busy loop.
			select {
			case <-ctx.Done():
				return
			case <-time.After(readPollInterval):
			}
			continue
		}
		pkt, ok := decodePunch(buf[:n])
		if !ok || pkt.Session != cfg.Session {
			continue
		}
		switch pkt.Kind {
		case punchProbe:
			// The peer reached us: learn its real source so every sender starts
			// punching that exact endpoint (closing the loop even when our port
			// prediction of the peer was wrong), and ack it back.
			learned.add(src)
			ack := encodePunch(punchPacket{Kind: punchAck, Session: cfg.Session, Nonce: pkt.Nonce})
			_, _ = conn.WriteToUDP(ack, src)
		case punchAck:
			// Our probe reached the peer and it replied: bidirectional path.
			// Keep this reader alive after reporting the hit: Punch deliberately
			// holds every socket through the grace period, and the peer may still
			// need this winning socket to ack its own probes before both sides
			// converge on the path.
			if !reported {
				local, _ := conn.LocalAddr().(*net.UDPAddr)
				select {
				case resultCh <- &Result{Conn: conn, LocalAddr: local, RemoteAddr: src, Method: cfg.Method}:
					reported = true
				default:
				}
			}
		}
	}
}

// punchSender sends probe bursts each round until ctx ends: to the fixed target
// ports and, when BirthdayN>0, a fresh random spray, then to every learned real
// peer source so a single correct prediction on either side locks in a path.
func punchSender(ctx context.Context, conn *net.UDPConn, cfg Config, learned *peerSet) {
	var rng *rand.Rand
	lo, hi := cfg.BirthdayLo, cfg.BirthdayHi
	if cfg.BirthdayN > 0 {
		seed := time.Now().UnixNano()
		if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			seed += int64(la.Port) * 2654435761
		}
		rng = rand.New(rand.NewSource(seed))
	}
	sendProbe := func(port int) {
		if port < 1 || port > 65535 {
			return
		}
		dst := &net.UDPAddr{IP: cfg.RemoteIP, Port: port}
		for b := 0; b < cfg.Burst; b++ {
			probe := encodePunch(punchPacket{Kind: punchProbe, Session: cfg.Session, Nonce: randNonce()})
			_, _ = conn.WriteToUDP(probe, dst)
		}
	}
	for {
		if ctx.Err() != nil {
			return
		}
		for _, port := range cfg.TargetPorts {
			sendProbe(port)
		}
		if cfg.BirthdayN > 0 {
			for i := 0; i < cfg.BirthdayN; i++ {
				sendProbe(lo + rng.Intn(hi-lo+1))
			}
		}
		for _, dst := range learned.list() {
			for b := 0; b < cfg.Burst; b++ {
				probe := encodePunch(punchPacket{Kind: punchProbe, Session: cfg.Session, Nonce: randNonce()})
				_, _ = conn.WriteToUDP(probe, dst)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.RoundDelay):
		}
	}
}

// peerSet collects real peer source addresses learned on one source socket.
// Keeping it socket-local preserves the exact NAT tuple that produced the
// observation and that may later be handed to the data plane.
type peerSet struct {
	mu sync.Mutex
	m  map[string]*net.UDPAddr
}

func (p *peerSet) add(a *net.UDPAddr) {
	if a == nil || a.IP == nil {
		return
	}
	p.mu.Lock()
	if _, ok := p.m[a.String()]; !ok {
		p.m[a.String()] = &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port}
	}
	p.mu.Unlock()
}

func (p *peerSet) list() []*net.UDPAddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*net.UDPAddr, 0, len(p.m))
	for _, a := range p.m {
		out = append(out, a)
	}
	return out
}
