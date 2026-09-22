//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/v2/fieldc1c"
)

const maxDatagramBytes = 9216

type natKey struct {
	local  netip.AddrPort
	target netip.AddrPort
}
type natMapping struct {
	conn          *net.UDPConn
	local, public netip.AddrPort
	allowed       map[netip.AddrPort]bool
	created, last time.Time
	ordinal       int
	connected     bool
}
type natReply struct {
	mapping *natMapping
	source  netip.AddrPort
	payload []byte
}
type mappingSample struct {
	local, remote           netip.AddrPort
	role, ref               string
	created, last, observed time.Time
}

type natRouter struct {
	cfg              fieldc1c.RouterDomain
	peer             netip.Addr
	observers        [4]netip.AddrPort
	namespace        *os.File
	ctx              context.Context
	cancel           context.CancelFunc
	tun              *os.File
	mu               sync.Mutex
	closed           bool
	mappings         map[natKey]*natMapping
	all              []*natMapping
	readers          sync.WaitGroup
	done             chan error
	samples          chan<- mappingSample
	next             int
	allocationKey    [32]byte
	perTarget        map[netip.AddrPort]uint32
	failure          chan error
	started          bool
	out, in, dropped atomic.Uint64
	peak             atomic.Uint64
	budget           *atomic.Uint64
}

func newNAT(ctx context.Context, ns *os.File, domain fieldc1c.RouterDomain, peer netip.Addr, observers [4]netip.AddrPort, samples chan<- mappingSample, seed string, budget *atomic.Uint64) (*natRouter, error) {
	if budget == nil {
		return nil, ErrInvalid
	}
	child, cancel := context.WithCancel(ctx)
	r := &natRouter{cfg: domain, peer: peer, observers: observers, namespace: ns, ctx: child, cancel: cancel, done: make(chan error, 1), failure: make(chan error, 1), mappings: map[natKey]*natMapping{}, samples: samples}
	r.budget = budget
	if domain.Mode == "apdm_uniform16/1" {
		r.allocationKey = sha256.Sum256([]byte("winkyou-c1c-nat-allocation/1\n" + seed + domain.Role))
		r.perTarget = map[netip.AddrPort]uint32{}
	}
	err := inNamespace(ns, func() error { var e error; r.tun, e = openRouterTUN(); return e })
	if err != nil {
		cancel()
		return nil, err
	}
	return r, nil
}

func openRouterTUN() (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errIO
	}
	request, err := unix.NewIfreq("wyctun")
	if err == nil {
		request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, request)
	}
	if err == nil {
		err = unix.SetNonblock(fd, true)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, errIO
	}
	f := os.NewFile(uintptr(fd), "owned-router-tun")
	if f == nil {
		_ = unix.Close(fd)
		return nil, errIO
	}
	return f, nil
}

func (r *natRouter) start() {
	r.started = true
	go func() { r.done <- inNamespace(r.namespace, r.run) }()
}
func (r *natRouter) run() error {
	out := make(chan datagram, QueueCapacity)
	in := make(chan natReply, QueueCapacity)
	fail := r.failure
	r.readers.Add(1)
	go func() {
		defer r.readers.Done()
		buf := make([]byte, 28+maxDatagramBytes+1)
		defer clear(buf)
		for {
			n, e := r.tun.Read(buf)
			if e != nil {
				select {
				case fail <- errIO:
				case <-r.ctx.Done():
				}
				return
			}
			p, e := parseUDP(buf[:n])
			if e != nil {
				r.dropped.Add(1)
				continue
			}
			select {
			case out <- p:
			case <-r.ctx.Done():
				clear(p.payload)
				return
			}
		}
	}()
	defer func() {
		r.cancel()
		r.closeDescriptors()
		r.readers.Wait()
		for len(out) > 0 {
			p := <-out
			clear(p.payload)
		}
		for len(in) > 0 {
			p := <-in
			clear(p.payload)
		}
	}()
	private := netip.MustParsePrefix(r.cfg.EndpointPrefix).Addr()
	for {
		select {
		case <-r.ctx.Done():
			return nil
		case e := <-fail:
			if r.ctx.Err() != nil {
				return nil
			}
			return e
		case p := <-out:
			if r.ctx.Err() != nil {
				clear(p.payload)
				return nil
			}
			allowed := p.target.Addr() == r.peer
			for _, o := range r.observers {
				allowed = allowed || p.target == o
			}
			if p.source.Addr() != private || !allowed || len(p.payload) > maxDatagramBytes {
				clear(p.payload)
				return ErrResource
			}
			e := r.forward(p, in)
			clear(p.payload)
			if e != nil {
				return e
			}
		case p := <-in:
			if r.ctx.Err() != nil {
				clear(p.payload)
				return nil
			}
			if !p.mapping.allowed[p.source] {
				r.dropped.Add(1)
				clear(p.payload)
				continue
			}
			if r.in.Load() >= RouterPacketCap {
				clear(p.payload)
				return ErrResource
			}
			b, e := encodeUDP(p.source, p.mapping.local, p.payload)
			clear(p.payload)
			if e != nil {
				return e
			}
			_ = r.tun.SetWriteDeadline(time.Now().Add(QueryTimeout))
			n, e := r.tun.Write(b)
			clear(b)
			if e != nil || n != len(b) {
				return errIO
			}
			r.in.Add(1)
		}
	}
}

func (r *natRouter) forward(p datagram, replies chan<- natReply) error {
	if r.out.Load() >= RouterPacketCap {
		return ErrResource
	}
	key := natKey{local: p.source}
	if r.cfg.Mode != "eim/1" {
		key.target = p.target
	}
	m := r.mappings[key]
	if m == nil {
		// The only mapping writer reserves before every OS socket open.
		if len(r.mappings) >= MappingHardCap {
			return ErrResource
		}
		// Shared across both domains, charged before open and never refunded
		// during this one-shot invocation (including a failed bind).
		if r.budget.Add(1) > MappingHardCap {
			return ErrResource
		}
		port, e := r.reservePort(p.target)
		if e != nil {
			return e
		}
		local := netip.AddrPortFrom(netip.MustParsePrefix(r.cfg.PublicPrefix).Addr(), port)
		// Serialize publication with terminal close. No fd may be opened after
		// closeDescriptors has taken ownership of the descriptor set.
		r.mu.Lock()
		if r.closed || r.ctx.Err() != nil {
			r.mu.Unlock()
			return context.Canceled
		}
		connected := r.cfg.Mode == "apdm_uniform16/1"
		conn, e := openMapping(r.ctx, local, p.target, connected)
		if e != nil {
			r.mu.Unlock()
			return e
		}
		m = &natMapping{conn: conn, local: p.source, public: local, allowed: map[netip.AddrPort]bool{}, created: time.Now(), ordinal: len(r.mappings), connected: connected}
		r.mappings[key] = m
		r.all = append(r.all, m)
		r.peak.Store(uint64(len(r.all)))
		r.mu.Unlock()
		r.readers.Add(1)
		go r.readMapping(m, replies)
	}
	m.allowed[p.target] = true
	m.last = time.Now()
	_ = m.conn.SetWriteDeadline(time.Now().Add(QueryTimeout))
	var n int
	var e error
	if m.connected {
		n, e = m.conn.Write(p.payload)
	} else {
		n, e = m.conn.WriteToUDPAddrPort(p.payload, p.target)
	}
	if e != nil || n != len(p.payload) {
		return errIO
	}
	r.out.Add(1)
	if p.target.Addr() == r.peer {
		select {
		case r.samples <- mappingSample{m.public, p.target, r.cfg.Role, strconv.Itoa(m.ordinal), m.created, m.last, time.Now()}:
		default:
			r.dropped.Add(1)
		}
	}
	return nil
}

func (r *natRouter) reservePort(target netip.AddrPort) (uint16, error) {
	if r.cfg.Mode == "apdm_uniform16/1" {
		ordinal := r.perTarget[target]
		if ordinal >= 16384 {
			return 0, ErrResource
		}
		r.perTarget[target] = ordinal + 1
		// Six-round 14-bit Feistel is a deterministic model permutation, not
		// a handshake primitive. Each remote gets its own complete universe;
		// connected sockets may reuse a public port across different remotes.
		key := sha256.Sum256(append(append([]byte(nil), r.allocationKey[:]...), []byte(target.String())...))
		left, right := byte(ordinal>>7), byte(ordinal&127)
		for round := byte(0); round < 6; round++ {
			var input [34]byte
			copy(input[:32], key[:])
			input[32], input[33] = round, right
			h := sha256.Sum256(input[:])
			left, right = right, left^(h[0]&127)
		}
		return 49152 + (uint16(left) << 7) + uint16(right), nil
	}
	if r.next >= 9000 {
		return 0, ErrResource
	}
	port := uint16(40000 + r.next)
	r.next++
	return port, nil
}

// owner=sealed-router; called only inside the owned NAT namespace and after
// the mapping cap. Neither the endpoint nor probeio can consume this socket.
func openMapping(ctx context.Context, local, target netip.AddrPort, connected bool) (*net.UDPConn, error) {
	if connected {
		dialer := net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(local), Control: func(_, _ string, raw syscall.RawConn) error {
			var failure error
			if e := raw.Control(func(fd uintptr) {
				if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
					failure = e
					return
				}
				failure = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); e != nil {
				return e
			}
			return failure
		}}
		conn, e := dialer.DialContext(ctx, "udp4", target.String())
		if e != nil {
			return nil, errIO
		}
		udp, ok := conn.(*net.UDPConn)
		if !ok {
			_ = conn.Close()
			return nil, errIO
		}
		return udp, nil
	}
	c, e := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(local))
	if e != nil {
		return nil, errIO
	}
	return c, nil
}
func (r *natRouter) readMapping(m *natMapping, replies chan<- natReply) {
	defer r.readers.Done()
	buf := make([]byte, maxDatagramBytes+1)
	defer clear(buf)
	for {
		n, source, e := m.conn.ReadFromUDPAddrPort(buf)
		if e != nil {
			if r.ctx.Err() == nil {
				select {
				case r.failure <- errIO:
				case <-r.ctx.Done():
				}
			}
			return
		}
		if n > maxDatagramBytes {
			select {
			case r.failure <- ErrResource:
			case <-r.ctx.Done():
			}
			return
		}
		p := append([]byte(nil), buf[:n]...)
		select {
		case replies <- natReply{m, source, p}:
		case <-r.ctx.Done():
			clear(p)
			return
		}
	}
}
func (r *natRouter) closeDescriptors() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.tun != nil {
		_ = r.tun.Close()
	}
	for _, m := range r.all {
		_ = m.conn.Close()
	}
}
func (r *natRouter) close() error {
	r.cancel()
	if !r.started {
		r.closeDescriptors()
		return nil
	}
	select {
	case e := <-r.done:
		if errors.Is(e, context.Canceled) {
			return nil
		}
		return e
	case <-time.After(DrainTimeout):
		return ErrDrain
	}
}
