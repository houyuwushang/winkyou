package netif

import (
	"errors"
	"net"
	"sync"
)

var (
	errIPv4Required  = errors.New("netif: ipv4 address required")
	errMaskRequired  = errors.New("netif: ipv4 mask required")
	errRouteRequired = errors.New("netif: route destination required")
)

type routeEntry struct {
	dst     *net.IPNet
	gateway net.IP
}

// memoryInterface is a stateful in-memory NetworkInterface implementation.
// It stores interface configuration and packets in process memory only.
type memoryInterface struct {
	name   string
	ifType string
	mtu    int

	mu            sync.Mutex
	readCond      *sync.Cond
	writeCond     *sync.Cond
	closed        bool
	outboundQueue [][]byte
	inboundQueue  [][]byte

	ip     net.IP
	mask   net.IPMask
	routes map[string]routeEntry
}

func newMemoryInterface(cfg Config) *memoryInterface {
	m := &memoryInterface{
		name:   "wink0",
		ifType: cfg.Backend,
		mtu:    cfg.MTU,
		routes: make(map[string]routeEntry),
	}
	m.readCond = sync.NewCond(&m.mu)
	m.writeCond = sync.NewCond(&m.mu)
	return m
}

func (m *memoryInterface) Name() string { return m.name }
func (m *memoryInterface) Type() string { return m.ifType }
func (m *memoryInterface) MTU() int     { return m.mtu }

func (m *memoryInterface) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for len(m.outboundQueue) == 0 && !m.closed {
		m.readCond.Wait()
	}

	if len(m.outboundQueue) == 0 && m.closed {
		return 0, net.ErrClosed
	}

	packet := m.outboundQueue[0]
	m.outboundQueue[0] = nil
	m.outboundQueue = m.outboundQueue[1:]
	return copy(buf, packet), nil
}

func (m *memoryInterface) Write(buf []byte) (int, error) {
	return m.enqueueInbound(buf)
}

func (m *memoryInterface) InjectPacket(buf []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, net.ErrClosed
	}
	if len(buf) == 0 {
		return 0, nil
	}

	packet := append([]byte(nil), buf...)
	m.outboundQueue = append(m.outboundQueue, packet)
	m.readCond.Signal()
	return len(packet), nil
}

func (m *memoryInterface) ReceivePacket(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for len(m.inboundQueue) == 0 && !m.closed {
		m.writeCond.Wait()
	}

	if len(m.inboundQueue) == 0 && m.closed {
		return 0, net.ErrClosed
	}

	packet := m.inboundQueue[0]
	m.inboundQueue[0] = nil
	m.inboundQueue = m.inboundQueue[1:]
	return copy(buf, packet), nil
}

func (m *memoryInterface) enqueueInbound(buf []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, net.ErrClosed
	}
	if len(buf) == 0 {
		return 0, nil
	}

	packet := append([]byte(nil), buf...)
	m.inboundQueue = append(m.inboundQueue, packet)
	m.writeCond.Signal()
	return len(packet), nil
}

func (m *memoryInterface) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true
	m.readCond.Broadcast()
	m.writeCond.Broadcast()
	return nil
}

func (m *memoryInterface) SetIP(ip net.IP, mask net.IPMask) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return net.ErrClosed
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return errIPv4Required
	}
	if mask == nil {
		return errMaskRequired
	}

	m.ip = cloneIP(ip4)
	m.mask = cloneMask(mask)
	return nil
}

func (m *memoryInterface) AddRoute(dst *net.IPNet, gateway net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return net.ErrClosed
	}
	if dst == nil {
		return errRouteRequired
	}

	normalized := cloneIPNet(dst)
	m.routes[routeKey(normalized)] = routeEntry{
		dst:     normalized,
		gateway: cloneIP(gateway),
	}
	return nil
}

func (m *memoryInterface) RemoveRoute(dst *net.IPNet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return net.ErrClosed
	}
	if dst == nil {
		return errRouteRequired
	}

	delete(m.routes, routeKey(dst))
	return nil
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func cloneMask(mask net.IPMask) net.IPMask {
	if mask == nil {
		return nil
	}
	return append(net.IPMask(nil), mask...)
}

func cloneIPNet(dst *net.IPNet) *net.IPNet {
	if dst == nil {
		return nil
	}

	cloned := &net.IPNet{
		IP:   cloneIP(dst.IP),
		Mask: cloneMask(dst.Mask),
	}
	if cloned.IP != nil && cloned.Mask != nil {
		cloned.IP = cloned.IP.Mask(cloned.Mask)
	}
	return cloned
}

func routeKey(dst *net.IPNet) string {
	if dst == nil {
		return ""
	}
	return cloneIPNet(dst).String()
}
