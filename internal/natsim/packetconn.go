package natsim

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var _ net.PacketConn = (*PacketConn)(nil)

type virtualDatagram struct {
	packet []byte
	source netip.AddrPort
}

// PacketConn is a pure-memory implementation of net.PacketConn.
type PacketConn struct {
	network   *Network
	localAddr netip.AddrPort
	natChain  []*NAT
	inbound   chan virtualDatagram
	closed    atomic.Bool
	closeOnce sync.Once
	closedCh  chan struct{}

	deadlineMu         sync.Mutex
	readDeadline       time.Time
	writeDeadline      time.Time
	readDeadlineChange chan struct{}
}

func newPacketConn(network *Network, local netip.AddrPort, chain []*NAT, queueCapacity int) *PacketConn {
	return &PacketConn{
		network:            network,
		localAddr:          local,
		natChain:           chain,
		inbound:            make(chan virtualDatagram, queueCapacity),
		closedCh:           make(chan struct{}),
		readDeadlineChange: make(chan struct{}),
	}
}

func (connection *PacketConn) ReadFrom(dst []byte) (int, net.Addr, error) {
	if connection == nil || connection.network == nil || connection.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	for {
		deadline, changed := connection.readDeadlineSnapshot()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}
		select {
		case datagram := <-connection.inbound:
			stopTimer(timer)
			connection.network.consumeQueued()
			if connection.closed.Load() {
				return 0, nil, net.ErrClosed
			}
			n := copy(dst, datagram.packet)
			return n, net.UDPAddrFromAddrPort(datagram.source), nil
		case <-connection.closedCh:
			stopTimer(timer)
			return 0, nil, net.ErrClosed
		case <-changed:
			stopTimer(timer)
			continue
		case <-timerC:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (connection *PacketConn) WriteTo(packet []byte, address net.Addr) (int, error) {
	if connection == nil || connection.network == nil || connection.closed.Load() {
		return 0, net.ErrClosed
	}
	if deadline := connection.writeDeadlineSnapshot(); !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	destination, err := endpointFromNetAddr(address)
	if err != nil {
		return 0, err
	}
	n, err := connection.network.transmit(connection, packet, destination)
	if errors.Is(err, ErrClosed) {
		return 0, net.ErrClosed
	}
	return n, err
}

// WriteToAddrPort is the zero-OS-I/O value adapter for simulation packages
// that must not import net merely to construct a UDPAddr. It has the same
// deadline, copy, routing, and resource semantics as WriteTo.
func (connection *PacketConn) WriteToAddrPort(packet []byte, destination netip.AddrPort) (int, error) {
	if connection == nil || connection.network == nil || connection.closed.Load() {
		return 0, net.ErrClosed
	}
	if deadline := connection.writeDeadlineSnapshot(); !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := validateEndpoint(destination); err != nil {
		return 0, err
	}
	n, err := connection.network.transmit(connection, packet, destination)
	if errors.Is(err, ErrClosed) {
		return 0, net.ErrClosed
	}
	return n, err
}

// TryReadFromAddrPort consumes one already queued in-memory datagram without
// blocking. ok=false means the deterministic queue is currently empty. It
// never starts a timer or touches an operating-system socket.
func (connection *PacketConn) TryReadFromAddrPort(dst []byte) (n int, source netip.AddrPort, ok bool, err error) {
	if connection == nil || connection.network == nil || connection.closed.Load() {
		return 0, netip.AddrPort{}, false, net.ErrClosed
	}
	select {
	case datagram := <-connection.inbound:
		connection.network.consumeQueued()
		if connection.closed.Load() {
			clear(datagram.packet)
			return 0, netip.AddrPort{}, false, net.ErrClosed
		}
		if len(datagram.packet) > len(dst) {
			copy(dst, datagram.packet[:len(dst)])
			clear(datagram.packet)
			return len(dst), datagram.source, true, io.ErrShortBuffer
		}
		copy(dst, datagram.packet)
		clear(datagram.packet)
		return len(datagram.packet), datagram.source, true, nil
	case <-connection.closedCh:
		return 0, netip.AddrPort{}, false, net.ErrClosed
	default:
		return 0, netip.AddrPort{}, false, nil
	}
}

func (connection *PacketConn) Close() error {
	if connection == nil {
		return nil
	}
	connection.closeOnce.Do(func() {
		connection.closed.Store(true)
		if connection.network != nil {
			connection.network.closePacketConn(connection)
		}
		close(connection.closedCh)
	})
	return nil
}

func (connection *PacketConn) LocalAddr() net.Addr {
	if connection == nil {
		return nil
	}
	return net.UDPAddrFromAddrPort(connection.localAddr)
}

func (connection *PacketConn) SetDeadline(deadline time.Time) error {
	if connection == nil || connection.closed.Load() {
		return net.ErrClosed
	}
	connection.deadlineMu.Lock()
	connection.readDeadline = deadline
	connection.writeDeadline = deadline
	close(connection.readDeadlineChange)
	connection.readDeadlineChange = make(chan struct{})
	connection.deadlineMu.Unlock()
	return nil
}

func (connection *PacketConn) SetReadDeadline(deadline time.Time) error {
	if connection == nil || connection.closed.Load() {
		return net.ErrClosed
	}
	connection.deadlineMu.Lock()
	connection.readDeadline = deadline
	close(connection.readDeadlineChange)
	connection.readDeadlineChange = make(chan struct{})
	connection.deadlineMu.Unlock()
	return nil
}

func (connection *PacketConn) SetWriteDeadline(deadline time.Time) error {
	if connection == nil || connection.closed.Load() {
		return net.ErrClosed
	}
	connection.deadlineMu.Lock()
	connection.writeDeadline = deadline
	connection.deadlineMu.Unlock()
	return nil
}

func (connection *PacketConn) readDeadlineSnapshot() (time.Time, <-chan struct{}) {
	connection.deadlineMu.Lock()
	defer connection.deadlineMu.Unlock()
	return connection.readDeadline, connection.readDeadlineChange
}

func (connection *PacketConn) writeDeadlineSnapshot() time.Time {
	connection.deadlineMu.Lock()
	defer connection.deadlineMu.Unlock()
	return connection.writeDeadline
}

func endpointFromNetAddr(address net.Addr) (netip.AddrPort, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok || udpAddress == nil {
		return netip.AddrPort{}, ErrInvalidConfig
	}
	endpoint := udpAddress.AddrPort()
	if err := validateEndpoint(endpoint); err != nil {
		return netip.AddrPort{}, err
	}
	return endpoint, nil
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
