package probeio

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const windowsWSAENOBUFS syscall.Errno = 10055

// AllowedTargetScope fixes the address class a UDPFactory may contact. Its
// zero value is deliberately loopback-only.
type AllowedTargetScope uint8

const (
	AllowedTargetScopeLoopback AllowedTargetScope = iota
	AllowedTargetScopeUnicast
)

// UDPFactoryConfig fixes the local address of one reviewed OS UDP opener.
// The default scope accepts loopback binds and targets only. Explicit unicast
// scope may additionally bind an unspecified address at ephemeral port zero,
// letting the OS select the concrete source address without granting callers
// an arbitrary interface or fixed-port bind.
type UDPFactoryConfig struct {
	LocalAddr          netip.AddrPort
	AllowedTargetScope AllowedTargetScope
}

// UDPFactory is the production, governor-owned Datagram factory. Its Open
// result is returned only through the Datagram interface, so callers cannot
// obtain the underlying *net.UDPConn or its file descriptor.
type UDPFactory struct {
	localAddr   netip.AddrPort
	targetScope AllowedTargetScope
}

type factoryOpenPermit struct {
	used atomic.Bool
}

type factoryOpenPermitKey struct{}

// NewUDPFactory constructs the reviewed Phase 1a UDP adapter. Loopback remains
// the default; selecting unicast is an explicit capability request but is not
// by itself authorization to perform live-network I/O.
func NewUDPFactory(config UDPFactoryConfig) (*UDPFactory, error) {
	if !config.AllowedTargetScope.valid() {
		return nil, fmt.Errorf("%w: unsupported target scope %d", ErrInvalidConfig, config.AllowedTargetScope)
	}
	local, err := canonicalLocalEndpoint(config.LocalAddr, config.AllowedTargetScope)
	if err != nil {
		return nil, fmt.Errorf("%w: local UDP bind: %v", ErrInvalidConfig, err)
	}
	return &UDPFactory{localAddr: local, targetScope: config.AllowedTargetScope}, nil
}

// Open creates one real OS UDP socket after Controller has reserved the socket
// budget. The only raw socket opener in the governed v2 dependency closure is
// openGovernedUDP below (architecture owner: governor).
func (factory *UDPFactory) Open(ctx context.Context) (Datagram, error) {
	if factory == nil {
		return nil, fmt.Errorf("%w: UDP factory is nil", ErrInvalidConfig)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !consumeFactoryOpenPermit(ctx) {
		return nil, ErrFactoryUnauthorized
	}

	network := "udp6"
	if factory.localAddr.Addr().Is4() {
		network = "udp4"
	}
	connection, err := openGovernedUDP(network, net.UDPAddrFromAddrPort(factory.localAddr))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return &udpDatagram{connection: connection, targetScope: factory.targetScope}, nil
}

func authorizeFactoryOpen(ctx context.Context) context.Context {
	return context.WithValue(ctx, factoryOpenPermitKey{}, &factoryOpenPermit{})
}

func consumeFactoryOpenPermit(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	permit, ok := ctx.Value(factoryOpenPermitKey{}).(*factoryOpenPermit)
	return ok && permit != nil && permit.used.CompareAndSwap(false, true)
}

// openGovernedUDP is the sole reviewed net.ListenUDP call owned by the
// governor/probeio boundary. Its caller has already restricted the bind to
// loopback or an unspecified ephemeral address. Keep this function small so
// the architecture inventory can identify the capability exactly.
func openGovernedUDP(network string, address *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP(network, address)
}

// IsResourceExhausted classifies the stable probeio sentinel and the operating
// system buffer exhaustion errors used by Unix and Windows UDP stacks.
func IsResourceExhausted(err error) bool {
	return errors.Is(err, ErrResourceExhausted) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, windowsWSAENOBUFS)
}

type udpDatagram struct {
	connection  *net.UDPConn
	targetScope AllowedTargetScope
	readMu      sync.Mutex
	writeMu     sync.Mutex
	closeOnce   sync.Once
	closeErr    error
}

func (datagram *udpDatagram) ReadFrom(ctx context.Context, dst []byte) (int, netip.AddrPort, error) {
	if datagram == nil || datagram.connection == nil {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	if ctx == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return 0, netip.AddrPort{}, err
	}

	datagram.readMu.Lock()
	defer datagram.readMu.Unlock()
	disarm, err := armContextDeadline(ctx, datagram.connection.SetReadDeadline)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	defer disarm()

	n, from, err := datagram.connection.ReadFromUDPAddrPort(dst)
	if mapped := contextErrorForIO(ctx, err); mapped != nil {
		return 0, netip.AddrPort{}, mapped
	}
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	canonical, canonicalErr := canonicalTargetEndpoint(from, datagram.targetScope)
	if canonicalErr != nil {
		return n, from, canonicalErr
	}
	return n, canonical, nil
}

func (datagram *udpDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if datagram == nil || datagram.connection == nil {
		return 0, net.ErrClosed
	}
	if ctx == nil {
		return 0, fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	canonical, err := canonicalTargetEndpoint(target, datagram.targetScope)
	if err != nil {
		return 0, err
	}

	datagram.writeMu.Lock()
	defer datagram.writeMu.Unlock()
	disarm, err := armContextDeadline(ctx, datagram.connection.SetWriteDeadline)
	if err != nil {
		return 0, err
	}
	defer disarm()

	n, err := datagram.connection.WriteToUDPAddrPort(packet, canonical)
	if mapped := contextErrorForIO(ctx, err); mapped != nil {
		return 0, mapped
	}
	return n, err
}

func (datagram *udpDatagram) SetDeadline(deadline time.Time) error {
	if datagram == nil || datagram.connection == nil {
		return net.ErrClosed
	}
	return datagram.connection.SetDeadline(deadline)
}

func (datagram *udpDatagram) LocalAddr() net.Addr {
	if datagram == nil || datagram.connection == nil {
		return nil
	}
	address, ok := datagram.connection.LocalAddr().(*net.UDPAddr)
	if !ok || address == nil {
		return nil
	}
	return net.UDPAddrFromAddrPort(address.AddrPort())
}

func (datagram *udpDatagram) allowsUnspecifiedLocalAddr() bool {
	return datagram != nil && datagram.targetScope == AllowedTargetScopeUnicast
}

func (datagram *udpDatagram) Close() error {
	if datagram == nil {
		return nil
	}
	datagram.closeOnce.Do(func() {
		if datagram.connection != nil {
			datagram.closeErr = datagram.connection.Close()
		}
	})
	return datagram.closeErr
}

func (scope AllowedTargetScope) valid() bool {
	return scope == AllowedTargetScopeLoopback || scope == AllowedTargetScopeUnicast
}

func canonicalLocalEndpoint(endpoint netip.AddrPort, scope AllowedTargetScope) (netip.AddrPort, error) {
	if !endpoint.IsValid() || endpoint.Addr().Zone() != "" {
		return netip.AddrPort{}, ErrInvalidTarget
	}
	address := endpoint.Addr().Unmap()
	if address.IsLoopback() {
		return netip.AddrPortFrom(address, endpoint.Port()), nil
	}
	if scope == AllowedTargetScopeUnicast && address.IsUnspecified() && endpoint.Port() == 0 {
		return netip.AddrPortFrom(address, 0), nil
	}
	return netip.AddrPort{}, ErrInvalidTarget
}

func canonicalTargetEndpoint(endpoint netip.AddrPort, scope AllowedTargetScope) (netip.AddrPort, error) {
	if !endpoint.IsValid() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		return netip.AddrPort{}, ErrInvalidTarget
	}
	address := endpoint.Addr().Unmap()
	if !address.IsLoopback() && (scope != AllowedTargetScopeUnicast || !address.IsGlobalUnicast()) {
		return netip.AddrPort{}, ErrInvalidTarget
	}
	return netip.AddrPortFrom(address, endpoint.Port()), nil
}

// contextErrorForIO deterministically attributes an I/O result to the context
// when the context is responsible. armContextDeadline makes the armed context
// deadline the only OS deadline during a governed read or write, and the OS
// timer often fires a moment before ctx.Err() is set; a timeout with a
// deadline-carrying context therefore always belongs to the context.
func contextErrorForIO(ctx context.Context, err error) error {
	// A completed system call is the emission/receipt commit point. The
	// context may be cancelled immediately after the kernel has accepted a
	// datagram; rewriting that successful result as cancellation would make
	// the caller under-count a packet that was actually emitted. Cancellation
	// remains authoritative when the I/O itself reports an error.
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var networkErr net.Error
	if !errors.As(err, &networkErr) || !networkErr.Timeout() {
		return nil
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return context.DeadlineExceeded
	}
	return nil
}

func armContextDeadline(ctx context.Context, setDeadline func(time.Time) error) (func(), error) {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Time{}
	}
	if err := setDeadline(deadline); err != nil {
		return nil, err
	}

	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())
		close(fired)
	})
	return func() {
		if !stop() {
			<-fired
		}
		_ = setDeadline(time.Time{})
	}, nil
}
