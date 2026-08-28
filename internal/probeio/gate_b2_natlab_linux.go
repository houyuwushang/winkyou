//go:build linux && natlab

package probeio

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"regexp"
)

var gateB2NATLabNamespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

var (
	gateB2ObserverAddressA = netip.MustParseAddr("198.51.100.2")
	gateB2ObserverAddressB = netip.MustParseAddr("203.0.113.1")
	gateB2LeftPeerAddress  = netip.MustParseAddr("203.0.113.2")
	gateB2RightPeerAddress = netip.MustParseAddr("198.51.100.1")
)

// GateB2NATLabSide identifies one endpoint in the repository's fixed N2d/B2
// TEST-NET topology. It does not accept an address supplied by the caller.
type GateB2NATLabSide uint8

const (
	GateB2NATLabLeft GateB2NATLabSide = iota + 1
	GateB2NATLabRight
)

type gateB2NATLabFactory struct {
	namespace string
	udp       *UDPFactory
	observers [4]netip.AddrPort
	local     netip.Addr
	peer      netip.Addr
}

// NewGateB2NATLabFactory is deliberately unavailable without both linux and
// natlab build tags. It proves that the helper is already executing in the
// named namespace and freezes the only non-loopback addresses the wrapped OS
// datagram may contact.
func NewGateB2NATLabFactory(namespace string, side GateB2NATLabSide, observers [4]netip.AddrPort) (IsolatedNATLabFactory, error) {
	if !gateB2NATLabNamespacePattern.MatchString(namespace) || validateGateB2NATLabNamespace(namespace) != nil ||
		validateGateB2ObserverEndpoints(observers) != nil {
		return nil, ErrInvalidConfig
	}
	local, peer := gateB2RightPeerAddress, gateB2LeftPeerAddress
	if side == GateB2NATLabRight {
		local, peer = gateB2LeftPeerAddress, gateB2RightPeerAddress
	} else if side != GateB2NATLabLeft {
		return nil, ErrInvalidConfig
	}
	udp, err := NewUDPFactory(UDPFactoryConfig{
		LocalAddr:          netip.MustParseAddrPort("0.0.0.0:0"),
		AllowedTargetScope: AllowedTargetScopeUnicast,
	})
	if err != nil {
		return nil, err
	}
	return &gateB2NATLabFactory{namespace: namespace, udp: udp, observers: observers, local: local, peer: peer}, nil
}

func (factory *gateB2NATLabFactory) isolatedNATLabFactory() {}

func (factory *gateB2NATLabFactory) ValidateObserverEndpoints(endpoints [4]netip.AddrPort) error {
	if factory == nil || validateGateB2NATLabNamespace(factory.namespace) != nil ||
		validateGateB2ObserverEndpoints(endpoints) != nil || endpoints != factory.observers {
		return ErrInvalidConfig
	}
	return nil
}

func (factory *gateB2NATLabFactory) ValidatePeerAddress(address netip.Addr) error {
	if factory == nil || validateGateB2NATLabNamespace(factory.namespace) != nil || address.Unmap() != factory.peer {
		return ErrInvalidTarget
	}
	return nil
}

func (factory *gateB2NATLabFactory) ValidateLocalAddress(address netip.Addr) error {
	if factory == nil || validateGateB2NATLabNamespace(factory.namespace) != nil || address.Unmap() != factory.local {
		return ErrInvalidTarget
	}
	return nil
}

func (factory *gateB2NATLabFactory) Open(ctx context.Context) (Datagram, error) {
	if factory == nil || factory.udp == nil || validateGateB2NATLabNamespace(factory.namespace) != nil {
		return nil, ErrInvalidConfig
	}
	datagram, err := factory.udp.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &gateB2NATLabDatagram{Datagram: datagram, observers: factory.observers, peer: factory.peer}, nil
}

type gateB2NATLabDatagram struct {
	Datagram
	observers [4]netip.AddrPort
	peer      netip.Addr
}

func (datagram *gateB2NATLabDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if datagram == nil || datagram.Datagram == nil || !gateB2NATLabTargetAllowed(target, datagram.observers, datagram.peer) {
		return 0, ErrInvalidTarget
	}
	return datagram.Datagram.WriteTo(ctx, packet, target)
}

func (datagram *gateB2NATLabDatagram) LocalAddr() net.Addr {
	if datagram == nil || datagram.Datagram == nil {
		return nil
	}
	return datagram.Datagram.LocalAddr()
}

func gateB2NATLabTargetAllowed(target netip.AddrPort, observers [4]netip.AddrPort, peer netip.Addr) bool {
	if !target.IsValid() || target.Port() == 0 || target.Addr().Zone() != "" {
		return false
	}
	address := target.Addr().Unmap()
	if address == peer {
		return true
	}
	for _, observer := range observers {
		if target == observer {
			return true
		}
	}
	return false
}

func validateGateB2ObserverEndpoints(endpoints [4]netip.AddrPort) error {
	for _, endpoint := range endpoints {
		if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" || !endpoint.Addr().Is4() {
			return ErrInvalidTarget
		}
	}
	if endpoints[0].Addr().Unmap() != gateB2ObserverAddressA || endpoints[1].Addr().Unmap() != gateB2ObserverAddressA ||
		endpoints[2].Addr().Unmap() != gateB2ObserverAddressB || endpoints[3].Addr().Unmap() != gateB2ObserverAddressB ||
		endpoints[0].Port() != endpoints[2].Port() || endpoints[1].Port() != endpoints[3].Port() ||
		endpoints[0].Port() == endpoints[1].Port() {
		return ErrInvalidTarget
	}
	return nil
}

func validateGateB2NATLabNamespace(namespace string) error {
	if !gateB2NATLabNamespacePattern.MatchString(namespace) {
		return ErrInvalidConfig
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return errors.Join(ErrInvalidConfig, err)
	}
	expected, err := os.Stat("/var/run/netns/" + namespace)
	if err != nil {
		return errors.Join(ErrInvalidConfig, err)
	}
	if !os.SameFile(current, expected) {
		return ErrInvalidConfig
	}
	return nil
}
