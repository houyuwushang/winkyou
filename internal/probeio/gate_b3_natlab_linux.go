//go:build linux && natlab

package probeio

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
)

const (
	hardNATCampaignPortMin = 49152
	hardNATCampaignPortMax = 65535
)

type hardNATCampaignNATLabFactory struct {
	namespace string
	udp       *UDPFactory
	observers [4]netip.AddrPort
	local     netip.Addr
	peer      netip.Addr
	writes    atomic.Uint64
	enobufsAt uint64
}

// NewGateB3NATLabFactory exists only in linux+natlab builds. It reuses the
// reviewed fixed TEST-NET topology and namespace identity proof but narrows
// peer targets to the exact 49152-65535 campaign universe.
func NewGateB3NATLabFactory(namespace string, side GateB2NATLabSide, observers [4]netip.AddrPort) (HardNATCampaignNATLabFactory, error) {
	return newGateB3NATLabFactory(namespace, side, observers, 0)
}

// NewGateB3ENOBUFSNATLabFactory is the exact required-netns fault seam. It is
// absent from ordinary builds and injects ENOBUFS on the first write after the
// frozen 13-packet evidence slice. The fault cannot widen endpoint authority.
func NewGateB3ENOBUFSNATLabFactory(namespace string, side GateB2NATLabSide, observers [4]netip.AddrPort) (HardNATCampaignNATLabFactory, error) {
	return newGateB3NATLabFactory(namespace, side, observers, 14)
}

func newGateB3NATLabFactory(namespace string, side GateB2NATLabSide, observers [4]netip.AddrPort,
	enobufsAt uint64,
) (HardNATCampaignNATLabFactory, error) {
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
	udp, err := NewUDPFactory(UDPFactoryConfig{LocalAddr: netip.MustParseAddrPort("0.0.0.0:0"), AllowedTargetScope: AllowedTargetScopeUnicast})
	if err != nil {
		return nil, err
	}
	return &hardNATCampaignNATLabFactory{
		namespace: namespace, udp: udp, observers: observers, local: local, peer: peer, enobufsAt: enobufsAt,
	}, nil
}

func (*hardNATCampaignNATLabFactory) hardNATCampaignNATLabFactory() {}

func (factory *hardNATCampaignNATLabFactory) ValidateObserverEndpoints(endpoints [4]netip.AddrPort) error {
	if factory == nil || validateGateB2NATLabNamespace(factory.namespace) != nil ||
		validateGateB2ObserverEndpoints(endpoints) != nil || endpoints != factory.observers {
		return ErrInvalidConfig
	}
	return nil
}

func (factory *hardNATCampaignNATLabFactory) ValidatePeerAddress(address netip.Addr) error {
	if factory == nil || validateGateB2NATLabNamespace(factory.namespace) != nil || address.Unmap() != factory.peer {
		return ErrInvalidTarget
	}
	return nil
}

func (factory *hardNATCampaignNATLabFactory) ValidateLocalAddress(address netip.Addr) error {
	if factory == nil || validateGateB2NATLabNamespace(factory.namespace) != nil || address.Unmap() != factory.local {
		return ErrInvalidTarget
	}
	return nil
}

func (factory *hardNATCampaignNATLabFactory) Open(ctx context.Context) (Datagram, error) {
	if factory == nil || factory.udp == nil || validateGateB2NATLabNamespace(factory.namespace) != nil {
		return nil, ErrInvalidConfig
	}
	datagram, err := factory.udp.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &hardNATCampaignNATLabDatagram{
		Datagram: datagram, observers: factory.observers, peer: factory.peer,
		writes: &factory.writes, enobufsAt: factory.enobufsAt,
	}, nil
}

type hardNATCampaignNATLabDatagram struct {
	Datagram
	observers [4]netip.AddrPort
	peer      netip.Addr
	writes    *atomic.Uint64
	enobufsAt uint64
}

func (datagram *hardNATCampaignNATLabDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if datagram == nil || datagram.Datagram == nil || !hardNATCampaignNATLabTargetAllowed(target, datagram.observers, datagram.peer) {
		return 0, ErrInvalidTarget
	}
	if datagram.enobufsAt > 0 && datagram.writes != nil && datagram.writes.Add(1) >= datagram.enobufsAt {
		return 0, syscall.ENOBUFS
	}
	return datagram.Datagram.WriteTo(ctx, packet, target)
}

func (datagram *hardNATCampaignNATLabDatagram) LocalAddr() net.Addr {
	if datagram == nil || datagram.Datagram == nil {
		return nil
	}
	return datagram.Datagram.LocalAddr()
}

func hardNATCampaignNATLabTargetAllowed(target netip.AddrPort, observers [4]netip.AddrPort, peer netip.Addr) bool {
	if !target.IsValid() || target.Port() == 0 || target.Addr().Zone() != "" {
		return false
	}
	for _, observer := range observers {
		if target == observer {
			return true
		}
	}
	return target.Addr().Unmap() == peer && target.Port() >= hardNATCampaignPortMin && target.Port() <= hardNATCampaignPortMax
}
