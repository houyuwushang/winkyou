package session

import (
	"context"
	"fmt"
	"net"
	"time"

	"winkyou/pkg/transport"
	"winkyou/pkg/tunnel"
)

type Binder interface {
	Bind(ctx context.Context, peerID string, pt transport.PacketTransport) error
	Unbind(ctx context.Context, peerID string) error
}

type BindingPeer struct {
	PublicKey  tunnel.PublicKey
	AllowedIPs []net.IPNet
	Endpoint   *net.UDPAddr
	Keepalive  time.Duration
}

type BindingPeerProvider interface {
	BindingPeer(ctx context.Context, peerID string) (*BindingPeer, error)
}

type TunnelBinder struct {
	tun      tunnel.Tunnel
	provider BindingPeerProvider
}

func NewTunnelBinder(tun tunnel.Tunnel, provider BindingPeerProvider) *TunnelBinder {
	return &TunnelBinder{tun: tun, provider: provider}
}

func (b *TunnelBinder) Bind(ctx context.Context, peerID string, pt transport.PacketTransport) error {
	if b == nil || b.tun == nil {
		return fmt.Errorf("session: tunnel binder is nil")
	}
	if b.provider == nil {
		return fmt.Errorf("session: binding peer provider is nil")
	}
	peer, err := b.provider.BindingPeer(ctx, peerID)
	if err != nil {
		return err
	}
	cfg := &tunnel.PeerConfig{
		PublicKey:  peer.PublicKey,
		AllowedIPs: append([]net.IPNet(nil), peer.AllowedIPs...),
		Endpoint:   cloneUDPAddr(peer.Endpoint),
		Transport:  pt,
		Keepalive:  peer.Keepalive,
	}
	if cfg.Endpoint == nil {
		cfg.Endpoint = udpAddrFromAddr(pt.RemoteAddr())
	}
	return b.tun.AddPeer(cfg)
}

func (b *TunnelBinder) Unbind(ctx context.Context, peerID string) error {
	if b == nil || b.tun == nil || b.provider == nil {
		return nil
	}
	peer, err := b.provider.BindingPeer(ctx, peerID)
	if err != nil {
		return err
	}
	return b.tun.RemovePeer(peer.PublicKey)
}

func udpAddrFromAddr(addr net.Addr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return cloneUDPAddr(udpAddr)
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	port, err := net.LookupPort("udp", portText)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}
