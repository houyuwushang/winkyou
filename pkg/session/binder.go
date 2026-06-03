package session

import (
	"context"
	"fmt"
	"net"
	"time"

	"winkyou/pkg/netutil"
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
		Endpoint:   netutil.CloneUDPAddr(peer.Endpoint),
		Transport:  pt,
		Keepalive:  peer.Keepalive,
	}
	if cfg.Endpoint == nil {
		cfg.Endpoint = netutil.UDPAddrFromAddr(pt.RemoteAddr())
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
