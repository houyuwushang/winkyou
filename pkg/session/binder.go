package session

import (
	"context"
	"errors"
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

// OneShotHandshakeBinder is the narrow post-bind trigger used by the Gate C
// foreground composition. It cannot request retries or replace the peer.
type OneShotHandshakeBinder interface {
	InitiateHandshake(ctx context.Context, peerID string) error
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

type peerReplacingTunnel interface {
	ReplacePeer(peer *tunnel.PeerConfig) error
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
	if err := b.tun.AddPeer(cfg); err != nil {
		if errors.Is(err, tunnel.ErrPeerExists) {
			if replacer, ok := b.tun.(peerReplacingTunnel); ok {
				return replacer.ReplacePeer(cfg)
			}
		}
		return err
	}
	return nil
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

// InitiateHandshake resolves the peer only from the trusted local provider and
// invokes the tunnel's one-shot trigger. It does not stage an inner packet.
func (b *TunnelBinder) InitiateHandshake(ctx context.Context, peerID string) error {
	if b == nil || b.tun == nil || b.provider == nil || ctx == nil {
		return tunnel.ErrHandshakeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	peer, err := b.provider.BindingPeer(ctx, peerID)
	if err != nil {
		return err
	}
	initiator, ok := b.tun.(tunnel.OneShotHandshakeInitiator)
	if !ok {
		return tunnel.ErrHandshakeUnavailable
	}
	if err := initiator.InitiatePeerHandshake(peer.PublicKey); err != nil {
		return err
	}
	return ctx.Err()
}
