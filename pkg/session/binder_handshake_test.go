package session

import (
	"context"
	"errors"
	"net"
	"testing"

	"winkyou/pkg/tunnel"
)

func TestTunnelBinderInitiatesTrustedPeerExactlyOnce(t *testing.T) {
	peerKey := tunnel.PublicKey{7}
	tun := &oneShotTunnel{events: make(chan tunnel.TunnelEvent)}
	provider := &oneShotPeerProvider{peer: &BindingPeer{PublicKey: peerKey}}
	binder := NewTunnelBinder(tun, provider)
	if err := binder.InitiateHandshake(context.Background(), "trusted-peer-ref"); err != nil {
		t.Fatal(err)
	}
	if tun.initiated != peerKey || provider.lastPeerID != "trusted-peer-ref" {
		t.Fatalf("trusted binding not used: key=%v peer_ref=%q", tun.initiated, provider.lastPeerID)
	}
	if err := binder.InitiateHandshake(context.Background(), "trusted-peer-ref"); !errors.Is(err, tunnel.ErrHandshakeAlreadyInitiated) {
		t.Fatalf("second initiation = %v", err)
	}
}

func TestTunnelBinderInitiateHonorsCallerCancellation(t *testing.T) {
	tun := &oneShotTunnel{events: make(chan tunnel.TunnelEvent)}
	provider := &oneShotPeerProvider{peer: &BindingPeer{PublicKey: tunnel.PublicKey{8}}}
	binder := NewTunnelBinder(tun, provider)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := binder.InitiateHandshake(ctx, "trusted-peer-ref"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled initiation = %v", err)
	}
	if tun.calls != 0 || provider.lastPeerID != "" {
		t.Fatal("canceled initiation reached trusted provider or tunnel")
	}
}

type oneShotPeerProvider struct {
	peer       *BindingPeer
	lastPeerID string
}

func (provider *oneShotPeerProvider) BindingPeer(_ context.Context, peerID string) (*BindingPeer, error) {
	provider.lastPeerID = peerID
	return provider.peer, nil
}

type oneShotTunnel struct {
	initiated tunnel.PublicKey
	calls     int
	events    chan tunnel.TunnelEvent
}

func (oneShot *oneShotTunnel) Start() error                                            { return nil }
func (oneShot *oneShotTunnel) Stop() error                                             { return nil }
func (oneShot *oneShotTunnel) AddPeer(*tunnel.PeerConfig) error                        { return nil }
func (oneShot *oneShotTunnel) RemovePeer(tunnel.PublicKey) error                       { return nil }
func (oneShot *oneShotTunnel) UpdatePeerEndpoint(tunnel.PublicKey, *net.UDPAddr) error { return nil }
func (oneShot *oneShotTunnel) GetPeers() []*tunnel.PeerStatus                          { return nil }
func (oneShot *oneShotTunnel) GetStats() *tunnel.TunnelStats                           { return &tunnel.TunnelStats{} }
func (oneShot *oneShotTunnel) Events() <-chan tunnel.TunnelEvent                       { return oneShot.events }
func (oneShot *oneShotTunnel) InitiatePeerHandshake(publicKey tunnel.PublicKey) error {
	oneShot.calls++
	if oneShot.calls > 1 {
		return tunnel.ErrHandshakeAlreadyInitiated
	}
	oneShot.initiated = publicKey
	return nil
}

var _ tunnel.Tunnel = (*oneShotTunnel)(nil)
var _ tunnel.OneShotHandshakeInitiator = (*oneShotTunnel)(nil)
