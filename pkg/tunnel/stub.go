package tunnel

import (
	"errors"
	"net"
	"sync"
)

// stubTunnel is a skeleton Tunnel implementation that satisfies the
// interface contract but returns ErrNotImplemented for all operational
// methods. Used during development until the wireguard-go backend is
// wired up in tunnel_wggo.go.
type stubTunnel struct {
	cfg    Config
	events chan TunnelEvent

	mu      sync.RWMutex
	started bool
	peers   map[PublicKey]*PeerStatus
}

func newStubTunnel(cfg Config) *stubTunnel {
	return &stubTunnel{
		cfg:    cfg,
		events: make(chan TunnelEvent, 64),
		peers:  make(map[PublicKey]*PeerStatus),
	}
}

func (s *stubTunnel) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("tunnel: already started")
	}
	s.started = true
	return ErrNotImplemented
}

func (s *stubTunnel) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = false
	return nil
}

func (s *stubTunnel) AddPeer(peer *PeerConfig) error {
	return ErrNotImplemented
}

func (s *stubTunnel) RemovePeer(publicKey PublicKey) error {
	return ErrNotImplemented
}

func (s *stubTunnel) UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error {
	return ErrNotImplemented
}

func (s *stubTunnel) GetPeers() []*PeerStatus {
	return nil
}

func (s *stubTunnel) GetStats() *TunnelStats {
	return &TunnelStats{}
}

func (s *stubTunnel) Events() <-chan TunnelEvent {
	return s.events
}
