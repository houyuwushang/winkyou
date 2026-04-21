package tunnel

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// memTunnel is a stateful in-memory Tunnel implementation.
// It maintains peer state and emits events, but does no real network I/O.
// Designed to be driven by pkg/client orchestration and integration tests.
type memTunnel struct {
	cfg    Config
	events chan TunnelEvent

	mu      sync.RWMutex
	started bool
	stopped bool
	peers   map[PublicKey]*PeerStatus
}

func newMemTunnel(cfg Config) *memTunnel {
	return &memTunnel{
		cfg:    cfg,
		events: make(chan TunnelEvent, 64),
		peers:  make(map[PublicKey]*PeerStatus),
	}
}

func (m *memTunnel) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return errors.New("tunnel: already started")
	}
	m.started = true
	m.stopped = false
	return nil
}

func (m *memTunnel) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = false
	m.stopped = true
	return nil
}

func (m *memTunnel) AddPeer(peer *PeerConfig) error {
	if peer == nil {
		return errors.New("tunnel: peer config is nil")
	}
	if peer.PublicKey == (PublicKey{}) {
		return errors.New("tunnel: peer public key is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.peers[peer.PublicKey]; exists {
		return fmt.Errorf("tunnel: peer %s already exists", peer.PublicKey)
	}

	// Deep-copy AllowedIPs.
	var allowedIPs []net.IPNet
	for _, ipn := range peer.AllowedIPs {
		cp := net.IPNet{
			IP:   make(net.IP, len(ipn.IP)),
			Mask: make(net.IPMask, len(ipn.Mask)),
		}
		copy(cp.IP, ipn.IP)
		copy(cp.Mask, ipn.Mask)
		allowedIPs = append(allowedIPs, cp)
	}

	var ep *net.UDPAddr
	if peer.Endpoint != nil {
		ep = &net.UDPAddr{
			IP:   make(net.IP, len(peer.Endpoint.IP)),
			Port: peer.Endpoint.Port,
		}
		copy(ep.IP, peer.Endpoint.IP)
	}

	m.peers[peer.PublicKey] = &PeerStatus{
		PublicKey:  peer.PublicKey,
		Endpoint:   ep,
		AllowedIPs: allowedIPs,
	}

	m.emitLocked(TunnelEvent{
		Type:      EventPeerAdded,
		PeerKey:   peer.PublicKey,
		Timestamp: time.Now(),
	})

	return nil
}

func (m *memTunnel) RemovePeer(publicKey PublicKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.peers[publicKey]; !exists {
		return fmt.Errorf("tunnel: peer %s not found", publicKey)
	}

	delete(m.peers, publicKey)

	m.emitLocked(TunnelEvent{
		Type:      EventPeerRemoved,
		PeerKey:   publicKey,
		Timestamp: time.Now(),
	})

	return nil
}

func (m *memTunnel) UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ps, exists := m.peers[publicKey]
	if !exists {
		return fmt.Errorf("tunnel: peer %s not found", publicKey)
	}

	if endpoint != nil {
		ps.Endpoint = &net.UDPAddr{
			IP:   make(net.IP, len(endpoint.IP)),
			Port: endpoint.Port,
		}
		copy(ps.Endpoint.IP, endpoint.IP)
	} else {
		ps.Endpoint = nil
	}

	m.emitLocked(TunnelEvent{
		Type:      EventPeerEndpointChanged,
		PeerKey:   publicKey,
		Timestamp: time.Now(),
	})

	return nil
}

// GetPeers returns a deep-copied, deterministically sorted snapshot.
func (m *memTunnel) GetPeers() []*PeerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*PeerStatus, 0, len(m.peers))
	for _, ps := range m.peers {
		result = append(result, clonePeerStatus(ps))
	}

	// Sort by PublicKey bytes for deterministic output.
	sort.Slice(result, func(i, j int) bool {
		ki := result[i].PublicKey
		kj := result[j].PublicKey
		for b := 0; b < 32; b++ {
			if ki[b] != kj[b] {
				return ki[b] < kj[b]
			}
		}
		return false
	})

	return result
}

func (m *memTunnel) GetStats() *TunnelStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var stats TunnelStats
	stats.Peers = len(m.peers)
	for _, ps := range m.peers {
		stats.TxBytes += ps.TxBytes
		stats.RxBytes += ps.RxBytes
	}
	return &stats
}

func (m *memTunnel) Events() <-chan TunnelEvent {
	return m.events
}

// emitLocked sends an event on the events channel without blocking.
// Must be called with m.mu held.
func (m *memTunnel) emitLocked(ev TunnelEvent) {
	select {
	case m.events <- ev:
	default:
		// Channel full; drop oldest to make room.
		select {
		case <-m.events:
		default:
		}
		select {
		case m.events <- ev:
		default:
		}
	}
}

// clonePeerStatus returns a deep copy of a PeerStatus.
func clonePeerStatus(ps *PeerStatus) *PeerStatus {
	cp := &PeerStatus{
		PublicKey:          ps.PublicKey,
		LastHandshake:      ps.LastHandshake,
		TxBytes:            ps.TxBytes,
		RxBytes:            ps.RxBytes,
		TransportTxPackets: ps.TransportTxPackets,
		TransportTxBytes:   ps.TransportTxBytes,
		TransportRxPackets: ps.TransportRxPackets,
		TransportRxBytes:   ps.TransportRxBytes,
		TransportLastError: ps.TransportLastError,
	}
	if ps.Endpoint != nil {
		cp.Endpoint = &net.UDPAddr{
			IP:   make(net.IP, len(ps.Endpoint.IP)),
			Port: ps.Endpoint.Port,
		}
		copy(cp.Endpoint.IP, ps.Endpoint.IP)
	}
	for _, ipn := range ps.AllowedIPs {
		n := net.IPNet{
			IP:   make(net.IP, len(ipn.IP)),
			Mask: make(net.IPMask, len(ipn.Mask)),
		}
		copy(n.IP, ipn.IP)
		copy(n.Mask, ipn.Mask)
		cp.AllowedIPs = append(cp.AllowedIPs, n)
	}
	return cp
}
