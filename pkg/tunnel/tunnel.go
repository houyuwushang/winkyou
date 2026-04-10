// Package tunnel defines the WireGuard tunnel abstraction for the MVP.
// The concrete wireguard-go implementation will live in tunnel_wggo.go;
// this file freezes the public interface contract.
package tunnel

import (
	"errors"
	"net"
	"time"

	"winkyou/pkg/netif"
)

// ErrNotImplemented is returned by stub methods that have no real
// implementation yet.
var ErrNotImplemented = errors.New("tunnel: not implemented")

// Config holds the parameters needed to create a Tunnel.
type Config struct {
	Interface  netif.NetworkInterface
	PrivateKey PrivateKey
	ListenPort int // 0 = random
}

// PeerConfig defines the configuration for adding a peer.
type PeerConfig struct {
	PublicKey    PublicKey
	PresharedKey *PresharedKey   // optional
	AllowedIPs   []net.IPNet
	Endpoint     *net.UDPAddr    // optional; set if already known
	Keepalive    time.Duration   // 0 = disabled
}

// PeerStatus represents the current state of a peer.
type PeerStatus struct {
	PublicKey     PublicKey
	Endpoint      *net.UDPAddr
	LastHandshake time.Time
	TxBytes       uint64
	RxBytes       uint64
	AllowedIPs    []net.IPNet
}

// TunnelStats holds aggregate tunnel statistics.
type TunnelStats struct {
	TxBytes   uint64
	RxBytes   uint64
	TxPackets uint64
	RxPackets uint64
	Peers     int
}

// TunnelEvent represents an event from the tunnel.
type TunnelEvent struct {
	Type      EventType
	PeerKey   PublicKey
	Timestamp time.Time
	Details   interface{}
}

// EventType enumerates known tunnel events.
type EventType int

const (
	EventPeerAdded          EventType = iota
	EventPeerRemoved
	EventPeerHandshake
	EventPeerEndpointChanged
)

// Tunnel is the main WireGuard tunnel interface.
type Tunnel interface {
	// Lifecycle
	Start() error
	Stop() error

	// Peer management
	AddPeer(peer *PeerConfig) error
	RemovePeer(publicKey PublicKey) error
	UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error

	// State query
	GetPeers() []*PeerStatus
	GetStats() *TunnelStats

	// Events returns a read-only channel that emits tunnel events.
	Events() <-chan TunnelEvent
}

// New creates a Tunnel backed by the given config.
// The real wireguard-go implementation will be wired here.
func New(cfg Config) (Tunnel, error) {
	return newStubTunnel(cfg), nil
}
