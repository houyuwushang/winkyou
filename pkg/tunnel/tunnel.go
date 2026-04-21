// Package tunnel defines the WireGuard tunnel abstraction for the MVP.
// The concrete wireguard-go implementation will live in tunnel_wggo.go;
// this file freezes the public interface contract.
package tunnel

import (
	"errors"
	"net"
	"time"

	"winkyou/pkg/netif"
	"winkyou/pkg/transport"
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
	PresharedKey *PresharedKey // optional
	AllowedIPs   []net.IPNet
	Endpoint     *net.UDPAddr              // optional; set if already known
	Transport    transport.PacketTransport // optional; long-lived packet transport selected by solver
	Keepalive    time.Duration             // 0 = disabled
}

// AddrMeta holds generic transport address information.
// This keeps the transport/binder layer generic even when the concrete
// tunnel implementation still needs to synthesize UDP endpoints for WG IPC.
type AddrMeta struct {
	Network string
	Address string
}

func AddrMetaFromAddr(addr net.Addr) AddrMeta {
	if addr == nil {
		return AddrMeta{}
	}
	return AddrMeta{Network: addr.Network(), Address: addr.String()}
}

// PeerStatus represents the current state of a peer.
type PeerStatus struct {
	PublicKey          PublicKey
	Endpoint           *net.UDPAddr
	EndpointMeta       AddrMeta
	LastHandshake      time.Time
	TxBytes            uint64
	RxBytes            uint64
	AllowedIPs         []net.IPNet
	TransportTxPackets uint64
	TransportTxBytes   uint64
	TransportRxPackets uint64
	TransportRxBytes   uint64
	TransportLastError string
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
	EventPeerAdded EventType = iota
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
// Memory backend is retained for unit tests and unprivileged test runs.
func New(cfg Config) (Tunnel, error) {
	if allowMemoryTunnelForTest() {
		return newMemTunnel(cfg), nil
	}
	return newWGGoTunnel(cfg), nil
}
