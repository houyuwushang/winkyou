package client

import (
	"context"
	"net"
	"time"
)

type Engine interface {
	Start(ctx context.Context) error
	Stop() error
	Status() *EngineStatus
	GetPeers() []*PeerStatus
	ConnectToPeer(nodeID string) error
	DisconnectFromPeer(nodeID string) error
	OnStatusChange(handler func(status *EngineStatus))
	OnPeerChange(handler func(peer *PeerStatus, event PeerEvent))
}

type EngineStatus struct {
	State          EngineState
	NodeID         string
	NodeName       string
	PublicKey      string
	VirtualIP      net.IP
	NetworkCIDR    *net.IPNet
	Backend        string
	NATType        string
	CoordinatorURL string
	StartedAt      time.Time
	Uptime         time.Duration
	ConnectedPeers int
	BytesSent      uint64
	BytesRecv      uint64
	LastError      string
}

type EngineState int

const (
	EngineStateStopped EngineState = iota
	EngineStateStarting
	EngineStateConnecting
	EngineStateConnected
	EngineStateReconnecting
	EngineStateStopping
)

func (s EngineState) String() string {
	switch s {
	case EngineStateStarting:
		return "starting"
	case EngineStateConnecting:
		return "connecting"
	case EngineStateConnected:
		return "connected"
	case EngineStateReconnecting:
		return "reconnecting"
	case EngineStateStopping:
		return "stopping"
	default:
		return "stopped"
	}
}

type PeerStatus struct {
	NodeID         string
	Name           string
	VirtualIP      net.IP
	PublicKey      string
	State          PeerState
	Endpoint       *net.UDPAddr
	Latency        time.Duration
	LastSeen       time.Time
	LastHandshake  time.Time
	TxBytes        uint64
	RxBytes        uint64
	ConnectionType ConnectionType
	ICEState       string
	LocalCandidate string
	RemoteCandidate string
}

type PeerEvent int

const (
	PeerEventUnknown PeerEvent = iota
	PeerEventUpsert
	PeerEventOnline
	PeerEventOffline
	PeerEventDeleted
)

type PeerState int

const (
	PeerStateDisconnected PeerState = iota
	PeerStateConnecting
	PeerStateConnected
)

func (s PeerState) String() string {
	switch s {
	case PeerStateConnecting:
		return "connecting"
	case PeerStateConnected:
		return "connected"
	default:
		return "disconnected"
	}
}

type ConnectionType int

const (
	ConnectionTypeDirect ConnectionType = iota
	ConnectionTypeRelay
)

func (c ConnectionType) String() string {
	switch c {
	case ConnectionTypeRelay:
		return "relay"
	default:
		return "direct"
	}
}
