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

// DoneEngine is implemented by runtimes that can receive an authenticated
// process-control shutdown request independently of the parent signal context.
type DoneEngine interface {
	Done() <-chan struct{}
}

type EngineStatus struct {
	Mode           string
	State          EngineState
	NodeID         string
	NodeName       string
	PublicKey      string
	VirtualIP      net.IP
	NetworkCIDR    *net.IPNet
	Backend        string
	NATType        string
	CoordinatorURL string
	// InfrastructureCoordinatorStarted distinguishes optional discovery/control
	// infrastructure from ordinary trusted mesh peers that coordinate shortcut
	// attempts or forward graph traffic.
	InfrastructureCoordinatorStarted bool
	MeshListen                       string
	ControlListen                    string
	StartedAt                        time.Time
	Uptime                           time.Duration
	ConnectedPeers                   int
	BytesSent                        uint64
	BytesRecv                        uint64
	LastError                        string
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
	NodeID                 string
	Name                   string
	VirtualIP              net.IP
	PublicKey              string
	AdvertisedRoutes       []net.IPNet
	State                  PeerState
	ControlState           PeerControlState
	DataState              PeerDataState
	Endpoint               *net.UDPAddr
	Latency                time.Duration
	LastSeen               time.Time
	LastHandshake          time.Time
	TxBytes                uint64
	RxBytes                uint64
	ConnectionType         ConnectionType
	ICEState               string
	LocalCandidate         string
	RemoteCandidate        string
	TransportTxPackets     uint64
	TransportTxBytes       uint64
	TransportRxPackets     uint64
	TransportRxBytes       uint64
	TransportLastError     string
	MultipathEnabled       bool
	PrimaryPathID          string
	ProtectedDirectPathID  string
	StandbyPathIDs         []string
	ActivePathID           string
	LastFailoverAt         time.Time
	LastFailoverWhy        string
	LastInbandHeartbeatAt  time.Time
	LastInbandPathHealthAt time.Time
	LastPathID             string
	LastPathStrategy       string
	LastPathPlanID         string
	LastPathRole           string
	LastPathDependencies   []string
	LastPathDetails        map[string]string
	LastPathEndpoint       string
	LastPathConnType       string
	LastPathUpdatedAt      time.Time
	RouteNextHop           string
	RoutePath              []string
	RouteHopCount          int
	NeighborKind           string
	ProtectedDirect        bool
	MaintainedState        string
	SelfBootstrapState     string
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

type PeerControlState string

const (
	PeerControlStateConnected    PeerControlState = "connected"
	PeerControlStateDegraded     PeerControlState = "degraded"
	PeerControlStateDisconnected PeerControlState = "disconnected"
)

func (s PeerControlState) String() string {
	if s == "" {
		return "unknown"
	}
	return string(s)
}

type PeerDataState string

const (
	PeerDataStateConnecting PeerDataState = "connecting"
	PeerDataStateBound      PeerDataState = "bound"
	PeerDataStateAlive      PeerDataState = "alive"
	PeerDataStateStale      PeerDataState = "stale"
	PeerDataStateFailed     PeerDataState = "failed"
)

func (s PeerDataState) String() string {
	if s == "" {
		return "stale"
	}
	return string(s)
}

type ConnectionType int

const (
	ConnectionTypeDirect ConnectionType = iota
	ConnectionTypeRelay
	ConnectionTypeMeshRoute
)

func (c ConnectionType) String() string {
	switch c {
	case ConnectionTypeRelay:
		return "relay"
	case ConnectionTypeMeshRoute:
		return "mesh_route"
	default:
		return "direct"
	}
}
