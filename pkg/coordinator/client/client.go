package client

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrNotImplemented = errors.New("coordinator client: transport not implemented")

// Config contains the client-side coordinator settings used by the
// transport stub and future gRPC integration.
type Config struct {
	URL     string
	AuthKey string
	Timeout time.Duration
	Retry   RetryPolicy
}

// RetryPolicy describes how a real transport should retry transient
// failures. The stub records the values but does not act on them.
type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type RegisterRequest struct {
	PublicKey string
	Name      string
	AuthKey   string
	Metadata  map[string]string
}

type RegisterResponse struct {
	NodeID      string
	VirtualIP   string
	ExpiresAt   int64
	NetworkCIDR string
}

type HeartbeatRequest struct {
	NodeID    string
	Timestamp int64
}

type HeartbeatResponse struct {
	ServerTime   int64
	UpdatedPeers []string
}

type ListPeersRequest struct {
	OnlineOnly bool
}

type ListPeersResponse struct {
	Peers []PeerInfo
}

type ListOption func(*ListPeersRequest)

func WithOnlineOnly(onlineOnly bool) ListOption {
	return func(req *ListPeersRequest) {
		req.OnlineOnly = onlineOnly
	}
}

type GetPeerRequest struct {
	NodeID string
}

type PeerInfo struct {
	NodeID    string
	Name      string
	PublicKey string
	VirtualIP string
	Online    bool
	LastSeen  int64
	Endpoints []string
}

type SignalType int

const (
	SIGNAL_UNSPECIFIED SignalType = iota
	SIGNAL_ICE_CANDIDATE
	SIGNAL_ICE_OFFER
	SIGNAL_ICE_ANSWER
)

const (
	SignalTypeUnspecified = SIGNAL_UNSPECIFIED
	SignalTypeICECandidate = SIGNAL_ICE_CANDIDATE
	SignalTypeICEOffer     = SIGNAL_ICE_OFFER
	SignalTypeICEAnswer    = SIGNAL_ICE_ANSWER
)

func (s SignalType) String() string {
	switch s {
	case SIGNAL_ICE_CANDIDATE:
		return "ice_candidate"
	case SIGNAL_ICE_OFFER:
		return "ice_offer"
	case SIGNAL_ICE_ANSWER:
		return "ice_answer"
	default:
		return "unspecified"
	}
}

type SignalNotification struct {
	FromNode  string
	ToNode    string
	Type      SignalType
	Payload   []byte
	Timestamp int64
}

type PeerEvent int

const (
	PeerEventUnknown PeerEvent = iota
	PeerEventUpsert
	PeerEventOnline
	PeerEventOffline
	PeerEventDeleted
)

type CoordinatorClient interface {
	Connect(ctx context.Context) error
	Close() error
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
	StartHeartbeat(ctx context.Context, interval time.Duration) error
	StopHeartbeat()
	ListPeers(ctx context.Context, opts ...ListOption) ([]*PeerInfo, error)
	GetPeer(ctx context.Context, nodeID string) (*PeerInfo, error)
	SendSignal(ctx context.Context, to string, signalType SignalType, payload []byte) error
	OnSignal(handler func(signal *SignalNotification))
	OnPeerUpdate(handler func(peer *PeerInfo, event PeerEvent))
}

func DefaultConfig() Config {
	return Config{
		Timeout: 10 * time.Second,
		Retry: RetryPolicy{
			MaxAttempts:    3,
			InitialBackoff: 250 * time.Millisecond,
			MaxBackoff:     2 * time.Second,
		},
	}
}

func validateConfig(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.Timeout < 0 {
		return fmt.Errorf("coordinator client: timeout must be non-negative")
	}
	if cfg.Retry.MaxAttempts < 0 {
		return fmt.Errorf("coordinator client: retry max attempts must be non-negative")
	}
	if cfg.Retry.InitialBackoff < 0 || cfg.Retry.MaxBackoff < 0 {
		return fmt.Errorf("coordinator client: retry backoff must be non-negative")
	}
	return nil
}

func applyListOptions(opts []ListOption) ListPeersRequest {
	req := ListPeersRequest{}
	for _, opt := range opts {
		if opt != nil {
			opt(&req)
		}
	}
	return req
}
