package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"winkyou/pkg/coordinator/client"
)

var (
	ErrNodeNotFound  = errors.New("coordinator server: node not found")
	ErrUnauthorized  = errors.New("coordinator server: unauthorized")
	ErrSignalDropped = errors.New("coordinator server: signal dropped")
)

type Config struct {
	ListenAddress string
	NetworkCIDR   string
	LeaseTTL      time.Duration
	AuthKey       string
	Now           func() time.Time
	StoreBackend  string
	SQLitePath    string
}

func DefaultConfig() Config {
	return Config{
		ListenAddress: ":9443",
		NetworkCIDR:   "10.42.0.0/24",
		LeaseTTL:      30 * time.Second,
		StoreBackend:  "memory",
	}
}

// Node is the coordinator registry record.
type Node struct {
	NodeID    string
	Name      string
	PublicKey string
	Metadata  map[string]string
	VirtualIP string
	Online    bool
	LastSeen  time.Time
	ExpiresAt time.Time
	ChangedAt time.Time
	LastSync  time.Time
	Endpoints []string
}

// Store defines coordinator persistence behavior.
type Store interface {
	Register(req *client.RegisterRequest, expectedAuthKey string) (*Node, error)
	Heartbeat(nodeID string, timestamp time.Time) (*Node, []string, error)
	List(onlineOnly bool) []client.PeerInfo
	Get(nodeID string) (*client.PeerInfo, error)
	ForwardSignal(notification *client.SignalNotification) (bool, error)
	DrainSignals(nodeID string) ([]client.SignalNotification, error)
	Close() error
}

type Server struct {
	cfg   Config
	store Store
}

func New(cfg *Config) (*Server, error) {
	merged, err := newConfig(cfg)
	if err != nil {
		return nil, err
	}

	store, err := newStoreForConfig(merged)
	if err != nil {
		return nil, err
	}

	return &Server{cfg: merged, store: store}, nil
}

func (s *Server) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Close()
}

func (s *Server) Config() Config        { return s.cfg }
func (s *Server) Store() Store          { return s.store }
func (s *Server) ListenAddress() string { return s.cfg.ListenAddress }
func (s *Server) NetworkCIDR() string   { return s.cfg.NetworkCIDR }

func (s *Server) Register(ctx context.Context, req *client.RegisterRequest) (*client.RegisterResponse, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	node, err := s.store.Register(req, s.cfg.AuthKey)
	if err != nil {
		return nil, err
	}
	return &client.RegisterResponse{NodeID: node.NodeID, VirtualIP: node.VirtualIP, ExpiresAt: node.ExpiresAt.Unix(), NetworkCIDR: s.cfg.NetworkCIDR}, nil
}

func (s *Server) Heartbeat(ctx context.Context, req *client.HeartbeatRequest) (*client.HeartbeatResponse, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("coordinator server: heartbeat request is nil")
	}
	timestamp := s.cfg.Now()
	if req.Timestamp > 0 {
		timestamp = time.Unix(req.Timestamp, 0)
	}
	_, updatedPeers, err := s.store.Heartbeat(req.NodeID, timestamp)
	if err != nil {
		return nil, err
	}
	return &client.HeartbeatResponse{ServerTime: s.cfg.Now().Unix(), UpdatedPeers: updatedPeers}, nil
}

func (s *Server) ListPeers(ctx context.Context, req *client.ListPeersRequest) (*client.ListPeersResponse, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		req = &client.ListPeersRequest{}
	}
	return &client.ListPeersResponse{Peers: s.store.List(req.OnlineOnly)}, nil
}

func (s *Server) GetPeer(ctx context.Context, req *client.GetPeerRequest) (*client.PeerInfo, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("coordinator server: get peer request is nil")
	}
	return s.store.Get(req.NodeID)
}

func (s *Server) ForwardSignal(ctx context.Context, notification *client.SignalNotification) (bool, error) {
	if err := ctxErr(ctx); err != nil {
		return false, err
	}
	return s.store.ForwardSignal(notification)
}

func newStoreForConfig(cfg Config) (Store, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.StoreBackend)) {
	case "", "memory":
		return NewMemoryStore(cfg.NetworkCIDR, cfg.LeaseTTL, cfg.Now)
	case "sqlite":
		if strings.TrimSpace(cfg.SQLitePath) == "" {
			return nil, fmt.Errorf("coordinator server: sqlite_path is required when store_backend=sqlite")
		}
		return NewSQLiteStore(cfg.NetworkCIDR, cfg.LeaseTTL, cfg.Now, cfg.SQLitePath)
	default:
		return nil, fmt.Errorf("coordinator server: unknown store backend %q", cfg.StoreBackend)
	}
}

func newConfig(cfg *Config) (Config, error) {
	merged := DefaultConfig()
	if cfg != nil {
		if strings.TrimSpace(cfg.ListenAddress) != "" {
			merged.ListenAddress = cfg.ListenAddress
		}
		if strings.TrimSpace(cfg.NetworkCIDR) != "" {
			merged.NetworkCIDR = cfg.NetworkCIDR
		}
		if cfg.LeaseTTL > 0 {
			merged.LeaseTTL = cfg.LeaseTTL
		}
		merged.AuthKey = cfg.AuthKey
		if cfg.Now != nil {
			merged.Now = cfg.Now
		}
		if strings.TrimSpace(cfg.StoreBackend) != "" {
			merged.StoreBackend = cfg.StoreBackend
		}
		if strings.TrimSpace(cfg.SQLitePath) != "" {
			merged.SQLitePath = cfg.SQLitePath
		}
	}
	if merged.Now == nil {
		merged.Now = time.Now
	}
	if strings.TrimSpace(merged.ListenAddress) == "" {
		return Config{}, fmt.Errorf("coordinator server: listen address is required")
	}
	if merged.LeaseTTL <= 0 {
		return Config{}, fmt.Errorf("coordinator server: lease ttl must be greater than zero")
	}
	if _, err := netip.ParsePrefix(merged.NetworkCIDR); err != nil {
		return Config{}, fmt.Errorf("coordinator server: invalid network cidr: %w", err)
	}
	return merged, nil
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
