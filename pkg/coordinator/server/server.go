package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
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
}

func DefaultConfig() Config {
	return Config{
		ListenAddress: ":9443",
		NetworkCIDR:   "10.42.0.0/24",
		LeaseTTL:      30 * time.Second,
	}
}

// Node is the in-memory registry record tracked by the coordinator.
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

// Store is the in-memory node registry backing the server skeleton.
type Store struct {
	mu         sync.RWMutex
	network    netip.Prefix
	leaseTTL   time.Duration
	now        func() time.Time
	nextNodeID uint64
	nextIP     netip.Addr
	nodes      map[string]*Node
	byKey      map[string]string
	signals    map[string][]client.SignalNotification
}

type Server struct {
	cfg   Config
	store *Store
}

func New(cfg *Config) (*Server, error) {
	merged, err := newConfig(cfg)
	if err != nil {
		return nil, err
	}

	store, err := NewStore(merged.NetworkCIDR, merged.LeaseTTL, merged.Now)
	if err != nil {
		return nil, err
	}

	return &Server{cfg: merged, store: store}, nil
}

func NewStore(networkCIDR string, leaseTTL time.Duration, now func() time.Time) (*Store, error) {
	if strings.TrimSpace(networkCIDR) == "" {
		networkCIDR = DefaultConfig().NetworkCIDR
	}
	if leaseTTL <= 0 {
		leaseTTL = DefaultConfig().LeaseTTL
	}
	if now == nil {
		now = time.Now
	}

	prefix, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("coordinator server: invalid network cidr: %w", err)
	}

	return &Store{
		network:  prefix.Masked(),
		leaseTTL: leaseTTL,
		now:      now,
		nextIP:   prefix.Masked().Addr().Next(),
		nodes:    make(map[string]*Node),
		byKey:    make(map[string]string),
		signals:  make(map[string][]client.SignalNotification),
	}, nil
}

func (s *Server) Config() Config {
	return s.cfg
}

func (s *Server) Store() *Store {
	return s.store
}

func (s *Server) ListenAddress() string {
	return s.cfg.ListenAddress
}

func (s *Server) NetworkCIDR() string {
	return s.cfg.NetworkCIDR
}

func (s *Server) Register(ctx context.Context, req *client.RegisterRequest) (*client.RegisterResponse, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	node, err := s.store.Register(req, s.cfg.AuthKey)
	if err != nil {
		return nil, err
	}
	return &client.RegisterResponse{
		NodeID:      node.NodeID,
		VirtualIP:   node.VirtualIP,
		ExpiresAt:   node.ExpiresAt.Unix(),
		NetworkCIDR: s.cfg.NetworkCIDR,
	}, nil
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

	return &client.HeartbeatResponse{
		ServerTime:   s.cfg.Now().Unix(),
		UpdatedPeers: updatedPeers,
	}, nil
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

func (s *Store) Register(req *client.RegisterRequest, expectedAuthKey string) (*Node, error) {
	if req == nil {
		return nil, fmt.Errorf("coordinator server: register request is nil")
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		return nil, fmt.Errorf("coordinator server: public_key is required")
	}
	if strings.TrimSpace(expectedAuthKey) != "" && req.AuthKey != expectedAuthKey {
		return nil, ErrUnauthorized
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if nodeID, ok := s.byKey[req.PublicKey]; ok {
		node := s.nodes[nodeID]
		node.Name = req.Name
		node.Metadata = cloneMap(req.Metadata)
		node.LastSeen = now
		node.ExpiresAt = now.Add(s.leaseTTL)
		node.ChangedAt = now
		node.Online = true
		return cloneNode(node), nil
	}

	s.nextNodeID++
	virtualIP, err := s.allocateIPLocked()
	if err != nil {
		return nil, err
	}

	node := &Node{
		NodeID:    fmt.Sprintf("node-%06d", s.nextNodeID),
		Name:      req.Name,
		PublicKey: req.PublicKey,
		Metadata:  cloneMap(req.Metadata),
		VirtualIP: virtualIP.String(),
		Online:    true,
		LastSeen:  now,
		ExpiresAt: now.Add(s.leaseTTL),
		ChangedAt: now,
	}
	s.nodes[node.NodeID] = node
	s.byKey[node.PublicKey] = node.NodeID

	return cloneNode(node), nil
}

func (s *Store) Heartbeat(nodeID string, timestamp time.Time) (*Node, []string, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, nil, fmt.Errorf("coordinator server: node_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.refreshExpiredLocked(now)

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, nil, ErrNodeNotFound
	}

	cutoff := node.LastSync
	if timestamp.IsZero() {
		timestamp = now
	}
	node.LastSeen = timestamp
	node.ExpiresAt = now.Add(s.leaseTTL)
	node.ChangedAt = now
	node.Online = true

	updated := make([]string, 0, len(s.nodes))
	for id, peer := range s.nodes {
		if id == nodeID {
			continue
		}
		if peer.ChangedAt.After(cutoff) {
			updated = append(updated, id)
		}
	}
	sort.Strings(updated)
	node.LastSync = now

	return cloneNode(node), updated, nil
}

func (s *Store) List(onlineOnly bool) []client.PeerInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.refreshExpiredLocked(now)

	peers := make([]client.PeerInfo, 0, len(s.nodes))
	for _, node := range s.nodes {
		if onlineOnly && !node.Online {
			continue
		}
		peers = append(peers, toPeerInfo(node))
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].NodeID < peers[j].NodeID
	})
	return peers
}

func (s *Store) Get(nodeID string) (*client.PeerInfo, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, fmt.Errorf("coordinator server: node_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.refreshExpiredLocked(now)

	node, ok := s.nodes[nodeID]
	if !ok {
		return nil, ErrNodeNotFound
	}

	info := toPeerInfo(node)
	return &info, nil
}

func (s *Store) ForwardSignal(notification *client.SignalNotification) (bool, error) {
	if notification == nil {
		return false, fmt.Errorf("coordinator server: signal notification is nil")
	}
	if strings.TrimSpace(notification.FromNode) == "" || strings.TrimSpace(notification.ToNode) == "" {
		return false, fmt.Errorf("coordinator server: signal requires from_node and to_node")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.refreshExpiredLocked(now)

	if _, ok := s.nodes[notification.FromNode]; !ok {
		return false, ErrNodeNotFound
	}

	target, ok := s.nodes[notification.ToNode]
	if !ok {
		return false, ErrNodeNotFound
	}
	if !target.Online {
		return false, nil
	}

	cloned := cloneSignal(notification)
	if cloned.Timestamp == 0 {
		cloned.Timestamp = now.Unix()
	}
	s.signals[target.NodeID] = append(s.signals[target.NodeID], cloned)
	return true, nil
}

func (s *Store) DrainSignals(nodeID string) ([]client.SignalNotification, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, fmt.Errorf("coordinator server: node_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.nodes[nodeID]; !ok {
		return nil, ErrNodeNotFound
	}

	queue := s.signals[nodeID]
	out := make([]client.SignalNotification, len(queue))
	copy(out, queue)
	s.signals[nodeID] = nil
	return out, nil
}

func (s *Store) refreshExpiredLocked(now time.Time) {
	for _, node := range s.nodes {
		if node.Online && !node.ExpiresAt.IsZero() && now.After(node.ExpiresAt) {
			node.Online = false
			node.ChangedAt = now
		}
	}
}

func (s *Store) allocateIPLocked() (netip.Addr, error) {
	addr := s.nextIP
	for {
		if !addr.IsValid() || !s.network.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("coordinator server: network %s is exhausted", s.network)
		}
		if s.ipAvailableLocked(addr) {
			s.nextIP = addr.Next()
			return addr, nil
		}
		addr = addr.Next()
	}
}

func (s *Store) ipAvailableLocked(addr netip.Addr) bool {
	for _, node := range s.nodes {
		if node.VirtualIP == addr.String() {
			return false
		}
	}
	return true
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

func toPeerInfo(node *Node) client.PeerInfo {
	return client.PeerInfo{
		NodeID:    node.NodeID,
		Name:      node.Name,
		PublicKey: node.PublicKey,
		VirtualIP: node.VirtualIP,
		Online:    node.Online,
		LastSeen:  node.LastSeen.Unix(),
		Endpoints: cloneSlice(node.Endpoints),
	}
}

func cloneNode(node *Node) *Node {
	if node == nil {
		return nil
	}
	out := *node
	out.Metadata = cloneMap(node.Metadata)
	out.Endpoints = cloneSlice(node.Endpoints)
	return &out
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneSignal(notification *client.SignalNotification) client.SignalNotification {
	out := *notification
	if len(notification.Payload) > 0 {
		out.Payload = make([]byte, len(notification.Payload))
		copy(out.Payload, notification.Payload)
	}
	return out
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
