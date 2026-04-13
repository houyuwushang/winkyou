package server

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/coordinator/client"
)

type MemoryStore struct {
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

func NewMemoryStore(networkCIDR string, leaseTTL time.Duration, now func() time.Time) (*MemoryStore, error) {
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

	return &MemoryStore{
		network:  prefix.Masked(),
		leaseTTL: leaseTTL,
		now:      now,
		nextIP:   prefix.Masked().Addr().Next(),
		nodes:    make(map[string]*Node),
		byKey:    make(map[string]string),
		signals:  make(map[string][]client.SignalNotification),
	}, nil
}

func (s *MemoryStore) Close() error { return nil }

func (s *MemoryStore) Register(req *client.RegisterRequest, expectedAuthKey string) (*Node, error) {
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

func (s *MemoryStore) Heartbeat(nodeID string, timestamp time.Time) (*Node, []string, error) {
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

func (s *MemoryStore) List(onlineOnly bool) []client.PeerInfo {
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
	sort.Slice(peers, func(i, j int) bool { return peers[i].NodeID < peers[j].NodeID })
	return peers
}

func (s *MemoryStore) Get(nodeID string) (*client.PeerInfo, error) {
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

func (s *MemoryStore) ForwardSignal(notification *client.SignalNotification) (bool, error) {
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

func (s *MemoryStore) DrainSignals(nodeID string) ([]client.SignalNotification, error) {
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

func (s *MemoryStore) refreshExpiredLocked(now time.Time) {
	for _, node := range s.nodes {
		if node.Online && !node.ExpiresAt.IsZero() && now.After(node.ExpiresAt) {
			node.Online = false
			node.ChangedAt = now
		}
	}
}

func (s *MemoryStore) allocateIPLocked() (netip.Addr, error) {
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

func (s *MemoryStore) ipAvailableLocked(addr netip.Addr) bool {
	for _, node := range s.nodes {
		if node.VirtualIP == addr.String() {
			return false
		}
	}
	return true
}
