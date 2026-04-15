package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/version"
)

var ErrRuntimeStateNotFound = errors.New("client runtime state not found")

type RuntimeState struct {
	Version   string              `json:"version"`
	PID       int                 `json:"pid"`
	StartedAt time.Time           `json:"started_at"`
	UpdatedAt time.Time           `json:"updated_at"`
	Status    RuntimeEngineStatus `json:"status"`
	Peers     []RuntimePeerStatus `json:"peers"`
}

type RuntimeEngineStatus struct {
	State          string `json:"state"`
	NodeID         string `json:"node_id"`
	NodeName       string `json:"node_name"`
	PublicKey      string `json:"public_key"`
	VirtualIP      string `json:"virtual_ip"`
	NetworkCIDR    string `json:"network_cidr"`
	Backend        string `json:"backend"`
	NATType        string `json:"nat_type"`
	CoordinatorURL string `json:"coordinator_url"`
	Uptime         string `json:"uptime"`
	ConnectedPeers int    `json:"connected_peers"`
	BytesSent      uint64 `json:"bytes_sent"`
	BytesRecv      uint64 `json:"bytes_recv"`
	LastError      string `json:"last_error,omitempty"`
}

type RuntimePeerStatus struct {
	NodeID         string    `json:"node_id"`
	Name           string    `json:"name"`
	VirtualIP      string    `json:"virtual_ip"`
	PublicKey      string    `json:"public_key"`
	State          string    `json:"state"`
	Endpoint       string    `json:"endpoint,omitempty"`
	LastSeen       time.Time `json:"last_seen"`
	LastHandshake  time.Time `json:"last_handshake"`
	TxBytes        uint64    `json:"tx_bytes"`
	RxBytes        uint64    `json:"rx_bytes"`
	ConnectionType string    `json:"connection_type"`
}

func RuntimeStatePath(configPath string) string {
	resolved := strings.TrimSpace(configPath)
	if resolved == "" {
		resolved = config.DefaultPath()
	}

	dir := filepath.Dir(resolved)
	base := strings.TrimSuffix(filepath.Base(resolved), filepath.Ext(resolved))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "wink"
	}
	return filepath.Join(dir, base+".runtime.json")
}

func LoadRuntimeState(path string) (*RuntimeState, error) {
	raw, err := os.ReadFile(RuntimeStatePath(path))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrRuntimeStateNotFound
		}
		return nil, err
	}

	var state RuntimeState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func WriteRuntimeState(path string, state *RuntimeState) error {
	if state == nil {
		return fmt.Errorf("client runtime state is nil")
	}

	target := RuntimeStatePath(path)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(target, payload, 0o644)
}

func RemoveRuntimeState(path string) error {
	target := RuntimeStatePath(path)
	err := os.Remove(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *RuntimeState) IsFresh(maxAge time.Duration) bool {
	if s == nil {
		return false
	}
	if maxAge <= 0 || s.UpdatedAt.IsZero() {
		return true
	}
	return time.Since(s.UpdatedAt) <= maxAge
}

func newRuntimeStateSnapshot(status *EngineStatus, peers []*PeerStatus) *RuntimeState {
	state := &RuntimeState{
		Version:   version.Version,
		PID:       os.Getpid(),
		StartedAt: status.StartedAt,
		UpdatedAt: time.Now(),
		Status: RuntimeEngineStatus{
			State:          status.State.String(),
			NodeID:         status.NodeID,
			NodeName:       status.NodeName,
			PublicKey:      status.PublicKey,
			VirtualIP:      ipString(status.VirtualIP),
			NetworkCIDR:    cidrString(status.NetworkCIDR),
			Backend:        status.Backend,
			NATType:        status.NATType,
			CoordinatorURL: status.CoordinatorURL,
			Uptime:         status.Uptime.String(),
			ConnectedPeers: status.ConnectedPeers,
			BytesSent:      status.BytesSent,
			BytesRecv:      status.BytesRecv,
			LastError:      status.LastError,
		},
		Peers: make([]RuntimePeerStatus, 0, len(peers)),
	}

	for _, peer := range peers {
		if peer == nil {
			continue
		}
		state.Peers = append(state.Peers, RuntimePeerStatus{
			NodeID:         peer.NodeID,
			Name:           peer.Name,
			VirtualIP:      ipString(peer.VirtualIP),
			PublicKey:      peer.PublicKey,
			State:          peer.State.String(),
			Endpoint:       udpAddrString(peer.Endpoint),
			LastSeen:       peer.LastSeen,
			LastHandshake:  peer.LastHandshake,
			TxBytes:        peer.TxBytes,
			RxBytes:        peer.RxBytes,
			ConnectionType: peer.ConnectionType.String(),
		})
	}

	return state
}

func ipString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func cidrString(prefix *net.IPNet) string {
	if prefix == nil {
		return ""
	}
	return prefix.String()
}

func udpAddrString(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
