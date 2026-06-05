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
	NodeID                 string            `json:"node_id"`
	Name                   string            `json:"name"`
	VirtualIP              string            `json:"virtual_ip"`
	PublicKey              string            `json:"public_key"`
	State                  string            `json:"state"`
	ControlState           string            `json:"control_state"`
	DataState              string            `json:"data_state"`
	Endpoint               string            `json:"endpoint,omitempty"`
	LastSeen               time.Time         `json:"last_seen"`
	LastHandshake          time.Time         `json:"last_handshake"`
	TxBytes                uint64            `json:"tx_bytes"`
	RxBytes                uint64            `json:"rx_bytes"`
	ConnectionType         string            `json:"connection_type"`
	ICEState               string            `json:"ice_state,omitempty"`
	LocalCandidate         string            `json:"local_candidate,omitempty"`
	RemoteCandidate        string            `json:"remote_candidate,omitempty"`
	TransportTxPackets     uint64            `json:"transport_tx_packets"`
	TransportTxBytes       uint64            `json:"transport_tx_bytes"`
	TransportRxPackets     uint64            `json:"transport_rx_packets"`
	TransportRxBytes       uint64            `json:"transport_rx_bytes"`
	TransportLastError     string            `json:"transport_last_error,omitempty"`
	MultipathEnabled       bool              `json:"multipath_enabled"`
	PrimaryPathID          string            `json:"primary_path_id,omitempty"`
	ProtectedDirectPathID  string            `json:"protected_direct_path_id,omitempty"`
	StandbyPathIDs         []string          `json:"standby_path_ids,omitempty"`
	ActivePathID           string            `json:"active_path_id,omitempty"`
	LastFailoverAt         time.Time         `json:"last_failover_at,omitempty"`
	LastInbandHeartbeatAt  time.Time         `json:"last_inband_heartbeat_at,omitempty"`
	LastInbandPathHealthAt time.Time         `json:"last_inband_path_health_at,omitempty"`
	LastPathID             string            `json:"last_path_id,omitempty"`
	LastPathStrategy       string            `json:"last_path_strategy,omitempty"`
	LastPathPlanID         string            `json:"last_path_plan_id,omitempty"`
	LastPathRole           string            `json:"last_path_role,omitempty"`
	LastPathDependencies   []string          `json:"last_path_dependencies,omitempty"`
	LastPathDetails        map[string]string `json:"last_path_details,omitempty"`
	LastPathEndpoint       string            `json:"last_path_endpoint,omitempty"`
	LastPathConnType       string            `json:"last_path_connection_type,omitempty"`
	LastPathUpdatedAt      time.Time         `json:"last_path_updated_at,omitempty"`
}

func RuntimeStatePath(configPath string) string {
	resolved := strings.TrimSpace(configPath)
	if strings.HasSuffix(strings.ToLower(filepath.Base(resolved)), ".runtime.json") {
		return resolved
	}
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
	return removePathWithRetry(target)
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
			NodeID:                 peer.NodeID,
			Name:                   peer.Name,
			VirtualIP:              ipString(peer.VirtualIP),
			PublicKey:              peer.PublicKey,
			State:                  peer.State.String(),
			ControlState:           peer.ControlState.String(),
			DataState:              peer.DataState.String(),
			Endpoint:               udpAddrString(peer.Endpoint),
			LastSeen:               peer.LastSeen,
			LastHandshake:          peer.LastHandshake,
			TxBytes:                peer.TxBytes,
			RxBytes:                peer.RxBytes,
			ConnectionType:         peer.ConnectionType.String(),
			ICEState:               peer.ICEState,
			LocalCandidate:         peer.LocalCandidate,
			RemoteCandidate:        peer.RemoteCandidate,
			TransportTxPackets:     peer.TransportTxPackets,
			TransportTxBytes:       peer.TransportTxBytes,
			TransportRxPackets:     peer.TransportRxPackets,
			TransportRxBytes:       peer.TransportRxBytes,
			TransportLastError:     peer.TransportLastError,
			MultipathEnabled:       peer.MultipathEnabled,
			PrimaryPathID:          peer.PrimaryPathID,
			ProtectedDirectPathID:  peer.ProtectedDirectPathID,
			StandbyPathIDs:         append([]string(nil), peer.StandbyPathIDs...),
			ActivePathID:           peer.ActivePathID,
			LastFailoverAt:         peer.LastFailoverAt,
			LastInbandHeartbeatAt:  peer.LastInbandHeartbeatAt,
			LastInbandPathHealthAt: peer.LastInbandPathHealthAt,
			LastPathID:             peer.LastPathID,
			LastPathStrategy:       peer.LastPathStrategy,
			LastPathPlanID:         peer.LastPathPlanID,
			LastPathRole:           peer.LastPathRole,
			LastPathDependencies:   append([]string(nil), peer.LastPathDependencies...),
			LastPathDetails:        cloneStringMap(peer.LastPathDetails),
			LastPathEndpoint:       peer.LastPathEndpoint,
			LastPathConnType:       peer.LastPathConnType,
			LastPathUpdatedAt:      peer.LastPathUpdatedAt,
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

func removePathWithRetry(target string) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.Remove(target)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
}
