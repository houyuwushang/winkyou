package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	winkclient "winkyou/pkg/client"
)

func TestPeersNoRuntimeState(t *testing.T) {
	// Point at a config path in a temp dir with no runtime state file.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	opts := &Options{ConfigPath: configPath}
	cmd := newPeersCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("peers execute error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No peers") {
		t.Errorf("expected 'No peers' in output, got: %q", output)
	}
}

func TestPeersNoRuntimeStateJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	opts := &Options{ConfigPath: configPath}
	cmd := newPeersCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("peers --json execute error: %v", err)
	}

	var result []any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\nOutput: %s", err, buf.String())
	}
	if len(result) != 0 {
		t.Errorf("expected empty array, got %d elements", len(result))
	}
}

func TestPeersWithRuntimeState(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Write a fake runtime state.
	state := &winkclient.RuntimeState{
		Version:   "test",
		PID:       1,
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status: winkclient.RuntimeEngineStatus{
			State: "connected",
		},
		Peers: []winkclient.RuntimePeerStatus{
			{
				NodeID:                 "node-abc",
				Name:                   "alice",
				VirtualIP:              "10.100.0.2",
				PublicKey:              "AAAA",
				AdvertisedRoutes:       []string{"10.6.22.0/24"},
				State:                  "connected",
				ControlState:           "connected",
				DataState:              "alive",
				Endpoint:               "1.2.3.4:51820",
				ConnectionType:         "direct",
				LastPathID:             "legacyice/direct_prefer",
				LastPathStrategy:       "legacy_ice_udp",
				LastPathPlanID:         "legacyice/direct_prefer",
				LastPathRole:           "primary_candidate",
				LastPathDependencies:   []string{"unknown:remote_cgnat_or_overlay_candidate"},
				LastPathDetails:        map[string]string{"child_paths": "id=relay/path,role=primary_candidate,deps=relay:turn_or_relay_candidate;id=direct/path,role=protected_direct,deps=none"},
				LastPathEndpoint:       "1.2.3.4:51820",
				TxBytes:                1024,
				RxBytes:                2048,
				ICEState:               "connected",
				LocalCandidate:         "relay:203.0.113.10:50000",
				RemoteCandidate:        "host:10.0.0.2:51820",
				TransportTxPackets:     7,
				TransportTxBytes:       700,
				TransportRxPackets:     8,
				TransportRxBytes:       800,
				TransportLastError:     "read: broken pipe",
				MultipathEnabled:       true,
				PrimaryPathID:          "relay/path",
				ProtectedDirectPathID:  "direct/path",
				StandbyPathIDs:         []string{"direct/path"},
				ActivePathID:           "direct/path",
				LastFailoverAt:         time.Date(2026, 4, 10, 12, 1, 0, 0, time.UTC),
				LastFailoverWhy:        "active_path_rx_silence:relay/path",
				LastInbandHeartbeatAt:  time.Date(2026, 4, 10, 12, 2, 0, 0, time.UTC),
				LastInbandPathHealthAt: time.Date(2026, 4, 10, 12, 3, 0, 0, time.UTC),
				LastSeen:               time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
			},
			{
				NodeID:    "node-def",
				Name:      "bob",
				VirtualIP: "10.100.0.3",
				State:     "disconnected",
			},
		},
	}

	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	// Text output.
	opts := &Options{ConfigPath: configPath}
	cmd := newPeersCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("peers execute error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "alice") {
		t.Error("output should contain peer name 'alice'")
	}
	if !strings.Contains(output, "bob") {
		t.Error("output should contain peer name 'bob'")
	}
	if !strings.Contains(output, "node-abc") {
		t.Error("output should contain node ID 'node-abc'")
	}
	if !strings.Contains(output, "10.100.0.2") {
		t.Error("output should contain virtual IP")
	}
	if !strings.Contains(output, "Routes:     10.6.22.0/24") {
		t.Errorf("output should contain advertised routes, got: %s", output)
	}
	if !strings.Contains(output, "1.2.3.4:51820") {
		t.Error("output should contain endpoint")
	}
	if !strings.Contains(output, "Control:") || !strings.Contains(output, "Data:") {
		t.Errorf("output should contain control/data state, got: %s", output)
	}
	if !strings.Contains(output, "In-band HB: 2026-04-10T12:02:00Z") || !strings.Contains(output, "In-band PH: 2026-04-10T12:03:00Z") {
		t.Errorf("output should contain in-band health timestamps, got: %s", output)
	}
	if !strings.Contains(output, "legacyice/direct_prefer") || !strings.Contains(output, "legacy_ice_udp") {
		t.Errorf("output should contain last path cache, got: %s", output)
	}
	if !strings.Contains(output, "Path Role:  primary_candidate") || !strings.Contains(output, "unknown:remote_cgnat_or_overlay_candidate") {
		t.Errorf("output should contain path role/dependency, got: %s", output)
	}
	if !strings.Contains(output, "1.0 KiB") {
		t.Errorf("output should contain formatted tx bytes, got: %s", output)
	}
	if !strings.Contains(output, "relay:203.0.113.10:50000") {
		t.Errorf("output should contain local candidate, got: %s", output)
	}
	if !strings.Contains(output, "7 pkts / 700 B") {
		t.Errorf("output should contain transport tx stats, got: %s", output)
	}
	if !strings.Contains(output, "read: broken pipe") {
		t.Errorf("output should contain transport error, got: %s", output)
	}
	if !strings.Contains(output, "Multipath:  enabled") || !strings.Contains(output, "Protected:  direct/path") || !strings.Contains(output, "Active:     direct/path") {
		t.Errorf("output should contain multipath state, got: %s", output)
	}
	if !strings.Contains(output, "Children:   id=relay/path,role=primary_candidate") {
		t.Errorf("output should contain child path details, got: %s", output)
	}
	if !strings.Contains(output, "Failover:   2026-04-10T12:01:00Z (active_path_rx_silence:relay/path)") {
		t.Errorf("output should contain failover reason, got: %s", output)
	}

	// Clean up for next subtest.
	os.Remove(winkclient.RuntimeStatePath(configPath))
}

func TestPeersWithRuntimeStateJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	state := &winkclient.RuntimeState{
		Version:   "test",
		PID:       1,
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status: winkclient.RuntimeEngineStatus{
			State: "connected",
		},
		Peers: []winkclient.RuntimePeerStatus{
			{
				NodeID:                 "node-abc",
				Name:                   "alice",
				VirtualIP:              "10.100.0.2",
				AdvertisedRoutes:       []string{"10.6.22.0/24"},
				State:                  "connected",
				ControlState:           "connected",
				DataState:              "alive",
				LastPathID:             "relayonly/turn_relay",
				LastPathStrategy:       "relay_only",
				LastPathPlanID:         "relayonly/turn_relay",
				LastPathRole:           "primary_candidate",
				LastPathDependencies:   []string{"relay:turn_or_relay_candidate"},
				MultipathEnabled:       true,
				PrimaryPathID:          "relay/path",
				ProtectedDirectPathID:  "direct/path",
				StandbyPathIDs:         []string{"direct/path"},
				ActivePathID:           "relay/path",
				LastFailoverWhy:        "active_path_rx_silence:direct/path",
				LastInbandHeartbeatAt:  time.Date(2026, 4, 10, 12, 2, 0, 0, time.UTC),
				LastInbandPathHealthAt: time.Date(2026, 4, 10, 12, 3, 0, 0, time.UTC),
				TxBytes:                5000,
				RxBytes:                6000,
			},
		},
	}

	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	opts := &Options{ConfigPath: configPath}
	cmd := newPeersCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("peers --json execute error: %v", err)
	}

	var result []winkclient.RuntimePeerStatus
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\nOutput: %s", err, buf.String())
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(result))
	}
	if result[0].NodeID != "node-abc" {
		t.Errorf("NodeID = %q, want %q", result[0].NodeID, "node-abc")
	}
	if result[0].Name != "alice" {
		t.Errorf("Name = %q, want %q", result[0].Name, "alice")
	}
	if len(result[0].AdvertisedRoutes) != 1 || result[0].AdvertisedRoutes[0] != "10.6.22.0/24" {
		t.Errorf("AdvertisedRoutes = %#v, want 10.6.22.0/24", result[0].AdvertisedRoutes)
	}
	if result[0].TxBytes != 5000 {
		t.Errorf("TxBytes = %d, want 5000", result[0].TxBytes)
	}
	if result[0].ControlState != "connected" || result[0].DataState != "alive" {
		t.Errorf("states = control=%q data=%q", result[0].ControlState, result[0].DataState)
	}
	if result[0].LastPathStrategy != "relay_only" {
		t.Errorf("LastPathStrategy = %q, want relay_only", result[0].LastPathStrategy)
	}
	if result[0].LastPathPlanID != "relayonly/turn_relay" || result[0].LastPathRole != "primary_candidate" || len(result[0].LastPathDependencies) != 1 {
		t.Errorf("last path diagnostics = %#v", result[0])
	}
	if !result[0].MultipathEnabled || result[0].ProtectedDirectPathID != "direct/path" {
		t.Errorf("multipath fields = %#v", result[0])
	}
	if result[0].LastFailoverWhy != "active_path_rx_silence:direct/path" {
		t.Errorf("LastFailoverWhy = %q, want active path silence reason", result[0].LastFailoverWhy)
	}
	if result[0].LastInbandHeartbeatAt.IsZero() || result[0].LastInbandPathHealthAt.IsZero() {
		t.Errorf("in-band fields = %#v", result[0])
	}
}

func TestPeersEmptyPeerList(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	state := &winkclient.RuntimeState{
		Version:   "test",
		PID:       1,
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status: winkclient.RuntimeEngineStatus{
			State: "connected",
		},
		Peers: []winkclient.RuntimePeerStatus{},
	}

	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	opts := &Options{ConfigPath: configPath}
	cmd := newPeersCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("peers execute error: %v", err)
	}

	if !strings.Contains(buf.String(), "No peers") {
		t.Errorf("expected 'No peers' for empty list, got: %q", buf.String())
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
