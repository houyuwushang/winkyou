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
				NodeID:         "node-abc",
				Name:           "alice",
				VirtualIP:      "10.100.0.2",
				PublicKey:      "AAAA",
				State:          "connected",
				Endpoint:       "1.2.3.4:51820",
				ConnectionType: "direct",
				TxBytes:        1024,
				RxBytes:        2048,
				LastSeen:       time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
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
	if !strings.Contains(output, "1.2.3.4:51820") {
		t.Error("output should contain endpoint")
	}
	if !strings.Contains(output, "1.0 KiB") {
		t.Errorf("output should contain formatted tx bytes, got: %s", output)
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
				NodeID:    "node-abc",
				Name:      "alice",
				VirtualIP: "10.100.0.2",
				State:     "connected",
				TxBytes:   5000,
				RxBytes:   6000,
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
	if result[0].TxBytes != 5000 {
		t.Errorf("TxBytes = %d, want 5000", result[0].TxBytes)
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
