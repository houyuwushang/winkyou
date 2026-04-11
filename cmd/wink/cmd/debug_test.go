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
	"winkyou/pkg/config"
)

func TestDebugDefaultBehaviorWithoutExplicitConfigPath(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("APPDATA", tmpDir)
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	cmd := newRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"debug"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("debug execute error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, config.DefaultPath()) {
		t.Fatalf("output should contain default config path %q, got: %s", config.DefaultPath(), output)
	}
	if !strings.Contains(output, "Config Exists:      no") {
		t.Fatalf("output should report missing config, got: %s", output)
	}
	if !strings.Contains(output, "Config Loadable:    yes") {
		t.Fatalf("output should report loadable default config, got: %s", output)
	}
	if !strings.Contains(output, "Runtime State:      no") {
		t.Fatalf("output should report missing runtime state, got: %s", output)
	}
}

func TestDebugTextOutputWithRuntimeState(t *testing.T) {
	configPath := writeDebugConfig(t, `
node:
  name: alpha
netif:
  backend: userspace
coordinator:
  url: grpc://127.0.0.1:9443
`)

	state := &winkclient.RuntimeState{
		Version:   "dev",
		PID:       123,
		StartedAt: time.Now().Add(-time.Minute),
		UpdatedAt: time.Date(2026, 4, 11, 10, 0, 0, 0, time.UTC),
		Status: winkclient.RuntimeEngineStatus{
			State:          "connected",
			NodeID:         "node-123",
			NodeName:       "alpha",
			VirtualIP:      "10.88.0.10",
			NetworkCIDR:    "10.88.0.0/24",
			NATType:        "unknown",
			Backend:        "userspace",
			CoordinatorURL: "grpc://127.0.0.1:9443",
		},
		Peers: []winkclient.RuntimePeerStatus{
			{NodeID: "node-234", Name: "beta"},
			{NodeID: "node-345", Name: "gamma"},
		},
	}
	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("WriteRuntimeState() error = %v", err)
	}

	opts := &Options{ConfigPath: configPath}
	cmd := newDebugCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("debug execute error: %v", err)
	}

	output := buf.String()
	assertContains(t, output, "Config Exists:      yes")
	assertContains(t, output, "Config Loadable:    yes")
	assertContains(t, output, "Node Name:          alpha")
	assertContains(t, output, "Backend:            userspace")
	assertContains(t, output, "Coordinator URL:    grpc://127.0.0.1:9443")
	assertContains(t, output, "Runtime State:      yes")
	assertContains(t, output, "State:              connected")
	assertContains(t, output, "Node ID:            node-123")
	assertContains(t, output, "Virtual IP:         10.88.0.10")
	assertContains(t, output, "Network CIDR:       10.88.0.0/24")
	assertContains(t, output, "NAT Type:           unknown")
	assertContains(t, output, "Known Peers:        2")
}

func TestDebugJSONOutputWithRuntimeState(t *testing.T) {
	configPath := writeDebugConfig(t, `
node:
  name: beta
netif:
  backend: proxy
coordinator:
  url: grpc://127.0.0.1:9555
`)

	state := &winkclient.RuntimeState{
		Version:   "dev",
		PID:       456,
		StartedAt: time.Now().Add(-2 * time.Minute),
		UpdatedAt: time.Now(),
		Status: winkclient.RuntimeEngineStatus{
			State:          "connected",
			NodeID:         "node-456",
			NodeName:       "beta",
			VirtualIP:      "10.99.0.20",
			NetworkCIDR:    "10.99.0.0/24",
			NATType:        "unknown",
			Backend:        "proxy",
			CoordinatorURL: "grpc://127.0.0.1:9555",
		},
		Peers: []winkclient.RuntimePeerStatus{
			{NodeID: "node-1"},
		},
	}
	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("WriteRuntimeState() error = %v", err)
	}

	opts := &Options{ConfigPath: configPath}
	cmd := newDebugCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("debug --json execute error: %v", err)
	}

	var result debugOutput
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\nOutput: %s", err, buf.String())
	}

	if result.ConfigPath != configPath {
		t.Fatalf("config_path = %q, want %q", result.ConfigPath, configPath)
	}
	if !result.ConfigExists || !result.ConfigLoadable {
		t.Fatalf("expected config to exist and load, got exists=%v loadable=%v", result.ConfigExists, result.ConfigLoadable)
	}
	if result.NodeName != "beta" {
		t.Fatalf("node_name = %q, want beta", result.NodeName)
	}
	if result.Backend != "proxy" {
		t.Fatalf("backend = %q, want proxy", result.Backend)
	}
	if result.CoordinatorURL != "grpc://127.0.0.1:9555" {
		t.Fatalf("coordinator_url = %q, want grpc://127.0.0.1:9555", result.CoordinatorURL)
	}
	if result.RuntimeState == nil || !result.RuntimeState.Exists {
		t.Fatal("expected runtime_state.exists to be true")
	}
	if result.RuntimeState.State != "connected" {
		t.Fatalf("runtime_state.state = %q, want connected", result.RuntimeState.State)
	}
	if result.RuntimeState.NodeID != "node-456" {
		t.Fatalf("runtime_state.node_id = %q, want node-456", result.RuntimeState.NodeID)
	}
	if result.RuntimeState.VirtualIP != "10.99.0.20" {
		t.Fatalf("runtime_state.virtual_ip = %q, want 10.99.0.20", result.RuntimeState.VirtualIP)
	}
	if result.RuntimeState.NetworkCIDR != "10.99.0.0/24" {
		t.Fatalf("runtime_state.network_cidr = %q, want 10.99.0.0/24", result.RuntimeState.NetworkCIDR)
	}
	if result.RuntimeState.NATType != "unknown" {
		t.Fatalf("runtime_state.nat_type = %q, want unknown", result.RuntimeState.NATType)
	}
	if result.RuntimeState.KnownPeers != 1 {
		t.Fatalf("runtime_state.known_peers = %d, want 1", result.RuntimeState.KnownPeers)
	}
}

func TestDebugNoRuntimeStateDoesNotFail(t *testing.T) {
	configPath := writeDebugConfig(t, `
node:
  name: gamma
netif:
  backend: tun
coordinator:
  url: grpc://127.0.0.1:9777
`)

	opts := &Options{ConfigPath: configPath}
	cmd := newDebugCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("debug execute error: %v", err)
	}

	output := buf.String()
	assertContains(t, output, "Runtime State:      no")
	assertContains(t, output, "State:              not connected (no runtime state file)")
	assertContains(t, output, "Known Peers:        0")
}

func writeDebugConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func assertContains(t *testing.T, output, want string) {
	t.Helper()
	if !strings.Contains(output, want) {
		t.Fatalf("output should contain %q, got:\n%s", want, output)
	}
}
