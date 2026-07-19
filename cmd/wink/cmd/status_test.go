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

func TestStatusAutonomousMeshText(t *testing.T) {
	configPath := writeStatusTestConfig(t)
	writeStatusTestState(t, configPath)

	cmd := newStatusCmd(&Options{ConfigPath: configPath})
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status execute: %v", err)
	}
	text := output.String()
	for _, want := range []string{
		"Mode:          autonomous_mesh",
		"Infra Coord:   not started",
		"Mesh Listen:   127.0.0.1:32100",
		"Control:       127.0.0.1:32110",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("status output missing %q:\n%s", want, text)
		}
	}
}

func TestStatusJSONRedactsShutdownToken(t *testing.T) {
	configPath := writeStatusTestConfig(t)
	writeStatusTestState(t, configPath)

	cmd := newStatusCmd(&Options{ConfigPath: configPath})
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status --json execute: %v", err)
	}
	if strings.Contains(output.String(), "super-secret") || strings.Contains(output.String(), "shutdown_token") {
		t.Fatalf("status JSON leaked shutdown token: %s", output.String())
	}
	var state map[string]any
	if err := json.Unmarshal(output.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal status JSON: %v", err)
	}
	if state["control_endpoint"] != "127.0.0.1:32110" {
		t.Fatalf("control endpoint = %#v", state["control_endpoint"])
	}
}

func TestStatusDisconnectedAutonomousMeshUsesAutonomousConfiguration(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "wink.yaml")
	configBody := `node:
  name: alpha
autonomous_mesh:
  enabled: true
  node_id: A
  virtual_ip: fd7a:115c:a1e0::a
  listen: off
  control_listen: 127.0.0.1:32110
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newStatusCmd(&Options{ConfigPath: configPath})
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status execute: %v", err)
	}
	text := output.String()
	for _, want := range []string{
		"Mode:          autonomous_mesh",
		"Backend:       userspace-mesh",
		"Coordinator:   -",
		"Virtual IP:    fd7a:115c:a1e0::a",
		"Control:       127.0.0.1:32110",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("disconnected status missing %q:\n%s", want, text)
		}
	}
}

func writeStatusTestConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wink.yaml")
	if err := os.WriteFile(path, []byte("node:\n  name: alpha\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeStatusTestState(t *testing.T, configPath string) {
	t.Helper()
	state := &winkclient.RuntimeState{
		SchemaVersion:   1,
		InstanceID:      "instance-a",
		PID:             1234,
		StartedAt:       time.Now().Add(-time.Minute),
		UpdatedAt:       time.Now(),
		ControlEndpoint: "127.0.0.1:32110",
		ShutdownToken:   "super-secret",
		Status: winkclient.RuntimeEngineStatus{
			Mode: "autonomous_mesh", State: "connected", NodeID: "A", NodeName: "alpha",
			VirtualIP: "fd7a:115c:a1e0::a", NetworkCIDR: "fd7a:115c:a1e0::a/128",
			Backend: "userspace-mesh", MeshListen: "127.0.0.1:32100", ControlListen: "127.0.0.1:32110",
			Uptime: "1m0s",
		},
	}
	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}
}
