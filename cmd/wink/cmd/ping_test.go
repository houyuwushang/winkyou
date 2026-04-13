package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	winkclient "winkyou/pkg/client"
)

func TestPingCommandWithRuntimePeer(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	state := &winkclient.RuntimeState{
		Version:   "test",
		PID:       1,
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status:    winkclient.RuntimeEngineStatus{State: "connected"},
		Peers: []winkclient.RuntimePeerStatus{{
			NodeID:         "node-a",
			Name:           "alpha",
			VirtualIP:      "127.0.0.1",
			State:          "connected",
			ConnectionType: "direct",
			Endpoint:       "127.0.0.1:51820",
		}},
	}
	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("WriteRuntimeState() error: %v", err)
	}

	cmd := newPingCmd(&Options{ConfigPath: configPath})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"alpha"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ping execute error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "PING 127.0.0.1") {
		t.Fatalf("unexpected output: %s", out)
	}
	if !strings.Contains(out, "context=direct") {
		t.Fatalf("missing connection context: %s", out)
	}
}
