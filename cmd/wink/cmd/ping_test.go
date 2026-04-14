package cmd

import (
	"bytes"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	winkclient "winkyou/pkg/client"
)

func TestPingCommandWithRuntimePeer(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: winkclient.PingPort})
	if err != nil {
		t.Fatalf("ListenUDP() error: %v", err)
	}
	defer server.Close()

	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			request, err := winkclient.UnmarshalPingRequest(buffer[:n])
			if err != nil {
				continue
			}
			response, err := winkclient.MarshalPingResponse(winkclient.PingResponse{ID: request.ID})
			if err != nil {
				continue
			}
			_, _ = server.WriteToUDP(response, addr)
		}
	}()

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
	if !strings.Contains(out, "reply: time=") {
		t.Fatalf("missing reply line: %s", out)
	}
	if !strings.Contains(out, "context=direct") {
		t.Fatalf("missing connection context: %s", out)
	}
}
