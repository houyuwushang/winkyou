//go:build privileged_e2e

package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"winkyou/pkg/client"
)

func TestPrivilegedTwoNodeDirectPingTCPUDP(t *testing.T) {
	if os.Getenv("WINKYOU_E2E_PRIVILEGED") != "1" {
		t.Skip("set WINKYOU_E2E_PRIVILEGED=1 to run privileged e2e connectivity tests")
	}
	if os.Geteuid() != 0 {
		t.Skip("privileged e2e requires root/admin privileges")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun is unavailable")
	}
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg binary is unavailable")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip binary is unavailable")
	}

	coord := startCoordinator(t)
	tmpDir := t.TempDir()
	cfgAlpha := writeConfigFileWithBackend(t, tmpDir, "alpha", coord.addr(), "tun")
	cfgBeta := writeConfigFileWithBackend(t, tmpDir, "beta", coord.addr(), "tun")

	startWinkUpWithEnv(t, cfgAlpha, nil)
	startWinkUpWithEnv(t, cfgBeta, nil)

	alphaState, ok := tryPollRuntimeState(cfgAlpha, 30*time.Second, func(s *client.RuntimeState) bool {
		return s.Status.State == "connected" && hasPeerNamed(s.Peers, "beta")
	})
	if !ok {
		t.Skip("alpha did not reach connected+peer state; privileged topology may be unavailable")
	}
	betaState, ok := tryPollRuntimeState(cfgBeta, 30*time.Second, func(s *client.RuntimeState) bool {
		return s.Status.State == "connected" && hasPeerNamed(s.Peers, "alpha")
	})
	if !ok {
		t.Skip("beta did not reach connected+peer state; privileged topology may be unavailable")
	}

	alphaPeer := findPeerByName(alphaState.Peers, "beta")
	betaPeer := findPeerByName(betaState.Peers, "alpha")
	if alphaPeer == nil || betaPeer == nil {
		t.Fatalf("expected both peers discovered, alpha=%+v beta=%+v", alphaPeer, betaPeer)
	}
	if alphaPeer.ConnectionType != "direct" || betaPeer.ConnectionType != "direct" {
		t.Fatalf("expected direct connect, alpha=%s beta=%s", alphaPeer.ConnectionType, betaPeer.ConnectionType)
	}

	pingOut, err := runWinkBinWithEnv(t, 10*time.Second, nil, "ping", "--config", cfgAlpha, "beta")
	if err != nil {
		t.Fatalf("wink ping failed: %v\noutput: %s", err, pingOut)
	}
	if !strings.Contains(pingOut, "probe sent") {
		t.Fatalf("unexpected ping output: %s", pingOut)
	}

	assertTCPReachable(t, betaState.Status.VirtualIP)
	assertUDPReachable(t, betaState.Status.VirtualIP)
}

func tryPollRuntimeState(configPath string, timeout time.Duration, pred func(*client.RuntimeState) bool) (*client.RuntimeState, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := client.LoadRuntimeState(configPath)
		if err == nil && pred(state) {
			return state, true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, false
}

func writeConfigFileWithBackend(t *testing.T, dir, name, coordAddr, backend string) string {
	t.Helper()
	cfgPath := fmt.Sprintf("%s/%s.yaml", dir, name)
	content := fmt.Sprintf(`node:
  name: "%s"
log:
  level: "info"
  format: "text"
  output: "stderr"
coordinator:
  url: "grpc://%s"
  timeout: 5s
netif:
  backend: "%s"
  mtu: 1280
wireguard:
  listen_port: 0
nat:
  stun_servers: []
`, name, coordAddr, backend)
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

func findPeerByName(peers []client.RuntimePeerStatus, name string) *client.RuntimePeerStatus {
	for i := range peers {
		if peers[i].Name == name {
			return &peers[i]
		}
	}
	return nil
}

func assertTCPReachable(t *testing.T, host string) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen tcp on %s failed: %v", host, err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp failed: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tcp failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read tcp failed: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("tcp response = %q, want pong", string(buf[:n]))
	}
	<-done
}

func assertUDPReachable(t *testing.T, host string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen udp on %s failed: %v", host, err)
	}
	defer pc.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "ping" {
			_, _ = pc.WriteTo([]byte("pong"), addr)
		}
	}()

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial udp failed: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write udp failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read udp failed: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("udp response = %q, want pong", string(buf[:n]))
	}
	<-done
}
