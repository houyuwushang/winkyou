//go:build privileged_e2e && linux

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	"winkyou/pkg/client"
	"winkyou/pkg/coordinator/server"

	"google.golang.org/grpc"
)

func TestPrivilegedTwoNodeDirectPingTCPUDP(t *testing.T) {
	if os.Getenv("WINKYOU_E2E_PRIVILEGED") != "1" {
		t.Skip("set WINKYOU_E2E_PRIVILEGED=1 to run privileged e2e connectivity tests")
	}
	if os.Geteuid() != 0 {
		t.Skip("privileged e2e requires root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun is unavailable")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip binary is unavailable")
	}

	topology := createNamespaceTopology(t)
	coord := startCoordinatorOn(t, net.JoinHostPort(topology.bridgeIP, "0"))

	tmpDir := t.TempDir()
	cfgAlpha := writeConfigFileWithBackend(t, tmpDir, "alpha", coord.addr(), "tun")
	cfgBeta := writeConfigFileWithBackend(t, tmpDir, "beta", coord.addr(), "tun")

	alphaProc := startWinkUpInNamespace(t, topology.alphaNS, cfgAlpha, nil)
	betaProc := startWinkUpInNamespace(t, topology.betaNS, cfgBeta, nil)

	alphaState, ok := tryPollRuntimeState(cfgAlpha, 60*time.Second, func(state *client.RuntimeState) bool {
		peer := findPeerByName(state.Peers, "beta")
		return state.Status.State == "connected" && peer != nil && peer.State == "connected" && peer.ConnectionType == "direct"
	})
	if !ok {
		t.Fatalf("alpha did not reach connected direct state\nalpha output:\n%s\nbeta output:\n%s", alphaProc.output.String(), betaProc.output.String())
	}
	betaState, ok := tryPollRuntimeState(cfgBeta, 60*time.Second, func(state *client.RuntimeState) bool {
		peer := findPeerByName(state.Peers, "alpha")
		return state.Status.State == "connected" && peer != nil && peer.State == "connected" && peer.ConnectionType == "direct"
	})
	if !ok {
		t.Fatalf("beta did not reach connected direct state\nalpha output:\n%s\nbeta output:\n%s", alphaProc.output.String(), betaProc.output.String())
	}

	pingOut, err := runWinkInNamespace(t, topology.alphaNS, 10*time.Second, nil, "ping", "--config", cfgAlpha, "beta")
	if err != nil {
		t.Fatalf("wink ping failed: %v\noutput: %s", err, pingOut)
	}
	if !strings.Contains(pingOut, "reply: time=") {
		t.Fatalf("unexpected ping output: %s", pingOut)
	}
	if !strings.Contains(pingOut, "context=direct") {
		t.Fatalf("expected direct ping context, got: %s", pingOut)
	}

	probeBin := buildNetProbe(t)
	assertTCPAcrossNamespaces(t, probeBin, topology.betaNS, topology.alphaNS, betaState.Status.VirtualIP)
	assertUDPAcrossNamespaces(t, probeBin, topology.betaNS, topology.alphaNS, betaState.Status.VirtualIP)

	if alphaState.Status.ConnectedPeers < 1 || betaState.Status.ConnectedPeers < 1 {
		t.Fatalf("expected both nodes to report at least one connected peer, alpha=%d beta=%d", alphaState.Status.ConnectedPeers, betaState.Status.ConnectedPeers)
	}
}

type namespaceTopology struct {
	alphaNS  string
	betaNS   string
	bridge   string
	bridgeIP string
}

func createNamespaceTopology(t *testing.T) *namespaceTopology {
	t.Helper()

	suffix := fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	octet := 100 + int(time.Now().UnixNano()%100)
	topology := &namespaceTopology{
		alphaNS:  "wink-alpha-" + suffix,
		betaNS:   "wink-beta-" + suffix,
		bridge:   "wbr" + suffix,
		bridgeIP: fmt.Sprintf("172.31.%d.1", octet),
	}
	alphaIP := fmt.Sprintf("172.31.%d.2/24", octet)
	betaIP := fmt.Sprintf("172.31.%d.3/24", octet)

	runIP(t, "link", "add", topology.bridge, "type", "bridge")
	t.Cleanup(func() { _ = runIPIgnoreError("link", "del", topology.bridge) })
	runIP(t, "addr", "add", topology.bridgeIP+"/24", "dev", topology.bridge)
	runIP(t, "link", "set", topology.bridge, "up")

	setupNamespaceLink(t, topology.alphaNS, "wha"+suffix, topology.bridge, alphaIP)
	setupNamespaceLink(t, topology.betaNS, "whb"+suffix, topology.bridge, betaIP)
	return topology
}

func setupNamespaceLink(t *testing.T, namespace, hostVeth, bridge, addrCIDR string) {
	t.Helper()

	runIP(t, "netns", "add", namespace)
	t.Cleanup(func() { _ = runIPIgnoreError("netns", "del", namespace) })

	runIP(t, "link", "add", hostVeth, "type", "veth", "peer", "name", "eth0", "netns", namespace)
	runIP(t, "link", "set", hostVeth, "master", bridge)
	runIP(t, "link", "set", hostVeth, "up")
	runIP(t, "-n", namespace, "link", "set", "lo", "up")
	runIP(t, "-n", namespace, "addr", "add", addrCIDR, "dev", "eth0")
	runIP(t, "-n", namespace, "link", "set", "eth0", "up")
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func runIPIgnoreError(args ...string) error {
	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return nil
}

func startCoordinatorOn(t *testing.T, listenAddr string) *coordHarness {
	t.Helper()

	domain, err := server.New(&server.Config{
		ListenAddress: listenAddr,
		NetworkCIDR:   "10.99.0.0/24",
		LeaseTTL:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	coordinatorv1.RegisterCoordinatorServer(grpcServer, server.NewGRPCService(domain))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = grpcServer.Serve(listener)
	}()

	h := &coordHarness{listener: listener, grpcServer: grpcServer}
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
		<-done
	})
	return h
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
	cfgPath := filepath.Join(dir, name+".yaml")
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

func runWinkInNamespace(t *testing.T, namespace string, timeout time.Duration, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	return runBinaryInNamespace(t, namespace, timeout, extraEnv, buildWink(t), args...)
}

func startWinkUpInNamespace(t *testing.T, namespace, configPath string, extraEnv []string) *startedProcess {
	t.Helper()
	return startBinaryInNamespace(t, namespace, extraEnv, buildWink(t), "up", "--config", configPath)
}

func runBinaryInNamespace(t *testing.T, namespace string, timeout time.Duration, extraEnv []string, binary string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmdArgs := append([]string{"netns", "exec", namespace, binary}, args...)
	cmd := exec.CommandContext(ctx, "ip", cmdArgs...)
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type startedProcess struct {
	cmd    *exec.Cmd
	output *bytes.Buffer
}

func startBinaryInNamespace(t *testing.T, namespace string, extraEnv []string, binary string, args ...string) *startedProcess {
	t.Helper()

	cmdArgs := append([]string{"netns", "exec", namespace, binary}, args...)
	cmd := exec.Command("ip", cmdArgs...)
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(os.Environ(), extraEnv...)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start namespaced command: %v", err)
	}

	process := &startedProcess{cmd: cmd, output: &output}
	t.Cleanup(func() {
		if process.cmd.Process != nil {
			_ = process.cmd.Process.Kill()
			_ = process.cmd.Wait()
		}
	})
	return process
}

func waitStartedProcess(t *testing.T, process *startedProcess, timeout time.Duration) string {
	t.Helper()
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- process.cmd.Wait()
	}()

	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("namespaced command failed: %v\noutput: %s", err, process.output.String())
		}
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for namespaced command\noutput: %s", process.output.String())
	}
	return process.output.String()
}

var (
	probeBuildOnce sync.Once
	probeBin       string
	probeBuildErr  error
)

func buildNetProbe(t *testing.T) string {
	t.Helper()
	root := moduleRoot(t)
	probeBuildOnce.Do(func() {
		name := "wink-e2e-netprobe"
		probeBin = filepath.Join(os.TempDir(), name)
		cmd := exec.Command(goExe(), "build", "-o", probeBin, "./test/e2e/netprobe")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			probeBuildErr = fmt.Errorf("build netprobe: %v\n%s", err, out)
		}
	})
	if probeBuildErr != nil {
		t.Fatalf("build netprobe: %v", probeBuildErr)
	}
	return probeBin
}

func assertTCPAcrossNamespaces(t *testing.T, probeBin, serverNS, clientNS, host string) {
	t.Helper()
	server := startBinaryInNamespace(
		t,
		serverNS,
		nil,
		probeBin,
		"tcp-serve",
		"--listen", net.JoinHostPort(host, "19091"),
		"--expect", "ping",
		"--reply", "pong",
		"--timeout", "10s",
	)
	time.Sleep(500 * time.Millisecond)

	out, err := runBinaryInNamespace(
		t,
		clientNS,
		10*time.Second,
		nil,
		probeBin,
		"tcp-check",
		"--addr", net.JoinHostPort(host, "19091"),
		"--message", "ping",
		"--expect", "pong",
		"--timeout", "5s",
	)
	if err != nil {
		t.Fatalf("tcp client failed: %v\noutput: %s", err, out)
	}
	waitStartedProcess(t, server, 10*time.Second)
}

func assertUDPAcrossNamespaces(t *testing.T, probeBin, serverNS, clientNS, host string) {
	t.Helper()
	server := startBinaryInNamespace(
		t,
		serverNS,
		nil,
		probeBin,
		"udp-serve",
		"--listen", net.JoinHostPort(host, "19092"),
		"--expect", "ping",
		"--reply", "pong",
		"--timeout", "10s",
	)
	time.Sleep(500 * time.Millisecond)

	out, err := runBinaryInNamespace(
		t,
		clientNS,
		10*time.Second,
		nil,
		probeBin,
		"udp-check",
		"--addr", net.JoinHostPort(host, "19092"),
		"--message", "ping",
		"--expect", "pong",
		"--timeout", "5s",
	)
	if err != nil {
		t.Fatalf("udp client failed: %v\noutput: %s", err, out)
	}
	waitStartedProcess(t, server, 10*time.Second)
}
