package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	"winkyou/pkg/client"
	"winkyou/pkg/coordinator/server"
	"winkyou/pkg/tunnel"

	"google.golang.org/grpc"
)

// --- Build helpers ---

// goExe returns the Go compiler path.
func goExe() string {
	if p := os.Getenv("GOEXE"); p != "" {
		return p
	}
	if path, err := exec.LookPath("go"); err == nil {
		return path
	}
	if runtime.GOOS == "windows" {
		home, _ := os.UserHomeDir()
		candidate := filepath.Join(home, ".g", "go", "bin", "go.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "go"
}

// moduleRoot returns the project root by walking up to find go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}

var (
	buildOnce sync.Once
	winkBin   string
	buildErr  error
)

// buildWink compiles the wink binary once per test run and returns its path.
func buildWink(t *testing.T) string {
	t.Helper()
	root := moduleRoot(t)
	buildOnce.Do(func() {
		binName := "wink-e2e-test"
		if runtime.GOOS == "windows" {
			binName += ".exe"
		}
		outDir := t.TempDir()
		winkBin = filepath.Join(outDir, binName)
		// Build to a well-known temp path; we can't use t.TempDir() for
		// the sync.Once because only the first caller's t is available.
		// Instead, build to os.TempDir.
		winkBin = filepath.Join(os.TempDir(), binName)
		cmd := exec.Command(goExe(), "build", "-o", winkBin, "./cmd/wink")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build wink: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build wink binary: %v", buildErr)
	}
	t.Cleanup(func() {
		// Don't remove; other tests may still need it.
	})
	return winkBin
}

// --- Coordinator harness ---

type coordHarness struct {
	listener   net.Listener
	grpcServer *grpc.Server
}

func startCoordinator(t *testing.T) *coordHarness {
	t.Helper()

	domain, err := server.New(&server.Config{
		ListenAddress: "127.0.0.1:0",
		NetworkCIDR:   "10.99.0.0/24",
		LeaseTTL:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	gs := grpc.NewServer()
	coordinatorv1.RegisterCoordinatorServer(gs, server.NewGRPCService(domain))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = gs.Serve(lis)
	}()

	h := &coordHarness{listener: lis, grpcServer: gs}
	t.Cleanup(func() {
		gs.Stop()
		_ = lis.Close()
		<-done
	})
	return h
}

func (h *coordHarness) addr() string {
	return h.listener.Addr().String()
}

// --- Config file helpers ---

func writeConfigFile(t *testing.T, dir, name, coordAddr string) string {
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
  backend: "userspace"
  mtu: 1280
wireguard:
  listen_port: 0
nat:
  stun_servers: []
`, name, coordAddr)
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// --- Subprocess helpers ---

// runWinkBin runs the compiled wink binary synchronously with a timeout.
func runWinkBin(t *testing.T, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	bin := buildWink(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// startWinkUp starts the compiled wink binary with `up` in the background.
// Returns the exec.Cmd; cleanup kills the process.
func startWinkUp(t *testing.T, configPath string) *exec.Cmd {
	t.Helper()
	bin := buildWink(t)
	cmd := exec.Command(bin, "up", "--config", configPath)
	cmd.Dir = moduleRoot(t)
	// Pipe output to devnull to avoid the "Test I/O incomplete" issue
	// on Windows where killing the process doesn't close inherited pipes.
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start wink up: %v", err)
	}

	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd
}

// --- Polling helpers ---

func pollForRuntimeState(t *testing.T, configPath string, timeout time.Duration, pred func(*client.RuntimeState) bool) *client.RuntimeState {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := client.LoadRuntimeState(configPath)
		if err == nil && pred(state) {
			return state
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for runtime state condition (config=%s)", configPath)
	return nil
}

func pollForCondition(t *testing.T, timeout time.Duration, desc string, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", desc)
}

// ============================================================
// Test 1: Single node lifecycle — up, status, peers, down
// ============================================================

func TestSingleNodeLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test skipped in -short mode")
	}

	coord := startCoordinator(t)
	tmpDir := t.TempDir()
	cfgPath := writeConfigFile(t, tmpDir, "node1", coord.addr())

	// 1. Start wink up as subprocess.
	upCmd := startWinkUp(t, cfgPath)

	// 2. Wait for runtime state to show "connected".
	state := pollForRuntimeState(t, cfgPath, 30*time.Second, func(s *client.RuntimeState) bool {
		return s.Status.State == "connected" &&
			s.Status.NodeID != "" &&
			s.Status.VirtualIP != ""
	})

	if state.Status.NodeName != "node1" {
		t.Errorf("NodeName = %q, want node1", state.Status.NodeName)
	}
	if !strings.HasPrefix(state.Status.VirtualIP, "10.99.0.") {
		t.Errorf("VirtualIP = %q, want 10.99.0.x", state.Status.VirtualIP)
	}
	if state.Status.NetworkCIDR != "10.99.0.0/24" {
		t.Errorf("NetworkCIDR = %q, want 10.99.0.0/24", state.Status.NetworkCIDR)
	}

	// 3. Run `wink status --json` and verify.
	statusOut, err := runWinkBin(t, 15*time.Second, "status", "--config", cfgPath, "--json")
	if err != nil {
		t.Fatalf("wink status --json error: %v\nOutput: %s", err, statusOut)
	}
	var statusJSON client.RuntimeState
	if err := json.Unmarshal([]byte(statusOut), &statusJSON); err != nil {
		t.Fatalf("parse status json: %v\nRaw: %s", err, statusOut)
	}
	if statusJSON.Status.State != "connected" {
		t.Errorf("status state = %q, want connected", statusJSON.Status.State)
	}

	// 4. Run `wink peers --json` and verify empty list.
	peersOut, err := runWinkBin(t, 15*time.Second, "peers", "--config", cfgPath, "--json")
	if err != nil {
		t.Fatalf("wink peers --json error: %v\nOutput: %s", err, peersOut)
	}
	var peersJSON []json.RawMessage
	if err := json.Unmarshal([]byte(peersOut), &peersJSON); err != nil {
		t.Fatalf("parse peers json: %v\nRaw: %s", err, peersOut)
	}
	if len(peersJSON) != 0 {
		t.Errorf("peers count = %d, want 0", len(peersJSON))
	}

	// 5. Run `wink down` to stop.
	downOut, err := runWinkBin(t, 15*time.Second, "down", "--config", cfgPath)
	if err != nil {
		t.Fatalf("wink down error: %v\nOutput: %s", err, downOut)
	}

	// 6. Wait for the subprocess to exit.
	waitDone := make(chan error, 1)
	go func() { waitDone <- upCmd.Wait() }()
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		t.Log("wink up process did not exit after down; killing")
		_ = upCmd.Process.Kill()
		<-waitDone
	}

	// 7. Verify runtime state file is gone.
	pollForCondition(t, 5*time.Second, "runtime state removed", func() bool {
		_, err := client.LoadRuntimeState(cfgPath)
		return err != nil
	})
}

// ============================================================
// Test 2: Two nodes discover each other
// ============================================================

func TestTwoNodesDiscoverEachOther(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test skipped in -short mode")
	}

	coord := startCoordinator(t)
	tmpDir := t.TempDir()

	cfgAlpha := writeConfigFile(t, tmpDir, "alpha", coord.addr())
	cfgBeta := writeConfigFile(t, tmpDir, "beta", coord.addr())

	// Start both nodes.
	startWinkUp(t, cfgAlpha)
	startWinkUp(t, cfgBeta)

	// Wait for both to reach "connected".
	pollForRuntimeState(t, cfgAlpha, 30*time.Second, func(s *client.RuntimeState) bool {
		return s.Status.State == "connected"
	})
	pollForRuntimeState(t, cfgBeta, 30*time.Second, func(s *client.RuntimeState) bool {
		return s.Status.State == "connected"
	})

	// Wait for peer discovery via the runtime state file.
	pollForRuntimeState(t, cfgAlpha, 30*time.Second, func(s *client.RuntimeState) bool {
		return hasPeerNamed(s.Peers, "beta")
	})
	pollForRuntimeState(t, cfgBeta, 30*time.Second, func(s *client.RuntimeState) bool {
		return hasPeerNamed(s.Peers, "alpha")
	})

	// Verify via CLI: `wink peers --json` on alpha should show beta.
	peersOut, err := runWinkBin(t, 15*time.Second, "peers", "--config", cfgAlpha, "--json")
	if err != nil {
		t.Fatalf("wink peers --json (alpha) error: %v\nOutput: %s", err, peersOut)
	}
	var peers []client.RuntimePeerStatus
	if err := json.Unmarshal([]byte(peersOut), &peers); err != nil {
		t.Fatalf("parse peers json: %v\nRaw: %s", err, peersOut)
	}

	found := false
	for _, p := range peers {
		if p.Name == "beta" {
			found = true
			if p.VirtualIP == "" {
				t.Error("beta peer has empty VirtualIP")
			}
		}
	}
	if !found {
		t.Errorf("alpha's peers do not include beta; got: %+v", peers)
	}
}

// ============================================================
// Test 3: genkey CLI end-to-end
// ============================================================

func TestGenkeyE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test skipped in -short mode")
	}

	out, err := runWinkBin(t, 15*time.Second, "genkey", "--json")
	if err != nil {
		t.Fatalf("wink genkey --json error: %v\nOutput: %s", err, out)
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse genkey json: %v\nRaw: %s", err, out)
	}

	privStr, ok := result["private_key"]
	if !ok || privStr == "" {
		t.Fatal("genkey output missing private_key")
	}
	pubStr, ok := result["public_key"]
	if !ok || pubStr == "" {
		t.Fatal("genkey output missing public_key")
	}

	// Verify the private key can be parsed by pkg/tunnel.
	priv, err := tunnel.ParsePrivateKey(privStr)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	// Verify public key derivation is consistent.
	derived := priv.PublicKey()
	if derived.String() != pubStr {
		t.Errorf("derived public key %q != output public key %q", derived.String(), pubStr)
	}

	// Run genkey a second time and verify different keys.
	out2, err := runWinkBin(t, 15*time.Second, "genkey", "--json")
	if err != nil {
		t.Fatalf("second genkey error: %v", err)
	}
	if bytes.Equal([]byte(out), []byte(out2)) {
		t.Error("two genkey invocations produced identical output")
	}
}

// --- helpers ---

func hasPeerNamed(peers []client.RuntimePeerStatus, name string) bool {
	for _, p := range peers {
		if p.Name == name {
			return true
		}
	}
	return false
}
