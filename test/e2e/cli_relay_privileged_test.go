//go:build privileged_e2e && linux

package e2e_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winkyou/pkg/client"
	relayserver "winkyou/pkg/relay/server"
)

func TestPrivilegedTwoNodeRelayPingTCPUDP(t *testing.T) {
	if os.Getenv("WINKYOU_E2E_PRIVILEGED") != "1" {
		t.Skip("set WINKYOU_E2E_PRIVILEGED=1 to run privileged e2e connectivity tests")
	}
	if os.Geteuid() != 0 {
		t.Skip("privileged e2e requires root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun is unavailable")
	}

	// Determine relay source: prefer coturn if WINKYOU_TEST_TURN_URL is set,
	// otherwise start embedded wink-relay for CI convenience.
	turnURL := os.Getenv("WINKYOU_TEST_TURN_URL")
	turnUser := envOrDefault("WINKYOU_TEST_TURN_USER", "winkdemo")
	turnPass := envOrDefault("WINKYOU_TEST_TURN_PASS", "winkdemo-pass")

	topology := createNamespaceTopology(t)

	if turnURL == "" {
		// Start embedded relay on bridge IP
		relay := startEmbeddedRelay(t, topology.bridgeIP)
		turnURL = fmt.Sprintf("turn:%s", relay.Addr().String())
		t.Logf("using embedded relay at %s", turnURL)
	} else {
		t.Logf("using external TURN at %s", turnURL)
	}

	coord := startCoordinatorOn(t, net.JoinHostPort(topology.bridgeIP, "0"))

	tmpDir := t.TempDir()
	cfgAlpha := writeRelayConfigFile(t, tmpDir, "alpha", coord.addr(), "tun", turnURL, turnUser, turnPass, true)
	cfgBeta := writeRelayConfigFile(t, tmpDir, "beta", coord.addr(), "tun", turnURL, turnUser, turnPass, true)

	alphaProc := startWinkUpInNamespace(t, topology.alphaNS, cfgAlpha, nil)
	betaProc := startWinkUpInNamespace(t, topology.betaNS, cfgBeta, nil)

	// Wait for relay connection
	alphaState, ok := tryPollRuntimeState(cfgAlpha, 90*time.Second, func(state *client.RuntimeState) bool {
		peer := findPeerByName(state.Peers, "beta")
		return state.Status.State == "connected" && peer != nil && peer.State == "connected" && peer.ConnectionType == "relay"
	})
	if !ok {
		t.Fatalf("alpha did not reach connected relay state\nalpha output:\n%s\nbeta output:\n%s", alphaProc.output.String(), betaProc.output.String())
	}
	betaState, ok := tryPollRuntimeState(cfgBeta, 90*time.Second, func(state *client.RuntimeState) bool {
		peer := findPeerByName(state.Peers, "alpha")
		return state.Status.State == "connected" && peer != nil && peer.State == "connected" && peer.ConnectionType == "relay"
	})
	if !ok {
		t.Fatalf("beta did not reach connected relay state\nalpha output:\n%s\nbeta output:\n%s", alphaProc.output.String(), betaProc.output.String())
	}

	// Verify ICE diagnostics are populated
	alphaPeer := findPeerByName(alphaState.Peers, "beta")
	if alphaPeer.ICEState == "" {
		t.Error("alpha peer missing ICEState")
	}
	if alphaPeer.LocalCandidate == "" {
		t.Error("alpha peer missing LocalCandidate")
	}
	if alphaPeer.RemoteCandidate == "" {
		t.Error("alpha peer missing RemoteCandidate")
	}
	if !strings.Contains(alphaPeer.LocalCandidate, "relay") && !strings.Contains(alphaPeer.RemoteCandidate, "relay") {
		t.Errorf("expected at least one relay candidate, local=%s remote=%s", alphaPeer.LocalCandidate, alphaPeer.RemoteCandidate)
	}

	// Ping test
	pingOut, err := runWinkInNamespace(t, topology.alphaNS, 15*time.Second, nil, "ping", "--config", cfgAlpha, "beta")
	if err != nil {
		t.Fatalf("wink ping failed: %v\noutput: %s", err, pingOut)
	}
	if !strings.Contains(pingOut, "reply: time=") {
		t.Fatalf("unexpected ping output: %s", pingOut)
	}
	if !strings.Contains(pingOut, "context=relay") {
		t.Fatalf("expected relay ping context, got: %s", pingOut)
	}

	// TCP and UDP probe
	probeBin := buildNetProbe(t)
	assertTCPAcrossNamespaces(t, probeBin, topology.betaNS, topology.alphaNS, betaState.Status.VirtualIP)
	assertUDPAcrossNamespaces(t, probeBin, topology.betaNS, topology.alphaNS, betaState.Status.VirtualIP)

	// Verify handshake timestamps
	alphaPeerFinal := findPeerByName(alphaState.Peers, "beta")
	if alphaPeerFinal != nil && alphaPeerFinal.LastHandshake.IsZero() {
		t.Log("WARNING: Last handshake is zero - WireGuard handshake may not have completed yet")
	}

	t.Logf("relay e2e passed: alpha connection_type=%s beta connection_type=%s", alphaPeer.ConnectionType, findPeerByName(betaState.Peers, "alpha").ConnectionType)
}

func startEmbeddedRelay(t *testing.T, bindIP string) *relayserver.Server {
	t.Helper()

	srv, err := relayserver.New(relayserver.Config{
		ListenAddress: net.JoinHostPort(bindIP, "3478"),
		Realm:         "winkyou",
		Users:         map[string]string{"winkdemo": "winkdemo-pass"},
		RelayAddress:  bindIP,
		MinPort:       49152,
		MaxPort:       49252,
	})
	if err != nil {
		t.Fatalf("relay server New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("relay server Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func writeRelayConfigFile(t *testing.T, dir, name, coordAddr, backend, turnURL, turnUser, turnPass string, forceRelay bool) string {
	t.Helper()
	cfgPath := filepath.Join(dir, name+".yaml")
	content := fmt.Sprintf(`node:
  name: "%s"
log:
  level: "debug"
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
  force_relay: %v
  turn_servers:
    - url: "%s"
      username: "%s"
      password: "%s"
`, name, coordAddr, backend, forceRelay, turnURL, turnUser, turnPass)
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
