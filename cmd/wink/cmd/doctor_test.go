package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/config"
)

func TestDoctorResultSummary(t *testing.T) {
	result := doctorResult{}
	result.add(okCheck("config", "config loaded", "ok"))
	result.add(warnCheck("tunnel", "peers", "no peers", "start another client"))
	result.add(failCheck("coordinator", "reachable", "refused", "check port"))
	result.finish()

	if result.Summary.OK != 1 || result.Summary.Warn != 1 || result.Summary.Fail != 1 || result.Summary.Worst != doctorFail {
		t.Fatalf("summary = %#v, want 1/1/1 fail", result.Summary)
	}
}

func TestDoctorJSONAllOKWithFakeProbes(t *testing.T) {
	configPath := writeDoctorConfig(t)
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:             "node-b",
		Name:               "node-b",
		State:              winkclient.PeerStateConnected.String(),
		ConnectionType:     winkclient.ConnectionTypeRelay.String(),
		LastHandshake:      time.Now(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	cmd := newDoctorCmdWithProbes(&Options{ConfigPath: configPath}, healthyDoctorProbes())
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--json", "--relay", "--strategy", "relay_only"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor --json execute error: %v", err)
	}

	var result doctorResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("json unmarshal error: %v\n%s", err, buf.String())
	}
	if result.Summary.Fail != 0 {
		t.Fatalf("summary = %#v, want no failures; checks=%#v", result.Summary, result.Checks)
	}
	if check := findDoctorCheck(result, "strategy", "requested"); check.Status != doctorOK {
		t.Fatalf("requested strategy check = %#v, want ok", check)
	}
}

func TestDoctorCoordinatorFail(t *testing.T) {
	configPath := writeDoctorConfig(t)
	probes := healthyDoctorProbes()
	probes.Coordinator = func(context.Context, *config.Config) doctorCheck {
		return failCheck("coordinator", "reachable", "dial tcp: connection refused", "check coordinator host, port, firewall, and auth key")
	}

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, probes)
	check := findDoctorCheck(result, "coordinator", "reachable")
	if check.Status != doctorFail || !strings.Contains(check.Message, "connection refused") {
		t.Fatalf("coordinator check = %#v, want connection refused failure", check)
	}
}

func TestDoctorTURNFailWhenRelayRequired(t *testing.T) {
	configPath := writeDoctorConfig(t)
	probes := healthyDoctorProbes()
	probes.TURN = func(context.Context, *config.Config) doctorCheck {
		return failCheck("nat", "turn", "TURN relay gather failed", "check coturn external-ip and firewall UDP/TCP 3478")
	}

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{relay: true}, probes)
	check := findDoctorCheck(result, "nat", "turn")
	if check.Status != doctorFail || !strings.Contains(check.Message, "TURN relay gather failed") {
		t.Fatalf("turn check = %#v, want TURN failure", check)
	}
}

func TestDoctorTunnelPermissionFail(t *testing.T) {
	configPath := writeDoctorConfig(t)
	probes := healthyDoctorProbes()
	probes.LocalInterface = func(context.Context, *config.Config) doctorCheck {
		return failCheck("local_interface", "tun", "permission denied", "run as administrator or root")
	}

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, probes)
	check := findDoctorCheck(result, "local_interface", "tun")
	if check.Status != doctorFail || !strings.Contains(check.Message, "permission denied") {
		t.Fatalf("interface check = %#v, want permission failure", check)
	}
}

func TestDoctorTextOutput(t *testing.T) {
	configPath := writeDoctorConfig(t)
	cmd := newDoctorCmdWithProbes(&Options{ConfigPath: configPath}, healthyDoctorProbes())
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor execute error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "[OK] config loaded") {
		t.Fatalf("output missing config ok check:\n%s", output)
	}
	if !strings.Contains(output, "Summary:") {
		t.Fatalf("output missing summary:\n%s", output)
	}
}

func TestDoctorCandidateFilterDetectsExcludedRuntimeCandidate(t *testing.T) {
	configPath := writeDoctorConfigWithNATExtra(t, "  candidate_cidr_exclude:\n    - 100.64.0.0/10\n")
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:             "node-b",
		Name:               "node-b",
		State:              winkclient.PeerStateConnected.String(),
		LocalCandidate:     "host:100.64.1.2:50000",
		LastHandshake:      time.Now(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "nat", "candidate selected")
	if check.Status != doctorFail || !strings.Contains(check.Message, "candidate_cidr_exclude") {
		t.Fatalf("candidate selected check = %#v, want excluded CIDR failure", check)
	}
}

func TestDoctorCandidateFilterAllowsRuntimeCandidate(t *testing.T) {
	configPath := writeDoctorConfigWithNATExtra(t, "  candidate_cidr_include:\n    - 192.168.0.0/16\n  candidate_interface_exclude:\n    - tailscale0\n")
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:             "node-b",
		Name:               "node-b",
		State:              winkclient.PeerStateConnected.String(),
		LocalCandidate:     "host:192.168.1.2:50000",
		LastHandshake:      time.Now(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "nat", "candidate selected")
	if check.Status != doctorOK {
		t.Fatalf("candidate selected check = %#v, want ok", check)
	}
	filterCheck := findDoctorCheck(result, "nat", "candidate filters")
	if filterCheck.Status != doctorOK || !strings.Contains(filterCheck.Message, "interface_exclude=tailscale0") {
		t.Fatalf("candidate filters check = %#v, want configured filter summary", filterCheck)
	}
}

func TestDoctorMultipathDisabledSuggestsEnable(t *testing.T) {
	configPath := writeDoctorConfigWithMultipathDisabled(t)

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "multipath", "policy")
	if check.Status != doctorWarn || !strings.Contains(check.Suggestion, "connectivity.multipath.enabled=true") {
		t.Fatalf("multipath disabled check = %#v, want enable suggestion", check)
	}
}

func TestDoctorMultipathEnabledWithoutProtectedDirectWarns(t *testing.T) {
	configPath := writeDoctorConfigWithMultipath(t)
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:             "node-b",
		Name:               "node-b",
		State:              winkclient.PeerStateConnected.String(),
		MultipathEnabled:   true,
		PrimaryPathID:      "relay/path",
		ActivePathID:       "relay/path",
		LastHandshake:      time.Now(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "multipath", "protected direct")
	if check.Status != doctorWarn || !strings.Contains(check.Message, "protected direct standby is unavailable") {
		t.Fatalf("multipath protected direct check = %#v, want standby unavailable warning", check)
	}
}

func TestDoctorMultipathProtectedDirectOK(t *testing.T) {
	configPath := writeDoctorConfigWithMultipath(t)
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:                "node-b",
		Name:                  "node-b",
		State:                 winkclient.PeerStateConnected.String(),
		MultipathEnabled:      true,
		PrimaryPathID:         "relay/path",
		ProtectedDirectPathID: "direct/path",
		StandbyPathIDs:        []string{"direct/path"},
		ActivePathID:          "relay/path",
		LastHandshake:         time.Now(),
		TransportTxPackets:    2,
		TransportRxPackets:    3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "multipath", "protected direct")
	if check.Status != doctorOK || !strings.Contains(check.Message, "protected_direct=direct/path") {
		t.Fatalf("multipath protected direct check = %#v, want ok with protected path", check)
	}
}

func TestDoctorInbandHealthOK(t *testing.T) {
	configPath := writeDoctorConfig(t)
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:                 "node-b",
		Name:                   "node-b",
		State:                  winkclient.PeerStateConnected.String(),
		ControlState:           winkclient.PeerControlStateDegraded.String(),
		DataState:              winkclient.PeerDataStateAlive.String(),
		LastInbandHeartbeatAt:  time.Now(),
		LastInbandPathHealthAt: time.Now(),
		TransportTxPackets:     2,
		TransportRxPackets:     3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	heartbeat := findDoctorCheck(result, "in-band", "heartbeat")
	if heartbeat.Status != doctorOK || !strings.Contains(heartbeat.Message, "node-b") {
		t.Fatalf("in-band heartbeat check = %#v, want fresh ok", heartbeat)
	}
	pathHealth := findDoctorCheck(result, "in-band", "path health")
	if pathHealth.Status != doctorOK || !strings.Contains(pathHealth.Message, "node-b") {
		t.Fatalf("in-band path health check = %#v, want fresh ok", pathHealth)
	}
}

func TestDoctorInbandHealthMissingWarns(t *testing.T) {
	configPath := writeDoctorConfig(t)
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:             "node-b",
		Name:               "node-b",
		State:              winkclient.PeerStateConnected.String(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	heartbeat := findDoctorCheck(result, "in-band", "heartbeat")
	if heartbeat.Status != doctorWarn || !strings.Contains(heartbeat.Message, "no fresh in-band heartbeat") {
		t.Fatalf("in-band heartbeat check = %#v, want missing warning", heartbeat)
	}
	pathHealth := findDoctorCheck(result, "in-band", "path health")
	if pathHealth.Status != doctorWarn || !strings.Contains(pathHealth.Message, "no fresh in-band path_health") {
		t.Fatalf("in-band path health check = %#v, want missing warning", pathHealth)
	}
}

func healthyDoctorProbes() doctorProbes {
	return doctorProbes{
		Coordinator: func(context.Context, *config.Config) doctorCheck {
			return okCheck("coordinator", "reachable", "fake coordinator reachable")
		},
		TURN: func(context.Context, *config.Config) doctorCheck {
			return okCheck("nat", "turn", "fake TURN gather ok")
		},
		LocalInterface: func(context.Context, *config.Config) doctorCheck {
			return okCheck("local_interface", "backend", "fake interface ok")
		},
	}
}

func writeDoctorConfig(t *testing.T) string {
	return writeDoctorConfigWithNATExtra(t, "")
}

func writeDoctorConfigWithNATExtra(t *testing.T, natExtra string) string {
	t.Helper()
	body := `
node:
  name: node-a
coordinator:
  url: grpc://127.0.0.1:50051
  auth_key: test-auth
netif:
  backend: tun
wireguard:
  private_key: test-private-key
nat:
  turn_servers:
    - url: turn:127.0.0.1:3478?transport=udp
      username: wink
      password: secret
` + natExtra + `
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeDoctorConfigWithMultipathDisabled(t *testing.T) string {
	t.Helper()
	body := `
node:
  name: node-a
coordinator:
  url: grpc://127.0.0.1:50051
  auth_key: test-auth
netif:
  backend: tun
wireguard:
  private_key: test-private-key
nat:
  turn_servers:
    - url: turn:127.0.0.1:3478?transport=udp
      username: wink
      password: secret
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
  multipath:
    enabled: false
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeDoctorConfigWithMultipath(t *testing.T) string {
	t.Helper()
	body := `
node:
  name: node-a
coordinator:
  url: grpc://127.0.0.1:50051
  auth_key: test-auth
netif:
  backend: tun
wireguard:
  private_key: test-private-key
nat:
  turn_servers:
    - url: turn:127.0.0.1:3478?transport=udp
      username: wink
      password: secret
connectivity:
  mode: auto
  strategy_order:
    - relay_only
    - legacy_ice_udp
  multipath:
    enabled: true
    protect_direct: true
    max_paths: 2
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeDoctorRuntimeState(t *testing.T, configPath string, peers []winkclient.RuntimePeerStatus) {
	t.Helper()
	state := &winkclient.RuntimeState{
		Version:   "test",
		PID:       os.Getpid(),
		StartedAt: time.Now().Add(-time.Minute),
		UpdatedAt: time.Now(),
		Status: winkclient.RuntimeEngineStatus{
			State:          winkclient.EngineStateConnected.String(),
			NodeID:         "node-a",
			NodeName:       "node-a",
			VirtualIP:      "10.42.0.2",
			NetworkCIDR:    "10.42.0.0/24",
			Backend:        "tun",
			CoordinatorURL: "grpc://127.0.0.1:50051",
		},
		Peers: peers,
	}
	if err := winkclient.WriteRuntimeState(configPath, state); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}
}

func findDoctorCheck(result doctorResult, layer, name string) doctorCheck {
	for _, check := range result.Checks {
		if check.Layer == layer && check.Name == name {
			return check
		}
	}
	return doctorCheck{}
}
