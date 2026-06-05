package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	winkclient "winkyou/pkg/client"
	"winkyou/pkg/config"
	"winkyou/pkg/solver"
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

func TestDoctorSTUNWarnWhenProbeFails(t *testing.T) {
	configPath := writeDoctorConfig(t)
	probes := healthyDoctorProbes()
	probes.STUN = func(context.Context, *config.Config) doctorCheck {
		return warnCheck("nat", "stun", "all STUN probes failed: timeout", "configure a reachable STUN server")
	}

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, probes)
	check := findDoctorCheck(result, "nat", "stun")
	if check.Status != doctorWarn || !strings.Contains(check.Message, "all STUN probes failed") {
		t.Fatalf("stun check = %#v, want STUN warning", check)
	}
}

func TestDefaultSTUNProbeUsesUDPTURNAsPublicDirectHint(t *testing.T) {
	server := startDoctorFakeSTUNServer(t, net.IPv4(198, 51, 100, 44), 45678)
	defer server.Close()

	cfg := config.Default()
	cfg.NAT.STUNServers = nil
	cfg.NAT.TURNServers = []config.TURNServerConfig{{
		URL:      "turn:" + server.LocalAddr().String() + "?transport=udp",
		Username: "wink",
		Password: "secret",
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	check := defaultSTUNProbe(ctx, &cfg)
	if check.Status != doctorOK {
		t.Fatalf("defaultSTUNProbe() = %#v, want OK from UDP TURN-derived STUN source", check)
	}
	if !strings.Contains(check.Message, "mapped 198.51.100.44:45678") {
		t.Fatalf("defaultSTUNProbe() message = %q, want mapped address", check.Message)
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

func TestDoctorCandidateFilterSummaryIncludesPublicCandidateHints(t *testing.T) {
	configPath := writeDoctorConfigWithNATExtra(t, "  candidate_port_min: 40000\n  candidate_port_max: 40100\n  nat1to1_candidate_type: srflx\n  nat1to1_ips:\n    - 203.0.113.10/192.168.0.10\n  public_endpoint_hints:\n    - 117.48.146.2:41000/192.168.1.20:40000\n  direct_trusted_cidrs:\n    - 100.64.0.0/10\n  public_direct_trusted_cidrs:\n    - 198.18.0.0/15\n")

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "nat", "candidate filters")
	if check.Status != doctorOK ||
		!strings.Contains(check.Message, "port_range=40000-40100") ||
		!strings.Contains(check.Message, "nat1to1_candidate_type=srflx") ||
		!strings.Contains(check.Message, "nat1to1_ips=203.0.113.10/192.168.0.10") ||
		!strings.Contains(check.Message, "public_endpoint_hints=117.48.146.2:41000/192.168.1.20:40000") ||
		!strings.Contains(check.Message, "direct_trusted_cidrs=100.64.0.0/10") ||
		!strings.Contains(check.Message, "public_direct_trusted_cidrs=198.18.0.0/15") {
		t.Fatalf("candidate filters check = %#v, want public candidate hint summary", check)
	}
}

func TestPublicEndpointHintLocalBaseCheckOK(t *testing.T) {
	check := publicEndpointHintLocalBaseCheck(
		[]string{"117.48.146.2:41000/192.168.1.20:40000"},
		[]net.IP{net.ParseIP("192.168.1.20")},
	)
	if check == nil || check.Status != doctorOK || !strings.Contains(check.Message, "192.168.1.20") {
		t.Fatalf("publicEndpointHintLocalBaseCheck() = %#v, want ok for local base", check)
	}
}

func TestPublicEndpointHintLocalBaseCheckWarnsForMissingBase(t *testing.T) {
	check := publicEndpointHintLocalBaseCheck(
		[]string{"117.48.146.2:41000/192.168.1.20:40000"},
		[]net.IP{net.ParseIP("192.168.1.21")},
	)
	if check == nil || check.Status != doctorWarn ||
		!strings.Contains(check.Message, "192.168.1.20") ||
		!strings.Contains(check.Suggestion, "real underlay interface IP") {
		t.Fatalf("publicEndpointHintLocalBaseCheck() = %#v, want missing local base warning", check)
	}
}

func TestDirectTrustedCIDRWarnsForVirtualInterface(t *testing.T) {
	check := directTrustedCIDRLocalInterfaceCheck(
		[]string{"10.6.22.0/24"},
		[]doctorLocalInterfaceAddr{{
			Name: "natpierce",
			IP:   net.ParseIP("10.6.22.3"),
		}},
	)
	if check == nil || check.Status != doctorWarn ||
		!strings.Contains(check.Message, "natpierce=10.6.22.3") ||
		!strings.Contains(check.Suggestion, "real underlay") {
		t.Fatalf("directTrustedCIDRLocalInterfaceCheck() = %#v, want virtual interface warning", check)
	}
}

func TestDirectTrustedCIDROKForPhysicalInterface(t *testing.T) {
	check := directTrustedCIDRLocalInterfaceCheck(
		[]string{"100.64.0.0/10"},
		[]doctorLocalInterfaceAddr{{
			Name: "Ethernet",
			IP:   net.ParseIP("100.102.17.35"),
		}},
	)
	if check == nil || check.Status != doctorOK || !strings.Contains(check.Message, "Ethernet=100.102.17.35") {
		t.Fatalf("directTrustedCIDRLocalInterfaceCheck() = %#v, want physical interface ok", check)
	}
}

func TestDoctorPublicDirectEvidenceOK(t *testing.T) {
	configPath := writeDoctorConfig(t)
	writeDoctorObservationHistory(t, configPath, []solver.Observation{{
		PlanID:         "legacyice/public_direct",
		Event:          "path_committed",
		PathID:         "legacyice:direct:public_direct:session/node-a/node-b",
		ConnectionType: "direct",
		LocalAddr:      "192.168.1.10:50000",
		RemoteAddr:     "203.0.113.20:41000",
		Details: map[string]string{
			"path_role":                  "protected_direct",
			"local_candidate_kind":       "host",
			"remote_candidate_kind":      "prflx",
			"peer_reflexive_pair":        "true",
			"public_direct_learned_pair": "true",
			"selected_pair_summary":      "host:192.168.1.10:50000<->prflx:203.0.113.20:41000",
		},
		Timestamp: time.Now(),
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "nat", "public direct evidence")
	if check.Status != doctorOK ||
		!strings.Contains(check.Message, "public direct protected path selected") ||
		!strings.Contains(check.Message, "legacyice/public_direct") ||
		!strings.Contains(check.Message, "remote_candidate_kind=prflx") ||
		!strings.Contains(check.Message, "public_direct_learned_pair=true") {
		t.Fatalf("public direct evidence check = %#v, want protected direct ok", check)
	}
}

func TestDoctorPublicDirectEvidenceWarnsForUncommittedCandidateSuccess(t *testing.T) {
	configPath := writeDoctorConfig(t)
	writeDoctorObservationHistory(t, configPath, []solver.Observation{{
		PlanID:         "legacyice/public_direct",
		Event:          "candidate_succeeded",
		PathID:         "legacyice:direct:public_direct:session/node-a/node-b",
		ConnectionType: "direct",
		LocalAddr:      "192.168.1.10:50000",
		RemoteAddr:     "203.0.113.20:41000",
		Details: map[string]string{
			"remote_candidate_kind":      "prflx",
			"public_direct_learned_pair": "true",
		},
		Timestamp: time.Now(),
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "nat", "public direct evidence")
	if check.Status != doctorWarn ||
		!strings.Contains(check.Message, "not committed as protected direct") ||
		!strings.Contains(check.Suggestion, "path_role=protected_direct") {
		t.Fatalf("public direct evidence check = %#v, want uncommitted candidate warning", check)
	}
}

func TestDoctorPublicDirectEvidenceWarnsForRemoteFilterNoCandidates(t *testing.T) {
	configPath := writeDoctorConfig(t)
	writeDoctorObservationHistory(t, configPath, []solver.Observation{{
		PlanID: "legacyice/public_direct",
		Event:  "remote_candidates_filtered",
		Details: map[string]string{
			"candidate_side":             "remote",
			"candidate_total":            "2",
			"candidate_kept":             "0",
			"candidate_rejected":         "2",
			"candidate_reject_reasons":   "remote_cgnat_or_overlay_candidate=2",
			"candidate_rejected_samples": "host:100.102.17.35:41000(remote_cgnat_or_overlay_candidate);host:100.88.1.9:41001(remote_cgnat_or_overlay_candidate)",
		},
		Timestamp: time.Now(),
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "nat", "public direct evidence")
	if check.Status != doctorWarn ||
		!strings.Contains(check.Message, "remote has no usable public direct candidates") ||
		!strings.Contains(check.Message, "remote_cgnat_or_overlay_candidate") ||
		!strings.Contains(check.Message, "host:100.102.17.35:41000") {
		t.Fatalf("public direct evidence check = %#v, want remote candidate warning", check)
	}
}

func TestRuntimeStateKeyDefaultsToConfigDefault(t *testing.T) {
	if got := runtimeStateKey(&Options{}); got != config.DefaultPath() {
		t.Fatalf("runtimeStateKey(default) = %q, want %q", got, config.DefaultPath())
	}
	if got := runtimeStateKey(nil); got != config.DefaultPath() {
		t.Fatalf("runtimeStateKey(nil) = %q, want %q", got, config.DefaultPath())
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

func TestDoctorMultipathRelayOnlyModeWarnsSinglePath(t *testing.T) {
	configPath := writeDoctorConfigWithMultipathMode(t, "relay_only", false)

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "multipath", "policy")
	if check.Status != doctorWarn ||
		!strings.Contains(check.Message, "relay-only policy keeps sessions single-path") ||
		!strings.Contains(check.Suggestion, "connectivity.mode=auto") {
		t.Fatalf("multipath relay-only policy check = %#v, want single-path warning", check)
	}
}

func TestDoctorMultipathForceRelayWarnsSinglePath(t *testing.T) {
	configPath := writeDoctorConfigWithMultipathMode(t, "auto", true)

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "multipath", "policy")
	if check.Status != doctorWarn ||
		!strings.Contains(check.Message, "relay-only policy keeps sessions single-path") ||
		!strings.Contains(check.Suggestion, "remove nat.force_relay") {
		t.Fatalf("multipath force-relay policy check = %#v, want single-path warning", check)
	}
}

func TestDoctorMultipathEnabledWithoutProtectedDirectWarns(t *testing.T) {
	configPath := writeDoctorConfigWithMultipath(t)
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:           "node-b",
		Name:             "node-b",
		State:            winkclient.PeerStateConnected.String(),
		MultipathEnabled: true,
		PrimaryPathID:    "relay/path",
		ActivePathID:     "relay/path",
		LastPathID:       "overlay/direct",
		LastPathRole:     "primary_candidate",
		LastPathDependencies: []string{
			"unknown:remote_cgnat_or_overlay_candidate",
		},
		LastHandshake:      time.Now(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, healthyDoctorProbes())
	check := findDoctorCheck(result, "multipath", "protected direct")
	if check.Status != doctorWarn || !strings.Contains(check.Message, "protected direct standby is unavailable") || !strings.Contains(check.Message, "remote_cgnat_or_overlay_candidate") {
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

func TestDoctorAdvertisedRoutes(t *testing.T) {
	configPath := writeDoctorConfigWithNodeExtra(t, "  advertise_routes:\n    - 10.6.22.0/24\n")
	probes := healthyDoctorProbes()
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:             "node-b",
		Name:               "chen-win",
		VirtualIP:          "10.77.0.2",
		State:              winkclient.PeerStateConnected.String(),
		DataState:          winkclient.PeerDataStateBound.String(),
		AdvertisedRoutes:   []string{"10.7.0.0/24"},
		LastHandshake:      time.Now(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, probes)
	local := findDoctorCheck(result, "routing", "advertised routes")
	if local.Status != doctorOK || !strings.Contains(local.Message, "10.6.22.0/24") {
		t.Fatalf("advertised routes check = %#v, want local route summary", local)
	}
	returnPath := findDoctorCheck(result, "routing", "backend return path")
	if returnPath.Status != doctorWarn || !strings.Contains(returnPath.Suggestion, "SNAT") {
		t.Fatalf("backend return path check = %#v, want SNAT/return-route warning", returnPath)
	}
	remote := findDoctorCheck(result, "routing", "peer advertised routes")
	if remote.Status != doctorOK || !strings.Contains(remote.Message, "chen-win=10.7.0.0/24") {
		t.Fatalf("peer advertised routes check = %#v, want active peer route summary", remote)
	}
	osRoute := findDoctorCheck(result, "routing", "os route table")
	if osRoute.Status != doctorOK || !strings.Contains(osRoute.Message, "10.7.0.0/24 via 10.77.0.2") {
		t.Fatalf("os route table check = %#v, want route via gateway", osRoute)
	}
}

func TestDoctorAdvertisedRoutesFailWhenRouteTableIsWrong(t *testing.T) {
	configPath := writeDoctorConfig(t)
	probes := healthyDoctorProbes()
	probes.RouteTable = func(_ context.Context, input doctorAdvertisedRouteProbeInput) doctorCheck {
		return failCheck("routing", "os route table", input.Route+" next hop is 192.0.2.1, want "+input.PeerVirtualIP, "remove stale routes and reconnect the gateway peer")
	}
	writeDoctorRuntimeState(t, configPath, []winkclient.RuntimePeerStatus{{
		NodeID:             "node-b",
		Name:               "chen-win",
		VirtualIP:          "10.77.0.2",
		State:              winkclient.PeerStateConnected.String(),
		DataState:          winkclient.PeerDataStateBound.String(),
		AdvertisedRoutes:   []string{"10.7.0.0/24"},
		LastHandshake:      time.Now(),
		TransportTxPackets: 2,
		TransportRxPackets: 3,
	}})

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, probes)
	check := findDoctorCheck(result, "routing", "os route table")
	if check.Status != doctorFail || !strings.Contains(check.Message, "want 10.77.0.2") {
		t.Fatalf("os route table check = %#v, want stale route failure", check)
	}
}

func TestDoctorAdvertisedRoutesRequireIPForwarding(t *testing.T) {
	configPath := writeDoctorConfigWithNodeExtra(t, "  advertise_routes:\n    - 10.6.22.0/24\n")
	probes := healthyDoctorProbes()
	probes.IPForwarding = func(context.Context, *config.Config) doctorCheck {
		return failCheck("routing", "ip forwarding", "Windows IP forwarding appears disabled", "enable routing on the gateway peer")
	}

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{}, probes)
	check := findDoctorCheck(result, "routing", "ip forwarding")
	if check.Status != doctorFail || !strings.Contains(check.Message, "disabled") {
		t.Fatalf("ip forwarding check = %#v, want disabled failure", check)
	}
}

func TestDoctorRouteTargetWarnsExternalOverlay(t *testing.T) {
	configPath := writeDoctorConfig(t)
	probes := healthyDoctorProbes()
	probes.RouteTarget = func(_ context.Context, target string) doctorCheck {
		return routeTargetCheck(doctorRouteTargetProbeResult{
			Target:         target,
			InterfaceAlias: "natpierce",
			InterfaceIndex: "31",
			LocalAddress:   "10.6.22.3",
		})
	}

	result := runDoctor(context.Background(), &Options{ConfigPath: configPath}, doctorFlags{routeTargets: []string{"10.6.22.1"}}, probes)
	check := findDoctorCheck(result, "routing", "target route")
	if check.Status != doctorWarn ||
		!strings.Contains(check.Message, "10.6.22.1") ||
		!strings.Contains(check.Message, "interface=natpierce") ||
		!strings.Contains(check.Suggestion, "external overlay") {
		t.Fatalf("target route check = %#v, want external overlay warning", check)
	}
}

func TestDoctorRouteTargetAcceptsPhysicalInterface(t *testing.T) {
	check := routeTargetCheck(doctorRouteTargetProbeResult{
		Target:         "10.6.22.1",
		InterfaceAlias: "Ethernet",
		LocalAddress:   "192.168.1.20",
		NextHop:        "192.168.1.1",
	})
	if check.Status != doctorOK || !strings.Contains(check.Message, "interface=Ethernet") || !strings.Contains(check.Message, "next_hop=192.168.1.1") {
		t.Fatalf("target route check = %#v, want OK physical interface", check)
	}
}

func TestParseWindowsIPForwardingProbeOutput(t *testing.T) {
	enabled, detail := parseWindowsIPForwardingProbeOutput("IPEnableRouter=0\nForwardingEnabled=Ethernet,WinkYou\n")
	if !enabled || !strings.Contains(detail, "Ethernet,WinkYou") {
		t.Fatalf("parse enabled output = enabled=%v detail=%q, want enabled", enabled, detail)
	}
	enabled, detail = parseWindowsIPForwardingProbeOutput("IPEnableRouter=0\nForwardingEnabled=\n")
	if enabled || !strings.Contains(detail, "IPEnableRouter=0") {
		t.Fatalf("parse disabled output = enabled=%v detail=%q, want disabled", enabled, detail)
	}
}

func TestParseRouteTargetProbeOutput(t *testing.T) {
	route := parseWindowsRouteTargetProbeOutput("Target=10.6.22.1\nInterfaceAlias=natpierce\nInterfaceIndex=31\nLocalAddress=10.6.22.3\nNextHop=\n")
	if route.Target != "10.6.22.1" || route.InterfaceAlias != "natpierce" || route.InterfaceIndex != "31" || route.LocalAddress != "10.6.22.3" {
		t.Fatalf("parseWindowsRouteTargetProbeOutput() = %#v, want route target details", route)
	}

	route = parseLinuxRouteTargetProbeOutput("10.6.22.1", "10.6.22.1 via 192.168.1.1 dev eth0 src 192.168.1.20 uid 1000\n")
	if route.Target != "10.6.22.1" || route.InterfaceAlias != "eth0" || route.NextHop != "192.168.1.1" || route.LocalAddress != "192.168.1.20" {
		t.Fatalf("parseLinuxRouteTargetProbeOutput() = %#v, want Linux route target details", route)
	}
}

func TestParseRouteProbeNextHop(t *testing.T) {
	nextHop, detail := parseRouteProbeNextHop("DestinationPrefix=10.7.0.0/24\nNextHop=10.77.0.2\n")
	if nextHop != "10.77.0.2" || !strings.Contains(detail, "DestinationPrefix=10.7.0.0/24") {
		t.Fatalf("parseRouteProbeNextHop() = nextHop=%q detail=%q, want parsed next hop and detail", nextHop, detail)
	}
	nextHop, detail = parseRouteProbeNextHop("DestinationPrefix=10.7.0.0/24\n")
	if nextHop != "" || !strings.Contains(detail, "10.7.0.0/24") {
		t.Fatalf("parseRouteProbeNextHop() missing hop = nextHop=%q detail=%q, want empty hop and detail", nextHop, detail)
	}
}

func healthyDoctorProbes() doctorProbes {
	return doctorProbes{
		Coordinator: func(context.Context, *config.Config) doctorCheck {
			return okCheck("coordinator", "reachable", "fake coordinator reachable")
		},
		STUN: func(context.Context, *config.Config) doctorCheck {
			return okCheck("nat", "stun", "fake STUN mapped address")
		},
		TURN: func(context.Context, *config.Config) doctorCheck {
			return okCheck("nat", "turn", "fake TURN gather ok")
		},
		LocalInterface: func(context.Context, *config.Config) doctorCheck {
			return okCheck("local_interface", "backend", "fake interface ok")
		},
		IPForwarding: func(context.Context, *config.Config) doctorCheck {
			return okCheck("routing", "ip forwarding", "fake IP forwarding ok")
		},
		RouteTable: func(_ context.Context, input doctorAdvertisedRouteProbeInput) doctorCheck {
			return okCheck("routing", "os route table", input.Route+" via "+input.PeerVirtualIP+" for "+input.PeerName)
		},
	}
}

func writeDoctorConfig(t *testing.T) string {
	return writeDoctorConfigWithNATExtra(t, "")
}

func writeDoctorConfigWithNATExtra(t *testing.T, natExtra string) string {
	return writeDoctorConfigWithNodeAndNATExtra(t, "", natExtra)
}

func writeDoctorConfigWithNodeExtra(t *testing.T, nodeExtra string) string {
	return writeDoctorConfigWithNodeAndNATExtra(t, nodeExtra, "")
}

func writeDoctorConfigWithNodeAndNATExtra(t *testing.T, nodeExtra, natExtra string) string {
	t.Helper()
	body := `
node:
  name: node-a
` + nodeExtra + `
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
	return writeDoctorConfigWithMultipathMode(t, "auto", false)
}

func writeDoctorConfigWithMultipathMode(t *testing.T, mode string, forceRelay bool) string {
	t.Helper()
	forceRelayLine := ""
	if forceRelay {
		forceRelayLine = "  force_relay: true\n"
	}
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
` + forceRelayLine + `
connectivity:
  mode: ` + mode + `
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

func writeDoctorObservationHistory(t *testing.T, configPath string, observations []solver.Observation) {
	t.Helper()
	var buf strings.Builder
	encoder := json.NewEncoder(&buf)
	for _, obs := range observations {
		if err := encoder.Encode(obs); err != nil {
			t.Fatalf("encode observation: %v", err)
		}
	}
	if err := os.WriteFile(observationStatePathFromKey(configPath), []byte(buf.String()), 0o644); err != nil {
		t.Fatalf("write observations: %v", err)
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

func startDoctorFakeSTUNServer(t *testing.T, mappedIP net.IP, mappedPort int) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake STUN server listen: %v", err)
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, clientAddr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < doctorSTUNHeaderSize ||
				binary.BigEndian.Uint16(buf[0:2]) != doctorSTUNMsgTypeBindingReq ||
				binary.BigEndian.Uint32(buf[4:8]) != doctorSTUNMagicCookie {
				continue
			}
			resp := buildDoctorFakeSTUNBindingResponse(buf[8:20], mappedIP, mappedPort)
			_, _ = conn.WriteTo(resp, clientAddr)
		}
	}()
	return conn
}

func buildDoctorFakeSTUNBindingResponse(txID []byte, ip net.IP, port int) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		panic("doctor fake STUN helper only supports IPv4")
	}
	attrData := make([]byte, 8)
	attrData[1] = 0x01
	binary.BigEndian.PutUint16(attrData[2:4], uint16(port)^uint16(doctorSTUNMagicCookie>>16))
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, doctorSTUNMagicCookie)
	for i := range ip4 {
		attrData[4+i] = ip4[i] ^ cookieBytes[i]
	}

	attr := make([]byte, 4+len(attrData))
	binary.BigEndian.PutUint16(attr[0:2], doctorSTUNAttrXORMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(attrData)))
	copy(attr[4:], attrData)

	resp := make([]byte, doctorSTUNHeaderSize+len(attr))
	binary.BigEndian.PutUint16(resp[0:2], doctorSTUNMsgTypeBindingResp)
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(resp[4:8], doctorSTUNMagicCookie)
	copy(resp[8:20], txID)
	copy(resp[doctorSTUNHeaderSize:], attr)
	return resp
}

const (
	doctorSTUNMsgTypeBindingReq    = 0x0001
	doctorSTUNMsgTypeBindingResp   = 0x0101
	doctorSTUNAttrXORMappedAddress = 0x0020
	doctorSTUNMagicCookie          = 0x2112A442
	doctorSTUNHeaderSize           = 20
)
