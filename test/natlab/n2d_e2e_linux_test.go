//go:build linux && natlab

package natlab

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/rendezvouscarrier"
)

const n2dSuccessRepetitions = 3

func TestLinuxN2DEndToEndProof(t *testing.T) {
	requireN2DEnvironment(t)

	t.Run("eim_eim_success_exact_witness", testN2DEIMSuccess)
	t.Run("port_restricted_blind_open_success", testN2DPortRestrictedSuccess)
	t.Run("edm_participation_bounded_failure", testN2DEDMFailure)
	t.Run("absent_before_burn", testN2DAbsentBeforeBurn)
	t.Run("absent_after_burn", testN2DAbsentAfterBurn)
	t.Run("crash_restart_durable_rejection", testN2DCrashRestart)
	t.Run("hard_violations_persist_trip", testN2DHardViolations)
}

func testN2DEIMSuccess(t *testing.T) {
	for iteration := 0; iteration < n2dSuccessRepetitions; iteration++ {
		t.Run(fmt.Sprintf("repeat_%d", iteration+1), func(t *testing.T) {
			topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
			servers := startN2DServers(t, topology)
			artifacts := buildN2DArtifacts(t, fmt.Sprintf("eim-success-%d", iteration), time.Now())
			initiator := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator, n2dActionAttempt, "", "", "")
			responder := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleResponder, n2dActionAttempt, "", "", "")

			initiator.start(t)
			responder.start(t)
			initiatorResult := initiator.waitResult(t)
			responderResult := responder.waitResult(t)

			counts := requireN2DPacketCounts(t, topology)
			logN2DCounts(t, "eim_success", counts, initiatorResult, responderResult)
			assertN2DSuccessResult(t, initiatorResult, directattempt.RoleInitiator)
			assertN2DSuccessResult(t, responderResult, directattempt.RoleResponder)
			assertN2DPacketResultMatch(t, counts, initiatorResult, responderResult)
			if counts.InitiatorDirect != 2 || counts.ResponderDirect != 1 {
				t.Fatalf("N2d direct witness = %d/%d, want exact 2/1", counts.InitiatorDirect, counts.ResponderDirect)
			}
			if counts.InitiatorTotal > 5 || counts.ResponderTotal > 4 {
				t.Fatalf("N2d UDP witness = %d/%d, exceeds frozen 5/4 envelope", counts.InitiatorTotal, counts.ResponderTotal)
			}
			stunStats := servers.stun.Snapshot()
			if stunStats.Received != counts.InitiatorSTUN+counts.ResponderSTUN || stunStats.Responded != stunStats.Received {
				t.Fatalf("N2d STUN aggregate witness = received:%d responded:%d", stunStats.Received, stunStats.Responded)
			}
			carrierStats := servers.rendezvous.Stats()
			if carrierStats.Accepted != 2 || carrierStats.SlotARead != 7 || carrierStats.SlotAWritten != 6 ||
				carrierStats.SlotBRead != 6 || carrierStats.SlotBWritten != 7 {
				t.Fatalf("N2d carrier frame witness = accepted:%d active:%d A:%d/%d B:%d/%d",
					carrierStats.Accepted, carrierStats.Active, carrierStats.SlotARead, carrierStats.SlotAWritten,
					carrierStats.SlotBRead, carrierStats.SlotBWritten)
			}
			assertN2DNoResidue(t, topology, servers)
		})
	}
}

// testN2DPortRestrictedSuccess is the representative case the blind
// simultaneous-open semantics were frozen for: both NATs keep conntrack's
// address+port-dependent reply filtering, so each side's opener must pass only
// through the pinhole created by its own outbound packet. The initiator's SYN
// may race ahead of the responder's pinhole and be filtered; the responder
// still completes on ACK alone, so every asserted outbound count stays exact.
func testN2DPortRestrictedSuccess(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIMRestricted, n2dMappingEIMRestricted)
	servers := startN2DServers(t, topology)
	artifacts := buildN2DArtifacts(t, "port-restricted-success", time.Now())
	initiator := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator, n2dActionAttempt, "", "", "")
	responder := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleResponder, n2dActionAttempt, "", "", "")

	initiator.start(t)
	responder.start(t)
	initiatorResult := initiator.waitResult(t)
	responderResult := responder.waitResult(t)

	counts := requireN2DPacketCounts(t, topology)
	logN2DCounts(t, "port_restricted_success", counts, initiatorResult, responderResult)
	assertN2DSuccessResult(t, initiatorResult, directattempt.RoleInitiator)
	assertN2DSuccessResult(t, responderResult, directattempt.RoleResponder)
	assertN2DPacketResultMatch(t, counts, initiatorResult, responderResult)
	if counts.InitiatorDirect != 2 || counts.ResponderDirect != 1 {
		t.Fatalf("N2d port-restricted direct witness = %d/%d, want exact 2/1", counts.InitiatorDirect, counts.ResponderDirect)
	}
	if counts.InitiatorTotal > 5 || counts.ResponderTotal > 4 {
		t.Fatalf("N2d port-restricted UDP witness = %d/%d, exceeds frozen 5/4 envelope", counts.InitiatorTotal, counts.ResponderTotal)
	}
	stunStats := servers.stun.Snapshot()
	if stunStats.Received != counts.InitiatorSTUN+counts.ResponderSTUN || stunStats.Responded != stunStats.Received {
		t.Fatalf("N2d port-restricted STUN witness = received:%d responded:%d", stunStats.Received, stunStats.Responded)
	}
	assertN2DNoResidue(t, topology, servers)
}

func testN2DEDMFailure(t *testing.T) {
	cases := []struct {
		name      string
		initiator n2dMappingMode
		responder n2dMappingMode
	}{
		{name: "initiator_edm", initiator: n2dMappingEDM, responder: n2dMappingEIM},
		{name: "responder_edm", initiator: n2dMappingEIM, responder: n2dMappingEDM},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			topology := newN2DTopology(t, testCase.initiator, testCase.responder)
			servers := startN2DServers(t, topology)
			artifacts := buildN2DArtifacts(t, "edm-"+testCase.name, time.Now())
			initiator := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator, n2dActionAttempt, "", "", "")
			responder := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleResponder, n2dActionAttempt, "", "", "")

			initiator.start(t)
			responder.start(t)
			initiatorResult := initiator.waitResult(t)
			responderResult := responder.waitResult(t)
			assertN2DBoundedFailureResult(t, initiatorResult, true)
			assertN2DBoundedFailureResult(t, responderResult, true)
			if initiatorResult.Terminal == n2dTerminalSuccess || responderResult.Terminal == n2dTerminalSuccess {
				t.Fatal("N2d EDM mapping unexpectedly reached a success terminal")
			}
			counts := requireN2DPacketCounts(t, topology)
			assertN2DPacketResultMatch(t, counts, initiatorResult, responderResult)
			if counts.InitiatorDirect > 2 || counts.ResponderDirect > 1 || counts.InitiatorTotal > 5 || counts.ResponderTotal > 4 {
				t.Fatalf("N2d EDM failure exceeded frozen UDP envelope: %+v", counts)
			}
			logN2DCounts(t, "edm_bounded_failure", counts, initiatorResult, responderResult)
			assertN2DNoResidue(t, topology, servers)
		})
	}
}

func testN2DAbsentBeforeBurn(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startN2DServers(t, topology)
	artifacts := buildN2DArtifacts(t, "absent-preburn", time.Now())
	initiator := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator, n2dActionAttempt, "", "", "")

	initiator.start(t)
	result := initiator.waitResult(t)
	assertN2DCommonResult(t, result, n2dTerminalPresenceTimeout, "presence_timeout", false, false)
	if result.LedgerSequence != 1 || result.LedgerRecords != 1 || result.LedgerAdmissions != 0 || result.LedgerFailures != 0 {
		t.Fatalf("N2d pre-burn ledger witness = sequence:%d records:%d admissions:%d failures:%d",
			result.LedgerSequence, result.LedgerRecords, result.LedgerAdmissions, result.LedgerFailures)
	}
	counts := requireN2DPacketCounts(t, topology)
	if counts != (n2dPacketCounts{}) {
		t.Fatalf("N2d presence timeout emitted UDP packets: %+v", counts)
	}
	logN2DCounts(t, "presence_timeout", counts, result, n2dEndpointResult{})
	assertN2DNoResidue(t, topology, servers)
}

func testN2DAbsentAfterBurn(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startN2DServers(t, topology)
	artifacts := buildN2DArtifacts(t, "absent-postburn", time.Now())
	initiator := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator, n2dActionAttempt, "", "", "")
	responder := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleResponder, n2dActionAttempt, n2dStageActivated, "", "")

	initiator.start(t)
	responder.start(t)
	responder.waitStage(t, n2dStageActivated, 8*time.Second)
	responder.kill(t)
	initiatorResult := initiator.waitResult(t)
	assertN2DBoundedFailureResult(t, initiatorResult, true)
	if initiatorResult.ErrorClass != "handshake" && initiatorResult.ErrorClass != "activation" {
		t.Fatalf("N2d post-burn disappearance class = %q", initiatorResult.ErrorClass)
	}
	counts := requireN2DPacketCounts(t, topology)
	if counts != (n2dPacketCounts{}) {
		t.Fatalf("N2d post-burn disappearance emitted UDP packets: %+v", counts)
	}
	logN2DCounts(t, "postburn_disappearance", counts, initiatorResult, n2dEndpointResult{})
	assertN2DNoResidue(t, topology, servers)
}

func testN2DCrashRestart(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startN2DServers(t, topology)
	artifacts := buildN2DArtifacts(t, "crash-restart", time.Now())
	initiator := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator, n2dActionAttempt, n2dStagePunchSent, "", "")
	responder := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleResponder, n2dActionAttempt, "", "", "")

	initiator.start(t)
	responder.start(t)
	initiator.waitStage(t, n2dStagePunchSent, 8*time.Second)
	initiator.kill(t)
	responderResult := responder.waitResult(t)
	assertN2DBoundedFailureResult(t, responderResult, true)
	if responderResult.ErrorClass != "punch_timeout" {
		t.Fatalf("N2d crash survivor class = %q, want punch_timeout", responderResult.ErrorClass)
	}
	beforeRestart := requireN2DPacketCounts(t, topology)

	restart := newN2DEndpointProcess(t, topology, nil, artifacts, directattempt.RoleInitiator, n2dActionRestartCheck, "", initiator.governorDir, initiator.artifactPath)
	restart.start(t)
	restartResult := restart.waitResult(t)
	assertN2DCommonResult(t, restartResult, n2dTerminalReplayRejected, "credential_used", false, false)
	if restartResult.LedgerSequence != 2 || restartResult.LedgerRecords != 2 || restartResult.LedgerAdmissions != 1 {
		t.Fatalf("N2d restart ledger witness = sequence:%d records:%d admissions:%d",
			restartResult.LedgerSequence, restartResult.LedgerRecords, restartResult.LedgerAdmissions)
	}
	afterRestart := requireN2DPacketCounts(t, topology)
	if afterRestart != beforeRestart {
		t.Fatalf("N2d rejected restart emitted packets: before=%+v after=%+v", beforeRestart, afterRestart)
	}
	logN2DCounts(t, "crash_restart_rejected", afterRestart, restartResult, responderResult)
	assertN2DNoResidue(t, topology, servers)
}

func testN2DHardViolations(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startN2DServers(t, topology)
	artifacts := buildN2DArtifacts(t, "hard-violations", time.Now())
	tests := []struct {
		name       string
		action     string
		errorClass string
		emitted    int
	}{
		{name: "second_socket", action: n2dActionSecondSocket, errorClass: "second_socket", emitted: 0},
		{name: "third_target", action: n2dActionThirdTarget, errorClass: "third_target", emitted: 0},
		{name: "sixth_packet", action: n2dActionSixthPacket, errorClass: "sixth_packet", emitted: 5},
	}
	previous := requireN2DPacketCounts(t, topology)
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			process := newN2DEndpointProcess(t, topology, servers, artifacts, directattempt.RoleInitiator, testCase.action, "", "", "")
			process.start(t)
			result := process.waitResult(t)
			assertN2DCommonResult(t, result, n2dTerminalHardViolation, testCase.errorClass, false, true)
			assertN2DPersistentTrip(t, process.governorDir)
			current := requireN2DPacketCounts(t, topology)
			if got := int(current.InitiatorTotal - previous.InitiatorTotal); got != testCase.emitted {
				t.Fatalf("N2d %s emitted %d packets, want %d", testCase.name, got, testCase.emitted)
			}
			if current.ResponderTotal != previous.ResponderTotal {
				t.Fatalf("N2d %s changed responder packet witness", testCase.name)
			}
			previous = current
		})
	}
	logN2DCounts(t, "hard_violation_bounds", previous, n2dEndpointResult{}, n2dEndpointResult{})
	assertN2DNoResidue(t, topology, servers)
}

func requireN2DEnvironment(t *testing.T) {
	t.Helper()
	required := os.Getenv(n2dRequiredEnv) == "1"
	failOrSkip := func(message string) {
		if required {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	if os.Geteuid() != 0 {
		failOrSkip("N2d requires an isolated root network namespace")
	}
	for _, program := range []string{"ip", "iptables", "iptables-restore", "ss", "conntrack", "sysctl"} {
		if _, err := exec.LookPath(program); err != nil {
			failOrSkip("N2d isolated-network prerequisite is unavailable")
		}
	}
	if err := probeN1NamespaceAuthority(); err != nil {
		failOrSkip("N2d network namespace authority is unavailable")
	}
}

func assertN2DSuccessResult(t testing.TB, result n2dEndpointResult, role directattempt.Role) {
	t.Helper()
	assertN2DCommonResult(t, result, n2dTerminalSuccess, "", true, false)
	wantDirect, wantControl := 1, 3
	wantFramesRead, wantFramesWritten := 7, 6
	if role == directattempt.RoleInitiator {
		wantDirect, wantControl = 2, 4
		wantFramesRead, wantFramesWritten = 6, 7
	}
	if result.Role != string(role) || !result.SameSocket || result.STUNPackets < 1 || result.STUNPackets > 3 ||
		result.DirectPackets != wantDirect || result.ControlFrames != wantControl || result.HandshakeFrames != 1 ||
		result.UDPPackets != result.STUNPackets+wantDirect || result.CarrierFramesRead != wantFramesRead ||
		result.CarrierFramesWritten != wantFramesWritten || result.DNSResolutions != 0 {
		t.Fatalf("N2d success witness = role:%s stun:%d direct:%d udp:%d control:%d handshake:%d carrier:%d/%d dns:%d",
			result.Role, result.STUNPackets, result.DirectPackets, result.UDPPackets, result.ControlFrames,
			result.HandshakeFrames, result.CarrierFramesRead, result.CarrierFramesWritten, result.DNSResolutions)
	}
	if result.CarrierFramesRead > rendezvouscarrier.MaxFramesPerDirection || result.CarrierFramesWritten > rendezvouscarrier.MaxFramesPerDirection ||
		result.CarrierBytesRead > rendezvouscarrier.MaxApplicationBytes || result.CarrierBytesWritten > rendezvouscarrier.MaxApplicationBytes {
		t.Fatal("N2d carrier exceeded the frozen frame or byte envelope")
	}
	if result.LedgerSequence != 3 || result.LedgerRecords != 3 || result.LedgerAdmissions != 1 || result.LedgerFailures != 0 {
		t.Fatalf("N2d success ledger witness = sequence:%d records:%d admissions:%d failures:%d",
			result.LedgerSequence, result.LedgerRecords, result.LedgerAdmissions, result.LedgerFailures)
	}
}

func assertN2DBoundedFailureResult(t testing.TB, result n2dEndpointResult, burned bool) {
	t.Helper()
	assertN2DCommonResult(t, result, n2dTerminalExpired, result.ErrorClass, burned, false)
	if result.ErrorClass == "" || result.LedgerAdmissions != 1 || result.LedgerSequence != 3 || result.LedgerRecords != 3 || result.LedgerFailures != 1 {
		t.Fatalf("N2d bounded-failure ledger witness = class:%s sequence:%d records:%d admissions:%d failures:%d",
			result.ErrorClass, result.LedgerSequence, result.LedgerRecords, result.LedgerAdmissions, result.LedgerFailures)
	}
}

func assertN2DCommonResult(t testing.TB, result n2dEndpointResult, terminal, errorClass string, burned, tripped bool) {
	t.Helper()
	if !result.OK || result.Terminal != terminal || result.ErrorClass != errorClass || result.Burned != burned {
		t.Fatalf("N2d endpoint terminal = %s/%s burned:%t", result.Terminal, result.ErrorClass, result.Burned)
	}
	wantSafety := string(governor.SafetyTripClear)
	if tripped {
		wantSafety = string(governor.SafetyTripTripped)
	}
	if result.SafetyState != wantSafety || result.SafetyBlocksWork != tripped {
		t.Fatalf("N2d safety witness = %s/%t, want %s/%t", result.SafetyState, result.SafetyBlocksWork, wantSafety, tripped)
	}
	if !n2dResultHasNoResidue(result) {
		t.Fatal("N2d endpoint retained governor reservations")
	}
	if result.ElapsedMilliseconds < 0 || result.ElapsedMilliseconds >= n2dProcessLimit.Milliseconds() {
		t.Fatalf("N2d endpoint elapsed = %dms, want under %dms", result.ElapsedMilliseconds, n2dProcessLimit.Milliseconds())
	}
	assertN2DResultRedacted(t, result)
}

func assertN2DPacketResultMatch(t testing.TB, counts n2dPacketCounts, initiator, responder n2dEndpointResult) {
	t.Helper()
	if counts.InitiatorSTUN != uint64(initiator.STUNPackets) || counts.InitiatorDirect != uint64(initiator.DirectPackets) ||
		counts.InitiatorTotal != uint64(initiator.UDPPackets) || counts.ResponderSTUN != uint64(responder.STUNPackets) ||
		counts.ResponderDirect != uint64(responder.DirectPackets) || counts.ResponderTotal != uint64(responder.UDPPackets) {
		t.Fatalf("N2d OS/application packet mismatch: os=%+v app=%d/%d/%d,%d/%d/%d", counts,
			initiator.STUNPackets, initiator.DirectPackets, initiator.UDPPackets,
			responder.STUNPackets, responder.DirectPackets, responder.UDPPackets)
	}
}

func requireN2DPacketCounts(t testing.TB, topology *n2dTopology) n2dPacketCounts {
	t.Helper()
	counts, err := topology.packetCounts()
	if err != nil {
		t.Fatal("N2d packet counter witness failed")
	}
	return counts
}

func logN2DCounts(t testing.TB, scenario string, counts n2dPacketCounts, initiator, responder n2dEndpointResult) {
	t.Helper()
	t.Logf("N2d %s witness: stun=%d/%d direct=%d/%d udp=%d/%d control=%d/%d tcp_frames=%d/%d",
		scenario, counts.InitiatorSTUN, counts.ResponderSTUN, counts.InitiatorDirect, counts.ResponderDirect,
		counts.InitiatorTotal, counts.ResponderTotal, initiator.ControlFrames, responder.ControlFrames,
		initiator.CarrierFramesWritten, responder.CarrierFramesWritten)
}

func assertN2DPersistentTrip(t testing.TB, namespace string) {
	t.Helper()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "n2d-trip-reinspect")
	if err != nil {
		t.Fatal("N2d tripped governor owner lock remained held")
	}
	_, createErr := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if !errors.Is(createErr, governor.ErrSafetyTripped) {
		_ = owner.Close()
		t.Fatal("N2d hard violation did not persist fail-closed state")
	}
	if err := owner.Close(); err != nil {
		t.Fatal("N2d tripped governor owner release failed")
	}
}

func assertN2DNoResidue(t testing.TB, topology *n2dTopology, servers *n2dServers) {
	t.Helper()
	before := requireN2DPacketCounts(t, topology)
	time.Sleep(100 * time.Millisecond)
	after := requireN2DPacketCounts(t, topology)
	if after != before {
		t.Fatalf("N2d packet counters changed after terminal: before=%+v after=%+v", before, after)
	}
	if servers != nil && servers.rendezvous != nil && !servers.rendezvous.WaitForActive(0, n2dTerminalMargin) {
		t.Fatal("N2d rendezvous server retained an active connection")
	}
	if err := servers.Close(); err != nil {
		t.Fatal("N2d isolated server drain failed")
	}
	if sockets, err := topology.socketCount(); err != nil || sockets != 0 {
		t.Fatalf("N2d OS socket residue = %d", sockets)
	}
	if processes, err := topology.processCount(); err != nil || processes != 0 {
		t.Fatalf("N2d namespace process residue = %d", processes)
	}
	conntrackBefore, conntrackAfter, err := topology.flushConntrack()
	if err != nil || conntrackAfter != 0 {
		t.Fatal("N2d conntrack cleanup witness failed")
	}
	t.Logf("N2d terminal witness: sockets=0 processes=0 active_connections=0 packet_counters_stable=true conntrack_before_cleanup=%d conntrack_after_cleanup=%d", conntrackBefore, conntrackAfter)
	if err := topology.cleanup(); err != nil {
		t.Fatal("N2d topology cleanup failed")
	}
	if err := topology.assertNoLeaks(); err != nil {
		t.Fatal("N2d namespace or veth leak witness failed")
	}
}
