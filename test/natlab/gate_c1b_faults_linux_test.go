//go:build linux && natlab && c1bproof

package natlab

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directconnect/gateb"
)

// Each fault has fresh topology, credentials, durable stores and real root
// OpenSSH processes. Loopback refers only to SSH; governed UDP crosses the
// two isolated TEST-NET NATs. There is no attempt retry after a fault.
func testGateC1bFault(t *testing.T, fault string) {
	started := time.Now()
	armGateB3KernelReleaseMargin(t)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	t.Cleanup(func() { cleanupGateC1bEndpointProcesses(t, topology) })
	observer := startGateB2ObserverSet(t, topology.public)
	left, right := gateC1bRouters(t, topology, gateC1bProfiles[0])
	if err := topology.installGateB2PacketCounters(observer.topology); err != nil {
		t.Fatal("fault packet counter setup failed")
	}
	configs := gateC1bFixtureForFault(t, topology, observer.topology, gateC1bProfiles[0], true, fault)
	server := startGateC1bHost(t, configs[1])
	server.waitFile(t, configs[1].ReadyFile, 5*time.Second)
	client := startGateC1bHost(t, configs[0])
	var signalAt time.Time
	var signalToExit time.Duration
	if gateC1bResponderSignalFault(fault) {
		signalAt = signalGateC1bResponder(t, fault, topology, configs)
	}
	if fault == "parent-kill" {
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		poll := time.NewTicker(5 * time.Millisecond)
		defer poll.Stop()
		for {
			stage, _ := os.ReadFile(configs[0].StageFile)
			if string(stage) == gateb.StagePrepare {
				break
			}
			select {
			case <-client.done:
				t.Fatal("parent died before the controlled kill boundary")
			case <-deadline.C:
				t.Fatal("parent kill boundary unavailable")
			case <-poll.C:
			}
		}
		if client.command.Process.Kill() != nil {
			t.Fatal("owned parent kill failed")
		}
	}
	select {
	case <-client.done:
	case <-time.After(25 * time.Second):
		t.Fatal("fault initiator exceeded the frozen active/drain bound")
	}
	var initiator gateC1bProcessResult
	hasInitiator := readN1JSON(configs[0].ResultFile, &initiator)
	if fault != "parent-kill" && !hasInitiator {
		t.Fatal("fault initiator lost its structured terminal")
	}
	if hasInitiator && (initiator.OK || initiator.Product.DataPlaneReady || initiator.Class == "") {
		t.Fatal("fault incorrectly succeeded")
	}
	if fault == "child-kill" || fault == "consumer-crash" {
		marker, _ := os.ReadFile(configs[1].StageFile + ".fault")
		if string(marker) != fault {
			t.Fatal("intended endpoint crash was not witnessed")
		}
	}
	// A remote process killed by injected SIGKILL cannot publish an in-process
	// return value. OS process/socket/lock and on-disk ledger are its witnesses.
	deadline := time.Now().Add(5 * time.Second)
	for {
		processes, err := runCommand("ip", "netns", "pids", topology.clientB)
		if err == nil && len(strings.Fields(processes)) == 0 {
			if !signalAt.IsZero() {
				signalToExit = time.Since(signalAt)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fault responder did not exit without supervisor killing it")
		}
		time.Sleep(10 * time.Millisecond)
	}
	server.stop(t)
	counts := requireGateB2PacketCounts(t, topology)
	// Compiled predictive probe reservation (64), shared establishment (3),
	// one echo plus CLOSE (2). No active data is legal beyond this test slice.
	if counts.InitiatorTotal > 69 || counts.ResponderTotal > 69 {
		t.Fatal("fault escaped its exact governed envelope and session slice")
	}
	var peer gateC1bProcessResult
	hasPeer := readN1JSON(configs[1].ResultFile, &peer)
	if hasPeer && (peer.OK || peer.Product.DataPlaneReady) {
		t.Fatal("fault peer incorrectly succeeded")
	}
	var sequences [2]uint64
	// Preserve a useful RED witness even when a missing FINISH is fatal below.
	defer func() {
		if !signalAt.IsZero() {
			t.Logf("Gate C1b signal fault=%s class=%s peer_class=%s peer_result=%t ledger_sequence=%d/%d wall_ms=%d signal_to_exit_ms=%d retry=0",
				fault, initiator.Class, peer.Class, hasPeer, sequences[0], sequences[1], time.Since(started).Milliseconds(), signalToExit.Milliseconds())
		}
	}()
	for index, cfg := range configs {
		namespace := filepath.Join(cfg.MachineBase, "winkyou-safety-v2")
		status := inspectGateALedger(t, namespace)
		owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "gate-c1b-fault-reinspect")
		if err != nil {
			t.Fatal("fault machine lock was not released")
		}
		trip := owner.SafetyTripStatus()
		if err := owner.Close(); err != nil || trip.BlocksActiveWork {
			t.Fatal("clean fault left a persistent safety trip or owner residue")
		}
		sequences[index] = status.Sequence
		if fault == "pre-finish-eof" {
			if status.Sequence != 1 || status.TwentyFourHourAdmissions != 0 {
				t.Fatal("pre-presence EOF burned credentials")
			}
		} else if (fault == "child-kill" && index == 1) || (fault == "parent-kill" && index == 0) {
			if status.Sequence != 2 || status.TwentyFourHourAdmissions != 1 {
				t.Fatal("crash lost the durable burn or fabricated FINISH")
			}
		} else if fault != "child-kill" && (status.Sequence != 3 || status.TwentyFourHourAdmissions != 1) {
			t.Fatalf("fault did not preserve durable FINISH before release: side=%d sequence=%d admissions=%d", index, status.Sequence, status.TwentyFourHourAdmissions)
		}
	}
	if gateC1bResponderSignalFault(fault) && (!hasPeer || peer.Class != gateb.ClassAttemptExpired ||
		!peer.Product.Witness.GateB.CredentialBurned || !peer.Product.Witness.GateB.FinishRecorded) {
		t.Fatal("responder signal did not enter caller-cancel cleanup with durable FINISH")
	}
	if fault == "pre-finish-eof" && (counts.InitiatorTotal != 0 || counts.ResponderTotal != 0) {
		t.Fatal("pre-presence EOF emitted UDP")
	}
	t.Logf("Gate C1b fault=%s class=%s peer_class=%s udp=%d/%d ledger_sequence=%d/%d wall_ms=%d retry=0",
		fault, initiator.Class, peer.Class, counts.InitiatorTotal, counts.ResponderTotal, sequences[0], sequences[1], time.Since(started).Milliseconds())
	// No success-only ledger assumptions here: failure/crash journal assertions
	// above are distinct; the same external zero-residue proof still applies.
	assertGateB2NoResidue(t, topology, observer, left, right)
}

func gateC1bResponderSignalFault(fault string) bool {
	return fault == "responder-sighup" || fault == "responder-sigterm"
}

// Only the one wink image in the already validated endpoint namespace may be
// signalled. Pin it by pidfd before checking identity, so a recycled PID cannot
// address sshd, a host process or another test. Never publish PIDs or paths.
func signalGateC1bResponder(t *testing.T, fault string, topology *n2dTopology, configs [2]gateC1bHostConfig) time.Time {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(5 * time.Millisecond)
	defer poll.Stop()
	for {
		left, _ := os.ReadFile(configs[0].StageFile)
		right, _ := os.ReadFile(configs[1].StageFile)
		if string(left) == gateb.StageCandidates && string(right) == gateb.StageCandidates {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("bilateral post-burn signal boundary unavailable")
		case <-poll.C:
		}
	}
	expected, err := os.Stat("/var/run/netns/" + topology.clientB)
	if err != nil || !safeNamePattern.MatchString(topology.clientB) {
		t.Fatal("signal target namespace unavailable")
	}
	expectedBinary, err := os.Stat(filepath.Join(configs[1].InstallBase, "winkyou", "wink"))
	if err != nil {
		t.Fatal("owned responder image unavailable")
	}
	processes, err := runCommand("ip", "netns", "pids", topology.clientB)
	if err != nil {
		t.Fatal("signal target inventory failed")
	}
	var descriptors []int
	defer func() {
		for _, descriptor := range descriptors {
			_ = unix.Close(descriptor)
		}
	}()
	for _, text := range strings.Fields(processes) {
		pid, err := strconv.Atoi(text)
		if err != nil || pid <= 1 {
			t.Fatal("signal target inventory invalid")
		}
		descriptor, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal("signal target could not be pinned")
		}
		descriptors = append(descriptors, descriptor)
		executable, exeErr := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
		current, nsErr := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
		if exeErr != nil || nsErr != nil || !os.SameFile(current, expected) || !os.SameFile(executable, expectedBinary) {
			t.Fatal("signal target is not the isolated responder wink image")
		}
	}
	if len(descriptors) != 1 {
		t.Fatal("signal target must be exactly one responder child, never sshd")
	}
	signal := unix.SIGHUP
	if fault == "responder-sigterm" {
		signal = unix.SIGTERM
	}
	started := time.Now()
	if err := unix.PidfdSendSignal(descriptors[0], signal, nil, 0); err != nil {
		t.Fatal("owned responder signal delivery failed")
	}
	for _, cfg := range configs {
		if err := os.WriteFile(cfg.StopFile+".signal", []byte("release"), 0o600); err != nil {
			t.Fatal("signal fence release failed")
		}
	}
	return started
}
