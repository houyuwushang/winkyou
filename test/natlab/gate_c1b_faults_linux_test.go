//go:build linux && natlab && c1bproof

package natlab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	for index, cfg := range configs {
		status := inspectGateALedger(t, filepath.Join(cfg.MachineBase, "winkyou-safety-v2"))
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
			t.Fatal("fault did not preserve durable FINISH before release")
		}
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
