//go:build linux && natlab && c1bproof

package natlab

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"winkyou/internal/governor"
)

func testGateC1bLivenessCrash(t *testing.T, fault string) {
	t.Helper()
	armGateB3KernelReleaseMargin(t)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	t.Cleanup(func() { cleanupGateC1bEndpointProcesses(t, topology) })
	observer := startGateB2ObserverSet(t, topology.public)
	left, right := gateC1bRouters(t, topology, gateC1bProfiles[0])
	if topology.installGateB2PacketCounters(observer.topology) != nil {
		t.Fatal("crash counter setup failed")
	}
	configs := gateC1bFixtureForFault(t, topology, observer.topology, gateC1bProfiles[0], true, fault)
	server := startGateC1bHost(t, configs[1])
	server.waitFile(t, configs[1].ReadyFile, 5*time.Second)
	client := startGateC1bHost(t, configs[0])
	deadline := time.Now().Add(60 * time.Second)
	for {
		a, _ := os.ReadFile(configs[0].StageFile)
		b, _ := os.ReadFile(configs[1].StageFile)
		if string(a) == "data_plane_ready" && string(b) == "data_plane_ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("crash did not reach armed post-FINISH boundary")
		}
		time.Sleep(10 * time.Millisecond)
	}
	killed, survivor := 0, 1
	if fault == "liveness-parent-kill" {
		if client.command.Process.Kill() != nil {
			t.Fatal("exact owned parent kill failed")
		}
	} else {
		killed, survivor = 1, 0
		server.waitFile(t, configs[1].StageFile+".fault", 5*time.Second)
		marker, _ := os.ReadFile(configs[1].StageFile + ".fault")
		if string(marker) != fault {
			t.Fatal("consumer crash marker wrong")
		}
	}
	faultAt := time.Now()
	watcher := []*gateC1bHostProcess{client, server}[survivor]
	watcher.waitFile(t, configs[survivor].ResultFile, 67*time.Second)
	var result gateC1bProcessResult
	if !readN1JSON(configs[survivor].ResultFile, &result) || !gateC1bExpectedLivenessTimeout(configs[survivor], result) {
		t.Fatal("survivor did not terminate with clean liveness timeout")
	}
	validateGateC1bKernelLiveness(t, configs[survivor], result, faultAt)
	if _, err := os.Stat(configs[killed].ResultFile); !os.IsNotExist(err) {
		t.Fatal("killed process fabricated an in-process terminal")
	}
	select {
	case <-client.done:
	case <-time.After(3 * time.Second):
		t.Fatal("client crash/drain exceeded bound")
	}
	server.stop(t)
	counts := requireGateB2PacketCounts(t, topology)
	for index, actual := range []uint64{counts.InitiatorTotal, counts.ResponderTotal} {
		// Predictive establishment <=64, challenge 3, echo/CLOSE <=2,
		// unproved post-arm <=3 PINGs, automatic WG lane <=4 per second.
		// This is a conservative OS count bound, not additional authority.
		if actual > 64+3+2+3+4*65 {
			t.Fatal("crash escaped frozen independent emission bound")
		}
		namespace := filepath.Join(configs[index].MachineBase, "winkyou-safety-v2")
		status := inspectGateALedger(t, namespace)
		if status.Sequence != 3 || status.TwentyFourHourAdmissions != 1 {
			t.Fatal("post-FINISH crash changed durable journal or refunded burn")
		}
		owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "liveness-crash-reinspect")
		if err != nil {
			t.Fatal("post-crash machine lock survived")
		}
		trip := owner.SafetyTripStatus()
		if err := owner.Close(); err != nil || trip.BlocksActiveWork {
			t.Fatal("clean post-FINISH crash left trip or owner")
		}
	}
	before := counts
	time.Sleep(100 * time.Millisecond)
	after := requireGateB2PacketCounts(t, topology)
	if before.InitiatorTotal != after.InitiatorTotal || before.ResponderTotal != after.ResponderTotal {
		t.Fatal("post-drain packet emission")
	}
	t.Logf("liveness crash=%s udp=%d/%d FINISH=3/3 burns=1/1 trip=clear lock=free post_drain_writes=0 survivor_drain_ms=%d", fault, counts.InitiatorTotal, counts.ResponderTotal, time.Since(faultAt).Milliseconds())
	assertGateB2NoResidue(t, topology, observer, left, right)
}
