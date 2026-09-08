//go:build linux && natlab

package natlab

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
)

// Opt-in evidence job only. The existing required matrix still runs exactly
// three success repetitions and rejects both historical timeout signatures.
func TestLinuxN2DRepeatDiagnostics(t *testing.T) {
	if os.Getenv("WINKYOU_N2D_REPEAT_DIAGNOSTICS") != "1" {
		t.Skip("N2d repeat diagnostics are opt-in")
	}
	requireN2DEnvironment(t)
	for round := 1; round <= 3; round++ {
		t.Run(fmt.Sprintf("round_%d", round), func(t *testing.T) {
			runN2DEIMSuccess(t, 10, true)
		})
	}
}

// Read-only, bounded sampling. Counters are sequential snapshots, not an atomic
// ordering proof. Child monotonic stage times are relative to each child, not
// interchangeable cross-process clock readings. No raw command output is logged.
func observeN2DRepeat(t *testing.T, topology *n2dTopology, servers *n2dServers, left, right *n2dEndpointProcess, previous *[2]uint16) func() {
	t.Helper()
	started := time.Now()
	done, stopped := make(chan struct{}), make(chan struct{})
	var once sync.Once
	stages := []string{n2dStagePresent, n2dStageBurned, n2dStageActivated, n2dStageHandshake,
		n2dStagePrepare, n2dStageSocket, n2dStageSTUN, n2dStageReady, n2dStageFire,
		n2dStagePunchSent, n2dStagePunch, n2dStageVerify, n2dStageTerminal}
	seen := [2]map[string]bool{{}, {}}
	var currentPorts [2]uint16
	sampleStages := func() {
		for index, process := range []*n2dEndpointProcess{left, right} {
			for _, stage := range stages {
				if seen[index][stage] {
					continue
				}
				var event n2dEvent
				if !readN1JSON(filepath.Join(process.eventDir, stage+".json"), &event) || event.Stage != stage {
					continue
				}
				seen[index][stage] = true
				if event.Port != 0 {
					currentPorts[index] = event.Port
				}
				t.Logf("n2d_stage role=%s stage=%s child_us=%d observed_ms=%d", process.config.Role, stage,
					event.ElapsedMicroseconds, time.Since(started).Milliseconds())
			}
		}
	}
	sampleOS := func() {
		counts, err := topology.packetCounts()
		if err != nil {
			t.Error("n2d_repeat packet_snapshot_failed")
			return
		}
		conntrack, timeWait := 0, 0
		for _, namespace := range []string{topology.natA, topology.public, topology.natB} {
			out, err := runNamespaced(namespace, "conntrack", nil, "-C")
			count, parseErr := strconv.Atoi(strings.TrimSpace(out))
			if err != nil || parseErr != nil {
				t.Error("n2d_repeat conntrack_snapshot_failed")
				return
			}
			conntrack += count
		}
		for _, namespace := range []string{topology.clientA, topology.public, topology.clientB} {
			out, err := runNamespaced(namespace, "ss", nil, "-H", "-n", "-t", "state", "time-wait")
			if err != nil {
				t.Error("n2d_repeat tcp_state_snapshot_failed")
				return
			}
			if trimmed := strings.TrimSpace(out); trimmed != "" {
				timeWait += len(strings.Split(trimmed, "\n"))
			}
		}
		stats := servers.rendezvous.Stats()
		t.Logf("n2d_os sampled_ms=%d stun=%d/%d direct=%d/%d udp=%d/%d conntrack=%d time_wait=%d tcp_A=%d/%d tcp_B=%d/%d active=%d",
			time.Since(started).Milliseconds(), counts.InitiatorSTUN, counts.ResponderSTUN,
			counts.InitiatorDirect, counts.ResponderDirect, counts.InitiatorTotal, counts.ResponderTotal,
			conntrack, timeWait, stats.SlotARead, stats.SlotAWritten, stats.SlotBRead, stats.SlotBWritten, stats.Active)
	}
	// Establish absence of old flows before starting either child. This does not
	// claim to observe invisible RCU reclamation after a namespace is unlinked.
	sampleOS()
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				sampleStages()
				sampleOS()
				return
			case <-ticker.C:
				sampleStages()
				sampleOS()
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(done)
			<-stopped
			t.Logf("n2d_repeat reuse_previous_udp_port=%t/%t monotonic_namespace_sequence=true rcu_release_unobserved=true observer_workers=0",
				currentPorts[0] != 0 && currentPorts[0] == previous[0], currentPorts[1] != 0 && currentPorts[1] == previous[1])
			*previous = currentPorts
		})
	}
}

// Kept on the actual required success path, so accepting a bounded expiry is
// not a fix for #101. Detailed safety/ledger/resource assertions remain below it.
func n2dSuccessTerminalContract(result n2dEndpointResult, role directattempt.Role) bool {
	direct, control, read, written := 1, 3, 7, 6
	if role == directattempt.RoleInitiator {
		direct, control, read, written = 2, 4, 6, 7
	} else if role != directattempt.RoleResponder {
		return false
	}
	return result.OK && result.Role == string(role) && result.Terminal == n2dTerminalSuccess && result.ErrorClass == "" &&
		result.Burned && result.SameSocket && result.STUNPackets >= 1 && result.STUNPackets <= 3 &&
		result.DirectPackets == direct && result.UDPPackets == result.STUNPackets+direct &&
		result.ControlFrames == control && result.HandshakeFrames == 1 &&
		result.CarrierFramesRead == read && result.CarrierFramesWritten == written && result.DNSResolutions == 0
}

func TestN2DSuccessRejectsHistoricalTimeoutSignatures(t *testing.T) {
	for _, role := range []directattempt.Role{directattempt.RoleInitiator, directattempt.RoleResponder} {
		good := n2dEndpointResult{OK: true, Role: string(role), Terminal: n2dTerminalSuccess, Burned: true,
			SameSocket: true, STUNPackets: 1, DirectPackets: 1, UDPPackets: 2, ControlFrames: 3,
			HandshakeFrames: 1, CarrierFramesRead: 7, CarrierFramesWritten: 6}
		if role == directattempt.RoleInitiator {
			good.DirectPackets, good.UDPPackets, good.ControlFrames = 2, 3, 4
			good.CarrierFramesRead, good.CarrierFramesWritten = 6, 7
		}
		if !n2dSuccessTerminalContract(good, role) {
			t.Fatal("positive success vector rejected")
		}
		for _, signature := range []string{"punch_timeout", "verify"} {
			bad := good
			bad.Terminal, bad.ErrorClass = n2dTerminalExpired, signature
			if signature == "punch_timeout" {
				bad.DirectPackets, bad.UDPPackets = 1, 2
				bad.ControlFrames, bad.CarrierFramesWritten = 2, 5
				if role == directattempt.RoleInitiator {
					bad.ControlFrames, bad.CarrierFramesWritten = 3, 6
				}
			} else if role == directattempt.RoleResponder {
				bad.ControlFrames, bad.CarrierFramesWritten = 2, 5
			}
			if n2dSuccessTerminalContract(bad, role) {
				t.Fatalf("historical %s/%s vector accepted", role, signature)
			}
		}
		for _, mutate := range []func(*n2dEndpointResult){
			func(r *n2dEndpointResult) { r.DirectPackets-- },
			func(r *n2dEndpointResult) { r.ControlFrames-- },
			func(r *n2dEndpointResult) { r.CarrierFramesWritten-- },
			func(r *n2dEndpointResult) { r.CarrierFramesRead-- },
		} {
			bad := good
			mutate(&bad)
			if n2dSuccessTerminalContract(bad, role) {
				t.Fatal("success relabel hid a deficient packet/frame witness")
			}
		}
	}
}
