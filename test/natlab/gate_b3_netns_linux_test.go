//go:build linux && natlab

package natlab

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/hardnatattempt"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
)

const (
	gateB3ConntrackCap      = 40_000
	gateB3ConntrackFaultCap = 1_024
	// nf_conntrack_count is incremented before the kernel compares it with
	// nf_conntrack_max. This single-forwarder test router can therefore expose
	// the rejected allocation as a transient max+1 sample; terminal count must
	// still settle at or below the configured ceiling.
	gateB3ConntrackTransientAllowance = 1
	gateB3HostConntrackCapEnv         = "WINKYOU_GATE_B3_HOST_CONNTRACK_CAP"
	gateB3DisposableRunnerEnv         = "WINKYOU_GATE_B3_DISPOSABLE_RUNNER"
	gateB3PortMin                     = uint16(hardnatplan.DynamicPortMin)
	gateB3PortMax                     = uint16(hardnatplan.DynamicPortMax)
	gateB3ProcessLimit                = 52 * time.Second
	// Deleting a namespace removes its named handle synchronously, while RCU
	// reclamation of its netdevices or a 16K conntrack table may continue
	// briefly. This test-only margin separates independent campaigns and fresh
	// topology generations; it never retries an attempt or a setup operation.
	gateB3KernelReleaseMargin = time.Second
	// Socket zero registers all four authenticated RFC 5780 reply sources but
	// emits to only three of them. The protocol therefore owns 16,395 registered
	// five-tuples while each APDM test router opens exactly 16,394 mappings.
	gateB3EvidenceNATMappings = hardnatbudget.Hard16ActualFiveTupleMaximum - hardnatbudget.Hard16CandidatePackets - 1
	gateB3ParentEnv           = "WINKYOU_GATE_B3_PARENT_HELPER"
	gateB3ParentConfig        = "WINKYOU_GATE_B3_PARENT_CONFIG"
)

func TestGateB3EndpointParentProcess(t *testing.T) {
	if os.Getenv(gateB3ParentEnv) != "1" {
		return
	}
	configPath := os.Getenv(gateB3ParentConfig)
	var config gateB2EndpointConfig
	if !readN1JSON(configPath, &config) || !validGateB2EndpointConfig(config) || config.ReadyPath == "" {
		t.Fatal("Gate B3 parent helper configuration rejected")
	}
	streamFile := os.NewFile(gateB2StreamFD, "gate-b3-parent-oob")
	if streamFile == nil {
		t.Fatal("Gate B3 parent helper stream unavailable")
	}
	command := exec.Command(
		"ip", "netns", "exec", config.Namespace, os.Args[0],
		"-test.run=^TestGateB3EndpointProcess$", "-test.count=1", "-test.timeout=51s",
	)
	command.Env = append(os.Environ(), gateB3EndpointHelperEnv+"=1", gateB3HelperConfigEnv+"="+configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{streamFile}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		_ = streamFile.Close()
		t.Fatal("Gate B3 parent helper could not start child")
	}
	_ = streamFile.Close()
	if err := command.Wait(); err != nil {
		t.Fatal("Gate B3 parent helper child failed")
	}
}

func TestLinuxGateB3Hard16Proof(t *testing.T) {
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	t.Run("conntrack_counter_boundary", testGateB3ConntrackCounterBoundary)
	t.Run("topology_setup_error_redaction", testGateB3TopologySetupErrorRedaction)
	t.Run("router_mapping_cap_pre_io", testGateB3RouterMappingCapPreIO)
	t.Run("loss_terminal_contract", testGateB3LossTerminalContract)
	// Exercise the low-ceiling fault before any 16K topology can leave
	// invisible conntrack/RCU reclamation behind. The fault remains one-shot
	// and restores the reviewed 40K ceiling before the next subtest.
	t.Run("conntrack_full", func(t *testing.T) { testGateB3FullShape(t, 0, gateB3ConntrackFaultCap) })
	t.Run("full_shape_tail_hit", func(t *testing.T) { testGateB3FullShape(t, 0, gateB3ConntrackCap) })
	t.Run("full_exhaustion", func(t *testing.T) { testGateB3FullShape(t, 1, gateB3ConntrackCap) })
	t.Run("fifty_percent_candidate_loss", func(t *testing.T) { testGateB3FullShape(t, 2, gateB3ConntrackCap) })
	t.Run("enobufs", testGateB3ENOBUFS)
	t.Run("oob_eof_after_child_kill", testGateB3ChildKill)
	t.Run("parent_kill", testGateB3ParentKill)
	t.Run("prefire_fresh_namespace_teardown_100", testGateB3PreFIRETeardown100)
}

func testGateB3FullShape(t *testing.T, dropEvery uint64, conntrackCap int) {
	armGateB3KernelReleaseMargin(t)
	started := time.Now()
	setGateB3HostConntrackCapForSubtest(t, conntrackCap)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	if err := verifyGateB3NamespacedConntrackCap(topology.natA, topology.natB, conntrackCap); err != nil {
		t.Fatal("Gate B3 shared namespace conntrack cap could not be verified")
	}
	observer := startGateB2ObserverSet(t, topology.public)
	leftConfig, rightConfig := gateB3RouterConfig(topology, true, 11, dropEvery), gateB3RouterConfig(topology, false, 29, dropEvery)
	if dropEvery == 0 && conntrackCap == gateB3ConntrackCap {
		lateHit := newGateB3LateHitMappingPlan()
		leftConfig.gateB3MappingPlan, leftConfig.gateB3MappingPlanLeft = lateHit, true
		rightConfig.gateB3MappingPlan = lateHit
	}
	leftRouter := startGateB2NATRouter(t, leftConfig)
	rightRouter := startGateB2NATRouter(t, rightConfig)
	conntrackMonitor := startGateB3ConntrackMonitor(t, topology.natA, topology.natB)
	if err := topology.installGateB2PacketCounters(observer.topology); err != nil {
		t.Fatal("Gate B3 packet counter setup failed")
	}
	artifacts := buildGateB3Artifacts(t, fmt.Sprintf("drop-%d", dropEvery))
	defer clearGateB2Artifacts(&artifacts)
	initiator, responder := startGateB3Pair(t, topology, observer.topology, artifacts)
	initiatorResult, responderResult := waitGateB3Result(t, initiator), waitGateB3Result(t, responder)
	leftConntrackPeak, rightConntrackPeak, monitorErr := conntrackMonitor.Stop()
	if monitorErr != nil {
		t.Fatal("Gate B3 conntrack peak witness failed")
	}

	for _, result := range []gateB3EndpointResult{initiatorResult, responderResult} {
		assertGateB3FrozenShape(t, result)
	}
	counts := requireGateB2PacketCounts(t, topology)
	assertGateB2PacketCounts(t, counts, initiatorResult.gateB2EndpointResult, responderResult.gateB2EndpointResult)
	leftWitness, rightWitness := leftRouter.Witness(), rightRouter.Witness()
	if leftWitness.MappingHardCap != gateB3PerNATMappingCap || rightWitness.MappingHardCap != gateB3PerNATMappingCap ||
		leftWitness.MappingCapHit || rightWitness.MappingCapHit || leftWitness.PeakMappings > gateB3PerNATMappingCap ||
		rightWitness.PeakMappings > gateB3PerNATMappingCap {
		t.Fatalf("Gate B3 per-router mapping cap witness = %+v/%+v", leftWitness, rightWitness)
	}
	if conntrackCap == gateB3ConntrackCap {
		if leftWitness.PeakMappings != gateB3EvidenceNATMappings+initiatorResult.CandidatePackets ||
			rightWitness.PeakMappings != gateB3EvidenceNATMappings+responderResult.CandidatePackets {
			t.Fatalf("Gate B3 NAT mapping shape = %+v/%+v", leftWitness, rightWitness)
		}
	} else if leftWitness.PeakMappings <= 0 || rightWitness.PeakMappings <= 0 ||
		leftWitness.PeakMappings > hardnatbudget.Hard16ActualFiveTupleMaximum ||
		rightWitness.PeakMappings > hardnatbudget.Hard16ActualFiveTupleMaximum {
		t.Fatalf("Gate B3 conntrack-fault mapping prefix = %+v/%+v", leftWitness, rightWitness)
	}
	leftConntrack, err := readGateB3ConntrackCount(topology.natA)
	if err != nil {
		t.Fatal("Gate B3 left conntrack witness failed")
	}
	rightConntrack, err := readGateB3ConntrackCount(topology.natB)
	if err != nil {
		t.Fatal("Gate B3 right conntrack witness failed")
	}
	if !validGateB3ConntrackWitness(leftConntrack, leftConntrackPeak, conntrackCap) ||
		!validGateB3ConntrackWitness(rightConntrack, rightConntrackPeak, conntrackCap) {
		t.Fatalf("Gate B3 conntrack cap witness terminal=%d/%d peak=%d/%d cap=%d",
			leftConntrack, rightConntrack, leftConntrackPeak, rightConntrackPeak, conntrackCap)
	}
	if conntrackCap == gateB3ConntrackFaultCap &&
		(leftConntrackPeak < gateB3ConntrackFaultCap*9/10 || rightConntrackPeak < gateB3ConntrackFaultCap*9/10) {
		t.Fatalf("Gate B3 conntrack-full witness did not reach the bounded pressure window: %d/%d", leftConntrackPeak, rightConntrackPeak)
	}

	success := initiatorResult.Terminal == "success" && responderResult.Terminal == "success"
	if dropEvery == 0 && conntrackCap == gateB3ConntrackCap {
		if !success || initiatorResult.CandidatePackets != hardnatbudget.Hard16CandidatePackets ||
			responderResult.CandidatePackets != hardnatbudget.Hard16CandidatePackets ||
			initiatorResult.WinnerPackets+responderResult.WinnerPackets != 1 {
			t.Fatalf("Gate B3 full-shape success rejected: initiator=%+v responder=%+v", initiatorResult, responderResult)
		}
		assertGateB3NoResidue(t, topology, observer, leftRouter, rightRouter, false, false, initiator.governorDir, responder.governorDir)
	} else {
		if (dropEvery == 1 || conntrackCap < gateB3ConntrackCap) && success {
			t.Fatal("Gate B3 full candidate loss unexpectedly succeeded")
		}
		if !success {
			validTerminal := initiatorResult.ErrorClass == gateb.ClassCandidateExhausted &&
				responderResult.ErrorClass == gateb.ClassCandidateExhausted
			if dropEvery == 2 {
				validTerminal = validGateB3FiftyPercentLossTerminal(initiatorResult, responderResult)
			}
			if !validTerminal {
				leftWitness, rightWitness := gateB3LossTerminalWitnessFrom(initiatorResult), gateB3LossTerminalWitnessFrom(responderResult)
				t.Fatalf("Gate B3 lossy terminal rejected: class=%s/%s reason=%s witness=%+v/%+v",
					initiatorResult.ErrorClass, responderResult.ErrorClass,
					gateB3LossTerminalRejection(leftWitness, rightWitness), leftWitness, rightWitness)
			}
		}
		if !success && conntrackCap == gateB3ConntrackCap &&
			(initiatorResult.CandidatePackets != hardnatbudget.Hard16CandidatePackets ||
				responderResult.CandidatePackets != hardnatbudget.Hard16CandidatePackets) {
			t.Fatalf("Gate B3 lossy exhaustion did not consume the fixed schedule: %d/%d",
				initiatorResult.CandidatePackets, responderResult.CandidatePackets)
		}
		assertGateB3NoResidue(t, topology, observer, leftRouter, rightRouter, !success,
			conntrackCap < gateB3ConntrackCap, initiator.governorDir, responder.governorDir)
	}
	peakPPS := maxInt(initiatorResult.EnvelopePPS, responderResult.EnvelopePPS)
	t.Logf("Gate B3 isolated witness: success=%t loss_divisor=%d conntrack_cap=%d wall_ms=%d pps_max=%d packets=%d/%d targets=%d/%d tuples=%d/%d sockets=%d/%d conntrack_peak=%d/%d conntrack_terminal=%d/%d drain_ms<=2000",
		success, dropEvery, conntrackCap, time.Since(started).Milliseconds(), peakPPS, initiatorResult.UDPPackets,
		responderResult.UDPPackets, initiatorResult.TargetsRegistered, responderResult.TargetsRegistered,
		initiatorResult.FiveTuples, responderResult.FiveTuples, initiatorResult.SocketsOpened,
		responderResult.SocketsOpened, leftConntrackPeak, rightConntrackPeak, leftConntrack, rightConntrack)
}

// validGateB3FiftyPercentLossTerminal freezes the only two role-ordered
// no-winner outcomes admitted by ADR section 22. The initiator may report a
// transport close only when the responder has the authenticated local
// exhaustion witness and both endpoints prove the complete one-shot schedule.
// It must never turn an unreceived EXHAUSTED frame into candidate_exhausted.
func validGateB3FiftyPercentLossTerminal(initiator, responder gateB3EndpointResult) bool {
	return validGateB3LossTerminalPair(gateB3LossTerminalWitnessFrom(initiator), gateB3LossTerminalWitnessFrom(responder))
}

func gateB3LossTerminalWitnessFrom(result gateB3EndpointResult) gateB3LossTerminalWitness {
	return gateB3LossTerminalWitness{
		OK: result.OK, Role: result.Role, Terminal: result.Terminal, ErrorClass: result.ErrorClass,
		ErrorStage: result.ErrorStage, CredentialBurned: result.CredentialBurned,
		FinishRecorded: result.FinishRecorded, Bidirectional: result.Bidirectional,
		EvidencePackets: result.EvidencePackets, CandidatePackets: result.CandidatePackets,
		WinnerPackets: result.WinnerPackets, UDPPackets: result.UDPPackets,
		DataPacketsRead: result.DataPacketsRead, DataPacketsWritten: result.DataPacketsWritten,
		CarrierFramesRead: result.CarrierFramesRead, CarrierFramesWrite: result.CarrierFramesWrite,
		CarrierDrained: result.CarrierDrained, CampaignCircuit: result.CampaignCircuit,
		SafetyBlocksWork: result.SafetyBlocksWork,
	}
}

func validGateB3ConntrackWitness(terminal, peak, cap int) bool {
	return cap > 0 && terminal >= 0 && terminal <= cap && peak > 0 &&
		peak <= cap+gateB3ConntrackTransientAllowance
}

func testGateB3ConntrackCounterBoundary(t *testing.T) {
	for _, test := range []struct {
		terminal int
		peak     int
		valid    bool
	}{
		{terminal: gateB3ConntrackFaultCap, peak: gateB3ConntrackFaultCap, valid: true},
		{terminal: gateB3ConntrackFaultCap, peak: gateB3ConntrackFaultCap + 1, valid: true},
		{terminal: gateB3ConntrackFaultCap + 1, peak: gateB3ConntrackFaultCap + 1, valid: false},
		{terminal: gateB3ConntrackFaultCap, peak: gateB3ConntrackFaultCap + 2, valid: false},
	} {
		if got := validGateB3ConntrackWitness(test.terminal, test.peak, gateB3ConntrackFaultCap); got != test.valid {
			t.Fatalf("Gate B3 conntrack witness terminal=%d peak=%d valid=%t, want %t",
				test.terminal, test.peak, got, test.valid)
		}
	}
}

func testGateB3TopologySetupErrorRedaction(t *testing.T) {
	for _, test := range []struct {
		cause error
		want  string
	}{
		{cause: context.DeadlineExceeded, want: "link_pair_create_timeout"},
		{cause: errors.New("RTNETLINK answers: File exists"), want: "link_pair_create_conflict"},
		{cause: errors.New("RTNETLINK answers: Cannot allocate memory"), want: "link_pair_create_resource"},
		{cause: errors.New("RTNETLINK answers: Device or resource busy"), want: "link_pair_create_busy"},
		{cause: errors.New("RTNETLINK answers: Operation not permitted"), want: "link_pair_create_permission"},
		{cause: errors.New("sensitive setup detail"), want: "link_pair_create_other"},
	} {
		setupErr := &n2dTopologySetupError{stage: "link_pair_create", cause: test.cause}
		witness := n2dTopologySetupWitness(setupErr)
		if setupErr.Error() != "link_pair_create" || n2dTopologySetupStage(setupErr) != "link_pair_create" ||
			witness != test.want || strings.Contains(witness, "sensitive") {
			t.Fatalf("Gate B3 topology setup witness = %q, want %q", witness, test.want)
		}
	}
}

type gateB3LateHitMappingPlan struct {
	mu      sync.Mutex
	counts  [2]int
	final   [2]uint16
	ready   chan struct{}
	readyOK bool
}

func newGateB3LateHitMappingPlan() *gateB3LateHitMappingPlan {
	return &gateB3LateHitMappingPlan{ready: make(chan struct{})}
}

func (plan *gateB3LateHitMappingPlan) preferred(ctx context.Context, left bool, target uint16) (uint16, error) {
	if plan == nil || ctx == nil || target < gateB3PortMin || target > gateB3PortMax {
		return 0, errors.New("Gate B3 late-hit mapping input rejected")
	}
	side := 1
	if left {
		side = 0
	}
	plan.mu.Lock()
	ordinal := plan.counts[side]
	plan.counts[side]++
	if ordinal < hardnatbudget.Hard16CandidatePackets-1 {
		plan.mu.Unlock()
		if left {
			return target, nil
		}
		if target == gateB3PortMax {
			return gateB3PortMin, nil
		}
		return target + 1, nil
	}
	if ordinal != hardnatbudget.Hard16CandidatePackets-1 {
		plan.mu.Unlock()
		return 0, errors.New("Gate B3 late-hit mapping schedule exceeded")
	}
	plan.final[side] = target
	if plan.final[0] != 0 && plan.final[1] != 0 && !plan.readyOK {
		close(plan.ready)
		plan.readyOK = true
	}
	ready := plan.ready
	plan.mu.Unlock()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ready:
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
		return 0, errors.New("Gate B3 late-hit peer mapping deadline exceeded")
	}
	plan.mu.Lock()
	peerTarget := plan.final[1-side]
	plan.mu.Unlock()
	if peerTarget == 0 {
		return 0, errors.New("Gate B3 late-hit peer mapping absent")
	}
	return peerTarget, nil
}

type gateB3ConntrackMonitor struct {
	leftNamespace  string
	rightNamespace string
	stop           chan struct{}
	done           chan struct{}
	once           sync.Once
	mu             sync.Mutex
	leftPeak       int
	rightPeak      int
	err            error
}

func startGateB3ConntrackMonitor(t *testing.T, leftNamespace, rightNamespace string) *gateB3ConntrackMonitor {
	t.Helper()
	monitor := &gateB3ConntrackMonitor{
		leftNamespace: leftNamespace, rightNamespace: rightNamespace,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	t.Cleanup(func() { _, _, _ = monitor.Stop() })
	go monitor.run()
	return monitor
}

func (monitor *gateB3ConntrackMonitor) run() {
	defer close(monitor.done)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		left, leftErr := readGateB3ConntrackCount(monitor.leftNamespace)
		right, rightErr := readGateB3ConntrackCount(monitor.rightNamespace)
		monitor.mu.Lock()
		if leftErr != nil || rightErr != nil {
			monitor.err = errors.Join(leftErr, rightErr)
			monitor.mu.Unlock()
			return
		}
		monitor.leftPeak = maxInt(monitor.leftPeak, left)
		monitor.rightPeak = maxInt(monitor.rightPeak, right)
		monitor.mu.Unlock()
		select {
		case <-monitor.stop:
			return
		case <-ticker.C:
		}
	}
}

func (monitor *gateB3ConntrackMonitor) Stop() (int, int, error) {
	if monitor == nil {
		return 0, 0, errors.New("Gate B3 conntrack monitor unavailable")
	}
	monitor.once.Do(func() { close(monitor.stop) })
	<-monitor.done
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	return monitor.leftPeak, monitor.rightPeak, monitor.err
}

func gateB3RouterConfig(topology *n2dTopology, left bool, seed, dropEvery uint64) gateB2NATConfig {
	config := gateB2NATConfig{
		namespace: topology.natA, tunName: gateB2TUNName(topology.natA), mode: gateB2NATAPDM,
		private: netip.MustParseAddr(n2dClientAAddress), public: netip.MustParseAddr(n2dNATAWAN),
		peerPublic: netip.MustParseAddr(n2dNATBWAN), mappingPortMin: gateB3PortMin, mappingPortMax: gateB3PortMax,
		randomSeed: seed, reusePortsByTarget: true, dropEveryCandidateInbound: dropEvery,
		mappingHardCap: gateB3PerNATMappingCap,
	}
	if !left {
		config.namespace = topology.natB
		config.tunName = gateB2TUNName(topology.natB)
		config.private = netip.MustParseAddr(n2dClientBAddress)
		config.public = netip.MustParseAddr(n2dNATBWAN)
		config.peerPublic = netip.MustParseAddr(n2dNATAWAN)
	}
	return config
}

func testGateB3ENOBUFS(t *testing.T) {
	armGateB3KernelReleaseMargin(t)
	setGateB3HostConntrackCapForSubtest(t, gateB3ConntrackCap)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	if err := verifyGateB3NamespacedConntrackCap(topology.natA, topology.natB, gateB3ConntrackCap); err != nil {
		t.Fatal("Gate B3 ENOBUFS conntrack cap could not be verified")
	}
	observer := startGateB2ObserverSet(t, topology.public)
	leftRouter := startGateB2NATRouter(t, gateB3RouterConfig(topology, true, 11, 0))
	rightRouter := startGateB2NATRouter(t, gateB3RouterConfig(topology, false, 29, 0))
	if err := topology.installGateB2PacketCounters(observer.topology); err != nil {
		t.Fatal("Gate B3 ENOBUFS packet counter setup failed")
	}
	artifacts := buildGateB3Artifacts(t, "enobufs")
	defer clearGateB2Artifacts(&artifacts)
	leftFile, rightFile := gateASocketPair(t)
	initiator := newGateB3EndpointProcessWithFault(t, topology.clientA, directattempt.RoleInitiator,
		observer.topology, artifacts.initiator, leftFile, gateB3FaultENOBUFS)
	responder := newGateB3EndpointProcess(t, topology.clientB, directattempt.RoleResponder,
		observer.topology, artifacts.responder, rightFile)
	initiator.start(t)
	responder.start(t)
	initiatorResult, responderResult := waitGateB3Result(t, initiator), waitGateB3Result(t, responder)
	if initiatorResult.ErrorClass != gateb.ClassResourceBudgetExceeded ||
		initiatorResult.SafetyReason != string(governor.SafetyTripResourceExhausted) || !initiatorResult.SafetyBlocksWork ||
		initiatorResult.CandidatePackets != 0 || initiatorResult.UDPPackets != hardnatbudget.FreshEvidencePackets ||
		!initiatorResult.CredentialBurned || !initiatorResult.FinishRecorded || !initiatorResult.CampaignCircuit {
		t.Fatalf("Gate B3 ENOBUFS initiator witness rejected: %+v", initiatorResult)
	}
	if responderResult.Terminal == "success" || responderResult.SafetyBlocksWork ||
		!responderResult.CredentialBurned || !responderResult.FinishRecorded || !responderResult.CampaignCircuit ||
		responderResult.CandidatePackets > hardnatbudget.Hard16CandidatePackets {
		t.Fatalf("Gate B3 ENOBUFS peer witness rejected: %+v", responderResult)
	}
	counts := requireGateB2PacketCounts(t, topology)
	assertGateB2PacketCounts(t, counts, initiatorResult.gateB2EndpointResult, responderResult.gateB2EndpointResult)
	assertGateB3TripNoResidue(t, topology, observer, leftRouter, rightRouter,
		map[string]bool{initiator.governorDir: true, responder.governorDir: false})
	t.Logf("Gate B3 ENOBUFS witness: evidence=%d/%d candidate=%d/%d persistent_trip=true residue=0",
		initiatorResult.EvidencePackets, responderResult.EvidencePackets,
		initiatorResult.CandidatePackets, responderResult.CandidatePackets)
}

func testGateB3ChildKill(t *testing.T) {
	armGateB3KernelReleaseMargin(t)
	setGateB3HostConntrackCapForSubtest(t, gateB3ConntrackCap)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	if err := verifyGateB3NamespacedConntrackCap(topology.natA, topology.natB, gateB3ConntrackCap); err != nil {
		t.Fatal("Gate B3 child-kill conntrack cap could not be verified")
	}
	observer := startGateB2ObserverSet(t, topology.public)
	leftRouter := startGateB2NATRouter(t, gateB3RouterConfig(topology, true, 11, 0))
	rightRouter := startGateB2NATRouter(t, gateB3RouterConfig(topology, false, 29, 0))
	if err := topology.installGateB2PacketCounters(observer.topology); err != nil {
		t.Fatal("Gate B3 child-kill packet counter setup failed")
	}
	artifacts := buildGateB3Artifacts(t, "child-kill")
	defer clearGateB2Artifacts(&artifacts)
	initiator, responder := startGateB3Pair(t, topology, observer.topology, artifacts)
	deadline := time.Now().Add(15 * time.Second)
	for {
		counts := requireGateB2PacketCounts(t, topology)
		if counts.InitiatorEvidence == hardnatbudget.FreshEvidencePackets &&
			counts.ResponderEvidence == hardnatbudget.FreshEvidencePackets {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("Gate B3 child-kill post-burn witness was not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
	initiator.stop()
	responderResult := waitGateB3Result(t, responder)
	if responderResult.Terminal == "success" || responderResult.ErrorClass != gateb.ClassOOBStreamClosed ||
		!responderResult.CredentialBurned || !responderResult.FinishRecorded || !responderResult.CampaignCircuit ||
		responderResult.SafetyBlocksWork {
		t.Fatalf("Gate B3 child-kill peer terminal rejected: %+v", responderResult)
	}
	before := requireGateB2PacketCounts(t, topology)
	time.Sleep(100 * time.Millisecond)
	if after := requireGateB2PacketCounts(t, topology); after != before {
		t.Fatalf("Gate B3 child-kill emitted after OOB terminal: before=%+v after=%+v", before, after)
	}
	killedOrdinary, killedCampaign := inspectGateB3Ledger(t, initiator.governorDir)
	peerOrdinary, peerCampaign := inspectGateB3Ledger(t, responder.governorDir)
	if killedOrdinary.TwentyFourHourAdmissions != 0 || killedCampaign.TwentyFourHourAdmissions != 1 ||
		!killedCampaign.ExplicitResetRequired || peerOrdinary.Sequence != 3 || peerCampaign.TwentyFourHourAdmissions != 1 ||
		!peerCampaign.ExplicitResetRequired {
		t.Fatalf("Gate B3 child-kill durable witnesses rejected: killed=%+v/%+v peer=%+v/%+v",
			killedOrdinary, killedCampaign, peerOrdinary, peerCampaign)
	}
	assertGateB3TripNoResidue(t, topology, observer, leftRouter, rightRouter,
		map[string]bool{initiator.governorDir: false, responder.governorDir: false})
	t.Logf("Gate B3 child-kill witness: post_burn=true peer_class=%s packet_counters_stable=true residue=0",
		responderResult.ErrorClass)
}

func testGateB3ParentKill(t *testing.T) {
	armGateB3KernelReleaseMargin(t)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	artifacts := buildGateB3Artifacts(t, "parent-kill")
	defer clearGateB2Artifacts(&artifacts)
	leftFile, peerFile := gateASocketPair(t)
	defer peerFile.Close()
	process := newGateB3EndpointProcess(t, topology.clientA, directattempt.RoleInitiator,
		gateB3StaticObserverTopology(), artifacts.initiator, leftFile)
	process.command = exec.Command(os.Args[0], "-test.run=^TestGateB3EndpointParentProcess$", "-test.count=1", "-test.timeout=20s")
	process.command.Env = append(os.Environ(), gateB3ParentEnv+"=1", gateB3ParentConfig+"="+process.configPath)
	process.command.Stdout = io.Discard
	process.command.Stderr = io.Discard
	process.command.ExtraFiles = []*os.File{process.streamFile}
	process.start(t)
	waitGateB3Ready(t, process, 5*time.Second)
	if err := process.command.Process.Kill(); err != nil {
		t.Fatal("Gate B3 parent kill failed")
	}
	select {
	case <-process.done:
	case <-time.After(gateB2TerminalMargin):
		t.Fatal("Gate B3 killed parent did not exit")
	}
	if sockets, processes, err := waitGateB2NoOSResidue(topology, gateB2TerminalMargin); err != nil || sockets != 0 || processes != 0 {
		t.Fatalf("Gate B3 parent death left OS residue: sockets=%d processes=%d", sockets, processes)
	}
	ordinary, campaign := inspectGateB3Ledger(t, process.governorDir)
	if !gateB3LedgerHasOnlyInitialization(ordinary, campaign) {
		t.Fatalf("Gate B3 pre-burn parent death changed ledger: ordinary=%+v campaign=%+v", ordinary, campaign)
	}
	if err := topology.cleanup(); err != nil {
		t.Fatal("Gate B3 parent-kill topology cleanup failed")
	}
	if err := topology.assertNoLeaks(); err != nil {
		t.Fatal("Gate B3 parent-kill namespace residue")
	}
	t.Log("Gate B3 parent-kill witness: child_pdeathsig=true preburn=true sockets=0 processes=0 residue=0")
}

func buildGateB3Artifacts(t testing.TB, label string) gateB2ArtifactPair {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	psk := sha256.Sum256([]byte("gate-b3-netns-psk/" + label))
	set, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: n2dOpaqueID("gate-b3/" + label + "/credential"), AttemptID: n2dOpaqueID("gate-b3/" + label + "/attempt"),
		InitiatorParticipantID: n2dOpaqueID("gate-b3/" + label + "/initiator"), ResponderParticipantID: n2dOpaqueID("gate-b3/" + label + "/responder"),
		OOBChannelID: n2dOpaqueID("gate-b3/" + label + "/channel"), PlannerProfile: hardnatplan.ProfileHardBirthday,
		ResourceClass: hardnatplan.ResourceHard16KLab, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(10*time.Minute - time.Second),
	}, psk)
	clear(psk[:])
	if err != nil {
		t.Fatal("Gate B3 synthetic artifact construction failed")
	}
	clear(set.Manifest)
	return gateB2ArtifactPair{initiator: set.Initiator, responder: set.Responder}
}

func startGateB3Pair(t testing.TB, topology *n2dTopology, observer hardnatobserve.Topology,
	artifacts gateB2ArtifactPair,
) (*gateB2EndpointProcess, *gateB2EndpointProcess) {
	t.Helper()
	leftFile, rightFile := gateASocketPair(t)
	initiator := newGateB3EndpointProcess(t, topology.clientA, directattempt.RoleInitiator, observer, artifacts.initiator, leftFile)
	responder := newGateB3EndpointProcess(t, topology.clientB, directattempt.RoleResponder, observer, artifacts.responder, rightFile)
	initiator.start(t)
	responder.start(t)
	return initiator, responder
}

func newGateB3EndpointProcess(t testing.TB, namespace string, role directattempt.Role, observer hardnatobserve.Topology,
	artifact []byte, streamFile *os.File,
) *gateB2EndpointProcess {
	return newGateB3EndpointProcessWithFault(t, namespace, role, observer, artifact, streamFile, "")
}

func newGateB3EndpointProcessWithFault(t testing.TB, namespace string, role directattempt.Role,
	observer hardnatobserve.Topology, artifact []byte, streamFile *os.File, fault string,
) *gateB2EndpointProcess {
	t.Helper()
	directory := t.TempDir()
	governorDir := filepath.Join(directory, "governor")
	if err := os.Mkdir(governorDir, 0o700); err != nil {
		t.Fatal("Gate B3 governor namespace setup failed")
	}
	if err := governor.PrepareGateATestNamespace(governorDir, time.Now().UTC()); err != nil {
		t.Fatal("Gate B3 durable namespace preparation failed")
	}
	artifactPath := filepath.Join(directory, "artifact.json")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal("Gate B3 artifact staging failed")
	}
	resultPath := filepath.Join(directory, "result.json")
	readyPath := filepath.Join(directory, "ready")
	configPath := filepath.Join(directory, "config.json")
	config := gateB2EndpointConfig{
		Role: string(role), Namespace: namespace, GovernorDir: governorDir, ArtifactPath: artifactPath, ResultPath: resultPath,
		ObserverPrimary: observer.Primary.String(), ObserverOther: observer.Other.String(), Fault: fault, ReadyPath: readyPath,
	}
	if err := writeN1JSON(configPath, config); err != nil {
		t.Fatal("Gate B3 endpoint configuration write failed")
	}
	command := exec.Command(
		"ip", "netns", "exec", namespace, os.Args[0],
		"-test.run=^TestGateB3EndpointProcess$", "-test.count=1", "-test.timeout=51s",
	)
	command.Env = append(os.Environ(), gateB3EndpointHelperEnv+"=1", gateB3HelperConfigEnv+"="+configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{streamFile}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	process := &gateB2EndpointProcess{
		command: command, done: make(chan struct{}), streamFile: streamFile,
		resultPath: resultPath, readyPath: readyPath, configPath: configPath,
		governorDir: governorDir, artifactPath: artifactPath,
	}
	t.Cleanup(process.stop)
	return process
}

func waitGateB3Result(t testing.TB, process *gateB2EndpointProcess) gateB3EndpointResult {
	t.Helper()
	deadline := time.Now().Add(gateB3ProcessLimit)
	for time.Now().Before(deadline) {
		var result gateB3EndpointResult
		if readN1JSON(process.resultPath, &result) {
			select {
			case <-process.done:
			case <-time.After(gateB2TerminalMargin):
				t.Fatal("Gate B3 endpoint did not exit after result")
			}
			process.waitMu.Lock()
			waitErr := process.waitErr
			process.waitMu.Unlock()
			if waitErr != nil || !result.OK {
				t.Fatal("Gate B3 endpoint returned a harness failure")
			}
			return result
		}
		select {
		case <-process.done:
			t.Fatal("Gate B3 endpoint exited without a result")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	process.stop()
	t.Fatal("Gate B3 endpoint result deadline exceeded")
	return gateB3EndpointResult{}
}

func assertGateB3FrozenShape(t testing.TB, result gateB3EndpointResult) {
	t.Helper()
	if !result.OK || result.Profile != string(hardnatplan.ProfileHardBirthday) ||
		result.ResourceClass != string(hardnatplan.ResourceHard16KLab) || !result.CredentialBurned ||
		!result.FinishRecorded || result.Conditional != true || result.EvidencePackets != 13 ||
		result.CandidatePackets > hardnatbudget.Hard16CandidatePackets || result.WinnerPackets > 1 ||
		result.UDPPackets > hardnatbudget.Hard16ActualPacketsMaximum || result.SocketsOpened != 16 ||
		result.TargetsRegistered != hardnatbudget.Hard16ActualTargetsMaximum ||
		result.FiveTuples != hardnatbudget.Hard16ActualFiveTupleMaximum ||
		result.EnvelopeSockets != 16 || result.EnvelopeTargets != 16_400 ||
		result.EnvelopeFiveTuples != 16_400 || result.EnvelopePackets != 16_432 ||
		result.EnvelopePPS != 512 || result.EnvelopeDurationMS != 47_000 ||
		result.CarrierFramesRead > 8 || result.CarrierFramesWrite > 8 ||
		result.CarrierBytesRead > 8_256 || result.CarrierBytesWrite > 8_256 || !result.CarrierDrained ||
		result.CampaignAdmissions != 1 || result.CampaignPackets != 16_432 ||
		result.LedgerAdmissions != 0 || result.UnfinishedAdmission != 0 || result.UnfinishedPackets != 0 ||
		result.ActivePeers != 0 || result.ActiveAttempts != 0 || result.HeavyweightAttempts != 0 ||
		result.ReservedSockets != 0 || result.ReservedTargets != 0 || result.ReservedFiveTuples != 0 ||
		result.ReservedPackets != 0 || result.SafetyBlocksWork || gateB2ResultContainsPrivateMaterial(result.gateB2EndpointResult) {
		t.Fatalf("Gate B3 frozen endpoint shape rejected: %+v", result)
	}
	if result.Terminal == "success" {
		if result.CampaignState != string(governor.PairingLedgerRateLimited) || result.CampaignCircuit ||
			result.CarrierFramesRead != 8 || result.CarrierFramesWrite != 8 ||
			result.DataPacketsRead != 3 || result.DataPacketsWritten != 3 || !result.TransportAttached ||
			!result.TransportAdopted || !result.TransportStandby || !result.ChallengePassed ||
			!result.TransportDetached || !result.TransportDrained {
			t.Fatalf("Gate B3 successful handoff witness rejected: %+v", result)
		}
	} else if result.CampaignState != string(governor.PairingLedgerCircuitOpen) || !result.CampaignCircuit ||
		result.DataPacketsRead != 0 || result.DataPacketsWritten != 0 {
		t.Fatalf("Gate B3 failed campaign witness rejected: %+v", result)
	}
}

func assertGateB3NoResidue(t testing.TB, topology *n2dTopology, observer *gateB2ObserverSet,
	leftRouter, rightRouter *gateB2NATRouter, failed, allowNATOutboundFailure bool, governorDirs ...string,
) {
	t.Helper()
	before := requireGateB2PacketCounts(t, topology)
	time.Sleep(100 * time.Millisecond)
	after := requireGateB2PacketCounts(t, topology)
	if after != before {
		t.Fatalf("Gate B3 packet counters changed after terminal: before=%+v after=%+v", before, after)
	}
	if err := observer.Close(); err != nil {
		t.Fatal("Gate B3 observer drain failed")
	}
	leftErr, rightErr := leftRouter.Close(), rightRouter.Close()
	if allowNATOutboundFailure {
		if leftErr != nil && !errors.Is(leftErr, errGateB2NATOutbound) ||
			rightErr != nil && !errors.Is(rightErr, errGateB2NATOutbound) {
			t.Fatalf("Gate B3 conntrack-fault NAT drain escaped the expected class: left=%s right=%s",
				gateB2NATDrainClass(leftErr), gateB2NATDrainClass(rightErr))
		}
	} else if leftErr != nil || rightErr != nil {
		t.Fatalf("Gate B3 NAT drain failed: left=%s right=%s", gateB2NATDrainClass(leftErr), gateB2NATDrainClass(rightErr))
	}
	sockets, processes, err := waitGateB2NoOSResidue(topology, gateB2TerminalMargin)
	if err != nil || sockets != 0 || processes != 0 {
		t.Fatalf("Gate B3 OS residue after drain: sockets=%d processes=%d", sockets, processes)
	}
	for _, namespace := range governorDirs {
		ordinary, campaign := inspectGateB3Ledger(t, namespace)
		if ordinary.Sequence != 3 || ordinary.Records != 3 || ordinary.TwentyFourHourAdmissions != 0 ||
			campaign.TwentyFourHourAdmissions != 1 || campaign.TwentyFourHourPackets != 16_432 ||
			campaign.ExplicitResetRequired != failed {
			t.Fatalf("Gate B3 durable ledger witness rejected: ordinary=%+v campaign=%+v", ordinary, campaign)
		}
	}
	_, conntrackAfter, err := topology.flushConntrack()
	if err != nil || conntrackAfter != 0 {
		t.Fatal("Gate B3 conntrack cleanup witness failed")
	}
	if err := topology.cleanup(); err != nil {
		t.Fatal("Gate B3 topology cleanup failed")
	}
	if err := topology.assertNoLeaks(); err != nil {
		t.Fatal("Gate B3 namespace or veth leak witness failed")
	}
}

func assertGateB3TripNoResidue(t testing.TB, topology *n2dTopology, observer *gateB2ObserverSet,
	leftRouter, rightRouter *gateB2NATRouter, expectedTrips map[string]bool,
) {
	t.Helper()
	before := requireGateB2PacketCounts(t, topology)
	time.Sleep(100 * time.Millisecond)
	if after := requireGateB2PacketCounts(t, topology); after != before {
		t.Fatalf("Gate B3 fault path emitted after terminal: before=%+v after=%+v", before, after)
	}
	if err := observer.Close(); err != nil {
		t.Fatal("Gate B3 fault observer drain failed")
	}
	if leftErr, rightErr := leftRouter.Close(), rightRouter.Close(); leftErr != nil || rightErr != nil {
		t.Fatalf("Gate B3 fault NAT drain failed: left=%s right=%s", gateB2NATDrainClass(leftErr), gateB2NATDrainClass(rightErr))
	}
	if sockets, processes, err := waitGateB2NoOSResidue(topology, gateB2TerminalMargin); err != nil || sockets != 0 || processes != 0 {
		t.Fatalf("Gate B3 fault OS residue: sockets=%d processes=%d", sockets, processes)
	}
	for namespace, wantTrip := range expectedTrips {
		owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "gate-b3-trip-reinspect")
		if err != nil {
			t.Fatal("Gate B3 fault governor lock remained held")
		}
		status := owner.SafetyTripStatus()
		if err := owner.Close(); err != nil {
			t.Fatal("Gate B3 fault governor owner close failed")
		}
		if status.BlocksActiveWork != wantTrip || (wantTrip && status.Record.Reason != governor.SafetyTripResourceExhausted) {
			t.Fatalf("Gate B3 fault persistent trip mismatch: want=%t status=%+v", wantTrip, status)
		}
	}
	_, conntrackAfter, err := topology.flushConntrack()
	if err != nil || conntrackAfter != 0 {
		t.Fatal("Gate B3 fault conntrack cleanup witness failed")
	}
	if err := topology.cleanup(); err != nil {
		t.Fatal("Gate B3 fault topology cleanup failed")
	}
	if err := topology.assertNoLeaks(); err != nil {
		t.Fatal("Gate B3 fault namespace or veth residue")
	}
}

func armGateB3KernelReleaseMargin(t *testing.T) {
	t.Helper()
	// Registered before topology/process cleanups, therefore executed last in
	// the subtest's LIFO cleanup stack. Waiting inside the residue assertion is
	// too early because later cleanup callbacks can release final kernel refs.
	t.Cleanup(func() { time.Sleep(gateB3KernelReleaseMargin) })
}

func inspectGateB3Ledger(t testing.TB, namespace string) (governor.PairingLedgerStatus, governor.HardNATCampaignStatus) {
	t.Helper()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "gate-b3-reinspect")
	if err != nil {
		t.Fatal("Gate B3 governor lock remained held")
	}
	machine, err := governor.New(owner, governor.ProfilePhase1HardNATCampaign, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatal("Gate B3 governor reopen failed")
	}
	ledger, err := governor.GateATestPairingLedger(machine)
	if err != nil {
		_ = machine.Close()
		t.Fatal("Gate B3 ledger reopen failed")
	}
	ordinary, campaign := ledger.Status(), ledger.CampaignStatus()
	if err := machine.Close(); err != nil {
		t.Fatal("Gate B3 governor reinspection drain failed")
	}
	return ordinary, campaign
}

func gateB3LedgerHasOnlyInitialization(ordinary governor.PairingLedgerStatus, campaign governor.HardNATCampaignStatus) bool {
	return ordinary.State == governor.PairingLedgerReady && !ordinary.BlocksActiveWork &&
		ordinary.Sequence == 1 && ordinary.Records == 1 && ordinary.OneHourAdmissions == 0 &&
		ordinary.TwentyFourHourAdmissions == 0 && ordinary.TwentyFourHourPackets == 0 &&
		ordinary.ConsecutiveFailures == 0 && !ordinary.ExplicitResetRequired &&
		campaign.State == governor.PairingLedgerReady && !campaign.BlocksCampaign &&
		campaign.Sequence == 1 && campaign.Records == 1 && campaign.TwentyFourHourAdmissions == 0 &&
		campaign.TwentyFourHourPackets == 0 && !campaign.ExplicitResetRequired
}

func requireGateB3HostConntrackGuard(t *testing.T) {
	t.Helper()
	if os.Getenv(gateB3DisposableRunnerEnv) != "github-hosted" ||
		os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		os.Getenv(gateB3HostConntrackCapEnv) != strconv.Itoa(gateB3ConntrackCap) {
		t.Fatal("Gate B3 host conntrack guard authorization is absent")
	}
	if current, err := readGateB3ConntrackMax(""); err != nil || current != gateB3ConntrackCap {
		t.Fatal("Gate B3 host conntrack guard is not active")
	}
	t.Cleanup(func() {
		if current, err := readGateB3ConntrackMax(""); err != nil || current != gateB3ConntrackCap {
			t.Error("Gate B3 host conntrack cap was not restored after the matrix")
		}
	})
}

func setGateB3HostConntrackCapForSubtest(t *testing.T, value int) {
	t.Helper()
	if value <= 0 || value > gateB3ConntrackCap {
		t.Fatal("Gate B3 conntrack cap is outside the reviewed range")
	}
	current, err := readGateB3ConntrackMax("")
	if err != nil || current != gateB3ConntrackCap {
		t.Fatal("Gate B3 host conntrack guard drifted before subtest")
	}
	if value == gateB3ConntrackCap {
		return
	}
	hostCount, err := readGateB3ConntrackCount("")
	if err != nil || hostCount*2 >= value {
		t.Fatal("Gate B3 conntrack fault cap lacks safe init-namespace headroom")
	}
	if err := writeGateB3HostConntrackMax(value); err != nil {
		t.Fatal("Gate B3 conntrack fault cap could not be installed")
	}
	if !waitGateB3ConntrackMax(value) {
		_ = writeGateB3HostConntrackMax(gateB3ConntrackCap)
		t.Fatal("Gate B3 conntrack fault cap verification failed")
	}
	t.Cleanup(func() {
		if err := writeGateB3HostConntrackMax(gateB3ConntrackCap); err != nil {
			t.Error("Gate B3 conntrack fault cap restoration failed")
			return
		}
		if !waitGateB3ConntrackMax(gateB3ConntrackCap) {
			t.Error("Gate B3 conntrack fault cap restoration could not be verified")
		}
	})
}

func waitGateB3ConntrackMax(value int) bool {
	deadline := time.Now().Add(250 * time.Millisecond)
	consecutive := 0
	for {
		current, err := readGateB3ConntrackMax("")
		if err == nil && current == value {
			consecutive++
			if consecutive == 2 {
				return true
			}
		} else {
			consecutive = 0
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func verifyGateB3NamespacedConntrackCap(leftNamespace, rightNamespace string, value int) error {
	host, hostErr := readGateB3ConntrackMax("")
	left, leftErr := readGateB3ConntrackMax(leftNamespace)
	right, rightErr := readGateB3ConntrackMax(rightNamespace)
	if hostErr != nil || leftErr != nil || rightErr != nil || host != value || left != value || right != value {
		return fmt.Errorf("Gate B3 uniform namespace conntrack cap verification failed")
	}
	return nil
}

func readGateB3ConntrackMax(namespace string) (int, error) {
	var output string
	var err error
	if namespace == "" {
		output, err = runCommand("sysctl", "-n", "net.netfilter.nf_conntrack_max")
	} else {
		output, err = runNamespaced(namespace, "sysctl", nil, "-n", "net.netfilter.nf_conntrack_max")
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(output))
}

func writeGateB3HostConntrackMax(value int) error {
	argument := "net.netfilter.nf_conntrack_max=" + strconv.Itoa(value)
	_, err := runCommand("sysctl", "-qw", argument)
	return err
}

func readGateB3ConntrackCount(namespace string) (int, error) {
	var read string
	var err error
	if namespace == "" {
		read, err = runCommand("sysctl", "-n", "net.netfilter.nf_conntrack_count")
	} else {
		read, err = runNamespaced(namespace, "sysctl", nil, "-n", "net.netfilter.nf_conntrack_count")
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(read))
}

func testGateB3RouterMappingCapPreIO(t *testing.T) {
	router := &gateB2NATRouter{
		config:   gateB2NATConfig{mappingHardCap: 1},
		mappings: make(map[gateB2NATKey]*gateB2NATMapping),
		all:      []*gateB2NATMapping{{}},
	}
	_, err := router.newMapping(
		gateB2NATKey{internalPort: 1},
		netip.MustParseAddrPort("192.0.2.10:1"),
		netip.MustParseAddrPort("198.51.100.10:1"),
		nil,
	)
	if !errors.Is(err, errGateB3NATMappingCap) || len(router.all) != 1 || router.pending != 0 ||
		!router.mappingCapHit.Load() {
		t.Fatal("Gate B3 per-router mapping cap did not fail before socket open")
	}
}

func testGateB3PreFIRETeardown100(t *testing.T) {
	armGateB3KernelReleaseMargin(t)
	started := time.Now()
	for iteration := 0; iteration < 100; iteration++ {
		topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
		artifacts := buildGateB3Artifacts(t, fmt.Sprintf("prefire-%03d", iteration))
		leftFile, peerFile := gateASocketPair(t)
		process := newGateB3EndpointProcess(t, topology.clientA, directattempt.RoleInitiator,
			gateB3StaticObserverTopology(), artifacts.initiator, leftFile)
		process.start(t)
		waitGateB3Ready(t, process, 5*time.Second)
		if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("Gate B3 pre-FIRE cancel %d failed", iteration)
		}
		result := waitGateB3Result(t, process)
		_ = peerFile.Close()
		clearGateB2Artifacts(&artifacts)
		if result.CredentialBurned || result.FinishRecorded || result.CandidatePackets != 0 || result.UDPPackets != 0 ||
			result.CampaignAdmissions != 0 || result.CampaignCircuit || result.SafetyBlocksWork {
			t.Fatalf("Gate B3 pre-FIRE cancellation %d escaped zero-emission boundary: %+v", iteration, result)
		}
		ordinary, campaign := inspectGateB3Ledger(t, process.governorDir)
		if !gateB3LedgerHasOnlyInitialization(ordinary, campaign) {
			t.Fatalf("Gate B3 pre-FIRE cancellation %d changed ledger: ordinary=%+v campaign=%+v", iteration, ordinary, campaign)
		}
		if sockets, processes, err := waitGateB2NoOSResidue(topology, gateB2TerminalMargin); err != nil || sockets != 0 || processes != 0 {
			t.Fatalf("Gate B3 pre-FIRE cancellation %d left OS residue: sockets=%d processes=%d", iteration, sockets, processes)
		}
		if err := topology.cleanup(); err != nil {
			t.Fatalf("Gate B3 pre-FIRE teardown %d failed", iteration)
		}
		if err := topology.assertNoLeaks(); err != nil {
			t.Fatalf("Gate B3 pre-FIRE residue at iteration %d", iteration)
		}
		if iteration+1 < 100 {
			// Namespace and veth names are already unique and their named handles
			// are proven absent above. The kernel can still be completing the
			// previous netdevice/RCU teardown; keep that invisible lifetime out of
			// the next fresh topology instead of retrying a failed link creation.
			time.Sleep(gateB3KernelReleaseMargin)
		}
	}
	t.Logf("Gate B3 pre-FIRE lifecycle witness: fresh_namespaces=100 residue=0 wall_ms=%d", time.Since(started).Milliseconds())
}

func gateB3StaticObserverTopology() hardnatobserve.Topology {
	return hardnatobserve.Topology{
		Primary: netip.MustParseAddrPort("198.51.100.2:3478"),
		Other:   netip.MustParseAddrPort("203.0.113.1:3479"),
	}
}

func waitGateB3Ready(t testing.TB, process *gateB2EndpointProcess, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if payload, err := os.ReadFile(process.readyPath); err == nil && string(payload) == "ready\n" {
			return
		}
		select {
		case <-process.done:
			t.Fatal("Gate B3 endpoint exited before readiness witness")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Gate B3 endpoint readiness deadline exceeded")
}

func requireGateB3Environment(t *testing.T) {
	t.Helper()
	required := os.Getenv(gateB3RequiredEnv) == "1"
	if !required {
		t.Skip("Gate B3 disposable-runner execution was not explicitly required")
	}
	failOrSkip := func(message string) {
		if required {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	if os.Geteuid() != 0 {
		failOrSkip("Gate B3 requires an isolated root network namespace")
	}
	for _, program := range []string{"ip", "iptables", "iptables-restore", "ss", "conntrack", "sysctl", "tc"} {
		if _, err := exec.LookPath(program); err != nil {
			failOrSkip("Gate B3 isolated-network prerequisite is unavailable")
		}
	}
	if info, err := os.Stat("/dev/net/tun"); err != nil || info.IsDir() {
		failOrSkip("Gate B3 isolated TUN capability is unavailable")
	}
	if err := probeN1NamespaceAuthority(); err != nil {
		failOrSkip("Gate B3 network namespace authority is unavailable")
	}
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
