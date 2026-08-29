//go:build linux && natlab

package natlab

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/hardnatattempt"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
)

const gateB2TerminalMargin = 2 * time.Second

type gateB2ArtifactPair struct {
	initiator []byte
	responder []byte
}

type gateB2EndpointProcess struct {
	command      *exec.Cmd
	done         chan struct{}
	waitMu       sync.Mutex
	waitErr      error
	streamFile   *os.File
	resultPath   string
	readyPath    string
	configPath   string
	governorDir  string
	artifactPath string
	started      bool
	stopOnce     sync.Once
}

type gateB2PacketCounts struct {
	InitiatorEvidence uint64
	InitiatorDirect   uint64
	InitiatorTotal    uint64
	ResponderEvidence uint64
	ResponderDirect   uint64
	ResponderTotal    uint64
}

func TestLinuxGateB2HardNATProof(t *testing.T) {
	requireGateB2Environment(t)
	t.Run("predictive_apdm_apdm", testGateB2PredictiveAPDM)
	t.Run("asymmetric_mapping_role_initiates", func(t *testing.T) {
		testGateB2Asymmetric(t, hardnatplan.RoleMappingSet, hardnatplan.RoleTargetSet)
	})
	t.Run("asymmetric_target_role_initiates", func(t *testing.T) {
		testGateB2Asymmetric(t, hardnatplan.RoleTargetSet, hardnatplan.RoleMappingSet)
	})
}

func testGateB2PredictiveAPDM(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	observer := startGateB2ObserverSet(t, topology.public)
	leftRouter := startGateB2NATRouter(t, gateB2NATConfig{
		namespace: topology.natA, tunName: gateB2TUNName(topology.natA), mode: gateB2NATAPDM,
		private: netip.MustParseAddr(n2dClientAAddress), public: netip.MustParseAddr(n2dNATAWAN),
		peerPublic: netip.MustParseAddr(n2dNATBWAN),
	})
	rightRouter := startGateB2NATRouter(t, gateB2NATConfig{
		namespace: topology.natB, tunName: gateB2TUNName(topology.natB), mode: gateB2NATAPDM,
		private: netip.MustParseAddr(n2dClientBAddress), public: netip.MustParseAddr(n2dNATBWAN),
		peerPublic: netip.MustParseAddr(n2dNATAWAN),
	})
	if err := topology.installGateB2PacketCounters(observer.topology); err != nil {
		t.Fatal("Gate B2 predictive packet counter setup failed")
	}
	artifacts := buildGateB2Artifacts(t, "predictive", hardnatplan.ProfilePredictiveEdm,
		hardnatplan.ResourcePredictive, hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer clearGateB2Artifacts(&artifacts)
	initiator, responder := startGateB2Pair(t, topology, observer.topology, artifacts)
	initiatorResult, responderResult := initiator.waitResult(t), responder.waitResult(t)

	assertGateB2Success(t, initiatorResult, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, 8, 64, 64)
	assertGateB2Success(t, responderResult, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, 8, 64, 64)
	if initiatorResult.TargetsRegistered != 36 || responderResult.TargetsRegistered != 36 ||
		initiatorResult.FiveTuples != 43 || responderResult.FiveTuples != 43 ||
		initiatorResult.CandidatePackets < 1 || initiatorResult.CandidatePackets > 32 ||
		responderResult.CandidatePackets < 1 || responderResult.CandidatePackets > 32 ||
		initiatorResult.WinnerPackets+responderResult.WinnerPackets != 1 {
		t.Fatalf("Gate B2 predictive frozen emission prefix rejected: initiator=%+v responder=%+v", initiatorResult, responderResult)
	}
	counts := requireGateB2PacketCounts(t, topology)
	assertGateB2PacketCounts(t, counts, initiatorResult, responderResult)
	leftWitness, rightWitness := leftRouter.Witness(), rightRouter.Witness()
	if leftWitness.PeakMappings > 42 || rightWitness.PeakMappings > 42 || leftWitness.Outbound == 0 || rightWitness.Outbound == 0 {
		t.Fatalf("Gate B2 predictive NAT witness exceeded frozen prefix: left=%+v right=%+v", leftWitness, rightWitness)
	}
	assertGateB2NoResidue(t, topology, observer, leftRouter, rightRouter, initiator.governorDir, responder.governorDir)
	t.Logf("Gate B2 predictive witness: evidence=13/13 candidate=%d/%d winner_total=1 sockets=8/8 nat_peak=%d/%d",
		initiatorResult.CandidatePackets, responderResult.CandidatePackets, leftWitness.PeakMappings, rightWitness.PeakMappings)
}

func testGateB2Asymmetric(t *testing.T, initiatorPlannerRole, responderPlannerRole hardnatplan.Role) {
	leftNATMode, rightNATMode := gateB2NATAPDM, gateB2NATEIM
	if initiatorPlannerRole == hardnatplan.RoleTargetSet {
		leftNATMode, rightNATMode = gateB2NATEIM, gateB2NATAPDM
	}
	// The inherited topology's netfilter NAT is deliberately kept in EDM mode
	// on both sides. Gate B2's TUN routers own the EIM/APDM semantics for this
	// proof; enabling the inherited EIM DNAT would steal packets from their
	// mapped UDP sockets before the harness can enforce its filtering model.
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	observer := startGateB2ObserverSet(t, topology.public)
	favorable := newGateB2FavorablePorts()
	leftConfig := gateB2NATConfig{
		namespace: topology.natA, tunName: gateB2TUNName(topology.natA), mode: leftNATMode,
		private: netip.MustParseAddr(n2dClientAAddress), public: netip.MustParseAddr(n2dNATAWAN),
		peerPublic: netip.MustParseAddr(n2dNATBWAN),
	}
	rightConfig := gateB2NATConfig{
		namespace: topology.natB, tunName: gateB2TUNName(topology.natB), mode: rightNATMode,
		private: netip.MustParseAddr(n2dClientBAddress), public: netip.MustParseAddr(n2dNATBWAN),
		peerPublic: netip.MustParseAddr(n2dNATAWAN),
	}
	if leftNATMode == gateB2NATEIM {
		leftConfig.recordTargets = favorable
		rightConfig.useFavorable = favorable
	} else {
		rightConfig.recordTargets = favorable
		leftConfig.useFavorable = favorable
	}
	leftRouter := startGateB2NATRouter(t, leftConfig)
	rightRouter := startGateB2NATRouter(t, rightConfig)
	if err := topology.installGateB2PacketCounters(observer.topology); err != nil {
		t.Fatal("Gate B2 asymmetric packet counter setup failed")
	}
	label := "asymmetric-" + string(initiatorPlannerRole)
	artifacts := buildGateB2Artifacts(t, label, hardnatplan.ProfileAsymmetricBirthday,
		hardnatplan.ResourceAsymmetric, initiatorPlannerRole, responderPlannerRole)
	defer clearGateB2Artifacts(&artifacts)
	initiator, responder := startGateB2Pair(t, topology, observer.topology, artifacts)
	initiatorResult, responderResult := initiator.waitResult(t), responder.waitResult(t)
	preassertCounts := requireGateB2PacketCounts(t, topology)
	t.Logf("Gate B2 asymmetric preassert: initiator={%s} responder={%s} os=%+v nat=%+v/%+v favorable=%d",
		gateB2WitnessSummary(initiatorResult), gateB2WitnessSummary(responderResult), preassertCounts,
		leftRouter.Witness(), rightRouter.Witness(), favorable.count())

	assertGateB2Success(t, initiatorResult, hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, 128, 516, 523)
	assertGateB2Success(t, responderResult, hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, 128, 516, 523)
	resultsByPlannerRole := map[hardnatplan.Role]gateB2EndpointResult{
		initiatorPlannerRole: initiatorResult,
		responderPlannerRole: responderResult,
	}
	mappingResult, targetResult := resultsByPlannerRole[hardnatplan.RoleMappingSet], resultsByPlannerRole[hardnatplan.RoleTargetSet]
	if mappingResult.TargetsRegistered != 5 || mappingResult.FiveTuples != 139 ||
		targetResult.TargetsRegistered != 516 || targetResult.FiveTuples != 523 ||
		mappingResult.CandidatePackets < 1 || mappingResult.CandidatePackets > 128 || targetResult.CandidatePackets != 512 ||
		mappingResult.WinnerPackets != 0 || targetResult.WinnerPackets != 1 || favorable.count() != 512 {
		t.Fatalf("Gate B2 asymmetric frozen schedule rejected: mapping=%+v target=%+v favorable_count=%d",
			mappingResult, targetResult, favorable.count())
	}
	counts := requireGateB2PacketCounts(t, topology)
	assertGateB2PacketCounts(t, counts, initiatorResult, responderResult)
	leftWitness, rightWitness := leftRouter.Witness(), rightRouter.Witness()
	if leftWitness.PeakMappings > 141 || rightWitness.PeakMappings > 141 || leftWitness.Outbound == 0 || rightWitness.Outbound == 0 {
		t.Fatalf("Gate B2 asymmetric NAT witness exceeded frozen prefix: left=%+v right=%+v", leftWitness, rightWitness)
	}
	assertGateB2NoResidue(t, topology, observer, leftRouter, rightRouter, initiator.governorDir, responder.governorDir)
	t.Logf("Gate B2 asymmetric witness: carrier_roles=%s/%s target=512 mapping=%d winner=1 favorable_sample=128x512 nat_peak=%d/%d",
		directattempt.RoleInitiator, directattempt.RoleResponder, mappingResult.CandidatePackets, leftWitness.PeakMappings, rightWitness.PeakMappings)
}

func buildGateB2Artifacts(t testing.TB, label string, profile hardnatplan.Profile, resource hardnatplan.ResourceClass,
	initiatorPlannerRole, responderPlannerRole hardnatplan.Role,
) gateB2ArtifactPair {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	psk := sha256.Sum256([]byte("gate-b2-netns-psk/" + label))
	set, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID:           n2dOpaqueID("gate-b2/" + label + "/credential"),
		AttemptID:              n2dOpaqueID("gate-b2/" + label + "/attempt"),
		InitiatorParticipantID: n2dOpaqueID("gate-b2/" + label + "/initiator"),
		ResponderParticipantID: n2dOpaqueID("gate-b2/" + label + "/responder"),
		OOBChannelID:           n2dOpaqueID("gate-b2/" + label + "/channel"),
		PlannerProfile:         profile, ResourceClass: resource,
		InitiatorPlannerRole: initiatorPlannerRole, ResponderPlannerRole: responderPlannerRole,
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(10*time.Minute - time.Second),
	}, psk)
	clear(psk[:])
	if err != nil {
		t.Fatal("Gate B2 synthetic artifact construction failed")
	}
	clear(set.Manifest)
	return gateB2ArtifactPair{initiator: set.Initiator, responder: set.Responder}
}

func clearGateB2Artifacts(pair *gateB2ArtifactPair) {
	if pair == nil {
		return
	}
	clear(pair.initiator)
	clear(pair.responder)
	pair.initiator = nil
	pair.responder = nil
}

func startGateB2Pair(t testing.TB, topology *n2dTopology, observer hardnatobserve.Topology,
	artifacts gateB2ArtifactPair,
) (*gateB2EndpointProcess, *gateB2EndpointProcess) {
	t.Helper()
	leftFile, rightFile := gateASocketPair(t)
	initiator := newGateB2EndpointProcess(t, topology.clientA, directattempt.RoleInitiator, observer, artifacts.initiator, leftFile)
	responder := newGateB2EndpointProcess(t, topology.clientB, directattempt.RoleResponder, observer, artifacts.responder, rightFile)
	initiator.start(t)
	responder.start(t)
	return initiator, responder
}

func newGateB2EndpointProcess(t testing.TB, namespace string, role directattempt.Role, observer hardnatobserve.Topology,
	artifact []byte, streamFile *os.File,
) *gateB2EndpointProcess {
	t.Helper()
	directory := t.TempDir()
	governorDir := filepath.Join(directory, "governor")
	if err := os.Mkdir(governorDir, 0o700); err != nil {
		t.Fatal("Gate B2 governor namespace setup failed")
	}
	if err := governor.PrepareGateATestNamespace(governorDir, time.Now().UTC()); err != nil {
		t.Fatal("Gate B2 durable namespace preparation failed")
	}
	artifactPath := filepath.Join(directory, "artifact.json")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal("Gate B2 artifact staging failed")
	}
	resultPath := filepath.Join(directory, "result.json")
	configPath := filepath.Join(directory, "config.json")
	config := gateB2EndpointConfig{
		Role: string(role), Namespace: namespace, GovernorDir: governorDir, ArtifactPath: artifactPath, ResultPath: resultPath,
		ObserverPrimary: observer.Primary.String(), ObserverOther: observer.Other.String(),
	}
	if err := writeN1JSON(configPath, config); err != nil {
		t.Fatal("Gate B2 endpoint configuration write failed")
	}
	command := exec.Command(
		"ip", "netns", "exec", namespace, os.Args[0],
		"-test.run=^TestGateB2EndpointProcess$", "-test.count=1", "-test.timeout=24s",
	)
	command.Env = append(os.Environ(), gateB2EndpointHelperEnv+"=1", gateB2HelperConfigEnv+"="+configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.ExtraFiles = []*os.File{streamFile}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	process := &gateB2EndpointProcess{
		command: command, done: make(chan struct{}), streamFile: streamFile,
		resultPath: resultPath, configPath: configPath, governorDir: governorDir, artifactPath: artifactPath,
	}
	t.Cleanup(process.stop)
	return process
}

func (process *gateB2EndpointProcess) start(t testing.TB) {
	t.Helper()
	if process == nil || process.command == nil || process.streamFile == nil || process.started {
		t.Fatal("Gate B2 endpoint start contract failed")
	}
	if err := process.command.Start(); err != nil {
		_ = process.streamFile.Close()
		t.Fatal("Gate B2 endpoint process start failed")
	}
	process.started = true
	_ = process.streamFile.Close()
	process.streamFile = nil
	go func() {
		err := process.command.Wait()
		process.waitMu.Lock()
		process.waitErr = err
		process.waitMu.Unlock()
		close(process.done)
	}()
}

func (process *gateB2EndpointProcess) waitResult(t testing.TB) gateB2EndpointResult {
	t.Helper()
	deadline := time.Now().Add(gateB2EndpointLimit)
	for time.Now().Before(deadline) {
		var result gateB2EndpointResult
		if readN1JSON(process.resultPath, &result) {
			select {
			case <-process.done:
			case <-time.After(gateB2TerminalMargin):
				t.Fatal("Gate B2 endpoint did not exit after result")
			}
			process.waitMu.Lock()
			waitErr := process.waitErr
			process.waitMu.Unlock()
			if waitErr != nil || !result.OK {
				t.Fatal("Gate B2 endpoint returned a harness failure")
			}
			return result
		}
		select {
		case <-process.done:
			t.Fatal("Gate B2 endpoint exited without a result")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	process.stop()
	t.Fatal("Gate B2 endpoint result deadline exceeded")
	return gateB2EndpointResult{}
}

func (process *gateB2EndpointProcess) stop() {
	if process == nil {
		return
	}
	process.stopOnce.Do(func() {
		if process.streamFile != nil {
			_ = process.streamFile.Close()
			process.streamFile = nil
		}
		if !process.started {
			return
		}
		select {
		case <-process.done:
			return
		default:
		}
		if process.command != nil && process.command.Process != nil {
			_ = process.command.Process.Kill()
		}
		select {
		case <-process.done:
		case <-time.After(gateB2TerminalMargin):
		}
	})
}

func assertGateB2Success(t testing.TB, result gateB2EndpointResult, profile hardnatplan.Profile,
	resource hardnatplan.ResourceClass, sockets, targets, tuples int,
) {
	t.Helper()
	if !result.OK || result.Terminal != "success" || result.Profile != string(profile) || result.ResourceClass != string(resource) ||
		result.ErrorClass != "" || !result.CredentialBurned || !result.FinishRecorded || !result.Bidirectional ||
		!result.Conditional || result.EvidencePackets != 13 || result.SocketsOpened != sockets ||
		result.TargetsRegistered < 1 || result.TargetsRegistered > targets || result.FiveTuples < 1 || result.FiveTuples > tuples ||
		result.EnvelopeSockets != sockets || result.EnvelopeTargets != targets || result.EnvelopeFiveTuples != tuples ||
		result.DataPacketsRead != 3 ||
		result.DataPacketsWritten != 3 || !result.CarrierDrained || !result.TransportAttached ||
		!result.TransportAdopted || !result.TransportStandby || !result.ChallengePassed ||
		!result.TransportDetached || !result.TransportDrained || result.SafetyBlocksWork ||
		result.LedgerSequence != 3 || result.LedgerRecords != 3 || result.LedgerAdmissions != 1 ||
		result.LedgerFailures != 0 || result.UnfinishedAdmission != 0 || result.UnfinishedPackets != 0 ||
		result.ActivePeers != 0 || result.ActiveAttempts != 0 || result.HeavyweightAttempts != 0 ||
		result.ReservedSockets != 0 || result.ReservedTargets != 0 || result.ReservedFiveTuples != 0 || result.ReservedPackets != 0 ||
		result.CarrierFramesRead > 8 || result.CarrierFramesWrite > 8 || result.CarrierBytesRead > 8256 ||
		result.CarrierBytesWrite > 8256 || result.ElapsedMilliseconds < 0 || result.ElapsedMilliseconds >= gateB2EndpointLimit.Milliseconds() ||
		gateB2ResultContainsPrivateMaterial(result) {
		t.Fatalf("Gate B2 endpoint success witness rejected: %+v", result)
	}
	if profile == hardnatplan.ProfilePredictiveEdm && result.ProbabilityFloor != hardnatplan.ProbabilityScale {
		t.Fatalf("Gate B2 predictive probability = %d", result.ProbabilityFloor)
	}
	if profile == hardnatplan.ProfilePredictiveEdm &&
		(result.EnvelopePackets != 64 || result.EnvelopePPS != 32 || result.EnvelopeDurationMS != 22000) {
		t.Fatalf("Gate B2 predictive envelope = %+v", result)
	}
	if profile == hardnatplan.ProfileAsymmetricBirthday && result.ProbabilityFloor != 633926065852 {
		t.Fatalf("Gate B2 asymmetric probability = %d", result.ProbabilityFloor)
	}
	if profile == hardnatplan.ProfileAsymmetricBirthday &&
		(result.EnvelopePackets != 526 || result.EnvelopePPS != 64 || result.EnvelopeDurationMS != 22000) {
		t.Fatalf("Gate B2 asymmetric envelope = %+v", result)
	}
	if result.UDPPackets != result.EvidencePackets+result.CandidatePackets+result.WinnerPackets {
		t.Fatalf("Gate B2 application packet accounting mismatch: %+v", result)
	}
}

func (topology *n2dTopology) installGateB2PacketCounters(observer hardnatobserve.Topology) error {
	endpoints, err := observer.Endpoints()
	if err != nil {
		return err
	}
	for _, side := range []struct {
		namespace  string
		peerPublic string
	}{
		{topology.clientA, n2dNATBWAN},
		{topology.clientB, n2dNATAWAN},
	} {
		commands := [][]string{
			{"-w", "5", "-N", "WYGATEB2_TOTAL"},
			{"-w", "5", "-A", "WYGATEB2_TOTAL", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-j", "WYGATEB2_TOTAL"},
			{"-w", "5", "-N", "WYGATEB2_EVIDENCE"},
			{"-w", "5", "-A", "WYGATEB2_EVIDENCE", "-j", "RETURN"},
			{"-w", "5", "-N", "WYGATEB2_DIRECT"},
			{"-w", "5", "-A", "WYGATEB2_DIRECT", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-d", side.peerPublic, "-j", "WYGATEB2_DIRECT"},
		}
		for _, endpoint := range endpoints {
			commands = append(commands, []string{
				"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp",
				"-d", endpoint.Addr().String(), "--dport", strconv.Itoa(int(endpoint.Port())), "-j", "WYGATEB2_EVIDENCE",
			})
		}
		for _, args := range commands {
			if _, err := runNamespaced(side.namespace, "iptables", nil, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (topology *n2dTopology) gateB2PacketCounts() (gateB2PacketCounts, error) {
	read := func(namespace, chain string) (uint64, error) { return n2dChainPackets(namespace, chain) }
	leftEvidence, err := read(topology.clientA, "WYGATEB2_EVIDENCE")
	if err != nil {
		return gateB2PacketCounts{}, err
	}
	leftDirect, err := read(topology.clientA, "WYGATEB2_DIRECT")
	if err != nil {
		return gateB2PacketCounts{}, err
	}
	leftTotal, err := read(topology.clientA, "WYGATEB2_TOTAL")
	if err != nil {
		return gateB2PacketCounts{}, err
	}
	rightEvidence, err := read(topology.clientB, "WYGATEB2_EVIDENCE")
	if err != nil {
		return gateB2PacketCounts{}, err
	}
	rightDirect, err := read(topology.clientB, "WYGATEB2_DIRECT")
	if err != nil {
		return gateB2PacketCounts{}, err
	}
	rightTotal, err := read(topology.clientB, "WYGATEB2_TOTAL")
	if err != nil {
		return gateB2PacketCounts{}, err
	}
	return gateB2PacketCounts{
		InitiatorEvidence: leftEvidence, InitiatorDirect: leftDirect, InitiatorTotal: leftTotal,
		ResponderEvidence: rightEvidence, ResponderDirect: rightDirect, ResponderTotal: rightTotal,
	}, nil
}

func requireGateB2PacketCounts(t testing.TB, topology *n2dTopology) gateB2PacketCounts {
	t.Helper()
	counts, err := topology.gateB2PacketCounts()
	if err != nil {
		t.Fatal("Gate B2 packet counter witness failed")
	}
	return counts
}

func assertGateB2PacketCounts(t testing.TB, counts gateB2PacketCounts, initiator, responder gateB2EndpointResult) {
	t.Helper()
	if counts.InitiatorEvidence != uint64(initiator.EvidencePackets) ||
		counts.ResponderEvidence != uint64(responder.EvidencePackets) ||
		counts.InitiatorDirect != uint64(initiator.CandidatePackets+initiator.WinnerPackets+initiator.DataPacketsWritten) ||
		counts.ResponderDirect != uint64(responder.CandidatePackets+responder.WinnerPackets+responder.DataPacketsWritten) ||
		counts.InitiatorTotal != uint64(initiator.UDPPackets+initiator.DataPacketsWritten) ||
		counts.ResponderTotal != uint64(responder.UDPPackets+responder.DataPacketsWritten) {
		t.Fatalf("Gate B2 OS/application packet mismatch: os=%+v app=%+v/%+v", counts, initiator, responder)
	}
}

func assertGateB2NoResidue(t testing.TB, topology *n2dTopology, observer *gateB2ObserverSet,
	leftRouter, rightRouter *gateB2NATRouter, governorDirs ...string,
) {
	t.Helper()
	before := requireGateB2PacketCounts(t, topology)
	time.Sleep(100 * time.Millisecond)
	after := requireGateB2PacketCounts(t, topology)
	if after != before {
		t.Fatalf("Gate B2 packet counters changed after terminal: before=%+v after=%+v", before, after)
	}
	if err := observer.Close(); err != nil {
		t.Fatal("Gate B2 observer drain failed")
	}
	leftDrain, rightDrain := leftRouter.Close(), rightRouter.Close()
	if leftDrain != nil || rightDrain != nil {
		t.Fatalf("Gate B2 isolated NAT drain failed: left=%s right=%s",
			gateB2NATDrainClass(leftDrain), gateB2NATDrainClass(rightDrain))
	}
	sockets, processes, err := waitGateB2NoOSResidue(topology, gateB2TerminalMargin)
	if err != nil || sockets != 0 || processes != 0 {
		t.Fatalf("Gate B2 OS residue after bounded drain: sockets=%d processes=%d", sockets, processes)
	}
	for _, namespace := range governorDirs {
		status := inspectGateALedger(t, namespace)
		if status.Sequence != 3 || status.Records != 3 || status.TwentyFourHourAdmissions != 1 || status.ConsecutiveFailures != 0 {
			t.Fatalf("Gate B2 durable ledger witness rejected: %+v", status)
		}
	}
	conntrackBefore, conntrackAfter, err := topology.flushConntrack()
	if err != nil || conntrackAfter != 0 {
		t.Fatal("Gate B2 conntrack cleanup witness failed")
	}
	t.Logf("Gate B2 terminal witness: sockets=0 processes=0 packet_counters_stable=true conntrack_before_cleanup=%d conntrack_after_cleanup=%d",
		conntrackBefore, conntrackAfter)
	if err := topology.cleanup(); err != nil {
		t.Fatal("Gate B2 topology cleanup failed")
	}
	if err := topology.assertNoLeaks(); err != nil {
		t.Fatal("Gate B2 namespace or veth leak witness failed")
	}
}

func waitGateB2NoOSResidue(topology *n2dTopology, limit time.Duration) (sockets, processes int, resultErr error) {
	deadline := time.Now().Add(limit)
	for {
		sockets, resultErr = topology.socketCount()
		if resultErr != nil {
			return sockets, processes, resultErr
		}
		processes, resultErr = topology.processCount()
		if resultErr != nil {
			return sockets, processes, resultErr
		}
		if sockets == 0 && processes == 0 {
			return 0, 0, nil
		}
		if !time.Now().Before(deadline) {
			return sockets, processes, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func requireGateB2Environment(t *testing.T) {
	t.Helper()
	required := os.Getenv(gateB2RequiredEnv) == "1"
	failOrSkip := func(message string) {
		if required {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	if os.Geteuid() != 0 {
		failOrSkip("Gate B2 requires an isolated root network namespace")
	}
	for _, program := range []string{"ip", "iptables", "iptables-restore", "ss", "conntrack", "sysctl", "tc"} {
		if _, err := exec.LookPath(program); err != nil {
			failOrSkip("Gate B2 isolated-network prerequisite is unavailable")
		}
	}
	if info, err := os.Stat("/dev/net/tun"); err != nil || info.IsDir() {
		failOrSkip("Gate B2 isolated TUN capability is unavailable")
	}
	if err := probeN1NamespaceAuthority(); err != nil {
		failOrSkip("Gate B2 network namespace authority is unavailable")
	}
}

func gateB2WitnessSummary(result gateB2EndpointResult) string {
	return fmt.Sprintf("role=%s profile=%s terminal=%s class=%s evidence=%d candidate=%d winner=%d data=%d/%d sockets=%d targets=%d tuples=%d safety=%s/%s",
		result.Role, result.Profile, result.Terminal, result.ErrorClass, result.EvidencePackets, result.CandidatePackets,
		result.WinnerPackets, result.DataPacketsRead, result.DataPacketsWritten, result.SocketsOpened,
		result.TargetsRegistered, result.FiveTuples, result.SafetyState, result.SafetyReason)
}
