//go:build linux && natlab

package natlab

import (
	"context"
	"crypto/sha256"
	"errors"
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

	"golang.org/x/sys/unix"

	"winkyou/internal/governor"
	"winkyou/internal/stunserver"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gatea"
	"winkyou/internal/v2/oobattempt"
)

const gateATerminalMargin = 2 * time.Second

type gateAArtifactPair struct {
	Initiator []byte
	Responder []byte
}

type gateAPacketCounts struct {
	InitiatorSTUN   uint64
	InitiatorDirect uint64
	InitiatorTotal  uint64
	ResponderSTUN   uint64
	ResponderDirect uint64
	ResponderTotal  uint64
}

type gateASTUNPair struct {
	servers   [2]*stunserver.Server
	cancels   [2]context.CancelFunc
	done      [2]chan error
	closeOnce sync.Once
	closeErr  error
}

func TestLinuxGateAOOBHandoffProof(t *testing.T) {
	requireGateAEnvironment(t)
	t.Run("eim_eim_success", testGateAEIMEIMSuccess)
	t.Run("edm_bounded_failure", testGateAEDMBoundedFailure)
	t.Run("peer_absence_before_burn", testGateAPeerAbsence)
	t.Run("post_burn_crash_restart", testGateAPostBurnCrashRestart)
	t.Run("handoff_consumer_crash", testGateAHandoffConsumerCrash)
}

func testGateAEIMEIMSuccess(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startGateASTUNPair(t, topology)
	artifacts := buildGateAArtifacts(t, "eim-eim")
	defer clearGateAArtifacts(&artifacts)
	leftFile, rightFile := gateASocketPair(t)
	initiator := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleInitiator, servers.targets(), leftFile, "", "", "")
	responder := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleResponder, servers.targets(), rightFile, "", "", "")

	initiator.start(t)
	responder.start(t)
	initiatorResult := initiator.waitResult(t)
	responderResult := responder.waitResult(t)
	assertGateASuccessResult(t, initiatorResult, directattempt.RoleInitiator)
	assertGateASuccessResult(t, responderResult, directattempt.RoleResponder)
	counts := requireGateAPacketCounts(t, topology)
	want := gateAPacketCounts{
		InitiatorSTUN: 2, InitiatorDirect: 5, InitiatorTotal: 7,
		ResponderSTUN: 2, ResponderDirect: 4, ResponderTotal: 6,
	}
	if counts != want {
		t.Fatalf("Gate A EIM packet witness = %+v, want %+v", counts, want)
	}
	assertGateAApplicationPacketCounts(t, counts, initiatorResult, responderResult)
	assertGateANoResidue(t, topology, servers, initiator.governorDir, responder.governorDir)
	t.Logf("Gate A EIM witness: stun=2/2 establishment=4/3 data=3/3 os_udp=7/6 direct_path=5/4")
}

func testGateAEDMBoundedFailure(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEIM)
	servers := startGateASTUNPair(t, topology)
	artifacts := buildGateAArtifacts(t, "edm-bounded")
	defer clearGateAArtifacts(&artifacts)
	leftFile, rightFile := gateASocketPair(t)
	initiator := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleInitiator, servers.targets(), leftFile, "", "", "")
	responder := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleResponder, servers.targets(), rightFile, "", "", "")

	initiator.start(t)
	responder.start(t)
	leftResult := initiator.waitResult(t)
	rightResult := responder.waitResult(t)
	mappingFailures, peerTerminals := 0, 0
	for _, result := range []gateAEndpointResult{leftResult, rightResult} {
		assertGateABoundedResult(t, result, true)
		if result.DirectPackets != 0 || !result.FinishRecorded {
			t.Fatal("Gate A hard mapping emitted direct traffic or omitted FINISH")
		}
		switch result.ErrorClass {
		case gatea.ClassMappingNotDirectlyUsable:
			if result.ErrorStage != gatea.StageSTUN || result.MappingBehavior != "port_dependent" {
				t.Fatal("Gate A hard mapping evidence was not port-dependent")
			}
			mappingFailures++
		case gatea.ClassOOBStreamClosed:
			peerTerminals++
		default:
			t.Fatalf("Gate A hard mapping class = %q", result.ErrorClass)
		}
	}
	if mappingFailures < 1 || mappingFailures+peerTerminals != 2 {
		t.Fatalf("Gate A hard mapping terminals = mapping:%d peer:%d", mappingFailures, peerTerminals)
	}
	counts := requireGateAPacketCounts(t, topology)
	if counts.InitiatorDirect != 0 || counts.ResponderDirect != 0 || counts.InitiatorTotal > 2 || counts.ResponderTotal > 2 {
		t.Fatalf("Gate A hard mapping packet witness = %+v", counts)
	}
	assertGateANoResidue(t, topology, servers, initiator.governorDir, responder.governorDir)
	t.Logf("Gate A hard-mapping witness: direct=0/0 stun=%d/%d bounded=true", counts.InitiatorSTUN, counts.ResponderSTUN)
}

func testGateAPeerAbsence(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startGateASTUNPair(t, topology)
	artifacts := buildGateAArtifacts(t, "peer-absence")
	defer clearGateAArtifacts(&artifacts)
	localFile, absentFile := gateASocketPair(t)
	defer absentFile.Close()
	initiator := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleInitiator, servers.targets(), localFile, "", "", "")

	initiator.start(t)
	result := initiator.waitResult(t)
	assertGateABoundedResult(t, result, false)
	if result.ErrorClass != gatea.ClassOOBPresenceTimeout || result.CredentialBurned || result.LedgerSequence != 1 ||
		result.LedgerRecords != 1 || result.STUNPackets != 0 || result.DirectPackets != 0 {
		t.Fatalf("Gate A absence witness = %+v", result)
	}
	counts := requireGateAPacketCounts(t, topology)
	if counts != (gateAPacketCounts{}) {
		t.Fatalf("Gate A absence emitted packets: %+v", counts)
	}
	assertGateANoResidue(t, topology, servers, initiator.governorDir)
	t.Log("Gate A absence witness: presence_timeout=3s burned=false udp=0")
}

func testGateAPostBurnCrashRestart(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startGateASTUNPair(t, topology)
	artifacts := buildGateAArtifacts(t, "post-burn-crash")
	defer clearGateAArtifacts(&artifacts)
	leftFile, rightFile := gateASocketPair(t)
	initiator := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleInitiator, servers.targets(), leftFile, gatea.StageBurned, "", "")
	responder := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleResponder, servers.targets(), rightFile, "", "", "")

	initiator.start(t)
	responder.start(t)
	initiator.waitStage(t, gatea.StageBurned, 8*time.Second)
	initiator.kill(t)
	responderResult := responder.waitResult(t)
	assertGateABoundedResult(t, responderResult, true)
	if responderResult.ErrorClass != gatea.ClassOOBStreamClosed || !responderResult.FinishRecorded {
		t.Fatalf("Gate A crash survivor witness = %+v", responderResult)
	}
	crashedStatus := inspectGateALedger(t, initiator.governorDir)
	if crashedStatus.Sequence != 2 || crashedStatus.Records != 2 || crashedStatus.TwentyFourHourAdmissions != 1 ||
		inspectGateAUnfinished(t, initiator.governorDir) != 1 {
		t.Fatalf("Gate A crash journal witness = %+v", crashedStatus)
	}
	beforeRestart := requireGateAPacketCounts(t, topology)

	restartFile, unusedFile := gateASocketPair(t)
	defer unusedFile.Close()
	restart := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleInitiator, servers.targets(), restartFile, "", initiator.governorDir, initiator.artifactPath)
	restart.start(t)
	restartResult := restart.waitResult(t)
	assertGateACommonResult(t, restartResult)
	if restartResult.ErrorClass != gatea.ClassCredentialUsed || restartResult.ErrorStage != gatea.StagePreflight ||
		restartResult.CredentialBurned || restartResult.LedgerSequence != 2 || restartResult.LedgerAdmissions != 1 ||
		restartResult.UnfinishedAdmission != 1 {
		t.Fatalf("Gate A restart rejection witness = %+v", restartResult)
	}
	afterRestart := requireGateAPacketCounts(t, topology)
	if afterRestart != beforeRestart {
		t.Fatalf("Gate A rejected restart emitted packets: before=%+v after=%+v", beforeRestart, afterRestart)
	}
	assertGateANoResidue(t, topology, servers, initiator.governorDir, responder.governorDir)
	t.Log("Gate A crash/restart witness: journal=ADMIT+BURN unfinished=1 replay=credential_used udp_delta=0")
}

func testGateAHandoffConsumerCrash(t *testing.T) {
	topology := newN2DTopology(t, n2dMappingEIM, n2dMappingEIM)
	servers := startGateASTUNPair(t, topology)
	artifacts := buildGateAArtifacts(t, "handoff-crash")
	defer clearGateAArtifacts(&artifacts)
	leftFile, rightFile := gateASocketPair(t)
	initiator := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleInitiator, servers.targets(), leftFile, gatea.StageHandoff, "", "")
	responder := newGateAEndpointProcess(t, topology, artifacts, directattempt.RoleResponder, servers.targets(), rightFile, "", "", "")

	initiator.start(t)
	responder.start(t)
	initiator.waitStage(t, gatea.StageHandoff, 10*time.Second)
	initiator.kill(t)
	responderResult := responder.waitResult(t)
	assertGateABoundedResult(t, responderResult, true)
	if responderResult.ErrorClass != gatea.ClassDataPlaneChallengeFailed || !responderResult.FinishRecorded ||
		responderResult.SafetyBlocksWork {
		t.Fatalf("Gate A handoff crash survivor witness = %+v", responderResult)
	}
	crashedStatus := inspectGateALedger(t, initiator.governorDir)
	if crashedStatus.Sequence != 2 || inspectGateAUnfinished(t, initiator.governorDir) != 1 {
		t.Fatalf("Gate A handoff crash journal witness = %+v", crashedStatus)
	}
	assertGateANoResidue(t, topology, servers, initiator.governorDir, responder.governorDir)
	t.Log("Gate A handoff-crash witness: survivor_FINISH=true killed_attempt_unfinished=true sockets=0")
}

func buildGateAArtifacts(t testing.TB, label string) gateAArtifactPair {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	psk := sha256.Sum256([]byte("gate-a-natlab-psk/" + label))
	set, err := oobattempt.EncodeArtifactSet(oobattempt.ArtifactMaterial{
		CredentialID:           n2dOpaqueID("gate-a/" + label + "/credential"),
		AttemptID:              n2dOpaqueID("gate-a/" + label + "/attempt"),
		InitiatorParticipantID: n2dOpaqueID("gate-a/" + label + "/initiator"),
		ResponderParticipantID: n2dOpaqueID("gate-a/" + label + "/responder"),
		OOBChannelID:           n2dOpaqueID("gate-a/" + label + "/channel"),
		IssuedAt:               now.Add(-time.Second), ExpiresAt: now.Add(10*time.Minute - time.Second),
	}, psk)
	clear(psk[:])
	if err != nil {
		t.Fatal("Gate A synthetic artifact construction failed")
	}
	manifest := set.Manifest
	clear(manifest)
	return gateAArtifactPair{Initiator: set.Initiator, Responder: set.Responder}
}

func clearGateAArtifacts(pair *gateAArtifactPair) {
	if pair == nil {
		return
	}
	clear(pair.Initiator)
	clear(pair.Responder)
	pair.Initiator = nil
	pair.Responder = nil
}

func gateASocketPair(t testing.TB) (*os.File, *os.File) {
	t.Helper()
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Gate A inherited stream construction failed")
	}
	left := os.NewFile(uintptr(descriptors[0]), "gate-a-left")
	right := os.NewFile(uintptr(descriptors[1]), "gate-a-right")
	if left == nil || right == nil {
		if left != nil {
			_ = left.Close()
		}
		if right != nil {
			_ = right.Close()
		}
		t.Fatal("Gate A inherited stream wrapping failed")
	}
	return left, right
}

func newGateAEndpointProcess(t testing.TB, topology *n2dTopology, artifacts gateAArtifactPair,
	role directattempt.Role, stunTargets []string, streamFile *os.File, pauseStage, existingGovernorDir, existingArtifactPath string,
) *gateAEndpointProcess {
	t.Helper()
	directory := t.TempDir()
	governorDir := existingGovernorDir
	if governorDir == "" {
		governorDir = filepath.Join(directory, "governor")
		if err := os.Mkdir(governorDir, 0o700); err != nil {
			t.Fatal("Gate A governor namespace setup failed")
		}
		if err := governor.PrepareGateATestNamespace(governorDir, time.Now().UTC()); err != nil {
			t.Fatal("Gate A durable namespace preparation failed")
		}
	}
	artifactPath := existingArtifactPath
	if artifactPath == "" {
		artifactPath = filepath.Join(directory, "artifact.json")
		payload := artifacts.Initiator
		if role == directattempt.RoleResponder {
			payload = artifacts.Responder
		}
		if err := os.WriteFile(artifactPath, payload, 0o600); err != nil {
			t.Fatal("Gate A artifact staging failed")
		}
	}
	eventDir := filepath.Join(directory, "events")
	if err := os.Mkdir(eventDir, 0o700); err != nil {
		t.Fatal("Gate A event directory setup failed")
	}
	process := &gateAEndpointProcess{
		done: make(chan struct{}), streamFile: streamFile, governorDir: governorDir, artifactPath: artifactPath,
		resultPath: filepath.Join(directory, "result.json"), eventDir: eventDir,
		configPath: filepath.Join(directory, "config.json"),
	}
	if role == directattempt.RoleInitiator {
		process.namespace = topology.clientA
	} else {
		process.namespace = topology.clientB
	}
	process.config = gateAEndpointConfig{
		Role: string(role), GovernorDir: governorDir, ArtifactPath: artifactPath,
		ResultPath: process.resultPath, EventDir: eventDir, PauseStage: pauseStage,
		ReleasePath: filepath.Join(directory, "release.json"), STUNTargets: stunTargets,
	}
	if err := writeN1JSON(process.configPath, process.config); err != nil {
		t.Fatal("Gate A endpoint configuration write failed")
	}
	process.command = exec.Command(
		"ip", "netns", "exec", process.namespace, os.Args[0],
		"-test.run=^TestGateAEndpointProcess$", "-test.count=1", "-test.timeout=16s",
	)
	process.command.Env = append(os.Environ(), gateAEndpointHelperEnv+"=1", gateAHelperConfigEnv+"="+process.configPath)
	process.command.Stdout = io.Discard
	process.command.Stderr = io.Discard
	process.command.ExtraFiles = []*os.File{streamFile}
	process.command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	t.Cleanup(process.stop)
	return process
}

type gateAEndpointProcess struct {
	command      *exec.Cmd
	done         chan struct{}
	waitMu       sync.Mutex
	waitErr      error
	config       gateAEndpointConfig
	configPath   string
	artifactPath string
	resultPath   string
	governorDir  string
	eventDir     string
	namespace    string
	streamFile   *os.File
	started      bool
	stopOnce     sync.Once
}

func (process *gateAEndpointProcess) start(t testing.TB) {
	t.Helper()
	if process == nil || process.command == nil || process.streamFile == nil || process.started {
		t.Fatal("Gate A endpoint start contract failed")
	}
	if err := process.command.Start(); err != nil {
		_ = process.streamFile.Close()
		t.Fatal("Gate A endpoint process start failed")
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

func (process *gateAEndpointProcess) waitStage(t testing.TB, stage string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	path := filepath.Join(process.eventDir, stage+".json")
	for time.Now().Before(deadline) {
		var event gateAEndpointEvent
		if readN1JSON(path, &event) && event.Stage == stage {
			return
		}
		select {
		case <-process.done:
			t.Fatal("Gate A endpoint exited before expected stage")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Gate A endpoint stage deadline exceeded")
}

func (process *gateAEndpointProcess) waitResult(t testing.TB) gateAEndpointResult {
	t.Helper()
	deadline := time.Now().Add(gateAProcessLimit)
	for time.Now().Before(deadline) {
		var result gateAEndpointResult
		if readN1JSON(process.resultPath, &result) {
			select {
			case <-process.done:
			case <-time.After(gateATerminalMargin):
				t.Fatal("Gate A endpoint did not exit after result")
			}
			process.waitMu.Lock()
			waitErr := process.waitErr
			process.waitMu.Unlock()
			if waitErr != nil || !result.OK {
				t.Fatal("Gate A endpoint returned a harness failure")
			}
			return result
		}
		select {
		case <-process.done:
			t.Fatal("Gate A endpoint exited without a result")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	process.stop()
	t.Fatal("Gate A endpoint result deadline exceeded")
	return gateAEndpointResult{}
}

func (process *gateAEndpointProcess) kill(t testing.TB) {
	t.Helper()
	if process == nil || process.command == nil || process.command.Process == nil {
		t.Fatal("Gate A endpoint kill contract failed")
	}
	if err := process.command.Process.Kill(); err != nil {
		t.Fatal("Gate A endpoint kill failed")
	}
	select {
	case <-process.done:
	case <-time.After(gateATerminalMargin):
		t.Fatal("Gate A endpoint kill did not terminate in time")
	}
}

func (process *gateAEndpointProcess) stop() {
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
		case <-time.After(gateATerminalMargin):
		}
	})
}

func startGateASTUNPair(t interface {
	Helper()
	Fatal(args ...any)
	Cleanup(func())
}, topology *n2dTopology) *gateASTUNPair {
	t.Helper()
	pair := &gateASTUNPair{}
	for index := range pair.done {
		pair.done[index] = make(chan error, 1)
	}
	err := RunInNamespace(topology.public, func() error {
		for index := range pair.servers {
			server, openErr := stunserver.Open(stunserver.Config{
				ListenAddr: netip.AddrPortFrom(netip.MustParseAddr(n2dPublicA), 0), MaxPPS: 20,
			})
			if openErr != nil {
				return openErr
			}
			pair.servers[index] = server
		}
		return nil
	})
	if err != nil {
		_ = pair.Close()
		t.Fatal("Gate A isolated STUN pair failed to start")
	}
	for index, server := range pair.servers {
		ctx, cancel := context.WithCancel(context.Background())
		pair.cancels[index] = cancel
		go func(index int, server *stunserver.Server) { pair.done[index] <- server.Serve(ctx) }(index, server)
	}
	ports := []uint16{pair.servers[0].ListenAddr().Port(), pair.servers[1].ListenAddr().Port()}
	if err := topology.installGateAPacketCounters(ports); err != nil {
		_ = pair.Close()
		t.Fatal("Gate A packet counter setup failed")
	}
	t.Cleanup(func() { _ = pair.Close() })
	return pair
}

func (pair *gateASTUNPair) targets() []string {
	if pair == nil || pair.servers[0] == nil || pair.servers[1] == nil {
		return nil
	}
	return []string{pair.servers[0].ListenAddr().String(), pair.servers[1].ListenAddr().String()}
}

func (pair *gateASTUNPair) Close() error {
	if pair == nil {
		return nil
	}
	pair.closeOnce.Do(func() {
		for _, cancel := range pair.cancels {
			if cancel != nil {
				cancel()
			}
		}
		for _, server := range pair.servers {
			if server != nil {
				pair.closeErr = errors.Join(pair.closeErr, server.Close())
			}
		}
		for index, done := range pair.done {
			if pair.servers[index] == nil {
				continue
			}
			select {
			case err := <-done:
				pair.closeErr = errors.Join(pair.closeErr, err)
			case <-time.After(gateATerminalMargin):
				pair.closeErr = errors.Join(pair.closeErr, errors.New("Gate A STUN drain timeout"))
			}
		}
	})
	return pair.closeErr
}

func (topology *n2dTopology) installGateAPacketCounters(stunPorts []uint16) error {
	if len(stunPorts) != 2 || stunPorts[0] == 0 || stunPorts[1] == 0 || stunPorts[0] == stunPorts[1] {
		return errors.New("invalid Gate A STUN ports")
	}
	for _, endpoint := range []struct {
		namespace  string
		peerPublic string
	}{
		{topology.clientA, n2dNATBWAN},
		{topology.clientB, n2dNATAWAN},
	} {
		commands := [][]string{
			{"-w", "5", "-N", "WYGATEA_TOTAL"},
			{"-w", "5", "-A", "WYGATEA_TOTAL", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-j", "WYGATEA_TOTAL"},
			{"-w", "5", "-N", "WYGATEA_STUN"},
			{"-w", "5", "-A", "WYGATEA_STUN", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-d", n2dPublicA, "--dport", strconv.Itoa(int(stunPorts[0])), "-j", "WYGATEA_STUN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-d", n2dPublicA, "--dport", strconv.Itoa(int(stunPorts[1])), "-j", "WYGATEA_STUN"},
			{"-w", "5", "-N", "WYGATEA_DIRECT"},
			{"-w", "5", "-A", "WYGATEA_DIRECT", "-j", "RETURN"},
			{"-w", "5", "-A", "OUTPUT", "-o", n2dEndpointInterface, "-p", "udp", "-d", endpoint.peerPublic, "-j", "WYGATEA_DIRECT"},
		}
		for _, args := range commands {
			if _, err := runNamespaced(endpoint.namespace, "iptables", nil, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (topology *n2dTopology) gateAPacketCounts() (gateAPacketCounts, error) {
	read := func(namespace, chain string) (uint64, error) { return n2dChainPackets(namespace, chain) }
	leftSTUN, err := read(topology.clientA, "WYGATEA_STUN")
	if err != nil {
		return gateAPacketCounts{}, err
	}
	leftDirect, err := read(topology.clientA, "WYGATEA_DIRECT")
	if err != nil {
		return gateAPacketCounts{}, err
	}
	leftTotal, err := read(topology.clientA, "WYGATEA_TOTAL")
	if err != nil {
		return gateAPacketCounts{}, err
	}
	rightSTUN, err := read(topology.clientB, "WYGATEA_STUN")
	if err != nil {
		return gateAPacketCounts{}, err
	}
	rightDirect, err := read(topology.clientB, "WYGATEA_DIRECT")
	if err != nil {
		return gateAPacketCounts{}, err
	}
	rightTotal, err := read(topology.clientB, "WYGATEA_TOTAL")
	if err != nil {
		return gateAPacketCounts{}, err
	}
	return gateAPacketCounts{
		InitiatorSTUN: leftSTUN, InitiatorDirect: leftDirect, InitiatorTotal: leftTotal,
		ResponderSTUN: rightSTUN, ResponderDirect: rightDirect, ResponderTotal: rightTotal,
	}, nil
}

func requireGateAPacketCounts(t testing.TB, topology *n2dTopology) gateAPacketCounts {
	t.Helper()
	counts, err := topology.gateAPacketCounts()
	if err != nil {
		t.Fatal("Gate A packet counter witness failed")
	}
	return counts
}

func assertGateASuccessResult(t testing.TB, result gateAEndpointResult, role directattempt.Role) {
	t.Helper()
	assertGateACommonResult(t, result)
	wantDirect := 1
	if role == directattempt.RoleInitiator {
		wantDirect = 2
	}
	if result.Role != string(role) || result.Terminal != "success" || result.ErrorClass != "" ||
		!result.CredentialBurned || !result.FinishRecorded || !result.Bidirectional ||
		result.MappingBehavior != "consistent_same_address" || result.STUNPackets != 2 ||
		result.DirectPackets != wantDirect || result.UDPPackets != 2+wantDirect ||
		result.DataPacketsRead != 3 || result.DataPacketsWritten != 3 ||
		!result.CarrierDrained || !result.TransportAttached || !result.TransportAdopted ||
		!result.TransportStandby || !result.ChallengePassed || !result.TransportDetached || !result.TransportDrained {
		t.Fatalf("Gate A success witness = %+v", result)
	}
	if result.CarrierFramesRead > 8 || result.CarrierFramesWrite > 8 || result.LedgerSequence != 3 ||
		result.LedgerRecords != 3 || result.LedgerAdmissions != 1 || result.LedgerFailures != 0 ||
		result.UnfinishedAdmission != 0 {
		t.Fatalf("Gate A success bounded witness = %+v", result)
	}
}

func assertGateABoundedResult(t testing.TB, result gateAEndpointResult, burned bool) {
	t.Helper()
	assertGateACommonResult(t, result)
	if result.ErrorClass == "" || result.CredentialBurned != burned || result.Bidirectional || result.SafetyBlocksWork {
		t.Fatalf("Gate A bounded terminal witness = %+v", result)
	}
	if burned && (result.LedgerSequence != 3 || result.LedgerRecords != 3 || result.LedgerAdmissions != 1 || result.LedgerFailures != 1) {
		t.Fatalf("Gate A bounded terminal journal = %+v", result)
	}
	if !burned && result.LedgerAdmissions != 0 {
		t.Fatalf("Gate A pre-burn terminal consumed credential: %+v", result)
	}
}

func assertGateACommonResult(t testing.TB, result gateAEndpointResult) {
	t.Helper()
	if !result.OK || !gateAResultRedacted(result) || result.ElapsedMilliseconds < 0 ||
		result.ElapsedMilliseconds >= gateAProcessLimit.Milliseconds() ||
		result.ActivePeers != 0 || result.ActiveAttempts != 0 || result.ReservedSockets != 0 ||
		result.ReservedTargets != 0 || result.ReservedFiveTuples != 0 || result.ReservedPackets != 0 {
		t.Fatalf("Gate A endpoint result failed bounds or redaction: %+v", result)
	}
}

func assertGateAApplicationPacketCounts(t testing.TB, counts gateAPacketCounts, initiator, responder gateAEndpointResult) {
	t.Helper()
	if counts.InitiatorSTUN != uint64(initiator.STUNPackets) || counts.ResponderSTUN != uint64(responder.STUNPackets) ||
		counts.InitiatorDirect != uint64(initiator.DirectPackets+initiator.DataPacketsWritten) ||
		counts.ResponderDirect != uint64(responder.DirectPackets+responder.DataPacketsWritten) ||
		counts.InitiatorTotal != uint64(initiator.UDPPackets+initiator.DataPacketsWritten) ||
		counts.ResponderTotal != uint64(responder.UDPPackets+responder.DataPacketsWritten) {
		t.Fatalf("Gate A OS/application packet mismatch: os=%+v app=%+v/%+v", counts, initiator, responder)
	}
}

func inspectGateALedger(t testing.TB, namespace string) governor.PairingLedgerStatus {
	t.Helper()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "gate-a-reinspect")
	if err != nil {
		t.Fatal("Gate A governor lock remained held")
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatal("Gate A governor reopen failed")
	}
	ledger, err := governor.GateATestPairingLedger(machine)
	if err != nil {
		_ = machine.Close()
		t.Fatal("Gate A ledger reopen failed")
	}
	status := ledger.Status()
	if err := machine.Close(); err != nil {
		t.Fatal("Gate A governor reinspection drain failed")
	}
	return status
}

func inspectGateAUnfinished(t testing.TB, namespace string) int {
	t.Helper()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "gate-a-unfinished-reinspect")
	if err != nil {
		t.Fatal("Gate A governor lock remained held")
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatal("Gate A governor reopen failed")
	}
	admissions, _, err := governor.GateATestLedgerOccupancy(machine)
	if err != nil {
		_ = machine.Close()
		t.Fatal("Gate A unfinished ledger witness failed")
	}
	if err := machine.Close(); err != nil {
		t.Fatal("Gate A governor reinspection drain failed")
	}
	return admissions
}

func assertGateANoResidue(t testing.TB, topology *n2dTopology, servers *gateASTUNPair, governorDirs ...string) {
	t.Helper()
	before := requireGateAPacketCounts(t, topology)
	time.Sleep(100 * time.Millisecond)
	after := requireGateAPacketCounts(t, topology)
	if after != before {
		t.Fatalf("Gate A packet counters changed after terminal: before=%+v after=%+v", before, after)
	}
	if err := servers.Close(); err != nil {
		t.Fatal("Gate A STUN pair drain failed")
	}
	if sockets, err := topology.socketCount(); err != nil || sockets != 0 {
		t.Fatalf("Gate A OS socket residue = %d", sockets)
	}
	if processes, err := topology.processCount(); err != nil || processes != 0 {
		t.Fatalf("Gate A namespace process residue = %d", processes)
	}
	for _, namespace := range governorDirs {
		_ = inspectGateALedger(t, namespace)
	}
	conntrackBefore, conntrackAfter, err := topology.flushConntrack()
	if err != nil || conntrackAfter != 0 {
		t.Fatal("Gate A conntrack cleanup witness failed")
	}
	t.Logf("Gate A terminal witness: sockets=0 processes=0 packet_counters_stable=true conntrack_before_cleanup=%d conntrack_after_cleanup=%d", conntrackBefore, conntrackAfter)
	if err := topology.cleanup(); err != nil {
		t.Fatal("Gate A topology cleanup failed")
	}
	if err := topology.assertNoLeaks(); err != nil {
		t.Fatal("Gate A namespace or veth leak witness failed")
	}
}

func requireGateAEnvironment(t *testing.T) {
	t.Helper()
	required := os.Getenv(gateARequiredEnv) == "1"
	failOrSkip := func(message string) {
		if required {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	if os.Geteuid() != 0 {
		failOrSkip("Gate A requires an isolated root network namespace")
	}
	for _, program := range []string{"ip", "iptables", "iptables-restore", "ss", "conntrack", "sysctl", "tc"} {
		if _, err := exec.LookPath(program); err != nil {
			failOrSkip("Gate A isolated-network prerequisite is unavailable")
		}
	}
	if err := probeN1NamespaceAuthority(); err != nil {
		failOrSkip("Gate A network namespace authority is unavailable")
	}
}
