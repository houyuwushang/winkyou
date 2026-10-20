//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"winkyou/internal/governor"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/sshchildwrapper"
	"winkyou/pkg/netif"
	"winkyou/pkg/tunnel"
)

const fieldC1cHostEnv = "WINKYOU_C1C_HOST_CONFIG"
const fieldC1cPeerAbsentMutationEnv = "WINKYOU_C1C_PEER_ABSENT_MUTATION"

// The field image and its host are separate race binaries. The old C1b
// helper ran the product in-process; its 3s result wait excludes one exit.
// Frozen CLOSE + drain + both Go race exits, with 25% scheduling margin.
const (
	fieldC1cCloseAllowance    = time.Second
	fieldC1cRaceExitAllowance = 2 * time.Second
	fieldC1cStopBase          = fieldC1cCloseAllowance + gatecorchestrator.SessionDrainTimeout + fieldC1cRaceExitAllowance
	fieldC1cStopResultLimit   = (fieldC1cStopBase*5/4 + time.Second - 1) / time.Second * time.Second
)

func fieldC1cRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("C1c source root unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func TestLinuxFieldC1cExactBuildProof(t *testing.T) {
	if os.Getenv("WINKYOU_FIELD_C1C_REQUIRED") != "1" {
		t.Skip("C1c requires explicitly isolated Linux proof job")
	}
	guard := requireC1cProofEnvironment(t)
	testFieldC1cImageTraceThreads(t)
	binary := os.Getenv("WINKYOU_FIELD_C1C_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("C1c exact field binary unavailable")
	}
	for _, proof := range []struct {
		name       string
		profile    gateC1bProfile
		peerAbsent bool
		launcher   string
	}{
		{gateC1bProfiles[0].name, gateC1bProfiles[0], false, ""},
		{gateC1bProfiles[1].name, gateC1bProfiles[1], false, ""},
		{"peer_absent", gateC1bProfiles[0], true, ""},
		{"launcher_peer_absent", gateC1bProfiles[0], true, "hidden"},
		{"launcher_replaced_path", gateC1bProfiles[0], true, "replaced"},
		{"launcher_hash_mismatch", gateC1bProfiles[0], true, "bad_hash"},
		{"launcher_old_path_mutation", gateC1bProfiles[0], true, "old_path"},
	} {
		image := binary
		if proof.launcher == "old_path" {
			image = os.Getenv("WINKYOU_C1C_OLD_PATH_BINARY")
			if !filepath.IsAbs(image) {
				t.Fatal("required old pathname mutation image unavailable")
			}
		}
		if !t.Run(proof.name, guard(func(t *testing.T) { testFieldC1cProfile(t, proof.profile, image, proof.peerAbsent, proof.launcher) })) {
			t.FailNow()
		}
	}
}

func testFieldC1cProfile(t *testing.T, profile gateC1bProfile, binary string, peerAbsent bool, launcher string) {
	armGateB3KernelReleaseMargin(t)
	topology := newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	t.Cleanup(func() { cleanupGateC1bEndpointProcesses(t, topology) })
	observer := startGateB2ObserverSet(t, topology.public)
	left, right := gateC1bRouters(t, topology, profile)
	if topology.installGateB2PacketCounters(observer.topology) != nil {
		t.Fatal("C1c counter installation failed")
	}
	var release []func()
	for _, rule := range []struct{ namespace, source, destination, port string }{{topology.natA, n2dClientAAddress, n2dNATBWAN, "dport"}, {topology.natB, n2dClientBAddress, n2dNATAWAN, "sport"}} {
		if _, err := runNamespaced(rule.namespace, "ip", nil, "rule", "add", "priority", "101", "iif", "lan0", "from", rule.source+"/32", "to", rule.destination+"/32", "ipproto", "tcp", rule.port, "22", "lookup", "main"); err != nil {
			t.Fatal("C1c isolated SSH route failed")
		}
		namespace := rule.namespace
		removed := false
		cleanup := func() {
			if removed {
				return
			}
			removed = true
			if _, err := runNamespaced(namespace, "ip", nil, "rule", "del", "priority", "101"); err != nil {
				t.Error("C1c SSH policy cleanup failed")
			}
		}
		release = append(release, cleanup)
		t.Cleanup(cleanup)
	}
	if _, err := runNamespaced(topology.natB, "iptables", nil, "-t", "nat", "-A", "PREROUTING", "-i", "wan0", "-p", "tcp", "-d", n2dNATBWAN, "--dport", "22", "-j", "DNAT", "--to-destination", n2dClientBAddress+":22"); err != nil {
		t.Fatal("C1c isolated SSH tuple failed")
	}
	configs := fieldC1cFixture(t, gateC1bFixture(t, topology, observer.topology, profile, false), profile, binary)
	if peerAbsent {
		mutation := os.Getenv(fieldC1cPeerAbsentMutationEnv)
		if mutation != "" && mutation != "other_class" && mutation != "responder_present" {
			t.Fatal("unknown peer-absent test mutation")
		}
		journal := filepath.Join(configs[0].Host.MachineBase, "winkyou-safety-v2", "pairing-admission-v1.journal")
		before := fieldC1cJournalKinds(t, journal)
		configs[0].OwnerEvidence = configs[0].Host.ResultFile + ".owner-witness"
		if launcher != "" {
			configs[0] = fieldC1cLauncherFixture(t, configs[0], binary, launcher)
		}
		var mutantServer *gateC1bHostProcess
		if mutation == "responder_present" {
			mutantServer = startFieldC1cHost(t, configs[1])
			mutantServer.waitFile(t, configs[1].Host.ReadyFile, 5*time.Second)
		}
		client := startFieldC1cHost(t, configs[0])
		deadline := time.Now().Add(55 * time.Second)
		var terminal fieldC1cTerminal
		stopRequested := false
		rejected := false
	waitTerminal:
		for terminal.Class == "" && time.Now().Before(deadline) {
			if mutantServer != nil && !stopRequested && fieldC1cHasStage(configs[0].Evidence, gatecorchestrator.StageDataPlaneReady) && fieldC1cHasStage(configs[1].Evidence, gatecorchestrator.StageDataPlaneReady) {
				if os.WriteFile(configs[0].Host.StopFile, []byte("owned-sigint\n"), 0o600) != nil {
					t.Fatal("C1c responder-present mutation stop failed")
				}
				stopRequested = true
			}
			terminal = readFieldC1cTerminal(configs[0].Evidence)
			if terminal.Class == "" {
				if launcher != "" {
					select {
					case <-client.done:
						terminal = readFieldC1cTerminal(configs[0].Evidence)
						break waitTerminal
					default:
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		if launcher != "" {
			rejected = fieldC1cLauncherObservation(t, configs[0], terminal)
		}
		if terminal.Class == "" && !rejected {
			t.Fatal("C1c peer-absent private terminal absent")
		}
		// A non-success field terminal makes the harness exit nonzero. Await
		// that owned process without imposing the success-only wait helper.
		select {
		case <-client.done:
		case <-time.After(fieldC1cStopResultLimit):
			t.Fatal("C1c peer-absent process did not drain")
		}
		if mutantServer != nil {
			mutantServer.stop(t)
		}
		var owner struct{ Idle bool }
		ownerObserved := readN1JSON(configs[0].OwnerEvidence, &owner)
		// Pre-handoff failures have no Handoff witness. Release here means the
		// actual field process exited and its machine owner lock is available;
		// it does not claim visibility into its in-memory attempt map.
		released := ownerObserved && owner.Idle
		counts := requireGateB2PacketCounts(t, topology)
		witness := terminal.Result.Witness
		t.Logf("C1C_PEER_ABSENT class=%s stage=%s burned=%t finish_recorded=%t attempt_released=%t ssh_spawned=%t ssh_stderr_bytes=%d carrier_eof=%t carrier_closed=%t udp_total=%d",
			terminal.Class, terminal.FailureStage, terminal.Result.CredentialBurned, terminal.Result.FinishRecorded, released,
			witness.SSH.Spawned, witness.SSH.StderrBytes, witness.GateB.CarrierWitness.EOF, witness.GateB.CarrierWitness.Closed, counts.InitiatorTotal+counts.ResponderTotal)
		// Prove cleanup before the intentional mutation assertion can fail.
		// No success-only ledger assumptions apply to this external check.
		for _, cleanup := range release {
			cleanup()
		}
		assertGateC1bNoKernelInterfaceResidue(t, topology)
		assertGateB2NoResidue(t, topology, observer, left, right)
		if rejected {
			if !released || counts.InitiatorTotal+counts.ResponderTotal != 0 {
				t.Fatal("launcher rejection retained an owner or emitted UDP")
			}
			after := fieldC1cJournalKinds(t, journal)
			if after["burn_and_admit"] != before["burn_and_admit"] || after["finish"] != before["finish"] {
				t.Fatal("launcher rejection appended burn/finish")
			}
			t.Logf("C1C_LAUNCHER_REJECT mode=%s owner_released=true udp_total=0 burn_added=0 finish_added=0", launcher)
			return
		}
		// Discovery, exact field image 83328251b1d3476ee5daac7eae2dc9e9d7e8dc7f:
		// https://github.com/houyuwushang/winkyou/actions/runs/38834802667/job/116761412269
		// C1C_PEER_ABSENT class=oob_stream_closed stage=present burned=false finish_recorded=false attempt_released=true ssh_spawned=true ssh_stderr_bytes=62 carrier_eof=true carrier_closed=true udp_total=0
		expectedClass := "oob_stream_closed"
		if mutation == "other_class" {
			expectedClass = "ssh_transport_unavailable"
		}
		if counts.InitiatorTotal+counts.ResponderTotal != 0 {
			t.Log("C1C_PEER_ABSENT_REJECT reason=udp_total")
			t.Fatal("C1c peer-absent emitted UDP")
		}
		if terminal.Class != expectedClass {
			t.Log("C1C_PEER_ABSENT_REJECT reason=class")
			t.Fatal("C1c peer-absent class differs")
		}
		if terminal.FailureStage != "present" || terminal.Result.CredentialBurned || terminal.Result.FinishRecorded || !released {
			t.Fatal("C1c peer-absent terminal differs from the discovered no-burn/no-UDP outcome")
		}
		if !witness.SSH.Spawned || witness.SSH.StderrBytes == 0 || !witness.GateB.CarrierWitness.EOF || !witness.GateB.CarrierWitness.Closed {
			t.Fatal("C1c peer-absent SSH/carrier witness differs")
		}
		after := fieldC1cJournalKinds(t, journal)
		added := 0
		for _, kind := range fieldC1cJournalRecordKinds {
			delta := after[kind] - before[kind]
			added += delta
			t.Logf("C1C_PEER_ABSENT_JOURNAL kind=%s added=%d", kind, delta)
			want := 0
			if kind == "initialize" {
				want = 1
			}
			if delta != want {
				t.Fatal("C1c peer-absent journal delta changed")
			}
		}
		t.Logf("C1C_PEER_ABSENT_JOURNAL added_total=%d", added)
		if mutation == "" && launcher == "" {
			fieldC1cPeerAbsentMutations(t)
		}
		return
	}
	server := startFieldC1cHost(t, configs[1])
	server.waitFile(t, configs[1].Host.ReadyFile, 5*time.Second)
	client := startFieldC1cHost(t, configs[0])
	for side := range configs {
		deadline := time.Now().Add(55 * time.Second)
		for !fieldC1cHasStage(configs[side].Evidence, gatecorchestrator.StageDataPlaneReady) {
			if !time.Now().Before(deadline) {
				for index, cfg := range configs {
					snapshot := readFieldC1cTerminal(cfg.Evidence)
					witness := snapshot.Result.Witness
					transport := witness.Handoff.Transport
					t.Logf("C1C_WAIT side=%d class=%s last_work_stage=%s interface_closed=%t tunnel_stopped=%t consumer_ready=%t readiness_out=%d readiness_in=%d wg_out=%d wg_in=%d finish=%t", index, snapshot.Class, fieldC1cLastStage(cfg.Evidence),
						witness.InterfaceClosed, witness.TunnelStopped, transport.ConsumerReady, transport.ReadinessWrites, transport.ReadinessReads, len(transport.Outbound), len(transport.Inbound), witness.Handoff.FinishRecorded)
					t.Logf("C1C_BIND side=%d failure_stage=%s start_called=%t start_ok=%t peer_called=%t peer_ok=%t tun_reader_failed=%t", index, snapshot.FailureStage,
						snapshot.FieldWireGuard.StartCalled, snapshot.FieldWireGuard.StartSucceeded, snapshot.FieldWireGuard.PeerCalled, snapshot.FieldWireGuard.PeerSucceeded, snapshot.Interface.ReaderFailedBeforeClose)
					fieldC1cLines(cfg.Evidence, func(data []byte) {
						var point struct {
							Stage string `json:"stage"`
							AtNS  int64  `json:"at_ns"`
						}
						if json.Unmarshal(data, &point) == nil && (point.Stage == "handoff" || point.Stage == gatecorchestrator.StageTerminal) {
							t.Logf("C1C_TIMING side=%d stage=%s at_ns=%d", index, point.Stage, point.AtNS)
						}
					})
				}
				t.Fatal("C1c endpoint did not reach data-plane ready")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// This packet enters/exits the real kernel TUN, separately from the inner
	// protocol queue. One echo only; there is no retry or fallback.
	if _, err := runNamespaced(topology.clientA, "ping", nil, "-n", "-c", "1", "-W", "2", "192.0.2.101"); err != nil {
		t.Fatal("C1c kernel data-plane packet failed")
	}
	t.Logf("C1C_READY profile=%s endpoints=2 kernel_echo=1", profile.name)
	stopStarted := time.Now()
	if os.WriteFile(configs[0].Host.StopFile, []byte("owned-sigint\n"), 0o600) != nil {
		t.Fatal("C1c kill-switch request failed")
	}
	waitFieldC1cEndpoint(t, client, configs)
	t.Logf("C1C_STOP result_wait_ns=%d limit_ns=%d", time.Since(stopStarted).Nanoseconds(), fieldC1cStopResultLimit.Nanoseconds())
	var terminals [2]fieldC1cTerminal
	for side, cfg := range configs {
		deadline := time.Now().Add(5 * time.Second)
		for {
			terminals[side] = readFieldC1cTerminal(cfg.Evidence)
			if terminals[side].Class != "" {
				break
			}
			if !time.Now().Before(deadline) {
				t.Fatal("C1c private terminal witness absent")
			}
			time.Sleep(10 * time.Millisecond)
		}
		got := terminals[side]
		if got.Class != "success" || !got.Result.DataPlaneReady || !got.Result.FinishRecorded || !got.Result.Witness.Handoff.AttemptReleased || !got.Result.Witness.Handoff.OOBDrained ||
			!got.Result.Witness.TunnelStopped || !got.Result.Witness.InterfaceClosed || !got.Interface.Closed || !got.Interface.InterfaceChecked || !got.Interface.InterfaceAbsent || got.Interface.KernelPacketsRead == 0 || got.Interface.KernelPacketsWritten == 0 {
			t.Fatalf("C1c owned terminal rejected side=%d class=%s ready=%t finish=%t interface=%+v", side, got.Class, got.Result.DataPlaneReady, got.Result.FinishRecorded, got.Interface)
		}
		if got.Result.Witness.Liveness == nil || !got.Result.Witness.Liveness.Drained {
			t.Fatal("C1c liveness owner did not drain")
		}
	}
	server.stop(t)
	assertGateC1bNoKernelInterfaceResidue(t, topology)
	counts := requireGateB2PacketCounts(t, topology)
	for side, actual := range []uint64{counts.InitiatorTotal, counts.ResponderTotal} {
		w := terminals[side].Result.Witness
		want := uint64(w.GateB.Emissions.UDPPacketsTotal + w.WireGuard.ReadinessWrites + w.WireGuard.CompletionWrites + len(w.WireGuard.Outbound) + w.WireGuard.ActiveWrites)
		if actual != want {
			t.Fatalf("C1C_ACCOUNTING side=%d actual=%d charged=%d", side, actual, want)
		}
		t.Logf("C1C_ENDPOINT side=%d evidence=%d candidates=%d winner=%d kernel_read=%d kernel_write=%d", side, w.GateB.Emissions.EvidencePackets, w.GateB.Emissions.CandidatePackets, w.GateB.Emissions.WinnerPackets, terminals[side].Interface.KernelPacketsRead, terminals[side].Interface.KernelPacketsWritten)
	}
	for _, cleanup := range release {
		cleanup()
	}
	assertGateB2NoResidue(t, topology, observer, left, right, filepath.Join(configs[0].Host.MachineBase, "winkyou-safety-v2"), filepath.Join(configs[1].Host.MachineBase, "winkyou-safety-v2"))
	t.Logf("C1C_PROOF profile=%s exact_binary=true kill_switch=true kernel_business=true residue=0", profile.name)
}

// Each mutation gets a fresh isolated fixture and the same exact field image.
// The child must fail at the named real assertion, not at a setup or timeout.
// Only the test harness environment changes; no source/image is rewritten.
func fieldC1cPeerAbsentMutations(t *testing.T) {
	t.Helper()
	for _, mutation := range []struct{ name, reason string }{{"other_class", "class"}, {"responder_present", "udp_total"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
		command := exec.CommandContext(ctx, os.Args[0], "-test.v", "-test.run=^TestLinuxFieldC1cExactBuildProof$/^peer_absent$", "-test.count=1", "-test.timeout=70s")
		command.Env = append(os.Environ(), fieldC1cPeerAbsentMutationEnv+"="+mutation.name)
		output, err := command.CombinedOutput()
		timedOut := ctx.Err() != nil
		cancel()
		exit, exited := err.(*exec.ExitError)
		if !exited || exit.ExitCode() != 1 || timedOut || !strings.Contains(string(output), "C1C_PEER_ABSENT_REJECT reason="+mutation.reason) {
			t.Fatalf("C1c peer-absent mutation %s missed its assertion (exit_failure=%t timeout=%t)", mutation.name, exited, timedOut)
		}
		for _, line := range strings.Split(string(output), "\n") {
			if start := strings.Index(line, "C1C_PEER_ABSENT class="); start >= 0 {
				t.Log(line[start:])
			}
		}
		t.Logf("C1C_PEER_ABSENT_MUTATION name=%s RED reason=%s restored=true", mutation.name, mutation.reason)
	}
}

var fieldC1cJournalRecordKinds = [...]string{"initialize", "rebuild_baseline", "burn_and_admit", "finish", "circuit_reset"}

// Read only the framed journal's record types. Neither raw records nor errors
// containing a credential, attempt, or other private journal field are logged.
func fieldC1cJournalKinds(t *testing.T, path string) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return counts
	}
	if err != nil {
		t.Fatal("C1c journal read failed")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		t.Fatal("C1c journal size rejected")
	}
	for len(data) != 0 {
		if len(data) < 4 {
			t.Fatal("C1c journal prefix truncated")
		}
		n := int(binary.BigEndian.Uint32(data[:4]))
		data = data[4:]
		if n <= 0 || n > 16<<10 || n > len(data) {
			t.Fatal("C1c journal frame rejected")
		}
		var frame struct {
			Record   json.RawMessage `json:"record"`
			Checksum string          `json:"checksum"`
		}
		if json.Unmarshal(data[:n], &frame) != nil || fmt.Sprintf("%x", sha256.Sum256(frame.Record)) != frame.Checksum {
			t.Fatal("C1c journal checksum rejected")
		}
		var record struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(frame.Record, &record) != nil {
			t.Fatal("C1c journal record rejected")
		}
		known := false
		for _, kind := range fieldC1cJournalRecordKinds {
			known = known || record.Type == kind
		}
		if !known {
			t.Fatal("C1c journal kind rejected")
		}
		counts[record.Type]++
		data = data[n:]
	}
	return counts
}

func waitFieldC1cEndpoint(t *testing.T, process *gateC1bHostProcess, configs [2]fieldC1cHostConfig) {
	t.Helper()
	select {
	case <-process.done:
	case <-time.After(fieldC1cStopResultLimit):
		for side, config := range configs {
			terminal := readFieldC1cTerminal(config.Evidence)
			t.Logf("C1C_EXIT side=%d class=%s stage=%s ready=%t finish=%t interface_closed=%t", side,
				terminal.Class, fieldC1cLastStage(config.Evidence), terminal.Result.DataPlaneReady, terminal.Result.FinishRecorded, terminal.Interface.Closed)
		}
		t.Fatal("C1c owned endpoint result deadline exceeded")
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.waitErr != nil {
		t.Fatal("C1c owned endpoint exited unsuccessfully")
	}
}

func startFieldC1cHost(t *testing.T, cfg fieldC1cHostConfig) *gateC1bHostProcess {
	t.Helper()
	path := cfg.Host.RequestFile + ".field-harness"
	if writeN1JSON(path, cfg) != nil {
		t.Fatal("C1c private harness metadata failed")
	}
	command := exec.Command("ip", "netns", "exec", cfg.Host.HostNamespace, os.Args[0], "-test.run=^TestFieldC1cHostProcess$", "-test.count=1", "-test.timeout=80s")
	command.Env = append(os.Environ(), fieldC1cHostEnv+"="+path)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL, Setpgid: true}
	process := &gateC1bHostProcess{command: command, config: cfg.Host, done: make(chan struct{})}
	finished, err := startGateC1bOwnedProcess(command)
	if err != nil {
		t.Fatal("C1c isolated endpoint start failed")
	}
	go func() {
		err := <-finished
		process.mu.Lock()
		process.waitErr = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		select {
		case <-process.done:
			return
		default:
		}
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		select {
		case <-process.done:
		case <-time.After(2 * time.Second):
			t.Error("C1c host cleanup did not drain")
		}
	})
	return process
}

func TestFieldC1cHostProcess(t *testing.T) {
	path := os.Getenv(fieldC1cHostEnv)
	if path == "" {
		return
	}
	var cfg fieldC1cHostConfig
	if !readN1JSON(path, &cfg) || os.Getuid() != 0 || os.Geteuid() != 0 || !gateC1bIsolatedMount(cfg.Host.ParentMount) || !gateC1bCurrentNamespace(cfg.Host.HostNamespace) {
		t.Fatal("C1c host isolation rejected")
	}
	prepare := prepareGateC1bPrivateMounts
	if cfg.LauncherRoot != "" {
		prepare = func(gateC1bHostConfig) error { return prepareFieldC1cLauncherMounts(cfg) }
	}
	if prepare(cfg.Host) != nil {
		t.Fatal("C1c private mounts failed")
	}
	if unix.Mount(cfg.MachineIDFile, "/etc/machine-id", "", unix.MS_BIND, "") != nil {
		t.Fatal("C1c isolated machine identity failed")
	}
	if status, err := governor.SetupMachineNamespace(); err != nil || !status.Ready {
		t.Fatal("C1c machine namespace failed")
	}
	if cfg.Host.Server {
		if gatecstage.Stage(cfg.Host.RequestFile, time.Now().UTC()) != nil {
			t.Fatal("C1c staging failed")
		}
		runGateC1bPrivateSSHD(t, cfg.Host)
		return
	}
	output, err := os.OpenFile(cfg.Host.ResultFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("C1c private summary file failed")
	}
	defer output.Close()
	command := exec.Command(sshchildwrapper.FixedBinaryPath, "gate-c1c", "run", "--instance", cfg.Instance)
	if cfg.LauncherRoot != "" {
		command = fieldC1cLauncherCommand(t, cfg)
	}
	command.Stdout, command.Stderr = output, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	done, err := startGateC1bOwnedProcess(command)
	if err != nil {
		t.Fatal("C1c field entry start failed")
	}
	defer func() { _ = command.Process.Kill() }()
	deadline := time.NewTimer(75 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	signalled := false
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Error("C1c exact field entry failed")
			}
			if cfg.OwnerEvidence != "" {
				owner := governor.InspectMachineOwner()
				if writeN1JSON(cfg.OwnerEvidence, struct{ Idle bool }{owner.State == governor.OwnerIdle && !owner.Held}) != nil {
					t.Error("C1c private owner witness failed")
				}
			}
			return
		case <-deadline.C:
			t.Fatal("C1c field entry timeout")
		case <-poll.C:
			if !signalled {
				if _, err := os.Stat(cfg.Host.StopFile); err == nil {
					signalled = true
					if command.Process.Signal(syscall.SIGINT) != nil {
						t.Fatal("C1c owned signal failed")
					}
				}
			}
		}
	}
}

type fieldC1cTerminal struct {
	Result         gatecorchestrator.Result     `json:"result"`
	Class          string                       `json:"class"`
	FailureStage   string                       `json:"failure_stage"`
	Interface      netif.FieldInterfaceWitness  `json:"interface"`
	FieldWireGuard tunnel.FieldWireGuardWitness `json:"field_wireguard"`
}

func fieldC1cLines(path string, visit func([]byte)) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 1024*1024))
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		visit(scanner.Bytes())
	}
}
func fieldC1cHasStage(path, stage string) bool {
	found := false
	fieldC1cLines(path, func(data []byte) {
		var row struct {
			Stage string `json:"stage"`
		}
		if json.Unmarshal(data, &row) == nil && row.Stage == stage {
			found = true
		}
	})
	return found
}
func fieldC1cLastStage(path string) string {
	stage := "unobserved"
	fieldC1cLines(path, func(data []byte) {
		var row struct {
			Stage string `json:"stage"`
		}
		if json.Unmarshal(data, &row) == nil && row.Stage != "" && row.Stage != gatecorchestrator.StageTerminal {
			stage = row.Stage
		}
	})
	return stage
}
func readFieldC1cTerminal(path string) fieldC1cTerminal {
	var terminal fieldC1cTerminal
	fieldC1cLines(path, func(data []byte) {
		var row fieldC1cTerminal
		if json.Unmarshal(data, &row) == nil && row.Class != "" {
			terminal = row
		}
	})
	return terminal
}
