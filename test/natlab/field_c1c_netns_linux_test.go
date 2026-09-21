//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	binary := os.Getenv("WINKYOU_FIELD_C1C_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("C1c exact field binary unavailable")
	}
	for _, profile := range gateC1bProfiles[:2] {
		if !t.Run(profile.name, func(t *testing.T) { testFieldC1cProfile(t, profile, binary) }) {
			t.FailNow()
		}
	}
}

func testFieldC1cProfile(t *testing.T, profile gateC1bProfile, binary string) {
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
	if os.WriteFile(configs[0].Host.StopFile, []byte("owned-sigint\n"), 0o600) != nil {
		t.Fatal("C1c kill-switch request failed")
	}
	client.wait(t)
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
	if prepareGateC1bPrivateMounts(cfg.Host) != nil {
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
