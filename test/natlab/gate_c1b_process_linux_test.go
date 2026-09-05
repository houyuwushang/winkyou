//go:build linux && natlab && c1bproof

package natlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	winkcmd "winkyou/cmd/wink/cmd"
	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/sshassembly"
	"winkyou/internal/v2/sshchildwrapper"
	"winkyou/pkg/netif"
)

const (
	gateC1bHostEnv       = "WINKYOU_C1B_HOST_HELPER"
	gateC1bHostConfigEnv = "WINKYOU_C1B_HOST_CONFIG"
	gateC1bProofConfig   = "/var/lib/winkyou-safety-v2/gate-c1b-proof.json"
	gateC1bHostLimit     = 75 * time.Second
)

// All paths below are private harness files. They are never printed, stored
// in artifacts, or accepted by an ordinary product executable.
type gateC1bHostConfig struct {
	Server        bool
	HostNamespace string
	Namespace     string
	ParentMount   uint64
	MachineBase   string
	InstallBase   string
	HomeDirectory string
	RuntimeBase   string
	ShadowFile    string
	SSHDBinary    string
	IPBinary      string
	SSHDConfig    string
	RequestFile   string
	ConfigFile    string
	ResultFile    string
	ReadyFile     string
	StageFile     string
	StopFile      string
	Observers     [4]netip.AddrPort
	Side          probeio.GateB2NATLabSide
	SSHSide       sshassembly.NATLabSide
	Fault         string
	UseTUN        bool
}

type gateC1bProcessResult struct {
	OK      bool                     `json:"ok"`
	Root    bool                     `json:"root"`
	Class   string                   `json:"class,omitempty"`
	Stage   string                   `json:"stage,omitempty"`
	Stages  []string                 `json:"stages"`
	Product gatecorchestrator.Result `json:"product"`
	TUN     gateC1bTUNWitness        `json:"tun"`
}

// A copy of the race-enabled test binary supplies the two exact installed
// paths only inside the helper's private mount namespace. Exec replaces the
// wrapper; it does not create another child or transfer a PacketTransport.
func init() {
	if os.Args[0] != sshchildwrapper.FixedWrapperPath && os.Args[0] != sshchildwrapper.FixedBinaryPath {
		return
	}
	var cfg gateC1bHostConfig
	if !readN1JSON(gateC1bProofConfig, &cfg) || !gateC1bIsolatedMount(cfg.ParentMount) || os.Getuid() != 0 || os.Geteuid() != 0 {
		os.Exit(91)
	}
	reject := func(stage string, code int) {
		_ = writeN1JSON(cfg.ResultFile, gateC1bProcessResult{Root: true, Class: "harness_child_rejected", Stage: stage})
		os.Exit(code)
	}
	if os.Args[0] == sshchildwrapper.FixedWrapperPath {
		runtime.LockOSThread() // Keep setns and the replacing exec on this thread.
		plan, err := sshchildwrapper.PrepareRootExecution(os.Getenv("SSH_ORIGINAL_COMMAND"))
		if err != nil || !safeNamePattern.MatchString(cfg.Namespace) {
			reject("wrapper_validation", 92)
		}
		// The loopback-SSH case hosts sshd beside the client. The test-only
		// wrapper enters the other endpoint netns before the sole exact exec;
		// no governor, UDP socket, or session exists yet. All Go threads of the
		// new image therefore start in the target netns, not a setns thread mix.
		if !gateC1bCurrentNamespace(cfg.Namespace) {
			file, err := os.Open("/var/run/netns/" + cfg.Namespace)
			if err != nil || unix.Setns(int(file.Fd()), unix.CLONE_NEWNET) != nil {
				reject("wrapper_namespace", 93)
			}
			_ = file.Close()
		}
		unix.Umask(int(plan.Umask))
		if err := syscall.Exec(plan.Executable, append([]string{plan.Executable}, plan.Arguments...), plan.Environment); err != nil {
			reject("wrapper_exec", 94)
		}
	}
	if !gateC1bCurrentNamespace(cfg.Namespace) || len(os.Args) != 5 {
		reject("child_entry", 95)
	}
	if err := os.Chdir("/root"); err != nil {
		reject("child_directory", 96)
	}
	result := runGateC1bCLI(cfg, os.Args[1:])
	if writeN1JSON(cfg.ResultFile, result) != nil {
		os.Exit(97)
	}
	if !result.OK {
		os.Exit(98)
	}
	os.Exit(0)
}

func gateC1bIsolatedMount(parent uint64) bool {
	var current unix.Stat_t
	return parent != 0 && unix.Stat("/proc/self/ns/mnt", &current) == nil && current.Ino != parent
}

func gateC1bCurrentNamespace(name string) bool {
	if !safeNamePattern.MatchString(name) {
		return false
	}
	current, err1 := os.Stat("/proc/self/ns/net")
	expected, err2 := os.Stat("/var/run/netns/" + name)
	return err1 == nil && err2 == nil && os.SameFile(current, expected)
}

func TestGateC1bHostProcess(t *testing.T) {
	if os.Getenv(gateC1bHostEnv) != "1" {
		return
	}
	var cfg gateC1bHostConfig
	if !readN1JSON(os.Getenv(gateC1bHostConfigEnv), &cfg) || os.Getuid() != 0 || os.Geteuid() != 0 ||
		!gateC1bIsolatedMount(cfg.ParentMount) || !gateC1bCurrentNamespace(cfg.HostNamespace) {
		t.Fatal("Gate C1b host isolation rejected")
	}
	if err := prepareGateC1bPrivateMounts(cfg); err != nil {
		gateC1bSetupFailure(t, cfg, "private_mounts")
	}
	status, err := governor.SetupMachineNamespace()
	if err != nil || !status.Ready {
		gateC1bSetupFailure(t, cfg, "machine_namespace")
	}
	if err := writeN1JSON(gateC1bProofConfig, cfg); err != nil {
		gateC1bSetupFailure(t, cfg, "proof_metadata")
	}
	if cfg.Server {
		if err := gatecstage.Stage(cfg.RequestFile, time.Now().UTC()); err != nil {
			gateC1bSetupFailure(t, cfg, "responder_staging")
		}
		runGateC1bPrivateSSHD(t, cfg)
		return
	}
	result := runGateC1bCLI(cfg, []string{"--config", cfg.ConfigFile, "solver", "direct", "connect", "--request-file", cfg.RequestFile})
	if writeN1JSON(cfg.ResultFile, result) != nil {
		t.Fatal("Gate C1b result write failed")
	}
	if !result.OK {
		t.Error("Gate C1b product pipeline failed")
	}
}

func gateC1bSetupFailure(t *testing.T, cfg gateC1bHostConfig, stage string) {
	t.Helper()
	_ = writeN1JSON(cfg.ResultFile, gateC1bProcessResult{Root: os.Geteuid() == 0, Class: "harness_setup_rejected", Stage: stage})
	t.Fatal("Gate C1b private setup rejected")
}

// Linux Pdeathsig belongs to the OS thread that starts the child. Keeping that
// thread alive through Wait avoids treating Go thread retirement as parent death.
func startGateC1bOwnedProcess(command *exec.Cmd) (chan error, error) {
	started := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := command.Start()
		started <- err
		if err == nil {
			done <- command.Wait()
		}
	}()
	return done, <-started
}

func prepareGateC1bPrivateMounts(cfg gateC1bHostConfig) error {
	if !gateC1bIsolatedMount(cfg.ParentMount) || !gateC1bCurrentNamespace(cfg.HostNamespace) {
		return errors.New("isolated mount identity is absent")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	// Keep the named TEST-NET namespace registry visible after replacing /run.
	// Privilege separation must never require creating /run/sshd on the host.
	namespaceDirectory, err := os.Open("/run/netns")
	if err != nil {
		return err
	}
	defer namespaceDirectory.Close()
	for _, mount := range [][2]string{{cfg.MachineBase, "/var/lib"}, {cfg.InstallBase, "/usr/libexec"},
		{cfg.HomeDirectory, "/root"}, {cfg.ShadowFile, "/etc/shadow"}, {cfg.RuntimeBase, "/run"}} {
		if !filepath.IsAbs(mount[0]) {
			return errors.New("private mount path rejected")
		}
		if err := unix.Mount(mount[0], mount[1], "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", namespaceDirectory.Fd()), "/run/netns", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	return os.Chdir("/root")
}

func runGateC1bPrivateSSHD(t *testing.T, cfg gateC1bHostConfig) {
	t.Helper()
	resolved := exec.Command(cfg.SSHDBinary, "-T", "-f", cfg.SSHDConfig, "-C", "user=root,addr=127.0.0.1")
	resolved.Stderr = io.Discard
	configuration, err := resolved.Output()
	if err != nil || sshchildwrapper.ValidateRootSSHDResolvedConfig(configuration) != nil {
		gateC1bSetupFailure(t, cfg, "effective_sshd_policy")
	}
	clear(configuration)
	command := exec.Command(cfg.SSHDBinary, "-D", "-e", "-f", cfg.SSHDConfig)
	// Private test sshd diagnostics are reduced at the pipe boundary. No raw
	// line, address, key, account, path or command is saved or published.
	diagnostics := &gateC1bSSHDCounters{path: cfg.ReadyFile + ".counts"}
	defer func() {
		diagnostics.mu.Lock()
		clear(diagnostics.pending)
		diagnostics.pending = nil
		diagnostics.mu.Unlock()
	}()
	command.Stdout, command.Stderr = io.Discard, diagnostics
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	done, err := startGateC1bOwnedProcess(command)
	if err != nil {
		gateC1bSetupFailure(t, cfg, "sshd_start")
	}
	defer func() {
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Gate C1b isolated sshd did not drain")
		}
	}()
	deadline := time.Now().Add(gateC1bHostLimit)
	ready := false
	for time.Now().Before(deadline) {
		if !ready {
			// Passive readiness: no extra TCP connection is opened.
			check := exec.Command("ss", "-H", "-ltn", "sport = :22")
			check.Stderr = io.Discard
			listeners, err := check.Output()
			if err == nil && strings.TrimSpace(string(listeners)) != "" {
				ready = true
				if os.WriteFile(cfg.ReadyFile, []byte("ready\n"), 0o600) != nil {
					t.Fatal("Gate C1b listener readiness write failed")
				}
			}
		}
		if _, err := os.Stat(cfg.StopFile); err == nil {
			return
		}
		select {
		case <-done:
			// Refill the channel so deferred cleanup cannot wait a second time.
			done <- nil
			gateC1bSetupFailure(t, cfg, "sshd_early_exit")
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("Gate C1b isolated sshd lifetime exhausted")
}

type gateC1bSSHDWitness struct {
	Lines, AcceptedKey, FailedKey, AccountRejected, FileRejected, SessionStarted, SessionClosed, Fatal, OtherError int
	Overflow                                                                                                       bool
}

type gateC1bSSHDCounters struct {
	mu      sync.Mutex
	path    string
	pending []byte
	total   int
	witness gateC1bSSHDWitness
}

func (counter *gateC1bSSHDCounters) Write(data []byte) (int, error) {
	counter.mu.Lock()
	defer counter.mu.Unlock()
	for _, value := range data {
		if counter.total >= 64*1024 {
			counter.witness.Overflow = true
			break
		}
		counter.total++
		if value == '\n' {
			line := strings.ToLower(string(counter.pending))
			counter.witness.Lines++
			if strings.Contains(line, "accepted publickey") {
				counter.witness.AcceptedKey++
			}
			if strings.Contains(line, "failed publickey") {
				counter.witness.FailedKey++
			}
			if strings.Contains(line, "not allowed") || strings.Contains(line, "account is locked") {
				counter.witness.AccountRejected++
			}
			if strings.Contains(line, "bad ownership") || strings.Contains(line, "could not open") || strings.Contains(line, "authentication refused") {
				counter.witness.FileRejected++
			}
			if strings.Contains(line, "starting session") {
				counter.witness.SessionStarted++
			}
			if strings.Contains(line, "close session") || strings.Contains(line, "session closed") {
				counter.witness.SessionClosed++
			}
			if strings.Contains(line, "fatal:") {
				counter.witness.Fatal++
			}
			if strings.Contains(line, "error:") {
				counter.witness.OtherError++
			}
			clear(counter.pending)
			counter.pending = counter.pending[:0]
		} else if len(counter.pending) < 512 {
			counter.pending = append(counter.pending, value)
		}
	}
	if counter.path != "" {
		_ = writeN1JSON(counter.path, counter.witness)
	}
	return len(data), nil
}

func TestGateC1bSSHDiagnosticsAreBoundedAndRedacted(t *testing.T) {
	counter := &gateC1bSSHDCounters{}
	for _, chunk := range []string{"Authentication refused: bad owner", "ship or modes for directory /synthetic/private\n",
		"Accepted publickey for synthetic from 192.0.2.12 port 1234 ssh2: synthetic-key\n"} {
		if n, err := counter.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatal("diagnostic sink blocked sshd")
		}
	}
	if counter.witness.FileRejected != 1 || counter.witness.AcceptedKey != 1 {
		t.Fatal("diagnostic classification lost a split line")
	}
	payload, err := json.Marshal(counter.witness)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"synthetic", "192.0.2.12", "/private", "1234", "ssh2"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatal("diagnostic witness leaked source metadata")
		}
	}
	_, _ = counter.Write([]byte(strings.Repeat("x", 70*1024)))
	if !counter.witness.Overflow || counter.total > 64*1024 || len(counter.pending) > 512 {
		t.Fatal("diagnostic sink exceeded its hard memory bound")
	}
	clear(counter.pending)
}

func runGateC1bCLI(cfg gateC1bHostConfig, args []string) gateC1bProcessResult {
	result := gateC1bProcessResult{Root: os.Getuid() == 0 && os.Geteuid() == 0}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, gateC1bHostLimit-2*time.Second)
	defer cancel()
	proof := gatecorchestrator.NATLabProofOptions{Namespace: cfg.Namespace, Side: cfg.Side,
		SSHSide: cfg.SSHSide, Observers: cfg.Observers}
	var kernelInterface *gateC1bKernelInterface
	if cfg.UseTUN {
		proof.NewInterface = func(name string, mtu int) (netif.MemoryTestInterface, error) {
			var err error
			kernelInterface, err = newGateC1bKernelInterface(cfg, name, mtu)
			return kernelInterface, err
		}
	}
	proof.Progress = func(progress gatecorchestrator.Progress) error {
		result.Stages = append(result.Stages, progress.Stage)
		if err := os.WriteFile(cfg.StageFile, []byte(progress.Stage), 0o600); err != nil {
			return errors.New("private stage witness failed")
		}
		if progress.Stage == gatecorchestrator.StageDataPlaneReady && !cfg.Server {
			// Stop only after one completed post-OOB echo; this is the CLI's
			// normal caller cancellation path, not an attempt retry.
			cancel()
		}
		return nil
	}
	var err error
	result.Product, err = winkcmd.ExecuteGateCNATLabProof(ctx, args, os.Stdin, os.Stdout, os.Stderr, proof)
	if kernelInterface != nil {
		result.TUN = kernelInterface.witness()
	}
	if err != nil {
		var failure *gatecorchestrator.Failure
		if errors.As(err, &failure) {
			result.Class, result.Stage = failure.Class, failure.Stage
		} else if errors.Is(err, gatecorchestrator.ErrPeerUnauthorized) {
			result.Class, result.Stage = "peer_address_not_authorized", "isolated_authority"
		} else {
			result.Class = "gate_c_request_invalid"
		}
	}
	result.OK = err == nil && result.Product.DataPlaneReady && result.Product.FinishRecorded && result.Product.Terminal == "success"
	return result
}
