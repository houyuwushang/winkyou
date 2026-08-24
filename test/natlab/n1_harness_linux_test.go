//go:build linux && natlab

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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
)

const (
	n1RequiredEnv         = "WINKYOU_N1_REQUIRED"
	n1EndpointHelperEnv   = "WINKYOU_N1_ENDPOINT_HELPER"
	n1SupervisorHelperEnv = "WINKYOU_N1_SUPERVISOR_HELPER"
	n1HelperConfigEnv     = "WINKYOU_N1_HELPER_CONFIG"

	n1RoleLeft  = "left"
	n1RoleRight = "right"

	n1AttemptEnvelope = 15 * time.Second
	n1HarnessLimit    = 13 * time.Second
	n1TerminalMargin  = 2 * time.Second
	n1ProcessWait     = 16 * time.Second

	n1LeftAddress  = "192.0.2.1"
	n1RightAddress = "192.0.2.2"
	n1RightAlias   = "192.0.2.3"
	n1CIDRPrefix   = 29
	n1Interface    = "n1v0"

	n1ActionExchange      = "exchange"
	n1ActionSilentSender  = "silent_sender"
	n1ActionSilentPeer    = "silent_peer"
	n1ActionWaitCancel    = "wait_cancel"
	n1ActionHold          = "hold"
	n1ActionUnregistered  = "unregistered"
	n1ActionSecondTarget  = "second_target"
	n1ActionFourthPacket  = "fourth_packet"
	n1ActionOverPPS       = "over_pps"
	n1ActionWriterError   = "writer_error"
	n1TerminalExchanged   = "exchanged"
	n1TerminalSilent      = "silent"
	n1TerminalSilentPeer  = "silent_peer"
	n1TerminalCancelled   = "cancelled"
	n1TerminalFailClosed  = "fail_closed"
	n1TerminalWriterError = "writer_error"
)

var n1TopologySequence atomic.Uint32

var n1PlaintextSequence = [3][]byte{
	[]byte("WINKYOU-N1-1"),
	[]byte("WINKYOU-N1-2"),
	[]byte("WINKYOU-N1-3"),
}

type n1EndpointConfig struct {
	Role        string `json:"role"`
	GovernorDir string `json:"governor_dir"`
	ReadyPath   string `json:"ready_path"`
	ActionPath  string `json:"action_path"`
	ResultPath  string `json:"result_path"`
	PPS         int    `json:"pps"`
}

type n1SupervisorConfig struct {
	Namespace          string `json:"namespace"`
	EndpointConfigPath string `json:"endpoint_config_path"`
	ChildPIDPath       string `json:"child_pid_path"`
}

type n1SupervisorReady struct {
	PID int `json:"pid"`
}

type n1Ready struct {
	Port uint16 `json:"port"`
}

type n1Action struct {
	Kind       string `json:"kind"`
	PeerPort   uint16 `json:"peer_port,omitempty"`
	SecondPort uint16 `json:"second_port,omitempty"`
}

type n1EndpointResult struct {
	OK                  bool   `json:"ok"`
	Terminal            string `json:"terminal"`
	ErrorClass          string `json:"error_class,omitempty"`
	Sent                int    `json:"sent"`
	Received            int    `json:"received"`
	SafetyState         string `json:"safety_state"`
	SafetyBlocksWork    bool   `json:"safety_blocks_work"`
	ActivePeers         int    `json:"active_peers"`
	ActiveAttempts      int    `json:"active_attempts"`
	ReservedSockets     int    `json:"reserved_sockets"`
	ReservedTargets     int    `json:"reserved_targets"`
	ReservedFiveTuples  int    `json:"reserved_five_tuples"`
	ReservedPackets     int    `json:"reserved_packets"`
	ReservedPacketsPPS  int    `json:"reserved_packets_per_second"`
	ElapsedMilliseconds int64  `json:"elapsed_milliseconds"`
}

type n1PacketCounts struct {
	LeftOutbound  uint64
	LeftInbound   uint64
	RightOutbound uint64
	RightInbound  uint64
}

type n1Topology struct {
	leftNamespace  string
	rightNamespace string
	leftHostLink   string
	rightHostLink  string
	cleaned        bool
}

func TestN1EndpointProcess(t *testing.T) {
	if os.Getenv(n1EndpointHelperEnv) != "1" {
		return
	}
	config, ok := readN1EndpointConfig(os.Getenv(n1HelperConfigEnv))
	if !ok {
		t.Fatal("N1 endpoint helper configuration rejected")
	}
	result, runErr := runN1Endpoint(config)
	if runErr != nil {
		result.OK = false
		result.ErrorClass = classifyN1Error(runErr)
	}
	if err := writeN1JSON(config.ResultPath, result); err != nil {
		t.Fatal("N1 endpoint helper result write failed")
	}
	if runErr != nil {
		t.Error("N1 endpoint helper failed")
	}
}

func TestN1SupervisorProcess(t *testing.T) {
	if os.Getenv(n1SupervisorHelperEnv) != "1" {
		return
	}
	var config n1SupervisorConfig
	if !readN1JSON(os.Getenv(n1HelperConfigEnv), &config) || !safeNamePattern.MatchString(config.Namespace) || config.EndpointConfigPath == "" || config.ChildPIDPath == "" {
		t.Fatal("N1 supervisor helper configuration rejected")
	}
	command := n1EndpointCommand(config.Namespace, config.EndpointConfigPath)
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal("N1 supervised endpoint start failed")
	}
	if err := writeN1JSON(config.ChildPIDPath, n1SupervisorReady{PID: command.Process.Pid}); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("N1 supervisor readiness write failed")
	}
	if err := command.Wait(); err != nil {
		t.Error("N1 supervised endpoint stopped unexpectedly")
	}
}

func runN1Endpoint(config n1EndpointConfig) (result n1EndpointResult, resultErr error) {
	started := time.Now()
	result.SafetyState = string(governor.SafetyTripClear)
	defer func() {
		result.ElapsedMilliseconds = time.Since(started).Milliseconds()
	}()

	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	harnessContext, cancelHarness := context.WithDeadline(signalContext, started.Add(n1HarnessLimit))
	defer cancelHarness()

	owner, err := governor.AcquirePreparedNamespace(config.GovernorDir, governor.ScopeMachine, "n1-netns-test")
	if err != nil {
		return result, errors.Join(errors.New("owner_acquire"), err)
	}
	limits := n1GovernorLimits()
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, &limits)
	if err != nil {
		_ = owner.Close()
		return result, errors.Join(errors.New("governor_create"), err)
	}
	defer func() {
		if err := machine.Close(); err != nil && resultErr == nil {
			resultErr = errors.Join(errors.New("governor_close"), err)
		}
	}()

	peer, err := machine.AcquirePeer("n1-peer")
	if err != nil {
		return result, errors.Join(errors.New("peer_acquire"), err)
	}
	defer func() {
		if err := peer.Close(); err != nil && resultErr == nil {
			resultErr = errors.Join(errors.New("peer_close"), err)
		}
	}()

	resources := n1Resources()
	if config.PPS > 0 {
		resources.PacketsPerSecond = config.PPS
	}
	attempt, err := peer.AcquireAttempt(harnessContext, governor.AttemptRequest{
		ID:        "n1-attempt",
		Operation: governor.OperationConnectTest,
		Cost: governor.AttemptCost{
			Resources:   resources,
			Duration:    n1AttemptEnvelope,
			Heavyweight: true,
		},
	})
	if err != nil {
		return result, errors.Join(errors.New("attempt_acquire"), err)
	}

	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr:          netip.MustParseAddrPort("0.0.0.0:0"),
		AllowedTargetScope: probeio.AllowedTargetScopeUnicast,
	})
	if err != nil {
		_ = attempt.Close()
		return result, errors.Join(errors.New("factory_create"), err)
	}
	controller, err := probeio.New(probeio.Config{
		Lease:              attempt,
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "n1-netns-test",
	})
	if err != nil {
		_ = attempt.Close()
		return result, errors.Join(errors.New("controller_create"), err)
	}
	controllerClosed := false
	defer func() {
		if !controllerClosed {
			if err := controller.Close(); err != nil && resultErr == nil {
				resultErr = errors.Join(errors.New("controller_close"), err)
			}
		}
	}()

	socket, err := controller.OpenProbeSocket(harnessContext)
	if err != nil {
		return result, errors.Join(errors.New("socket_open"), err)
	}
	local, err := socket.LocalAddr()
	if err != nil || !local.Addr().IsUnspecified() || local.Port() == 0 {
		return result, errors.Join(errors.New("local_metadata"), err)
	}
	if err := writeN1JSON(config.ReadyPath, n1Ready{Port: local.Port()}); err != nil {
		return result, errors.Join(errors.New("ready_write"), err)
	}
	action, err := waitN1Action(harnessContext, config.ActionPath)
	if err != nil {
		return result, errors.Join(errors.New("action_wait"), err)
	}

	operationDeadline := started.Add(n1HarnessLimit - n1TerminalMargin)
	operationContext, cancelOperation := context.WithDeadline(harnessContext, operationDeadline)
	err = executeN1Action(operationContext, config.Role, socket, action, &result)
	cancelOperation()
	if err != nil {
		return result, err
	}

	if err := controller.Close(); err != nil {
		return result, errors.Join(errors.New("controller_close"), err)
	}
	controllerClosed = true
	if err := peer.Close(); err != nil {
		return result, errors.Join(errors.New("peer_close"), err)
	}
	snapshot := machine.Snapshot()
	result.SafetyState = string(snapshot.SafetyTrip.State)
	result.SafetyBlocksWork = snapshot.SafetyTrip.BlocksActiveWork
	result.ActivePeers = snapshot.ActivePeers
	result.ActiveAttempts = snapshot.ActiveAttempts
	result.ReservedSockets = snapshot.Reserved.Sockets
	result.ReservedTargets = snapshot.Reserved.Targets
	result.ReservedFiveTuples = snapshot.Reserved.FiveTuples
	result.ReservedPackets = snapshot.Reserved.Packets
	result.ReservedPacketsPPS = snapshot.Reserved.PacketsPerSecond
	result.OK = true
	return result, nil
}

func executeN1Action(ctx context.Context, role string, socket *probeio.ProbeSocket, action n1Action, result *n1EndpointResult) error {
	if result == nil || socket == nil {
		return errors.New("action_contract")
	}
	var target netip.AddrPort
	needsTarget := action.Kind != n1ActionSilentPeer && action.Kind != n1ActionWaitCancel && action.Kind != n1ActionHold
	if needsTarget {
		var err error
		target, err = n1TargetForRole(role, action.PeerPort)
		if err != nil {
			return errors.Join(errors.New("target_build"), err)
		}
	}

	switch action.Kind {
	case n1ActionExchange:
		if err := socket.RegisterTarget(target); err != nil {
			return errors.Join(errors.New("target_register"), err)
		}
		for _, packet := range n1PlaintextSequence {
			if err := socket.SendProbe(ctx, target, packet); err != nil {
				return errors.Join(errors.New("exchange_send"), err)
			}
			result.Sent++
		}
		for _, expected := range n1PlaintextSequence {
			buffer := make([]byte, 64)
			_, _, err := socket.ReceiveReply(ctx, buffer, func(packet []byte, from netip.AddrPort) error {
				if from != target || string(packet) != string(expected) {
					return errors.New("unexpected_plaintext")
				}
				return nil
			})
			if err != nil {
				return errors.Join(errors.New("exchange_receive"), err)
			}
			result.Received++
		}
		result.Terminal = n1TerminalExchanged
		return nil

	case n1ActionSilentSender:
		if err := socket.RegisterTarget(target); err != nil {
			return errors.Join(errors.New("target_register"), err)
		}
		for _, packet := range n1PlaintextSequence {
			if err := socket.SendProbe(ctx, target, packet); err != nil {
				return errors.Join(errors.New("silent_send"), err)
			}
			result.Sent++
		}
		_, _, err := socket.ReceiveReply(ctx, make([]byte, 64), func([]byte, netip.AddrPort) error { return nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(errors.New("silent_terminal"), err)
		}
		result.Terminal = n1TerminalSilent
		return nil

	case n1ActionSilentPeer:
		<-ctx.Done()
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.Join(errors.New("silent_peer_terminal"), ctx.Err())
		}
		result.Terminal = n1TerminalSilentPeer
		return nil

	case n1ActionWaitCancel:
		<-ctx.Done()
		if !errors.Is(ctx.Err(), context.Canceled) {
			return errors.Join(errors.New("cancel_terminal"), ctx.Err())
		}
		result.Terminal = n1TerminalCancelled
		return nil

	case n1ActionHold:
		<-ctx.Done()
		return errors.Join(errors.New("hold_terminal"), ctx.Err())

	case n1ActionUnregistered:
		err := socket.SendProbe(ctx, target, n1PlaintextSequence[0])
		if !errors.Is(err, probeio.ErrUnregisteredTarget) {
			return errors.Join(errors.New("unregistered_not_blocked"), err)
		}
		result.Terminal = n1TerminalFailClosed
		result.ErrorClass = "unregistered_target"
		return nil

	case n1ActionSecondTarget:
		if err := socket.RegisterTarget(target); err != nil {
			return errors.Join(errors.New("first_target_register"), err)
		}
		second, err := n1SecondTargetForRole(role, action.SecondPort)
		if err != nil || second == target {
			return errors.Join(errors.New("second_target_build"), err)
		}
		err = socket.RegisterTarget(second)
		if !errors.Is(err, probeio.ErrHardLimit) {
			return errors.Join(errors.New("second_target_not_blocked"), err)
		}
		result.Terminal = n1TerminalFailClosed
		result.ErrorClass = "second_target"
		return nil

	case n1ActionFourthPacket:
		if err := socket.RegisterTarget(target); err != nil {
			return errors.Join(errors.New("target_register"), err)
		}
		for _, packet := range n1PlaintextSequence {
			if err := socket.SendProbe(ctx, target, packet); err != nil {
				return errors.Join(errors.New("budgeted_send"), err)
			}
			result.Sent++
		}
		err := socket.SendProbe(ctx, target, []byte("WINKYOU-N1-4-BLOCKED"))
		if !errors.Is(err, probeio.ErrHardLimit) {
			return errors.Join(errors.New("fourth_packet_not_blocked"), err)
		}
		result.Terminal = n1TerminalFailClosed
		result.ErrorClass = "packet_limit"
		return nil

	case n1ActionOverPPS:
		if err := socket.RegisterTarget(target); err != nil {
			return errors.Join(errors.New("target_register"), err)
		}
		for index := 0; index < 2; index++ {
			if err := socket.SendProbe(ctx, target, n1PlaintextSequence[index]); err != nil {
				return errors.Join(errors.New("budgeted_send"), err)
			}
			result.Sent++
		}
		err := socket.SendProbe(ctx, target, n1PlaintextSequence[2])
		if !errors.Is(err, probeio.ErrHardLimit) {
			return errors.Join(errors.New("pps_not_blocked"), err)
		}
		result.Terminal = n1TerminalFailClosed
		result.ErrorClass = "pps_limit"
		return nil

	case n1ActionWriterError:
		if err := socket.RegisterTarget(target); err != nil {
			return errors.Join(errors.New("target_register"), err)
		}
		for index := 0; index < 3; index++ {
			err := socket.SendProbe(ctx, target, n1PlaintextSequence[index])
			if err == nil {
				return errors.New("writer_error_missing")
			}
			if index == 2 && !errors.Is(err, probeio.ErrWriteFailures) {
				return errors.Join(errors.New("writer_trip_missing"), err)
			}
		}
		result.Terminal = n1TerminalWriterError
		result.ErrorClass = "write_failures"
		return nil

	default:
		return errors.New("unknown_action")
	}
}

func n1Resources() governor.Resources {
	return governor.Resources{
		Sockets:          1,
		Targets:          1,
		PacketsPerSecond: 3,
		Packets:          3,
		FiveTuples:       1,
	}
}

func n1GovernorLimits() governor.Limits {
	resources := n1Resources()
	return governor.Limits{
		MaxActivePeers:           1,
		MaxActiveAttempts:        1,
		MaxAttemptsPerPeer:       1,
		MaxHeavyweightAttempts:   1,
		MaxAttemptDuration:       n1AttemptEnvelope,
		CancellationDrainTimeout: n1TerminalMargin,
		Aggregate:                resources,
		PerAttempt:               resources,
	}
}

func n1TargetForRole(role string, port uint16) (netip.AddrPort, error) {
	if port == 0 {
		return netip.AddrPort{}, errors.New("zero_port")
	}
	var address netip.Addr
	switch role {
	case n1RoleLeft:
		address = netip.MustParseAddr(n1RightAddress)
	case n1RoleRight:
		address = netip.MustParseAddr(n1LeftAddress)
	default:
		return netip.AddrPort{}, errors.New("invalid_role")
	}
	return netip.AddrPortFrom(address, port), nil
}

func n1SecondTargetForRole(role string, port uint16) (netip.AddrPort, error) {
	if role != n1RoleLeft || port == 0 {
		return netip.AddrPort{}, errors.New("invalid_second_target")
	}
	return netip.AddrPortFrom(netip.MustParseAddr(n1RightAlias), port), nil
}

func readN1EndpointConfig(path string) (n1EndpointConfig, bool) {
	var config n1EndpointConfig
	if !readN1JSON(path, &config) {
		return n1EndpointConfig{}, false
	}
	if config.Role != n1RoleLeft && config.Role != n1RoleRight {
		return n1EndpointConfig{}, false
	}
	if config.GovernorDir == "" || config.ReadyPath == "" || config.ActionPath == "" || config.ResultPath == "" {
		return n1EndpointConfig{}, false
	}
	if config.PPS != 0 && config.PPS != 2 && config.PPS != 3 {
		return n1EndpointConfig{}, false
	}
	return config, true
}

func waitN1Action(ctx context.Context, path string) (n1Action, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var action n1Action
		if readN1JSON(path, &action) {
			return action, nil
		}
		select {
		case <-ctx.Done():
			return n1Action{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func readN1JSON(path string, destination any) bool {
	if path == "" || destination == nil {
		return false
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	return true
}

func writeN1JSON(path string, value any) error {
	if path == "" {
		return errors.New("empty_path")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(payload)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func classifyN1Error(err error) string {
	if err == nil {
		return ""
	}
	stable := []string{
		"owner_acquire", "governor_create", "governor_close", "peer_acquire", "peer_close",
		"attempt_acquire", "factory_create", "controller_create", "controller_close", "socket_open",
		"local_metadata", "ready_write", "action_wait", "target_build", "target_register",
		"exchange_send", "exchange_receive", "silent_send", "silent_terminal", "silent_peer_terminal",
		"cancel_terminal", "hold_terminal", "unregistered_not_blocked", "first_target_register",
		"second_target_build", "second_target_not_blocked", "budgeted_send", "fourth_packet_not_blocked",
		"pps_not_blocked", "writer_error_missing", "writer_trip_missing", "unknown_action", "action_contract",
	}
	message := err.Error()
	for _, class := range stable {
		if strings.Contains(message, class) {
			return class
		}
	}
	return "internal_error"
}

type n1EndpointProcess struct {
	command     *exec.Cmd
	done        chan struct{}
	waitMu      sync.Mutex
	waitErr     error
	readyPath   string
	actionPath  string
	resultPath  string
	governorDir string
	configPath  string
	namespace   string
	role        string
	port        uint16
	cleanupOnce sync.Once
	started     bool
}

func newN1EndpointProcess(t *testing.T, topology *n1Topology, role string, pps int) *n1EndpointProcess {
	t.Helper()
	directory := t.TempDir()
	governorDir := filepath.Join(directory, "governor")
	if err := os.Mkdir(governorDir, 0o700); err != nil {
		t.Fatal("N1 governor namespace setup failed")
	}
	if err := governor.PrepareN1TestNamespace(governorDir, time.Now().UTC()); err != nil {
		t.Fatal("N1 governor safety state preparation failed")
	}
	process := &n1EndpointProcess{
		done:        make(chan struct{}),
		readyPath:   filepath.Join(directory, "ready.json"),
		actionPath:  filepath.Join(directory, "action.json"),
		resultPath:  filepath.Join(directory, "result.json"),
		governorDir: governorDir,
		configPath:  filepath.Join(directory, "config.json"),
		role:        role,
	}
	if role == n1RoleLeft {
		process.namespace = topology.leftNamespace
	} else if role == n1RoleRight {
		process.namespace = topology.rightNamespace
	} else {
		t.Fatal("N1 endpoint role rejected")
	}
	config := n1EndpointConfig{
		Role:        role,
		GovernorDir: governorDir,
		ReadyPath:   process.readyPath,
		ActionPath:  process.actionPath,
		ResultPath:  process.resultPath,
		PPS:         pps,
	}
	if err := writeN1JSON(process.configPath, config); err != nil {
		t.Fatal("N1 endpoint configuration write failed")
	}
	process.command = n1EndpointCommand(process.namespace, process.configPath)
	process.command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	process.command.Stdout = io.Discard
	process.command.Stderr = io.Discard
	t.Cleanup(process.stop)
	return process
}

func n1EndpointCommand(namespace, configPath string) *exec.Cmd {
	command := exec.Command(
		"ip", "netns", "exec", namespace, os.Args[0],
		"-test.run=^TestN1EndpointProcess$", "-test.count=1", "-test.timeout=18s",
	)
	command.Env = append(os.Environ(), n1EndpointHelperEnv+"=1", n1HelperConfigEnv+"="+configPath)
	return command
}

func (process *n1EndpointProcess) start(t *testing.T) {
	t.Helper()
	if process == nil || process.command == nil || process.started {
		t.Fatal("N1 endpoint start contract failed")
	}
	if err := process.command.Start(); err != nil {
		t.Fatal("N1 endpoint process start failed")
	}
	process.started = true
	go func() {
		err := process.command.Wait()
		process.waitMu.Lock()
		process.waitErr = err
		process.waitMu.Unlock()
		close(process.done)
	}()
}

func (process *n1EndpointProcess) waitReady(t *testing.T) uint16 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var ready n1Ready
		if readN1JSON(process.readyPath, &ready) && ready.Port != 0 {
			process.port = ready.Port
			return ready.Port
		}
		var result n1EndpointResult
		if readN1JSON(process.resultPath, &result) && !result.OK {
			t.Fatalf("N1 endpoint exited before socket-ready: class=%s", result.ErrorClass)
		}
		select {
		case <-process.done:
			t.Fatal("N1 endpoint exited before socket-ready without a result")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("N1 endpoint socket-ready deadline exceeded")
	return 0
}

func (process *n1EndpointProcess) writeAction(t *testing.T, action n1Action) {
	t.Helper()
	if err := writeN1JSON(process.actionPath, action); err != nil {
		t.Fatal("N1 endpoint action write failed")
	}
}

func (process *n1EndpointProcess) waitResult(t *testing.T) n1EndpointResult {
	t.Helper()
	deadline := time.Now().Add(n1ProcessWait)
	for time.Now().Before(deadline) {
		var result n1EndpointResult
		if readN1JSON(process.resultPath, &result) {
			if !process.await(2 * time.Second) {
				t.Fatal("N1 endpoint process did not exit after result")
			}
			process.waitMu.Lock()
			waitErr := process.waitErr
			process.waitMu.Unlock()
			if waitErr != nil {
				t.Fatal("N1 endpoint process returned failure")
			}
			return result
		}
		select {
		case <-process.done:
			t.Fatal("N1 endpoint exited without result")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	process.stop()
	t.Fatal("N1 endpoint result deadline exceeded")
	return n1EndpointResult{}
}

func (process *n1EndpointProcess) await(timeout time.Duration) bool {
	if process == nil || !process.started {
		return true
	}
	select {
	case <-process.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (process *n1EndpointProcess) signal(t *testing.T, signal os.Signal) {
	t.Helper()
	if process == nil || process.command == nil || process.command.Process == nil {
		t.Fatal("N1 endpoint signal contract failed")
	}
	if err := process.command.Process.Signal(signal); err != nil {
		t.Fatal("N1 endpoint signal failed")
	}
}

func (process *n1EndpointProcess) kill(t *testing.T) {
	t.Helper()
	if process == nil || process.command == nil || process.command.Process == nil {
		t.Fatal("N1 endpoint kill contract failed")
	}
	if err := process.command.Process.Kill(); err != nil {
		t.Fatal("N1 endpoint kill failed")
	}
	if !process.await(2 * time.Second) {
		t.Fatal("N1 endpoint kill was not bounded")
	}
}

func (process *n1EndpointProcess) stop() {
	if process == nil {
		return
	}
	process.cleanupOnce.Do(func() {
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
		case <-time.After(2 * time.Second):
		}
	})
}

func newN1Topology(t *testing.T) *n1Topology {
	t.Helper()
	sequence := n1TopologySequence.Add(1)
	suffix := fmt.Sprintf("%06x", (uint32(time.Now().UnixNano())+sequence)&0xffffff)
	topology := &n1Topology{
		leftNamespace:  "wyn1l" + suffix,
		rightNamespace: "wyn1r" + suffix,
		leftHostLink:   "n1l" + suffix,
		rightHostLink:  "n1r" + suffix,
	}
	t.Cleanup(func() {
		if err := topology.cleanup(); err != nil {
			t.Error("N1 topology cleanup failed")
		}
		if err := topology.assertNoLeaks(); err != nil {
			t.Error("N1 topology residue detected")
		}
	})
	if err := topology.create(); err != nil {
		_ = topology.cleanup()
		t.Fatal("N1 topology setup failed")
	}
	return topology
}

func (topology *n1Topology) create() error {
	if topology == nil {
		return errors.New("nil_topology")
	}
	if _, err := runCommand("ip", "netns", "add", topology.leftNamespace); err != nil {
		return err
	}
	if _, err := runCommand("ip", "netns", "add", topology.rightNamespace); err != nil {
		return err
	}
	if _, err := runCommand("ip", "link", "add", topology.leftHostLink, "type", "veth", "peer", "name", topology.rightHostLink); err != nil {
		return err
	}
	if _, err := runCommand("ip", "link", "set", topology.leftHostLink, "netns", topology.leftNamespace); err != nil {
		return err
	}
	if _, err := runCommand("ip", "link", "set", topology.rightHostLink, "netns", topology.rightNamespace); err != nil {
		return err
	}
	for _, namespace := range []string{topology.leftNamespace, topology.rightNamespace} {
		if _, err := runCommand("ip", "-n", namespace, "link", "set", "lo", "up"); err != nil {
			return err
		}
	}
	if err := topology.configureEnd(topology.leftNamespace, topology.leftHostLink, n1LeftAddress); err != nil {
		return err
	}
	if err := topology.configureEnd(topology.rightNamespace, topology.rightHostLink, n1RightAddress); err != nil {
		return err
	}
	if _, err := runCommand("ip", "-n", topology.rightNamespace, "addr", "add", n1RightAlias+"/"+strconv.Itoa(n1CIDRPrefix), "dev", n1Interface); err != nil {
		return err
	}
	for _, namespace := range []string{topology.leftNamespace, topology.rightNamespace} {
		if err := installN1PacketCounters(namespace); err != nil {
			return err
		}
	}
	return nil
}

func (topology *n1Topology) configureEnd(namespace, temporaryName, address string) error {
	if _, err := runCommand("ip", "-n", namespace, "link", "set", temporaryName, "name", n1Interface); err != nil {
		return err
	}
	if _, err := runCommand("ip", "-n", namespace, "addr", "add", address+"/"+strconv.Itoa(n1CIDRPrefix), "dev", n1Interface); err != nil {
		return err
	}
	_, err := runCommand("ip", "-n", namespace, "link", "set", n1Interface, "up")
	return err
}

func installN1PacketCounters(namespace string) error {
	commands := [][]string{
		{"-w", "5", "-N", "WINKYOU_N1_OUT"},
		{"-w", "5", "-A", "WINKYOU_N1_OUT", "-j", "RETURN"},
		{"-w", "5", "-A", "OUTPUT", "-o", n1Interface, "-p", "udp", "-j", "WINKYOU_N1_OUT"},
		{"-w", "5", "-N", "WINKYOU_N1_IN"},
		{"-w", "5", "-A", "WINKYOU_N1_IN", "-j", "RETURN"},
		{"-w", "5", "-A", "INPUT", "-i", n1Interface, "-p", "udp", "-j", "WINKYOU_N1_IN"},
	}
	for _, args := range commands {
		if _, err := runNamespaced(namespace, "iptables", nil, args...); err != nil {
			return err
		}
	}
	return nil
}

func (topology *n1Topology) packetCounts() (n1PacketCounts, error) {
	leftOut, err := n1ChainPackets(topology.leftNamespace, "WINKYOU_N1_OUT")
	if err != nil {
		return n1PacketCounts{}, err
	}
	leftIn, err := n1ChainPackets(topology.leftNamespace, "WINKYOU_N1_IN")
	if err != nil {
		return n1PacketCounts{}, err
	}
	rightOut, err := n1ChainPackets(topology.rightNamespace, "WINKYOU_N1_OUT")
	if err != nil {
		return n1PacketCounts{}, err
	}
	rightIn, err := n1ChainPackets(topology.rightNamespace, "WINKYOU_N1_IN")
	if err != nil {
		return n1PacketCounts{}, err
	}
	return n1PacketCounts{LeftOutbound: leftOut, LeftInbound: leftIn, RightOutbound: rightOut, RightInbound: rightIn}, nil
}

func n1ChainPackets(namespace, chain string) (uint64, error) {
	output, err := runNamespaced(namespace, "iptables", nil, "-w", "5", "-L", chain, "-v", "-n", "-x")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "RETURN" {
			continue
		}
		packets, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, err
		}
		return packets, nil
	}
	return 0, errors.New("counter_missing")
}

func (topology *n1Topology) socketCount(namespace string, port uint16) (int, error) {
	output, err := runNamespaced(namespace, "ss", nil, "-H", "-u", "-a", "-n")
	if err != nil {
		return 0, err
	}
	want := ":" + strconv.Itoa(int(port))
	count := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for _, field := range fields {
			if strings.HasSuffix(field, want) {
				count++
				break
			}
		}
	}
	return count, nil
}

func (topology *n1Topology) allSocketCount(namespace string) (int, error) {
	output, err := runNamespaced(namespace, "ss", nil, "-H", "-u", "-a", "-n")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}

func (topology *n1Topology) flushAndCountConntrack() (before, after int, resultErr error) {
	for _, namespace := range []string{topology.leftNamespace, topology.rightNamespace} {
		output, err := runNamespaced(namespace, "conntrack", nil, "-C")
		if err != nil {
			return 0, 0, err
		}
		count, err := strconv.Atoi(strings.TrimSpace(output))
		if err != nil {
			return 0, 0, err
		}
		before += count
		if _, err := runNamespaced(namespace, "conntrack", nil, "-F"); err != nil {
			return 0, 0, err
		}
		output, err = runNamespaced(namespace, "conntrack", nil, "-C")
		if err != nil {
			return 0, 0, err
		}
		count, err = strconv.Atoi(strings.TrimSpace(output))
		if err != nil {
			return 0, 0, err
		}
		after += count
	}
	return before, after, nil
}

func (topology *n1Topology) setLink(namespace string, up bool) error {
	state := "down"
	if up {
		state = "up"
	}
	_, err := runCommand("ip", "-n", namespace, "link", "set", n1Interface, state)
	return err
}

func (topology *n1Topology) cleanup() error {
	if topology == nil || topology.cleaned {
		return nil
	}
	topology.cleaned = true
	var result error
	for _, namespace := range []string{topology.leftNamespace, topology.rightNamespace} {
		exists, err := namespaceExists(namespace)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if exists {
			_, err = runCommand("ip", "netns", "del", namespace)
			result = errors.Join(result, err)
		}
	}
	for _, link := range []string{topology.leftHostLink, topology.rightHostLink} {
		exists, err := hostLinkExists(link)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if exists {
			_, err = runCommand("ip", "link", "del", link)
			result = errors.Join(result, err)
		}
	}
	return result
}

func (topology *n1Topology) assertNoLeaks() error {
	if topology == nil {
		return nil
	}
	for _, namespace := range []string{topology.leftNamespace, topology.rightNamespace} {
		exists, err := namespaceExists(namespace)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("namespace_residue")
		}
	}
	for _, link := range []string{topology.leftHostLink, topology.rightHostLink} {
		exists, err := hostLinkExists(link)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("link_residue")
		}
	}
	return nil
}
