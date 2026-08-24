//go:build linux && natlab

package natlab

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
)

func TestLinuxN1UnicastProof(t *testing.T) {
	requireN1Environment(t)

	t.Run("bidirectional_exact", testN1BidirectionalExact)
	t.Run("fail_closed_unregistered_target", testN1UnregisteredTarget)
	t.Run("fail_closed_second_target", testN1SecondTarget)
	t.Run("fail_closed_fourth_packet", testN1FourthPacket)
	t.Run("fail_closed_over_pps", testN1OverPPS)
	t.Run("silent_peer_clean_terminal", testN1SilentPeer)
	t.Run("active_cancel_bounded", testN1ActiveCancel)
	t.Run("writer_error_bounded", testN1WriterError)
	t.Run("child_kill_os_drain", testN1ChildKill)
	t.Run("parent_termination_os_drain", testN1ParentTermination)
}

func testN1BidirectionalExact(t *testing.T) {
	topology := newN1Topology(t)
	left := newN1EndpointProcess(t, topology, n1RoleLeft, 3)
	right := newN1EndpointProcess(t, topology, n1RoleRight, 3)
	left.start(t)
	right.start(t)
	leftPort := left.waitReady(t)
	rightPort := right.waitReady(t)
	assertN1SocketCount(t, topology, topology.leftNamespace, leftPort, 1)
	assertN1SocketCount(t, topology, topology.rightNamespace, rightPort, 1)

	left.writeAction(t, n1Action{Kind: n1ActionExchange, PeerPort: rightPort})
	right.writeAction(t, n1Action{Kind: n1ActionExchange, PeerPort: leftPort})
	leftResult := left.waitResult(t)
	rightResult := right.waitResult(t)
	assertN1Result(t, leftResult, n1TerminalExchanged, "", 3, 3, false)
	assertN1Result(t, rightResult, n1TerminalExchanged, "", 3, 3, false)

	counts := requireN1PacketCounts(t, topology)
	if counts != (n1PacketCounts{LeftOutbound: 3, LeftInbound: 3, RightOutbound: 3, RightInbound: 3}) {
		t.Fatalf("N1 bidirectional packet witness = %+v, want exact 3/3 per endpoint", counts)
	}
	logN1PacketCounts(t, counts)
	assertN1GovernorClear(t, left.governorDir)
	assertN1GovernorClear(t, right.governorDir)
	assertN1NoResidue(t, topology, left, right)
}

func testN1UnregisteredTarget(t *testing.T) {
	topology, left, right, _, rightPort := startN1LimitPair(t, 3)
	left.writeAction(t, n1Action{Kind: n1ActionUnregistered, PeerPort: rightPort})
	right.writeAction(t, n1Action{Kind: n1ActionHold})
	result := left.waitResult(t)
	assertN1Result(t, result, n1TerminalFailClosed, "unregistered_target", 0, 0, false)
	counts := requireN1PacketCounts(t, topology)
	if counts != (n1PacketCounts{}) {
		t.Fatalf("N1 unregistered target emitted packets: %+v", counts)
	}
	logN1PacketCounts(t, counts)
	right.kill(t)
	assertN1GovernorClear(t, left.governorDir)
	assertN1NoResidue(t, topology, left, right)
}

func testN1SecondTarget(t *testing.T) {
	topology, left, right, _, rightPort := startN1LimitPair(t, 3)
	left.writeAction(t, n1Action{Kind: n1ActionSecondTarget, PeerPort: rightPort, SecondPort: rightPort})
	right.writeAction(t, n1Action{Kind: n1ActionHold})
	result := left.waitResult(t)
	assertN1Result(t, result, n1TerminalFailClosed, "second_target", 0, 0, true)
	counts := requireN1PacketCounts(t, topology)
	if counts != (n1PacketCounts{}) {
		t.Fatalf("N1 second target emitted packets: %+v", counts)
	}
	logN1PacketCounts(t, counts)
	right.kill(t)
	assertN1GovernorTripped(t, left.governorDir)
	assertN1NoResidue(t, topology, left, right)
}

func testN1FourthPacket(t *testing.T) {
	topology, left, right, _, rightPort := startN1LimitPair(t, 3)
	left.writeAction(t, n1Action{Kind: n1ActionFourthPacket, PeerPort: rightPort})
	right.writeAction(t, n1Action{Kind: n1ActionHold})
	result := left.waitResult(t)
	assertN1Result(t, result, n1TerminalFailClosed, "packet_limit", 3, 0, true)
	counts := requireN1PacketCounts(t, topology)
	if counts.LeftOutbound != 3 || counts.RightInbound != 3 || counts.LeftInbound != 0 || counts.RightOutbound != 0 {
		t.Fatalf("N1 fourth-packet witness = %+v, want exactly three delivered packets", counts)
	}
	logN1PacketCounts(t, counts)
	right.kill(t)
	assertN1GovernorTripped(t, left.governorDir)
	assertN1NoResidue(t, topology, left, right)
}

func testN1OverPPS(t *testing.T) {
	// The frozen envelope remains 3 PPS. This attempt deliberately reserves a
	// narrower 2 PPS so the third packet proves the PPS branch without raising
	// the three-packet total budget merely to reach it.
	topology, left, right, _, rightPort := startN1LimitPair(t, 2)
	left.writeAction(t, n1Action{Kind: n1ActionOverPPS, PeerPort: rightPort})
	right.writeAction(t, n1Action{Kind: n1ActionHold})
	result := left.waitResult(t)
	assertN1Result(t, result, n1TerminalFailClosed, "pps_limit", 2, 0, true)
	counts := requireN1PacketCounts(t, topology)
	if counts.LeftOutbound != 2 || counts.RightInbound != 2 || counts.LeftInbound != 0 || counts.RightOutbound != 0 {
		t.Fatalf("N1 PPS witness = %+v, want exactly two delivered packets", counts)
	}
	logN1PacketCounts(t, counts)
	right.kill(t)
	assertN1GovernorTripped(t, left.governorDir)
	assertN1NoResidue(t, topology, left, right)
}

func testN1SilentPeer(t *testing.T) {
	topology := newN1Topology(t)
	left := newN1EndpointProcess(t, topology, n1RoleLeft, 3)
	right := newN1EndpointProcess(t, topology, n1RoleRight, 3)
	left.start(t)
	right.start(t)
	leftPort := left.waitReady(t)
	rightPort := right.waitReady(t)
	left.writeAction(t, n1Action{Kind: n1ActionSilentSender, PeerPort: rightPort})
	right.writeAction(t, n1Action{Kind: n1ActionSilentPeer, PeerPort: leftPort})
	started := time.Now()
	leftResult := left.waitResult(t)
	rightResult := right.waitResult(t)
	if elapsed := time.Since(started); elapsed >= n1HarnessLimit {
		t.Fatalf("N1 silent-peer terminal took %v, want under %v", elapsed, n1HarnessLimit)
	}
	assertN1Result(t, leftResult, n1TerminalSilent, "", 3, 0, false)
	assertN1Result(t, rightResult, n1TerminalSilentPeer, "", 0, 0, false)
	counts := requireN1PacketCounts(t, topology)
	if counts.LeftOutbound != 3 || counts.RightInbound != 3 || counts.LeftInbound != 0 || counts.RightOutbound != 0 {
		t.Fatalf("N1 silent-peer witness = %+v, want three one-way packets", counts)
	}
	logN1PacketCounts(t, counts)
	assertN1GovernorClear(t, left.governorDir)
	assertN1GovernorClear(t, right.governorDir)
	assertN1NoResidue(t, topology, left, right)
}

func testN1ActiveCancel(t *testing.T) {
	topology := newN1Topology(t)
	left := newN1EndpointProcess(t, topology, n1RoleLeft, 3)
	left.start(t)
	leftPort := left.waitReady(t)
	left.writeAction(t, n1Action{Kind: n1ActionWaitCancel})
	left.waitActionAccepted(t)
	assertN1SocketCount(t, topology, topology.leftNamespace, leftPort, 1)
	started := time.Now()
	left.signal(t, syscall.SIGTERM)
	result := left.waitResult(t)
	if elapsed := time.Since(started); elapsed >= n1TerminalMargin {
		t.Fatalf("N1 active cancellation took %v, want under %v", elapsed, n1TerminalMargin)
	}
	assertN1Result(t, result, n1TerminalCancelled, "", 0, 0, false)
	if counts := requireN1PacketCounts(t, topology); counts != (n1PacketCounts{}) {
		t.Fatalf("N1 cancellation emitted packets: %+v", counts)
	} else {
		logN1PacketCounts(t, counts)
	}
	assertN1GovernorClear(t, left.governorDir)
	assertN1NoResidue(t, topology, left)
}

func testN1WriterError(t *testing.T) {
	topology, left, right, _, rightPort := startN1LimitPair(t, 3)
	right.writeAction(t, n1Action{Kind: n1ActionHold})
	if err := topology.setLink(topology.leftNamespace, false); err != nil {
		t.Fatal("N1 writer-error fault injection failed")
	}
	time.Sleep(50 * time.Millisecond)
	left.writeAction(t, n1Action{Kind: n1ActionWriterError, PeerPort: rightPort})
	started := time.Now()
	result := left.waitResult(t)
	if elapsed := time.Since(started); elapsed >= n1TerminalMargin {
		t.Fatalf("N1 writer-error terminal took %v, want under %v", elapsed, n1TerminalMargin)
	}
	assertN1Result(t, result, n1TerminalWriterError, "write_failures", 0, 0, true)
	right.kill(t)
	if err := topology.setLink(topology.leftNamespace, true); err != nil {
		t.Fatal("N1 writer-error link restoration failed")
	}
	counts := requireN1PacketCounts(t, topology)
	if counts.LeftOutbound > 3 || counts.RightInbound > 3 || counts.RightOutbound != 0 || counts.LeftInbound != 0 {
		t.Fatalf("N1 writer-error packet witness exceeded the envelope: %+v", counts)
	}
	logN1PacketCounts(t, counts)
	assertN1GovernorTripped(t, left.governorDir)
	assertN1NoResidue(t, topology, left, right)
}

func testN1ChildKill(t *testing.T) {
	topology := newN1Topology(t)
	left := newN1EndpointProcess(t, topology, n1RoleLeft, 3)
	left.start(t)
	leftPort := left.waitReady(t)
	left.writeAction(t, n1Action{Kind: n1ActionHold})
	assertN1SocketCount(t, topology, topology.leftNamespace, leftPort, 1)
	started := time.Now()
	left.kill(t)
	assertN1SocketCount(t, topology, topology.leftNamespace, leftPort, 0)
	if elapsed := time.Since(started); elapsed >= n1TerminalMargin {
		t.Fatalf("N1 child-kill drain took %v, want under %v", elapsed, n1TerminalMargin)
	}
	if counts := requireN1PacketCounts(t, topology); counts != (n1PacketCounts{}) {
		t.Fatalf("N1 child kill emitted packets: %+v", counts)
	} else {
		logN1PacketCounts(t, counts)
	}
	assertN1OwnerLockReleased(t, left.governorDir)
	assertN1NoResidue(t, topology, left)
}

func testN1ParentTermination(t *testing.T) {
	topology := newN1Topology(t)
	endpoint := newN1EndpointProcess(t, topology, n1RoleLeft, 3)
	directory := t.TempDir()
	pidPath := filepath.Join(directory, "child.json")
	configPath := filepath.Join(directory, "supervisor.json")
	if err := writeN1JSON(configPath, n1SupervisorConfig{
		Namespace:          topology.leftNamespace,
		EndpointConfigPath: endpoint.configPath,
		ChildPIDPath:       pidPath,
	}); err != nil {
		t.Fatal("N1 supervisor configuration write failed")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestN1SupervisorProcess$", "-test.count=1", "-test.timeout=18s")
	command.Env = append(os.Environ(), n1SupervisorHelperEnv+"=1", n1HelperConfigEnv+"="+configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		t.Fatal("N1 supervisor process start failed")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() {
		select {
		case <-done:
		default:
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(n1TerminalMargin):
			}
		}
	}()

	leftPort := endpoint.waitReady(t)
	childPID := waitN1SupervisorPID(t, pidPath)
	defer func() { _ = syscall.Kill(childPID, syscall.SIGKILL) }()
	endpoint.writeAction(t, n1Action{Kind: n1ActionHold})
	assertN1SocketCount(t, topology, topology.leftNamespace, leftPort, 1)
	started := time.Now()
	if err := command.Process.Kill(); err != nil {
		t.Fatal("N1 supervisor termination failed")
	}
	select {
	case <-done:
	case <-time.After(n1TerminalMargin):
		t.Fatal("N1 supervisor termination was not bounded")
	}
	if !waitN1PIDGone(childPID, n1TerminalMargin) {
		t.Fatal("N1 parent-death child remained alive")
	}
	assertN1SocketCount(t, topology, topology.leftNamespace, leftPort, 0)
	if elapsed := time.Since(started); elapsed >= n1TerminalMargin {
		t.Fatalf("N1 parent-death drain took %v, want under %v", elapsed, n1TerminalMargin)
	}
	if counts := requireN1PacketCounts(t, topology); counts != (n1PacketCounts{}) {
		t.Fatalf("N1 parent termination emitted packets: %+v", counts)
	} else {
		logN1PacketCounts(t, counts)
	}
	assertN1OwnerLockReleased(t, endpoint.governorDir)
	assertN1NoResidue(t, topology, endpoint)
}

func startN1LimitPair(t *testing.T, leftPPS int) (*n1Topology, *n1EndpointProcess, *n1EndpointProcess, uint16, uint16) {
	t.Helper()
	topology := newN1Topology(t)
	left := newN1EndpointProcess(t, topology, n1RoleLeft, leftPPS)
	right := newN1EndpointProcess(t, topology, n1RoleRight, 3)
	left.start(t)
	right.start(t)
	leftPort := left.waitReady(t)
	rightPort := right.waitReady(t)
	assertN1SocketCount(t, topology, topology.leftNamespace, leftPort, 1)
	assertN1SocketCount(t, topology, topology.rightNamespace, rightPort, 1)
	return topology, left, right, leftPort, rightPort
}

func requireN1Environment(t *testing.T) {
	t.Helper()
	required := os.Getenv(n1RequiredEnv) == "1"
	failOrSkip := func(message string) {
		if required {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	if os.Geteuid() != 0 {
		failOrSkip("N1 requires an isolated root network namespace")
	}
	for _, program := range []string{"ip", "iptables", "ss", "conntrack"} {
		if _, err := exec.LookPath(program); err != nil {
			failOrSkip("N1 isolated-network prerequisite is unavailable")
		}
	}
	if err := probeN1NamespaceAuthority(); err != nil {
		failOrSkip("N1 network namespace authority is unavailable")
	}
}

func probeN1NamespaceAuthority() error {
	sequence := n1TopologySequence.Add(1)
	name := "wyn1p" + strconv.FormatUint(uint64(sequence), 16)
	if _, err := runCommand("ip", "netns", "add", name); err != nil {
		return err
	}
	defer func() { _, _ = runCommand("ip", "netns", "del", name) }()
	if _, err := runCommand("ip", "-n", name, "link", "set", "lo", "up"); err != nil {
		return err
	}
	if _, err := runNamespaced(name, "iptables", nil, "-w", "5", "-L", "OUTPUT", "-n"); err != nil {
		return err
	}
	if _, err := runNamespaced(name, "ss", nil, "-H", "-u", "-a", "-n"); err != nil {
		return err
	}
	if _, err := runNamespaced(name, "conntrack", nil, "-C"); err != nil {
		return err
	}
	return nil
}

func assertN1Result(t *testing.T, result n1EndpointResult, terminal, errorClass string, sent, received int, tripped bool) {
	t.Helper()
	if !result.OK || result.Terminal != terminal || result.ErrorClass != errorClass || result.Sent != sent || result.Received != received {
		t.Fatalf("N1 endpoint result = %+v, want terminal=%s class=%s sent=%d received=%d", result, terminal, errorClass, sent, received)
	}
	wantState := string(governor.SafetyTripClear)
	if tripped {
		wantState = string(governor.SafetyTripTripped)
	}
	if result.SafetyState != wantState || result.SafetyBlocksWork != tripped {
		t.Fatalf("N1 safety result = %s/%t, want %s/%t", result.SafetyState, result.SafetyBlocksWork, wantState, tripped)
	}
	if result.ActivePeers != 0 || result.ActiveAttempts != 0 || result.ReservedSockets != 0 || result.ReservedTargets != 0 ||
		result.ReservedFiveTuples != 0 || result.ReservedPackets != 0 || result.ReservedPacketsPPS != 0 {
		t.Fatalf("N1 governor reservation residue = %+v", result)
	}
	if result.ElapsedMilliseconds < 0 || result.ElapsedMilliseconds >= n1HarnessLimit.Milliseconds() {
		t.Fatalf("N1 endpoint elapsed = %dms, want under %dms", result.ElapsedMilliseconds, n1HarnessLimit.Milliseconds())
	}
	assertN1Redacted(t, result)
}

func assertN1Redacted(t *testing.T, result n1EndpointResult) {
	t.Helper()
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal("N1 result redaction encoding failed")
	}
	forbidden := []string{n1LeftAddress, n1RightAddress, n1RightAlias}
	if hostname, err := os.Hostname(); err == nil && len(hostname) >= 3 {
		forbidden = append(forbidden, hostname)
	}
	for _, key := range []string{"USER", "USERNAME"} {
		if value := os.Getenv(key); len(value) >= 3 {
			forbidden = append(forbidden, value)
		}
	}
	if directory, err := os.Getwd(); err == nil && len(directory) >= 3 {
		forbidden = append(forbidden, directory)
	}
	if home, err := os.UserHomeDir(); err == nil && len(home) >= 3 {
		forbidden = append(forbidden, home)
	}
	encoded := string(payload)
	for _, value := range forbidden {
		if value != "" && strings.Contains(encoded, value) {
			t.Fatal("N1 result contained forbidden environment metadata")
		}
	}
}

func requireN1PacketCounts(t *testing.T, topology *n1Topology) n1PacketCounts {
	t.Helper()
	counts, err := topology.packetCounts()
	if err != nil {
		t.Fatal("N1 packet counter witness failed")
	}
	return counts
}

func logN1PacketCounts(t *testing.T, counts n1PacketCounts) {
	t.Helper()
	t.Logf(
		"N1 packet witness: left_out=%d left_in=%d right_out=%d right_in=%d",
		counts.LeftOutbound,
		counts.LeftInbound,
		counts.RightOutbound,
		counts.RightInbound,
	)
}

func assertN1SocketCount(t *testing.T, topology *n1Topology, namespace string, port uint16, want int) {
	t.Helper()
	deadline := time.Now().Add(n1TerminalMargin)
	for time.Now().Before(deadline) {
		count, err := topology.socketCount(namespace, port)
		if err == nil && count == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("N1 OS socket witness did not reach count %d", want)
}

func assertN1NoResidue(t *testing.T, topology *n1Topology, processes ...*n1EndpointProcess) {
	t.Helper()
	for _, process := range processes {
		if process != nil && process.port != 0 {
			assertN1SocketCount(t, topology, process.namespace, process.port, 0)
		}
	}
	for _, namespace := range []string{topology.leftNamespace, topology.rightNamespace} {
		count, err := topology.allSocketCount(namespace)
		if err != nil || count != 0 {
			t.Fatal("N1 namespace retained a UDP socket")
		}
	}
	before := requireN1PacketCounts(t, topology)
	time.Sleep(100 * time.Millisecond)
	after := requireN1PacketCounts(t, topology)
	if after != before {
		t.Fatalf("N1 packet counters changed after terminal: before=%+v after=%+v", before, after)
	}
	conntrackBefore, conntrackAfter, err := topology.flushAndCountConntrack()
	if err != nil || conntrackBefore > 2 || conntrackAfter != 0 {
		t.Fatal("N1 conntrack cleanup witness was outside the owned bound")
	}
	t.Logf("N1 terminal witness: sockets=0 packet_counters_stable=true conntrack_before_cleanup=%d conntrack_after_cleanup=%d", conntrackBefore, conntrackAfter)
	if err := topology.cleanup(); err != nil {
		t.Fatal("N1 topology cleanup failed")
	}
	if err := topology.assertNoLeaks(); err != nil {
		t.Fatal("N1 topology leak witness failed")
	}
}

func assertN1GovernorClear(t *testing.T, namespace string) {
	t.Helper()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "n1-clear-restart")
	if err != nil {
		t.Fatal("N1 clear governor owner was not reusable")
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatal("N1 clean terminal persisted a safety trip")
	}
	if snapshot := machine.Snapshot(); snapshot.SafetyTrip.State != governor.SafetyTripClear || snapshot.SafetyTrip.BlocksActiveWork {
		_ = machine.Close()
		t.Fatal("N1 clean terminal safety state was not clear")
	}
	if err := machine.Close(); err != nil {
		t.Fatal("N1 clean governor re-close failed")
	}
}

func assertN1GovernorTripped(t *testing.T, namespace string) {
	t.Helper()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "n1-tripped-restart")
	if err != nil {
		t.Fatal("N1 tripped governor owner lock remained held")
	}
	_, createErr := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if !errors.Is(createErr, governor.ErrSafetyTripped) {
		_ = owner.Close()
		t.Fatal("N1 hard violation did not persist fail-closed state")
	}
	if err := owner.Close(); err != nil {
		t.Fatal("N1 tripped governor owner release failed")
	}
}

func assertN1OwnerLockReleased(t *testing.T, namespace string) {
	t.Helper()
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "n1-crash-restart")
	if err != nil {
		t.Fatal("N1 crash left the machine owner lock held")
	}
	if err := owner.Close(); err != nil {
		t.Fatal("N1 crash owner lock release failed")
	}
}

func waitN1SupervisorPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var ready n1SupervisorReady
		if readN1JSON(path, &ready) && ready.PID > 0 {
			return ready.PID
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("N1 supervisor child PID deadline exceeded")
	return 0
}

func waitN1PIDGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
