package governor_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/oobcarrier"
)

const (
	gateACrashChildEnv = "WINKYOU_GATE_A_PROMOTE_CRASH_CHILD"
	gateACrashNSenv    = "WINKYOU_GATE_A_PROMOTE_CRASH_NAMESPACE"
	gateACrashExitCode = 23
	gateAHandoffPath   = "gate-a/easy-direct/1"
)

func TestGateAPromoteBeforeFinishCrashSubprocess(t *testing.T) {
	if os.Getenv(gateACrashChildEnv) == "1" {
		runGateAPromoteCrashChild(t)
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	namespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestGateAPromoteBeforeFinishCrashSubprocess$", "-test.v")
	command.Env = append(os.Environ(), gateACrashChildEnv+"=1", gateACrashNSenv+"="+namespace)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != gateACrashExitCode {
		t.Fatalf("crash child exit=%v output=%s", err, redactTestOutput(output))
	}
	portPayload, err := os.ReadFile(filepath.Join(namespace, "promoted-port.txt"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(string(portPayload), 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("invalid redacted port witness")
	}
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))))
	if err != nil {
		t.Fatalf("promoted socket survived process death: %v", err)
	}
	_ = listener.Close()

	restarted, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "gate-a-crash-restart")
	if err != nil {
		t.Fatalf("restart acquire: %v", err)
	}
	defer restarted.Close()
	ledger, err := governor.LoopbackCarrierTestLedger(restarted)
	if err != nil {
		t.Fatal(err)
	}
	status := ledger.Status()
	unfinishedAdmissions, unfinishedPackets, err := governor.InspectLoopbackCarrierTestOccupancy(namespace, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if status.Sequence != 2 || status.Records != 2 ||
		status.TwentyFourHourPackets != oobcarrier.MaxInitiatorUDP || unfinishedAdmissions != 1 ||
		unfinishedPackets != oobcarrier.MaxInitiatorUDP {
		t.Fatalf("restart durable occupancy=%+v unfinished=%d/%d", status, unfinishedAdmissions, unfinishedPackets)
	}
	request := gateAHandoffAdmissionRequest(t, now, gateAHandoffAttemptCost(t))
	if err := ledger.Preflight(request); !errors.Is(err, governor.ErrPairingCredentialUsed) {
		t.Fatalf("unfinished credential replay=%v, want burned", err)
	}
	if trip := restarted.Snapshot().SafetyTrip; trip.BlocksActiveWork {
		t.Fatalf("process crash leaked persistent safety trip=%+v", trip)
	}
}

func runGateAPromoteCrashChild(t *testing.T) {
	namespace := os.Getenv(gateACrashNSenv)
	if namespace == "" {
		t.Fatal("missing crash namespace")
	}
	machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "gate-a-crash-child")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := governor.LoopbackCarrierTestLedger(machine)
	if err != nil {
		t.Fatal(err)
	}
	handoff := prepareGateAHandoff(t, machine, ledger, time.Now().UTC().Truncate(time.Second))
	port := handoff.local.Port()
	if err := os.WriteFile(filepath.Join(namespace, "promoted-port.txt"), []byte(strconv.FormatUint(uint64(port), 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Deliberate abrupt process death: no FINISH, no deferred Close. The OS
	// must reclaim the promoted socket while the durable burn remains pending.
	os.Exit(gateACrashExitCode)
}

func TestGateAFinishJournalPrecedesAttemptRelease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	namespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
		t.Fatal(err)
	}
	machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "gate-a-finish-order")
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	ledger, err := governor.LoopbackCarrierTestLedger(machine)
	if err != nil {
		t.Fatal(err)
	}
	handoff := prepareGateAHandoff(t, machine, ledger, now)
	owned, err := handoff.session.Adopt(context.Background(), handoff.binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := handoff.session.MarkStandby(); err != nil {
		t.Fatal(err)
	}
	if err := handoff.session.MarkChallengePassed(); err != nil {
		t.Fatal(err)
	}
	if err := handoff.authorization.Finish(governor.PairingTerminalSuccess); err != nil {
		t.Fatalf("durable FINISH: %v", err)
	}
	status := ledger.Status()
	unfinishedAdmissions, unfinishedPackets, err := governor.LoopbackCarrierTestOccupancy(machine)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := machine.Snapshot()
	if status.Sequence != 3 || status.Records != 3 || unfinishedAdmissions != 0 || unfinishedPackets != 0 ||
		snapshot.ActiveAttempts != 1 || snapshot.HeavyweightAttempts != 1 {
		t.Fatalf("FINISH-before-release witness status=%+v snapshot=%+v", status, snapshot)
	}
	if err := handoff.session.DetachAfterFinish(); err != nil {
		t.Fatal(err)
	}
	if err := handoff.controller.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handoff.peer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	_ = handoff.remote.Close()
	snapshot = machine.Snapshot()
	if snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 || snapshot.Reserved != (governor.Resources{}) {
		t.Fatalf("post-release residue=%+v", snapshot)
	}
}

type gateAHandoffFixture struct {
	peer          *governor.PeerLease
	controller    *probeio.Controller
	session       *probeio.TransportLease
	authorization *governor.CommittedCarrierAuthorization
	binding       probeio.TransportLeaseBinding
	local         netip.AddrPort
	remote        *net.UDPConn
}

func prepareGateAHandoff(t testing.TB, machine *governor.Governor, ledger *governor.PairingAdmissionLedger, now time.Time) gateAHandoffFixture {
	t.Helper()
	cost := gateAHandoffAttemptCost(t)
	peer, err := machine.AcquirePeer(gateAOpaqueID("handoff-peer"))
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), governor.AttemptRequest{
		ID: gateAOpaqueID("handoff-attempt"), Operation: governor.OperationConnectTest, Cost: cost,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := gateAHandoffAdmissionRequest(t, now, cost)
	committed, err := governor.NewPairingAdmissionGate().Commit(context.Background(), attempt, request)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := committed.ConsumeForCarrier(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.BeforeFirstEmission(context.Background()); err != nil {
		t.Fatal(err)
	}
	remote, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	target := remote.LocalAddr().(*net.UDPAddr).AddrPort()
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatal(err)
	}
	generation := probeio.NewGeneration(directattempt.Generation)
	udpCost, _ := stunobserve.GateASameSocketCost(2)
	controller, err := probeio.New(probeio.Config{
		Lease: attempt, Generation: generation, ExpectedGeneration: directattempt.Generation,
		Factory: factory, EnforcedCost: &udpCost, BuildVersion: "gate-a-handoff-order",
	})
	if err != nil {
		t.Fatal(err)
	}
	socket, err := controller.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	local, err := socket.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.RegisterTarget(target); err != nil {
		t.Fatal(err)
	}
	if err := socket.SendProbe(context.Background(), target, []byte("verify")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	n, source, err := remote.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "verify" {
		t.Fatalf("peer verify read=%q/%v", buffer[:n], err)
	}
	if _, err := remote.WriteToUDPAddrPort([]byte("ack"), source); err != nil {
		t.Fatal(err)
	}
	if _, _, err := socket.ReceiveReply(context.Background(), buffer, func(packet []byte, from netip.AddrPort) error {
		if string(packet) != "ack" || from != target {
			return errors.New("invalid peer ack")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	binding := probeio.TransportLeaseBinding{
		PeerID: peerID(attempt), AttemptID: attempt.Request().ID, Generation: directattempt.Generation,
		PathID: gateAHandoffPath, Target: target, ConsumerKind: probeio.GateATestConsumer,
	}
	session, err := probeio.IssueTransportLease(attempt, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.PromoteToLease(target, gateAHandoffPath, session); err != nil {
		t.Fatal(err)
	}
	return gateAHandoffFixture{
		peer: peer, controller: controller, session: session, authorization: authorization,
		binding: binding, local: local, remote: remote,
	}
}

func gateAHandoffAttemptCost(t testing.TB) governor.AttemptCost {
	t.Helper()
	cost, err := oobcarrier.AttemptCost(directattempt.RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	return cost
}

func gateAHandoffAdmissionRequest(t testing.TB, now time.Time, cost governor.AttemptCost) governor.PairingAdmissionRequest {
	t.Helper()
	digest := sha256.Sum256([]byte("gate-a-handoff-context"))
	return governor.PairingAdmissionRequest{
		CredentialID: gateAOpaqueID("handoff-credential"), AttemptID: gateAOpaqueID("handoff-attempt"),
		ContextDigest: hex.EncodeToString(digest[:]), Scope: governor.ScopeMachine,
		ExpiresAt: now.Add(10 * time.Minute), Envelope: governor.PairingEnvelopeFromAttemptCost(cost),
	}
}

func peerID(attempt *governor.AttemptLease) string { return attempt.PeerID() }

func redactTestOutput(output []byte) string {
	if len(output) == 0 {
		return "<empty>"
	}
	return "<redacted test output>"
}
