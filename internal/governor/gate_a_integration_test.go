package governor_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/stunserver"
	"winkyou/internal/stunwire"
	"winkyou/internal/v2/directconnect/gatea"
	"winkyou/internal/v2/oobattempt"
)

func TestGateALoopbackEndToEndHandoffAndDurableFinish(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatalf("prepare namespace: %v", err)
		}
	}
	leftMachine, err := governor.AcquireLoopbackCarrierTestGovernor(leftNamespace, "gate-a-loopback")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireLoopbackCarrierTestGovernor(rightNamespace, "gate-a-loopback")
	if err != nil {
		t.Fatal(err)
	}
	defer rightMachine.Close()
	leftLedger, err := governor.LoopbackCarrierTestLedger(leftMachine)
	if err != nil {
		t.Fatal(err)
	}
	rightLedger, err := governor.LoopbackCarrierTestLedger(rightMachine)
	if err != nil {
		t.Fatal(err)
	}

	firstSTUN := startGateASTUNServer(t)
	secondSTUN := startGateASTUNServer(t)
	material := oobattempt.ArtifactMaterial{
		CredentialID: gateAOpaqueID("credential"), AttemptID: gateAOpaqueID("attempt"),
		InitiatorParticipantID: gateAOpaqueID("initiator"), ResponderParticipantID: gateAOpaqueID("responder"),
		OOBChannelID: gateAOpaqueID("channel"), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}
	set, err := oobattempt.EncodeArtifactSet(material, [32]byte{1, 3, 5, 7, 9, 11, 13, 15})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	leftStream, rightStream := net.Pipe()

	type outcome struct {
		result gatea.Result
		err    error
		stages []string
	}
	results := make(chan outcome, 2)
	runSide := func(machine *governor.Governor, ledger *governor.PairingAdmissionLedger, artifact []byte, stream net.Conn) {
		var mu sync.Mutex
		stages := make([]string, 0, len(gatea.ProgressSequence))
		result, runErr := gatea.Run(context.Background(), gatea.Config{
			Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream,
			STUNTargets:  []netip.AddrPort{firstSTUN.ListenAddr(), secondSTUN.ListenAddr()},
			BuildVersion: "gate-a-loopback",
			Progress: func(stage string, _ bool) error {
				mu.Lock()
				stages = append(stages, stage)
				mu.Unlock()
				return nil
			},
		})
		mu.Lock()
		copyStages := append([]string(nil), stages...)
		mu.Unlock()
		results <- outcome{result: result, err: runErr, stages: copyStages}
	}
	go runSide(leftMachine, leftLedger, set.Initiator, leftStream)
	go runSide(rightMachine, rightLedger, set.Responder, rightStream)

	var outcomes []outcome
	for range 2 {
		select {
		case result := <-results:
			outcomes = append(outcomes, result)
		case <-time.After(5 * time.Second):
			t.Fatal("Gate A loopback run exceeded bounded envelope")
		}
	}
	for index, outcome := range outcomes {
		if outcome.err != nil {
			t.Fatalf("side %d: %v result=%+v stages=%v", index, outcome.err, outcome.result, outcome.stages)
		}
		if !reflect.DeepEqual(outcome.stages, gatea.ProgressSequence) {
			t.Fatalf("side %d stages=%v want=%v", index, outcome.stages, gatea.ProgressSequence)
		}
		result := outcome.result
		if result.Terminal != "success" || !result.Bidirectional || !result.CredentialBurned ||
			!result.FinishRecorded || !result.TransportDrained || result.MappingBehavior != "consistent_same_address" {
			t.Fatalf("side %d result=%+v", index, result)
		}
		if result.Emissions.STUNPackets != 2 || result.Emissions.DataPacketsRead != 3 || result.Emissions.DataPacketsWritten != 3 ||
			result.Emissions.CarrierFramesRead > 8 || result.Emissions.CarrierFramesWrite > 8 ||
			result.Emissions.CarrierBytesRead > 8256 || result.Emissions.CarrierBytesWrite > 8256 {
			t.Fatalf("side %d emissions=%+v", index, result.Emissions)
		}
		if !result.TransportWitness.Attached || !result.TransportWitness.Adopted || !result.TransportWitness.Standby ||
			!result.TransportWitness.ChallengePassed || !result.TransportWitness.AttemptDetached ||
			result.TransportWitness.PacketsRead != 3 || result.TransportWitness.PacketsWritten != 3 ||
			!result.TransportWitness.Drained || !result.TransportWitness.Closed {
			t.Fatalf("side %d transport witness=%+v", index, result.TransportWitness)
		}
	}
	if outcomes[0].result.Emissions.DirectPackets+outcomes[1].result.Emissions.DirectPackets != 3 ||
		outcomes[0].result.Emissions.UDPPacketsTotal+outcomes[1].result.Emissions.UDPPacketsTotal != 7 {
		t.Fatalf("direct/UDP emission totals = %d/%d", outcomes[0].result.Emissions.DirectPackets+outcomes[1].result.Emissions.DirectPackets,
			outcomes[0].result.Emissions.UDPPacketsTotal+outcomes[1].result.Emissions.UDPPacketsTotal)
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 || snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s governor residue=%+v", label, snapshot)
		}
	}
	for label, namespace := range map[string]string{"left": leftNamespace, "right": rightNamespace} {
		status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
		if err != nil || status.Sequence != 3 || status.Records != 3 || status.ConsecutiveFailures != 0 {
			t.Fatalf("%s durable journal=%+v/%v", label, status, err)
		}
	}
	if firstSTUN.Snapshot().Responded != 2 || secondSTUN.Snapshot().Responded != 2 {
		t.Fatalf("STUN response counts=%d/%d", firstSTUN.Snapshot().Responded, secondSTUN.Snapshot().Responded)
	}
}

func TestGateAPortDependentMappingStopsBeforeREADYAndDirectEmission(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatal(err)
		}
	}
	leftMachine, err := governor.AcquireLoopbackCarrierTestGovernor(leftNamespace, "gate-a-hard-mapping")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireLoopbackCarrierTestGovernor(rightNamespace, "gate-a-hard-mapping")
	if err != nil {
		t.Fatal(err)
	}
	defer rightMachine.Close()
	leftLedger, _ := governor.LoopbackCarrierTestLedger(leftMachine)
	rightLedger, _ := governor.LoopbackCarrierTestLedger(rightMachine)
	first := startForgedGateASTUN(t, 0)
	second := startForgedGateASTUN(t, 1)
	set, err := oobattempt.EncodeArtifactSet(oobattempt.ArtifactMaterial{
		CredentialID: gateAOpaqueID("hard-credential"), AttemptID: gateAOpaqueID("hard-attempt"),
		InitiatorParticipantID: gateAOpaqueID("hard-initiator"), ResponderParticipantID: gateAOpaqueID("hard-responder"),
		OOBChannelID: gateAOpaqueID("hard-channel"), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{2, 4, 6, 8})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	leftStream, rightStream := net.Pipe()
	type outcome struct {
		result gatea.Result
		err    error
		stages []string
	}
	results := make(chan outcome, 2)
	start := func(machine *governor.Governor, ledger *governor.PairingAdmissionLedger, artifact []byte, stream net.Conn) {
		var stages []string
		result, runErr := gatea.Run(context.Background(), gatea.Config{
			Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream,
			STUNTargets: []netip.AddrPort{first.endpoint, second.endpoint}, BuildVersion: "gate-a-hard-mapping",
			Progress: func(stage string, _ bool) error { stages = append(stages, stage); return nil },
		})
		results <- outcome{result: result, err: runErr, stages: stages}
	}
	go start(leftMachine, leftLedger, set.Initiator, leftStream)
	go start(rightMachine, rightLedger, set.Responder, rightStream)
	for side := 0; side < 2; side++ {
		select {
		case outcome := <-results:
			var failure *gatea.Failure
			if !errors.As(outcome.err, &failure) || failure.Class != gatea.ClassMappingNotDirectlyUsable ||
				failure.Stage != gatea.StageSTUN || !failure.CredentialBurned || failure.Retryable {
				t.Fatalf("side %d failure=%#v err=%v", side, failure, outcome.err)
			}
			if outcome.result.Emissions.DirectPackets != 0 || outcome.result.Emissions.UDPPacketsTotal != 2 ||
				outcome.result.MappingBehavior != "port_dependent" || !outcome.result.FinishRecorded ||
				outcome.result.SafetyTrip.BlocksActiveWork {
				t.Fatalf("side %d result=%+v", side, outcome.result)
			}
			wantStages := []string{
				gatea.StagePreflight, gatea.StageOOBAdopt, gatea.StagePresent, gatea.StageBurned,
				gatea.StageActivated, gatea.StageHandshake, gatea.StagePrepare, gatea.StageSocket,
				gatea.StageSTUN, gatea.StageTerminal,
			}
			if !reflect.DeepEqual(outcome.stages, wantStages) {
				t.Fatalf("side %d stages=%v", side, outcome.stages)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("hard mapping did not terminate")
		}
	}
	if first.packets.Load() != 2 || second.packets.Load() != 2 {
		t.Fatalf("STUN packets=%d/%d", first.packets.Load(), second.packets.Load())
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s residue=%+v", label, snapshot)
		}
	}
}

func TestGateAPeerAbsenceTimesOutBeforeBurnWithoutSafetyTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	namespace := t.TempDir()
	if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
		t.Fatal(err)
	}
	machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "gate-a-absent")
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	ledger, err := governor.LoopbackCarrierTestLedger(machine)
	if err != nil {
		t.Fatal(err)
	}
	set, err := oobattempt.EncodeArtifactSet(oobattempt.ArtifactMaterial{
		CredentialID: gateAOpaqueID("absent-credential"), AttemptID: gateAOpaqueID("absent-attempt"),
		InitiatorParticipantID: gateAOpaqueID("absent-initiator"), ResponderParticipantID: gateAOpaqueID("absent-responder"),
		OOBChannelID: gateAOpaqueID("absent-channel"), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{9, 8, 7, 6})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	local, absent := net.Pipe()
	defer absent.Close()
	var stages []string
	result, runErr := gatea.Run(context.Background(), gatea.Config{
		Machine: machine, Ledger: ledger, Artifact: set.Initiator, Stream: local,
		STUNTargets:  []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478"), netip.MustParseAddrPort("127.0.0.1:3479")},
		BuildVersion: "gate-a-absent", Progress: func(stage string, _ bool) error { stages = append(stages, stage); return nil },
	})
	var failure *gatea.Failure
	if !errors.As(runErr, &failure) || failure.Class != gatea.ClassOOBPresenceTimeout || failure.CredentialBurned {
		t.Fatalf("failure=%#v err=%v result=%+v", failure, runErr, result)
	}
	if !reflect.DeepEqual(stages, []string{gatea.StagePreflight, gatea.StageOOBAdopt, gatea.StageTerminal}) {
		t.Fatalf("stages=%v", stages)
	}
	if result.CredentialBurned || result.FinishRecorded || result.Emissions.STUNPackets != 0 || result.Emissions.DirectPackets != 0 {
		t.Fatalf("absence result=%+v", result)
	}
	status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
	if err != nil || status.Sequence != 1 || status.Records != 1 {
		t.Fatalf("absence journal=%+v/%v", status, err)
	}
	snapshot := machine.Snapshot()
	if snapshot.ActiveAttempts != 0 || snapshot.SafetyTrip.BlocksActiveWork {
		t.Fatalf("absence residue=%+v", snapshot)
	}
}

func startGateASTUNServer(t testing.TB) *stunserver.Server {
	t.Helper()
	server, err := stunserver.Open(stunserver.Config{
		ListenAddr: netip.MustParseAddrPort("127.0.0.1:0"), MaxPPS: stunserver.HardMaxPPS,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("STUN server drain: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("STUN server did not drain")
		}
	})
	return server
}

func gateAOpaqueID(label string) string {
	digest := sha256.Sum256([]byte("gate-a-test/" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

type forgedGateASTUN struct {
	connection *net.UDPConn
	endpoint   netip.AddrPort
	packets    atomic.Uint64
}

func startForgedGateASTUN(t testing.TB, portDelta uint16) *forgedGateASTUN {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	server := &forgedGateASTUN{connection: connection, endpoint: connection.LocalAddr().(*net.UDPAddr).AddrPort()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, stunwire.MaxRequestBytes+1)
		for {
			n, source, readErr := connection.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				return
			}
			transaction, parseErr := stunwire.ParseBindingRequest(buffer[:n])
			if parseErr != nil {
				continue
			}
			server.packets.Add(1)
			port := source.Port() + portDelta
			if port == 0 {
				port = source.Port() - 1
			}
			response, responseErr := stunwire.BindingSuccess(transaction, netip.AddrPortFrom(source.Addr().Unmap(), port))
			if responseErr == nil {
				_, _ = connection.WriteToUDPAddrPort(response, source)
			}
		}
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("forged STUN server did not drain")
		}
	})
	return server
}
