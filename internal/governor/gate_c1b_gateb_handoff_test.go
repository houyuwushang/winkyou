package governor_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/natsim"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/pkg/transport"
)

func TestGateC1bGateBProductHandoffRetainsOwnershipUntilFinish(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatal(err)
		}
	}
	leftMachine, err := governor.AcquireManualTraversalTestGovernor(leftNamespace, "gate-c1b-product-handoff")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireManualTraversalTestGovernor(rightNamespace, "gate-c1b-product-handoff")
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

	network, err := natsim.NewNetwork(natsim.Config{
		MaxPacketConns: 32, MaxMappings: 256, QueueCapacity: 2048, MaxDatagram: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	model := natsim.Model{
		Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 45000,
	}
	leftNAT, err := network.NewNAT(natsim.NATConfig{
		Name: "left-c1b", PublicAddr: netip.MustParseAddr("198.51.100.10"), Model: model,
	})
	if err != nil {
		t.Fatal(err)
	}
	rightNAT, err := network.NewNAT(natsim.NATConfig{
		Name: "right-c1b", PublicAddr: netip.MustParseAddr("198.51.100.20"), Model: model,
	})
	if err != nil {
		t.Fatal(err)
	}
	topology := hardnatobserve.Topology{
		Primary: netip.MustParseAddrPort("203.0.113.10:3478"),
		Other:   netip.MustParseAddrPort("203.0.113.11:3479"),
	}
	responders := startNATSimRFC5780Responders(t, network, topology)

	set, err := gatecattempt.EncodeArtifactSet(gatecattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID("c1b-credential"), AttemptID: gateB2OpaqueID("c1b-attempt"),
		InitiatorParticipantID: gateB2OpaqueID("c1b-initiator"), ResponderParticipantID: gateB2OpaqueID("c1b-responder"),
		OOBChannelID: gateB2OpaqueID("c1b-channel"), PlannerProfile: hardnatplan.ProfilePredictiveEdm,
		ResourceClass: hardnatplan.ResourcePredictive, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{1, 4, 9, 16, 25, 36, 49, 64})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	initiatorArtifact, err := gatecattempt.ParseArtifact(set.Initiator, now)
	if err != nil {
		t.Fatal(err)
	}
	defer initiatorArtifact.Close()
	responderArtifact, err := gatecattempt.ParseArtifact(set.Responder, now)
	if err != nil {
		t.Fatal(err)
	}
	defer responderArtifact.Close()

	leftStream, rightStream := net.Pipe()
	t.Cleanup(func() {
		_ = leftStream.Close()
		_ = rightStream.Close()
	})
	type outcome struct {
		role    directattempt.Role
		handoff *gateb.ProductHandoff
		result  gateb.Result
		err     error
		stages  []string
	}
	results := make(chan outcome, 2)
	runSide := func(role directattempt.Role, machine *governor.Governor, ledger *governor.PairingAdmissionLedger,
		artifact *gatecattempt.Artifact, stream net.Conn, factory probeio.Factory) {
		var stages []string
		handoff, result, runErr := gateb.RunForProduct(context.Background(), gateb.Config{
			Machine: machine, Ledger: ledger, PreparedArtifact: artifact,
			ObserverTopology: topology, BuildVersion: "gate-c1b-product-handoff", ProbeFactory: factory,
			ExpectedPeerAddress: map[directattempt.Role]netip.Addr{
				directattempt.RoleInitiator: netip.MustParseAddr("198.51.100.20"),
				directattempt.RoleResponder: netip.MustParseAddr("198.51.100.10"),
			}[role],
			OpenProductStream: func(_ context.Context, attempt *governor.AttemptLease, deadline time.Time) (oobcarrier.BoundedStream, error) {
				if attempt == nil || attempt.Request().ID != artifact.AttemptID || !deadline.After(time.Now()) {
					return nil, errors.New("product stream did not receive the frozen attempt")
				}
				return stream, nil
			},
			Progress: func(stage string, _ bool) error {
				stages = append(stages, stage)
				return nil
			},
		})
		results <- outcome{role: role, handoff: handoff, result: result, err: runErr, stages: stages}
	}
	go runSide(directattempt.RoleInitiator, leftMachine, leftLedger, initiatorArtifact, leftStream,
		&natSimProbeFactory{network: network, nat: leftNAT, localAddress: netip.MustParseAddr("192.0.2.10"), basePort: 30000,
			plannerRole: hardnatplan.RoleInitiator, witness: newCandidateWitness()})
	go runSide(directattempt.RoleResponder, rightMachine, rightLedger, responderArtifact, rightStream,
		&natSimProbeFactory{network: network, nat: rightNAT, localAddress: netip.MustParseAddr("192.0.2.20"), basePort: 31000,
			plannerRole: hardnatplan.RoleResponder, witness: newCandidateWitness()})

	outcomes := make(map[directattempt.Role]outcome, 2)
	for range 2 {
		select {
		case got := <-results:
			outcomes[got.role] = got
		case <-time.After(15 * time.Second):
			t.Fatal("Gate C1b product handoff exceeded bounded Gate B envelope")
		}
	}
	wantStages := gateb.ProgressSequence[:len(gateb.ProgressSequence)-2]
	for _, role := range []directattempt.Role{directattempt.RoleInitiator, directattempt.RoleResponder} {
		got := outcomes[role]
		if got.err != nil || got.handoff == nil {
			t.Fatalf("%s handoff=%v err=%v result=%+v stages=%v", role, got.handoff, got.err, got.result, got.stages)
		}
		if !reflect.DeepEqual(got.stages, wantStages) {
			t.Fatalf("%s stages=%v want=%v", role, got.stages, wantStages)
		}
		witness := got.handoff.Witness()
		if witness.FinishRecorded || witness.OOBDrained || witness.AttemptReleased ||
			witness.Transport.State != probeio.WireGuardGateStandby || witness.Transport.AttemptDetached {
			t.Fatalf("%s premature product completion=%+v", role, witness)
		}
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActiveAttempts != 1 || snapshot.HeavyweightAttempts != 1 {
			t.Fatalf("%s attempt was released before product challenge: %+v", label, snapshot)
		}
	}

	initiator := outcomes[directattempt.RoleInitiator].handoff
	responder := outcomes[directattempt.RoleResponder].handoff
	t.Cleanup(func() {
		_, _ = initiator.Abort(context.Canceled)
		_, _ = responder.Abort(context.Canceled)
		_ = initiator.CloseSession()
		_ = responder.CloseSession()
	})
	if err := initiator.BeginWireGuardChallenge(); err != nil {
		t.Fatal(err)
	}
	if err := responder.BeginWireGuardChallenge(); err != nil {
		t.Fatal(err)
	}
	challengeCtx, challengeCancel := context.WithTimeout(context.Background(), time.Second)
	defer challengeCancel()
	readyResults := make(chan error, 2)
	go func() { readyResults <- initiator.ConsumerReady(challengeCtx) }()
	go func() { readyResults <- responder.ConsumerReady(challengeCtx) }()
	for range 2 {
		if err := <-readyResults; err != nil {
			t.Fatal(err)
		}
	}
	initTransport, respTransport := initiator.Transport(), responder.Transport()
	writeGateC1bWireGuardPacket(t, challengeCtx, initTransport, probeio.WireGuardHandshakeInitiation)
	readGateC1bWireGuardPacket(t, challengeCtx, respTransport, probeio.WireGuardHandshakeInitiation)
	writeGateC1bWireGuardPacket(t, challengeCtx, respTransport, probeio.WireGuardHandshakeResponse)
	readGateC1bWireGuardPacket(t, challengeCtx, initTransport, probeio.WireGuardHandshakeResponse)
	writeGateC1bWireGuardPacket(t, challengeCtx, initTransport, probeio.WireGuardTransportData)
	readGateC1bWireGuardPacket(t, challengeCtx, respTransport, probeio.WireGuardTransportData)
	if err := initiator.MarkWireGuardChallengePassed(); err != nil {
		t.Fatal(err)
	}
	if err := responder.MarkWireGuardChallengePassed(); err != nil {
		t.Fatal(err)
	}

	sessionContext, sessionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sessionCancel()
	type finishOutcome struct {
		role    directattempt.Role
		witness gateb.ProductHandoffWitness
		err     error
	}
	finished := make(chan finishOutcome, 2)
	go func() {
		witness, finishErr := initiator.FinishAndDetach(sessionContext)
		finished <- finishOutcome{role: directattempt.RoleInitiator, witness: witness, err: finishErr}
	}()
	go func() {
		witness, finishErr := responder.FinishAndDetach(sessionContext)
		finished <- finishOutcome{role: directattempt.RoleResponder, witness: witness, err: finishErr}
	}()
	for range 2 {
		select {
		case got := <-finished:
			if got.err != nil {
				t.Fatalf("%s finish = %v witness=%+v", got.role, got.err, got.witness)
			}
			if !got.witness.FinishRecorded || !got.witness.OOBDrained || !got.witness.AttemptReleased ||
				got.witness.Transport.State != probeio.WireGuardGateActive || !got.witness.Transport.AttemptDetached {
				t.Fatalf("%s finish witness=%+v", got.role, got.witness)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Gate C1b FINISH/OOB drain did not terminate")
		}
	}

	writeGateC1bActivePacket(t, sessionContext, initiator.Transport(), []byte("post-finish-left"))
	readGateC1bActivePacket(t, sessionContext, responder.Transport(), []byte("post-finish-left"))
	writeGateC1bActivePacket(t, sessionContext, responder.Transport(), []byte("post-finish-right"))
	readGateC1bActivePacket(t, sessionContext, initiator.Transport(), []byte("post-finish-right"))
	if err := initiator.CloseSession(); err != nil {
		t.Fatal(err)
	}
	if err := responder.CloseSession(); err != nil {
		t.Fatal(err)
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 ||
			snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s governor residue=%+v", label, snapshot)
		}
	}
	for label, namespace := range map[string]string{"left": leftNamespace, "right": rightNamespace} {
		status, inspectErr := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
		if inspectErr != nil || status.Sequence != 3 || status.Records != 3 || status.ConsecutiveFailures != 0 {
			t.Fatalf("%s durable journal=%+v/%v", label, status, inspectErr)
		}
	}
	for _, responder := range responders {
		_ = responder.Close()
	}
	deadline := time.Now().Add(time.Second)
	for {
		counters := network.Snapshot()
		if counters.ActivePacketConns == 0 && counters.ActiveMappings == 0 && counters.QueuedPackets == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Gate C1b natsim residue=%+v", counters)
		}
		time.Sleep(time.Millisecond)
	}
}

func writeGateC1bWireGuardPacket(t *testing.T, ctx context.Context, target transport.PacketTransport, messageType probeio.WireGuardMessageType) {
	t.Helper()
	packet := make([]byte, 32)
	binary.LittleEndian.PutUint32(packet, uint32(messageType))
	if err := target.WritePacket(ctx, packet); err != nil {
		t.Fatalf("write WireGuard type %d = %v", messageType, err)
	}
}

func readGateC1bWireGuardPacket(t *testing.T, ctx context.Context, source transport.PacketTransport, want probeio.WireGuardMessageType) {
	t.Helper()
	buffer := make([]byte, 128)
	n, _, err := source.ReadPacket(ctx, buffer)
	if err != nil {
		t.Fatalf("read WireGuard type %d = %v", want, err)
	}
	if n < 4 || probeio.WireGuardMessageType(binary.LittleEndian.Uint32(buffer[:4])) != want {
		t.Fatalf("read WireGuard packet type=%d len=%d, want=%d", binary.LittleEndian.Uint32(buffer[:4]), n, want)
	}
}

func writeGateC1bActivePacket(t *testing.T, ctx context.Context, target transport.PacketTransport, packet []byte) {
	t.Helper()
	if err := target.WritePacket(ctx, packet); err != nil {
		t.Fatalf("active write = %v", err)
	}
}

func readGateC1bActivePacket(t *testing.T, ctx context.Context, source transport.PacketTransport, want []byte) {
	t.Helper()
	buffer := make([]byte, 128)
	n, _, err := source.ReadPacket(ctx, buffer)
	if err != nil {
		t.Fatalf("active read = %v", err)
	}
	if !reflect.DeepEqual(buffer[:n], want) {
		t.Fatalf("active packet=%q want=%q", buffer[:n], want)
	}
}
