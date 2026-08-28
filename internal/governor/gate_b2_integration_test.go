package governor_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/natsim"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/hardnatattempt"
	"winkyou/internal/v2/hardnatcontrol"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
)

func TestGateB2PredictiveAPDMNATSimEndToEndHandoff(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatal(err)
		}
	}
	leftMachine, err := governor.AcquireManualTraversalTestGovernor(leftNamespace, "gate-b2-predictive")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireManualTraversalTestGovernor(rightNamespace, "gate-b2-predictive")
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

	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 32, MaxMappings: 256, QueueCapacity: 2048, MaxDatagram: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	model := natsim.Model{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 45000}
	leftNAT, err := network.NewNAT(natsim.NATConfig{Name: "left", PublicAddr: netip.MustParseAddr("198.51.100.10"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	rightNAT, err := network.NewNAT(natsim.NATConfig{Name: "right", PublicAddr: netip.MustParseAddr("198.51.100.20"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	topology := hardnatobserve.Topology{
		Primary: netip.MustParseAddrPort("203.0.113.10:3478"),
		Other:   netip.MustParseAddrPort("203.0.113.11:3479"),
	}
	responders := startNATSimRFC5780Responders(t, network, topology)

	set, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID("credential"), AttemptID: gateB2OpaqueID("attempt"),
		InitiatorParticipantID: gateB2OpaqueID("initiator"), ResponderParticipantID: gateB2OpaqueID("responder"),
		OOBChannelID: gateB2OpaqueID("channel"), PlannerProfile: hardnatplan.ProfilePredictiveEdm,
		ResourceClass: hardnatplan.ResourcePredictive, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{1, 4, 9, 16, 25, 36, 49, 64})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	leftStream, rightStream := net.Pipe()
	type outcome struct {
		result gateb.Result
		err    error
		stages []string
	}
	results := make(chan outcome, 2)
	leftCandidates, rightCandidates := newCandidateWitness(), newCandidateWitness()
	runSide := func(machine *governor.Governor, ledger *governor.PairingAdmissionLedger, artifact []byte,
		stream net.Conn, factory probeio.Factory) {
		var stages []string
		result, runErr := gateb.Run(context.Background(), gateb.Config{
			Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream,
			ObserverTopology: topology, BuildVersion: "gate-b2-predictive",
			ProbeFactory: factory,
			Progress:     func(stage string, _ bool) error { stages = append(stages, stage); return nil },
		})
		results <- outcome{result: result, err: runErr, stages: stages}
	}
	go runSide(leftMachine, leftLedger, set.Initiator, leftStream,
		&natSimProbeFactory{network: network, nat: leftNAT, localAddress: netip.MustParseAddr("192.0.2.10"), basePort: 30000,
			plannerRole: hardnatplan.RoleInitiator, witness: leftCandidates})
	go runSide(rightMachine, rightLedger, set.Responder, rightStream,
		&natSimProbeFactory{network: network, nat: rightNAT, localAddress: netip.MustParseAddr("192.0.2.20"), basePort: 31000,
			plannerRole: hardnatplan.RoleResponder, witness: rightCandidates})

	var outcomes []outcome
	for range 2 {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-time.After(15 * time.Second):
			t.Fatal("Gate B2 predictive run exceeded bounded envelope")
		}
	}
	for index, outcome := range outcomes {
		if outcome.err != nil {
			t.Fatalf("side %d: %v intersection=%d reciprocal=%d left=%s right=%s result=%+v stages=%v", index, outcome.err,
				candidateIntersection(leftCandidates, rightCandidates), reciprocalCandidatePairs(leftCandidates, rightCandidates),
				leftCandidates.summary(), rightCandidates.summary(), outcome.result, outcome.stages)
		}
		if !reflect.DeepEqual(outcome.stages, gateb.ProgressSequence) {
			t.Fatalf("side %d stages=%v want=%v", index, outcome.stages, gateb.ProgressSequence)
		}
		result := outcome.result
		if result.Terminal != "success" || !result.Bidirectional || !result.CredentialBurned || !result.FinishRecorded ||
			!result.TransportDrained || result.Profile != hardnatplan.ProfilePredictiveEdm || !result.Conditional ||
			result.ProbabilityFloor != hardnatplan.ProbabilityScale {
			t.Fatalf("side %d result=%+v", index, result)
		}
		if result.Emissions.SocketsOpened != 8 || result.Emissions.EvidencePackets != 13 ||
			result.Emissions.CandidatePackets > 32 || result.Emissions.DataPacketsRead != 3 ||
			result.Emissions.DataPacketsWritten != 3 || result.Emissions.CarrierFramesRead > 8 ||
			result.Emissions.CarrierFramesWrite > 8 || result.Emissions.CarrierBytesRead > 8256 ||
			result.Emissions.CarrierBytesWrite > 8256 {
			t.Fatalf("side %d emissions=%+v", index, result.Emissions)
		}
		witness := result.TransportWitness
		if !witness.Attached || !witness.Adopted || !witness.Standby || !witness.ChallengePassed ||
			!witness.AttemptDetached || witness.PacketsRead != 3 || witness.PacketsWritten != 3 || !witness.Drained || !witness.Closed {
			t.Fatalf("side %d transport=%+v", index, witness)
		}
	}
	if outcomes[0].result.Emissions.WinnerPackets+outcomes[1].result.Emissions.WinnerPackets != 1 {
		t.Fatalf("winner packets = %d", outcomes[0].result.Emissions.WinnerPackets+outcomes[1].result.Emissions.WinnerPackets)
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 ||
			snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s governor residue=%+v", label, snapshot)
		}
	}
	for label, namespace := range map[string]string{"left": leftNamespace, "right": rightNamespace} {
		status, err := governor.InspectLoopbackCarrierTestLedger(namespace, time.Now())
		if err != nil || status.Sequence != 3 || status.Records != 3 || status.ConsecutiveFailures != 0 {
			t.Fatalf("%s durable journal=%+v/%v", label, status, err)
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
			t.Fatalf("natsim residue=%+v", counters)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGateB2PredictiveCandidateExhaustionIsCleanAndDoesNotRetry(t *testing.T) {
	namespaceNow := time.Now().UTC().Truncate(time.Second)
	artifactNow := time.Unix(2_000_000_000, 0).UTC()
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, namespaceNow); err != nil {
			t.Fatal(err)
		}
	}
	leftMachine, err := governor.AcquireManualTraversalTestGovernor(leftNamespace, "gate-b2-exhaustion")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireManualTraversalTestGovernor(rightNamespace, "gate-b2-exhaustion")
	if err != nil {
		t.Fatal(err)
	}
	defer rightMachine.Close()
	leftLedger, _ := governor.LoopbackCarrierTestLedger(leftMachine)
	rightLedger, _ := governor.LoopbackCarrierTestLedger(rightMachine)
	if err := governor.SetCarrierTestLedgerTime(leftMachine, artifactNow); err != nil {
		t.Fatal(err)
	}
	if err := governor.SetCarrierTestLedgerTime(rightMachine, artifactNow); err != nil {
		t.Fatal(err)
	}

	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 32, MaxMappings: 512, QueueCapacity: 2048, MaxDatagram: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	before := natsim.Model{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 45000}
	after := before
	after.PortMin, after.PortMax = 50000, 55000
	leftNAT, err := network.NewNAT(natsim.NATConfig{Name: "left-exhaustion", PublicAddr: netip.MustParseAddr("198.51.100.50"),
		Model: before, Changes: []natsim.BehaviorChange{{AfterOutboundPackets: 13, Model: after}}})
	if err != nil {
		t.Fatal(err)
	}
	rightNAT, err := network.NewNAT(natsim.NATConfig{Name: "right-exhaustion", PublicAddr: netip.MustParseAddr("198.51.100.60"),
		Model: before, Changes: []natsim.BehaviorChange{{AfterOutboundPackets: 13, Model: after}}})
	if err != nil {
		t.Fatal(err)
	}
	topology := hardnatobserve.Topology{Primary: netip.MustParseAddrPort("203.0.113.30:3478"), Other: netip.MustParseAddrPort("203.0.113.31:3479")}
	responders := startNATSimRFC5780Responders(t, network, topology)
	set, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID("exhaustion-credential"), AttemptID: gateB2OpaqueID("exhaustion-attempt"),
		InitiatorParticipantID: gateB2OpaqueID("exhaustion-initiator"), ResponderParticipantID: gateB2OpaqueID("exhaustion-responder"),
		OOBChannelID: gateB2OpaqueID("exhaustion-channel"), PlannerProfile: hardnatplan.ProfilePredictiveEdm,
		ResourceClass: hardnatplan.ResourcePredictive, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: artifactNow, ExpiresAt: artifactNow.Add(10 * time.Minute),
	}, [32]byte{3, 1, 4, 1, 5, 9, 2, 6})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	leftStream, rightStream := net.Pipe()
	leftClock, rightClock := newGateB2ManualClock(artifactNow), newGateB2ManualClock(artifactNow)
	type outcome struct {
		result gateb.Result
		err    error
	}
	results := make(chan outcome, 2)
	runSide := func(machine *governor.Governor, ledger *governor.PairingAdmissionLedger, artifact []byte, stream net.Conn,
		factory probeio.Factory, clock *gateB2ManualClock, randomByte byte) {
		result, runErr := gateb.Run(context.Background(), gateb.Config{
			Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream, ObserverTopology: topology,
			BuildVersion: "gate-b2-exhaustion", ProbeFactory: factory,
			Progress: func(string, bool) error { return nil },
			Harness: &gateb.HarnessHooks{
				NoiseRandom: bytes.NewReader(bytes.Repeat([]byte{randomByte}, 64)), ObservationRandom: gateB2ObservationRandom(randomByte),
				Now: clock.Now, NewTimer: clock.NewTimer, Wait: clock.Wait, CandidateWindow: 100 * time.Millisecond,
			},
		})
		results <- outcome{result: result, err: runErr}
	}
	go runSide(leftMachine, leftLedger, set.Initiator, leftStream,
		&natSimProbeFactory{network: network, nat: leftNAT, localAddress: netip.MustParseAddr("192.0.2.50"), basePort: 34000,
			plannerRole: hardnatplan.RoleInitiator, witness: newCandidateWitness()}, leftClock, 0xb1)
	go runSide(rightMachine, rightLedger, set.Responder, rightStream,
		&natSimProbeFactory{network: network, nat: rightNAT, localAddress: netip.MustParseAddr("192.0.2.60"), basePort: 35000,
			plannerRole: hardnatplan.RoleResponder, witness: newCandidateWitness()}, rightClock, 0xc2)

	var outcomes []outcome
	for range 2 {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-time.After(5 * time.Second):
			t.Fatal("candidate exhaustion did not terminate")
		}
	}
	exhausted := 0
	for index, outcome := range outcomes {
		var failure *gateb.Failure
		if !errors.As(outcome.err, &failure) {
			t.Fatalf("side %d error=%v", index, outcome.err)
		}
		if failure.Class == gateb.ClassCandidateExhausted {
			exhausted++
		} else if failure.Class != gateb.ClassOOBStreamClosed {
			t.Fatalf("side %d failure=%+v", index, failure)
		}
		if !outcome.result.CredentialBurned || !outcome.result.FinishRecorded || outcome.result.Bidirectional ||
			outcome.result.Emissions.CandidatePackets > 32 || outcome.result.Emissions.DataPacketsRead != 0 ||
			outcome.result.Emissions.DataPacketsWritten != 0 || outcome.result.SafetyTrip.BlocksActiveWork {
			t.Fatalf("side %d result=%+v", index, outcome.result)
		}
	}
	if exhausted == 0 {
		t.Fatal("candidate exhaustion stable class was not observed")
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 ||
			snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s exhaustion residue=%+v", label, snapshot)
		}
	}
	for _, responder := range responders {
		_ = responder.Close()
	}
	// 26 evidence requests + 26 observer responses + at most 64 frozen
	// candidates. Any larger prefix would imply an undeclared retry.
	if counters := network.Snapshot(); counters.PacketsWritten > 116 {
		t.Fatalf("candidate exhaustion retried outside the frozen prefix: %+v", counters)
	}
}

func TestGateB2AsymmetricEIMEDMNATSimBothCarrierRoleAssignments(t *testing.T) {
	tests := []struct {
		name                        string
		initiator, responder        hardnatplan.Role
		initiatorRandom, peerRandom byte
	}{
		{name: "mapping initiates", initiator: hardnatplan.RoleMappingSet, responder: hardnatplan.RoleTargetSet, initiatorRandom: 0x91, peerRandom: 0xa3},
		{name: "target initiates", initiator: hardnatplan.RoleTargetSet, responder: hardnatplan.RoleMappingSet, initiatorRandom: 0x91, peerRandom: 0xa3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runGateB2AsymmetricCase(t, test.initiator, test.responder, test.initiatorRandom, test.peerRandom)
		})
	}
}

func TestGateB2FIREFreshnessAndCarrierTerminalStopDirectEmissions(t *testing.T) {
	for _, mode := range []string{"stale_at_fire", "carrier_closed_at_candidates", "active_envelope_at_candidates"} {
		t.Run(mode, func(t *testing.T) {
			outcomes := runGateB2SafetyRegression(t, mode)
			for index, outcome := range outcomes {
				var failure *gateb.Failure
				if !errors.As(outcome.err, &failure) {
					t.Fatalf("side %d error=%v, want stable failure", index, outcome.err)
				}
				if mode == "stale_at_fire" {
					if failure.Class != gateb.ClassEvidenceDrifted || failure.Stage != gateb.StageFire {
						t.Fatalf("side %d failure=%+v, want FIRE evidence drift", index, failure)
					}
				} else if mode == "carrier_closed_at_candidates" && failure.Class != gateb.ClassOOBStreamClosed {
					t.Fatalf("side %d failure=%+v, want OOB stream closed", index, failure)
				} else if mode == "active_envelope_at_candidates" && failure.Class != gateb.ClassAttemptExpired {
					t.Fatalf("side %d failure=%+v, want active-envelope expiry", index, failure)
				}
				if outcome.result.Emissions.CandidatePackets != 0 || outcome.result.Emissions.WinnerPackets != 0 ||
					outcome.result.Emissions.DataPacketsRead != 0 || outcome.result.Emissions.DataPacketsWritten != 0 ||
					!outcome.result.CredentialBurned || !outcome.result.FinishRecorded || outcome.result.SafetyTrip.BlocksActiveWork {
					t.Fatalf("side %d emitted after terminal barrier: %+v", index, outcome.result)
				}
			}
		})
	}
}

type gateB2SafetyOutcome struct {
	result gateb.Result
	err    error
}

func runGateB2SafetyRegression(t testing.TB, mode string) []gateB2SafetyOutcome {
	t.Helper()
	namespaceNow := time.Now().UTC().Truncate(time.Second)
	artifactNow := time.Unix(2_000_100_000, 0).UTC()
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, namespaceNow); err != nil {
			t.Fatal(err)
		}
	}
	leftMachine, err := governor.AcquireManualTraversalTestGovernor(leftNamespace, "gate-b2-safety-left")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireManualTraversalTestGovernor(rightNamespace, "gate-b2-safety-right")
	if err != nil {
		t.Fatal(err)
	}
	defer rightMachine.Close()
	leftLedger, _ := governor.LoopbackCarrierTestLedger(leftMachine)
	rightLedger, _ := governor.LoopbackCarrierTestLedger(rightMachine)
	if err := governor.SetCarrierTestLedgerTime(leftMachine, artifactNow); err != nil {
		t.Fatal(err)
	}
	if err := governor.SetCarrierTestLedgerTime(rightMachine, artifactNow); err != nil {
		t.Fatal(err)
	}

	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 32, MaxMappings: 256, QueueCapacity: 2048, MaxDatagram: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	model := natsim.Model{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 45000}
	leftNAT, err := network.NewNAT(natsim.NATConfig{Name: "safety-left", PublicAddr: netip.MustParseAddr("198.51.100.70"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	rightNAT, err := network.NewNAT(natsim.NATConfig{Name: "safety-right", PublicAddr: netip.MustParseAddr("198.51.100.80"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	topology := hardnatobserve.Topology{Primary: netip.MustParseAddrPort("203.0.113.70:3478"), Other: netip.MustParseAddrPort("203.0.113.71:3479")}
	_ = startNATSimRFC5780Responders(t, network, topology)
	set, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID(mode + "-credential"), AttemptID: gateB2OpaqueID(mode + "-attempt"),
		InitiatorParticipantID: gateB2OpaqueID(mode + "-initiator"), ResponderParticipantID: gateB2OpaqueID(mode + "-responder"),
		OOBChannelID: gateB2OpaqueID(mode + "-channel"), PlannerProfile: hardnatplan.ProfilePredictiveEdm,
		ResourceClass: hardnatplan.ResourcePredictive, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: artifactNow, ExpiresAt: artifactNow.Add(10 * time.Minute),
	}, [32]byte{8, 6, 7, 5, 3, 0, 9})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	leftStream, rightStream := net.Pipe()
	leftClock, rightClock := newGateB2ManualClock(artifactNow), newGateB2ManualClock(artifactNow)
	results := make(chan gateB2SafetyOutcome, 2)
	var candidateSides atomic.Int32
	candidateBarrier := make(chan struct{})
	var closeStreams sync.Once
	progress := func(clock *gateB2ManualClock) gateb.ProgressReporter {
		return func(stage string, _ bool) error {
			if mode == "stale_at_fire" && stage == gateb.StageReady {
				clock.Advance(6 * time.Second)
			}
			if (mode == "carrier_closed_at_candidates" || mode == "active_envelope_at_candidates") && stage == gateb.StageCandidates {
				if candidateSides.Add(1) == 2 {
					closeStreams.Do(func() {
						if mode == "carrier_closed_at_candidates" {
							_ = leftStream.Close()
							_ = rightStream.Close()
						}
						close(candidateBarrier)
					})
				}
				select {
				case <-candidateBarrier:
				case <-time.After(time.Second):
					return errors.New("candidate barrier timed out")
				}
				if mode == "active_envelope_at_candidates" {
					time.Sleep(600 * time.Millisecond)
				} else {
					time.Sleep(20 * time.Millisecond)
				}
			}
			return nil
		}
	}
	runSide := func(machine *governor.Governor, ledger *governor.PairingAdmissionLedger, artifact []byte,
		stream net.Conn, factory probeio.Factory, clock *gateB2ManualClock, randomByte byte) {
		activeEnvelope := 2 * time.Second
		if mode == "active_envelope_at_candidates" {
			activeEnvelope = 500 * time.Millisecond
		}
		result, runErr := gateb.Run(context.Background(), gateb.Config{
			Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream, ObserverTopology: topology,
			BuildVersion: "gate-b2-safety", ProbeFactory: factory, Progress: progress(clock),
			Harness: &gateb.HarnessHooks{
				NoiseRandom: bytes.NewReader(bytes.Repeat([]byte{randomByte}, 64)), ObservationRandom: gateB2ObservationRandom(randomByte),
				Now: clock.Now, NewTimer: clock.NewTimer, Wait: clock.Wait, ActiveEnvelope: activeEnvelope,
				CandidateWindow: 200 * time.Millisecond,
			},
		})
		results <- gateB2SafetyOutcome{result: result, err: runErr}
	}
	go runSide(leftMachine, leftLedger, set.Initiator, leftStream,
		&natSimProbeFactory{network: network, nat: leftNAT, localAddress: netip.MustParseAddr("192.0.2.70"), basePort: 36000,
			plannerRole: hardnatplan.RoleInitiator, witness: newCandidateWitness()}, leftClock, 0xd1)
	go runSide(rightMachine, rightLedger, set.Responder, rightStream,
		&natSimProbeFactory{network: network, nat: rightNAT, localAddress: netip.MustParseAddr("192.0.2.80"), basePort: 37000,
			plannerRole: hardnatplan.RoleResponder, witness: newCandidateWitness()}, rightClock, 0xe2)
	outcomes := make([]gateB2SafetyOutcome, 0, 2)
	for range 2 {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-time.After(5 * time.Second):
			t.Fatal("Gate B2 safety regression exceeded bounded terminal window")
		}
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s safety regression residue=%+v", label, snapshot)
		}
	}
	return outcomes
}

func runGateB2AsymmetricCase(t *testing.T, initiatorRole, responderRole hardnatplan.Role, initiatorRandom, responderRandom byte) {
	t.Helper()
	namespaceNow := time.Now().UTC().Truncate(time.Second)
	artifactNow := time.Unix(2_000_000_000, 0).UTC()
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, namespaceNow); err != nil {
			t.Fatal(err)
		}
	}
	leftMachine, err := governor.AcquireManualTraversalTestGovernor(leftNamespace, "gate-b2-asymmetric")
	if err != nil {
		t.Fatal(err)
	}
	defer leftMachine.Close()
	rightMachine, err := governor.AcquireManualTraversalTestGovernor(rightNamespace, "gate-b2-asymmetric")
	if err != nil {
		t.Fatal(err)
	}
	defer rightMachine.Close()
	leftLedger, _ := governor.LoopbackCarrierTestLedger(leftMachine)
	rightLedger, _ := governor.LoopbackCarrierTestLedger(rightMachine)
	if err := governor.SetCarrierTestLedgerTime(leftMachine, artifactNow); err != nil {
		t.Fatal(err)
	}
	if err := governor.SetCarrierTestLedgerTime(rightMachine, artifactNow); err != nil {
		t.Fatal(err)
	}
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 300, MaxMappings: 4096, QueueCapacity: 4096, MaxDatagram: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	edm := natsim.Model{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterAddressPortDependent, PortMin: 40000, PortMax: 65535}
	eim := natsim.Model{Mapping: natsim.MappingEndpointIndependent, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterAddressPortDependent, PortMin: 46000, PortMax: 65535}
	leftModel, rightModel := edm, eim
	if initiatorRole == hardnatplan.RoleTargetSet {
		leftModel, rightModel = eim, edm
	}
	leftNAT, err := network.NewNAT(natsim.NATConfig{Name: "left-asymmetric", PublicAddr: netip.MustParseAddr("198.51.100.30"), Model: leftModel})
	if err != nil {
		t.Fatal(err)
	}
	rightNAT, err := network.NewNAT(natsim.NATConfig{Name: "right-asymmetric", PublicAddr: netip.MustParseAddr("198.51.100.40"), Model: rightModel})
	if err != nil {
		t.Fatal(err)
	}
	topology := hardnatobserve.Topology{Primary: netip.MustParseAddrPort("203.0.113.20:3478"), Other: netip.MustParseAddrPort("203.0.113.21:3479")}
	responders := startNATSimRFC5780Responders(t, network, topology)
	set, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID("asym-credential-" + string(initiatorRole)), AttemptID: gateB2OpaqueID("asym-attempt-" + string(initiatorRole)),
		InitiatorParticipantID: gateB2OpaqueID("asym-initiator-" + string(initiatorRole)), ResponderParticipantID: gateB2OpaqueID("asym-responder-" + string(initiatorRole)),
		OOBChannelID: gateB2OpaqueID("asym-channel-" + string(initiatorRole)), PlannerProfile: hardnatplan.ProfileAsymmetricBirthday,
		ResourceClass: hardnatplan.ResourceAsymmetric, InitiatorPlannerRole: initiatorRole, ResponderPlannerRole: responderRole,
		IssuedAt: artifactNow, ExpiresAt: artifactNow.Add(10 * time.Minute),
	}, [32]byte{2, 3, 5, 7, 11, 13, 17, 19})
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	leftStream, rightStream := net.Pipe()
	leftClock, rightClock := newGateB2ManualClock(artifactNow), newGateB2ManualClock(artifactNow)
	type outcome struct {
		result gateb.Result
		err    error
	}
	results := make(chan outcome, 2)
	leftCandidates, rightCandidates := newCandidateWitness(), newCandidateWitness()
	runSide := func(machine *governor.Governor, ledger *governor.PairingAdmissionLedger, artifact []byte, stream net.Conn,
		factory probeio.Factory, clock *gateB2ManualClock, randomByte byte) {
		result, runErr := gateb.Run(context.Background(), gateb.Config{
			Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream, ObserverTopology: topology,
			BuildVersion: "gate-b2-asymmetric", ProbeFactory: factory,
			Progress: func(string, bool) error { return nil },
			Harness: &gateb.HarnessHooks{
				NoiseRandom: bytes.NewReader(bytes.Repeat([]byte{randomByte}, 64)), ObservationRandom: gateB2ObservationRandom(randomByte),
				Now: clock.Now, NewTimer: clock.NewTimer, Wait: clock.Wait, CandidateWindow: 250 * time.Millisecond,
			},
		})
		results <- outcome{result: result, err: runErr}
	}
	go runSide(leftMachine, leftLedger, set.Initiator, leftStream,
		&natSimProbeFactory{network: network, nat: leftNAT, localAddress: netip.MustParseAddr("192.0.2.30"), basePort: 32000,
			plannerRole: initiatorRole, witness: leftCandidates}, leftClock, initiatorRandom)
	go runSide(rightMachine, rightLedger, set.Responder, rightStream,
		&natSimProbeFactory{network: network, nat: rightNAT, localAddress: netip.MustParseAddr("192.0.2.40"), basePort: 33000,
			plannerRole: responderRole, witness: rightCandidates}, rightClock, responderRandom)
	var outcomes []outcome
	for range 2 {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-time.After(5 * time.Second):
			t.Fatal("asymmetric Gate B2 run did not terminate")
		}
	}
	for index, outcome := range outcomes {
		if outcome.err != nil {
			var failure *gateb.Failure
			_ = errors.As(outcome.err, &failure)
			t.Fatalf("side %d: %v cause=%v intersection=%d reciprocal=%d left=%s right=%s result=%+v", index, outcome.err, failure.Cause,
				candidateIntersection(leftCandidates, rightCandidates), reciprocalCandidatePairs(leftCandidates, rightCandidates),
				leftCandidates.summary(), rightCandidates.summary(), outcome.result)
		}
		result := outcome.result
		if result.Terminal != "success" || !result.Bidirectional || !result.FinishRecorded || !result.TransportDrained ||
			result.Profile != hardnatplan.ProfileAsymmetricBirthday || result.ProbabilityFloor < 632_000_000_000 ||
			result.Emissions.SocketsOpened != 128 || result.Emissions.EvidencePackets != 13 ||
			result.Emissions.DataPacketsRead != 3 || result.Emissions.DataPacketsWritten != 3 {
			t.Fatalf("side %d result=%+v", index, result)
		}
	}
	if outcomes[0].result.Emissions.WinnerPackets+outcomes[1].result.Emissions.WinnerPackets != 1 {
		t.Fatalf("asymmetric winner count = %d", outcomes[0].result.Emissions.WinnerPackets+outcomes[1].result.Emissions.WinnerPackets)
	}
	seenFullTargetSet := false
	for _, outcome := range outcomes {
		if outcome.result.Emissions.TargetsRegistered == 516 && outcome.result.Emissions.FiveTuples == 523 {
			seenFullTargetSet = true
		}
	}
	if !seenFullTargetSet {
		t.Fatalf("missing 516 target / 523 tuple witness: %+v %+v", outcomes[0].result.Emissions, outcomes[1].result.Emissions)
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 ||
			snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s asymmetric governor residue=%+v", label, snapshot)
		}
	}
	for label, namespace := range map[string]string{"left": leftNamespace, "right": rightNamespace} {
		status, err := governor.InspectLoopbackCarrierTestLedger(namespace, artifactNow)
		if err != nil || status.Sequence != 3 || status.Records != 3 || status.ConsecutiveFailures != 0 {
			t.Fatalf("%s asymmetric durable journal=%+v/%v", label, status, err)
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
			t.Fatalf("asymmetric natsim residue=%+v", counters)
		}
		time.Sleep(time.Millisecond)
	}
}

func gateB2OpaqueID(label string) string {
	digest := sha256.Sum256([]byte("gate-b2-test/" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

type natSimProbeFactory struct {
	network      *natsim.Network
	nat          *natsim.NAT
	localAddress netip.Addr
	basePort     uint16
	opens        atomic.Uint32
	plannerRole  hardnatplan.Role
	witness      *candidateWitness
}

func (factory *natSimProbeFactory) Open(context.Context) (probeio.Datagram, error) {
	ordinal := factory.opens.Add(1) - 1
	connection, err := factory.network.NewPacketConn(natsim.EndpointConfig{
		LocalAddr: netip.AddrPortFrom(factory.localAddress, factory.basePort+uint16(ordinal)), NATChain: []*natsim.NAT{factory.nat},
	})
	if err != nil {
		return nil, err
	}
	return &natSimDatagram{connection: connection, network: factory.network, plannerRole: factory.plannerRole, witness: factory.witness}, nil
}

type natSimDatagram struct {
	connection  *natsim.PacketConn
	network     *natsim.Network
	plannerRole hardnatplan.Role
	witness     *candidateWitness
}

func (datagram *natSimDatagram) ReadFrom(ctx context.Context, target []byte) (int, netip.AddrPort, error) {
	for {
		n, source, ok, err := datagram.connection.TryReadFromAddrPort(target)
		if err != nil || ok {
			return n, source, err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, netip.AddrPort{}, ctx.Err()
		case <-timer.C:
		}
	}
}
func (datagram *natSimDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n, err := datagram.connection.WriteToAddrPort(packet, target)
	if err == nil && datagram.witness != nil {
		if metadata, inspectErr := hardnatcontrol.InspectFrame(packet); inspectErr == nil && metadata.Type == hardnatcontrol.FrameCandidate {
			if mapped, mapErr := datagram.network.MappedAddr(datagram.connection, target); mapErr == nil {
				datagram.witness.recordCandidate(mapped.Port(), target.Port())
			}
		}
	}
	return n, err
}
func (datagram *natSimDatagram) SetDeadline(deadline time.Time) error {
	return datagram.connection.SetDeadline(deadline)
}
func (datagram *natSimDatagram) LocalAddr() net.Addr { return datagram.connection.LocalAddr() }
func (datagram *natSimDatagram) Close() error        { return datagram.connection.Close() }

func startNATSimRFC5780Responders(t testing.TB, network *natsim.Network, topology hardnatobserve.Topology) []*natsim.PacketConn {
	t.Helper()
	endpoints, err := topology.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	responders := make([]*natsim.PacketConn, len(endpoints))
	for index, endpoint := range endpoints {
		responders[index], err = network.NewPacketConn(natsim.EndpointConfig{LocalAddr: endpoint})
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	for index, responder := range responders {
		index, responder := index, responder
		workers.Add(1)
		go func() {
			defer workers.Done()
			buffer := make([]byte, 1024)
			for {
				n, source, ok, readErr := responder.TryReadFromAddrPort(buffer)
				if readErr != nil {
					return
				}
				if !ok {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Millisecond):
						continue
					}
				}
				transaction, change, parseErr := hardnatplan.ParseBehaviorBindingRequest(buffer[:n])
				if parseErr != nil {
					continue
				}
				writerIndex := index
				if change.ChangeIP && change.ChangePort {
					writerIndex = 3
				} else if change.ChangePort {
					writerIndex = 1
				}
				mapped := planEndpoint(source)
				response, buildErr := hardnatplan.BuildBehaviorBindingSuccess(transaction, hardnatplan.BehaviorAttributes{
					Mapped: mapped, HasMapped: true, ResponseOrigin: planEndpoint(endpoints[writerIndex]), HasResponseOrigin: true,
					OtherAddress: planEndpoint(endpoints[3]), HasOtherAddress: true,
				})
				if buildErr == nil {
					_, _ = responders[writerIndex].WriteToAddrPort(response, source)
				}
				clear(response)
			}
		}()
	}
	t.Cleanup(func() {
		cancel()
		for _, responder := range responders {
			_ = responder.Close()
		}
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("RFC 5780 responders did not drain")
		}
	})
	return responders
}

func planEndpoint(endpoint netip.AddrPort) hardnatplan.AddressPort {
	address := endpoint.Addr().Unmap()
	if address.Is4() {
		return hardnatplan.AddressPort{Address: hardnatplan.Address4(address.As4()), Port: endpoint.Port()}
	}
	return hardnatplan.AddressPort{Address: hardnatplan.Address6(address.As16()), Port: endpoint.Port()}
}

type gateB2ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newGateB2ManualClock(now time.Time) *gateB2ManualClock { return &gateB2ManualClock{now: now} }
func (clock *gateB2ManualClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}
func (clock *gateB2ManualClock) Wait(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
	// Preserve the real scheduler's cross-peer batch interleaving while
	// compressing each one-second governed interval.
	delay := 2 * time.Millisecond
	if duration >= 7*time.Second {
		delay = 100 * time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	return nil
}
func (clock *gateB2ManualClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}
func (clock *gateB2ManualClock) NewTimer(time.Duration) probeio.Timer {
	return gateB2InertTimer{make(chan time.Time)}
}

type gateB2InertTimer struct{ channel <-chan time.Time }

func (timer gateB2InertTimer) C() <-chan time.Time { return timer.channel }
func (gateB2InertTimer) Stop() bool                { return true }

func gateB2ObservationRandom(seed byte) *bytes.Reader {
	payload := make([]byte, hardnatobserve.ObservationPacketCount*12)
	for ordinal := 0; ordinal < hardnatobserve.ObservationPacketCount; ordinal++ {
		payload[ordinal*12] = byte(ordinal + 1)
		for offset := 1; offset < 12; offset++ {
			payload[ordinal*12+offset] = seed + byte(offset)
		}
	}
	return bytes.NewReader(payload)
}

type candidateWitness struct {
	mu      sync.Mutex
	targets map[uint16]struct{}
	sources map[uint16]struct{}
	pairs   map[[2]uint16]struct{}
}

func newCandidateWitness() *candidateWitness {
	return &candidateWitness{targets: make(map[uint16]struct{}), sources: make(map[uint16]struct{}), pairs: make(map[[2]uint16]struct{})}
}
func (witness *candidateWitness) recordCandidate(source, target uint16) {
	witness.mu.Lock()
	witness.targets[target] = struct{}{}
	witness.sources[source] = struct{}{}
	witness.pairs[[2]uint16{source, target}] = struct{}{}
	witness.mu.Unlock()
}
func (witness *candidateWitness) snapshot() (map[uint16]struct{}, map[uint16]struct{}) {
	witness.mu.Lock()
	defer witness.mu.Unlock()
	targets, sources := make(map[uint16]struct{}, len(witness.targets)), make(map[uint16]struct{}, len(witness.sources))
	for port := range witness.targets {
		targets[port] = struct{}{}
	}
	for port := range witness.sources {
		sources[port] = struct{}{}
	}
	return targets, sources
}
func (witness *candidateWitness) summary() string {
	targets, sources := witness.snapshot()
	return fmt.Sprintf("targets=%d sources=%d", len(targets), len(sources))
}
func candidateIntersection(left, right *candidateWitness) int {
	leftTargets, leftSources := left.snapshot()
	rightTargets, rightSources := right.snapshot()
	count := 0
	for port := range leftTargets {
		if _, ok := rightSources[port]; ok {
			count++
		}
	}
	for port := range rightTargets {
		if _, ok := leftSources[port]; ok {
			count++
		}
	}
	return count
}

func reciprocalCandidatePairs(left, right *candidateWitness) int {
	left.mu.Lock()
	defer left.mu.Unlock()
	right.mu.Lock()
	defer right.mu.Unlock()
	count := 0
	for pair := range left.pairs {
		if _, ok := right.pairs[[2]uint16{pair[1], pair[0]}]; ok {
			count++
		}
	}
	return count
}
