package governor_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
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
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatcontrol"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
)

func TestGateB3Hard16NATSimFullShapeHandoff(t *testing.T) {
	left, right, closeFixture := newGateB3NATSimFixture(t, 11, 29)
	defer closeFixture()

	outcomes := runGateB3Pair(t, left, right, 12*time.Second, 8*time.Second)
	for index, outcome := range outcomes {
		if outcome.err != nil {
			t.Fatalf("side %d (%s) hard16 run: %v cause=%v reciprocal=%d left=%s right=%s result=%+v stages=%v", index, outcome.role, outcome.err,
				errors.Unwrap(outcome.err), reciprocalCandidatePairs(left.witness, right.witness), left.witness.summary(), right.witness.summary(), outcome.result, outcome.stages)
		}
		if !reflect.DeepEqual(outcome.stages, gateb.ProgressSequence) {
			t.Fatalf("side %d stages=%v", index, outcome.stages)
		}
		result := outcome.result
		if result.Terminal != "success" || !result.Bidirectional || !result.CredentialBurned || !result.FinishRecorded ||
			!result.TransportDrained || result.Profile != hardnatplan.ProfileHardBirthday ||
			result.ResourceClass != hardnatplan.ResourceHard16KLab || result.CampaignLedger == nil ||
			result.CampaignLedger.State != governor.PairingLedgerRateLimited {
			t.Fatalf("side %d result=%+v", index, result)
		}
		if result.ReservedEnvelope != governor.PairingEnvelopeFromAttemptCost(gateB3AttemptCost()) ||
			result.Emissions.SocketsOpened != 16 || result.Emissions.EvidencePackets != 13 ||
			result.Emissions.CandidatePackets > hardnatbudget.Hard16CandidatePackets ||
			result.Emissions.UDPPacketsTotal > hardnatbudget.Hard16ActualPacketsMaximum ||
			result.Emissions.TargetsRegistered != hardnatbudget.Hard16ActualTargetsMaximum ||
			result.Emissions.FiveTuples != hardnatbudget.Hard16ActualFiveTupleMaximum ||
			result.Emissions.DataPacketsRead != 3 || result.Emissions.DataPacketsWritten != 3 {
			t.Fatalf("side %d emissions=%+v reservation=%+v", index, result.Emissions, result.ReservedEnvelope)
		}
	}
	if outcomes[0].result.Emissions.WinnerPackets+outcomes[1].result.Emissions.WinnerPackets != 1 {
		t.Fatalf("winner packets=%d", outcomes[0].result.Emissions.WinnerPackets+outcomes[1].result.Emissions.WinnerPackets)
	}
	t.Logf("Gate B3 full-shape witness: roles=%s/%s candidates=%d/%d winner=%d/%d reciprocal_pairs=%d",
		outcomes[0].role, outcomes[1].role, outcomes[0].result.Emissions.CandidatePackets,
		outcomes[1].result.Emissions.CandidatePackets, outcomes[0].result.Emissions.WinnerPackets,
		outcomes[1].result.Emissions.WinnerPackets, reciprocalCandidatePairs(left.witness, right.witness))
	for label, side := range map[string]*gateB3Side{"left": left, "right": right} {
		snapshot := side.machine.Snapshot()
		if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 ||
			snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s governor residue=%+v", label, snapshot)
		}
		status := side.ledger.CampaignStatus()
		if status.State != governor.PairingLedgerRateLimited || status.TwentyFourHourAdmissions != 1 ||
			status.TwentyFourHourPackets != 16_432 || status.ExplicitResetRequired {
			t.Fatalf("%s campaign status=%+v", label, status)
		}
	}
}

func TestGateB3Hard16FullExhaustionIsOneShotAndOpensOnlyCampaignCircuit(t *testing.T) {
	left, right, closeFixture := newGateB3NATSimFixture(t, 7, 17)
	defer closeFixture()
	left.factory = &gateB3CandidateFaultFactory{base: left.factory, dropEvery: 1}
	right.factory = &gateB3CandidateFaultFactory{base: right.factory, dropEvery: 1}

	outcomes := runGateB3Pair(t, left, right, 12*time.Second, 2*time.Second)
	for index, outcome := range outcomes {
		var failure *gateb.Failure
		if !errors.As(outcome.err, &failure) || failure.Class != gateb.ClassCandidateExhausted ||
			!outcome.result.CredentialBurned || !outcome.result.FinishRecorded || outcome.result.SafetyTrip.BlocksActiveWork {
			t.Fatalf("side %d exhaustion=%+v err=%v", index, outcome.result, outcome.err)
		}
		if outcome.result.Emissions.CandidatePackets != hardnatbudget.Hard16CandidatePackets ||
			outcome.result.Emissions.WinnerPackets != 0 || outcome.result.Emissions.UDPPacketsTotal != 16_397 ||
			outcome.result.Emissions.SocketsOpened != 16 || outcome.result.Emissions.TargetsRegistered != 16_388 ||
			outcome.result.Emissions.FiveTuples != 16_395 {
			t.Fatalf("side %d exhaustion emissions=%+v", index, outcome.result.Emissions)
		}
		if outcome.result.CampaignLedger == nil || outcome.result.CampaignLedger.State != governor.PairingLedgerCircuitOpen ||
			!outcome.result.CampaignLedger.ExplicitResetRequired {
			t.Fatalf("side %d campaign circuit=%+v", index, outcome.result.CampaignLedger)
		}
	}
	for label, side := range map[string]*gateB3Side{"left": left, "right": right} {
		snapshot := side.machine.Snapshot()
		if snapshot.ActiveAttempts != 0 || snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Fatalf("%s exhaustion residue=%+v", label, snapshot)
		}
		if ordinary := side.ledger.Status(); ordinary.State != governor.PairingLedgerReady || ordinary.TwentyFourHourPackets != 0 {
			t.Fatalf("%s ordinary budget changed=%+v", label, ordinary)
		}
	}
}

func TestGateB3Hard16FiftyPercentCandidateLossStaysOneShot(t *testing.T) {
	left, right, closeFixture := newGateB3NATSimFixtureFor(t, "loss-50", 11, 29)
	defer closeFixture()
	left.factory = &gateB3CandidateFaultFactory{base: left.factory, dropEvery: 2}
	right.factory = &gateB3CandidateFaultFactory{base: right.factory, dropEvery: 2}
	outcomes := runGateB3Pair(t, left, right, 12*time.Second, 2*time.Second)
	winners := 0
	for index, outcome := range outcomes {
		var failure *gateb.Failure
		boundedFailure := errors.As(outcome.err, &failure) &&
			(failure.Class == gateb.ClassCandidateExhausted || failure.Class == gateb.ClassOOBStreamClosed)
		if outcome.err != nil && !boundedFailure {
			t.Fatalf("side %d 50%% loss = %v", index, outcome.err)
		}
		if outcome.result.Emissions.CandidatePackets != hardnatbudget.Hard16CandidatePackets ||
			outcome.result.Emissions.WinnerPackets > 1 || outcome.result.Emissions.SocketsOpened != 16 ||
			outcome.result.Emissions.TargetsRegistered != hardnatbudget.Hard16ActualTargetsMaximum ||
			outcome.result.Emissions.FiveTuples != hardnatbudget.Hard16ActualFiveTupleMaximum ||
			!outcome.result.CredentialBurned || !outcome.result.FinishRecorded ||
			outcome.result.SafetyTrip.BlocksActiveWork {
			t.Fatalf("side %d 50%% loss shape = %+v", index, outcome.result)
		}
		winners += outcome.result.Emissions.WinnerPackets
	}
	if winners > 1 {
		t.Fatalf("50%% loss emitted %d winners", winners)
	}
}

func TestGateB3ResourceTripRecordsFinishBeforeAttemptRelease(t *testing.T) {
	left, right, closeFixture := newGateB3NATSimFixtureFor(t, "resource-trip", 11, 29)
	defer closeFixture()
	left.factory = &gateB3CandidateFaultFactory{
		base: left.factory, dropEvery: 1, writeErr: probeio.ErrResourceExhausted,
	}

	outcomes := runGateB3Pair(t, left, right, 12*time.Second, 2*time.Second)
	tripped := 0
	for index, outcome := range outcomes {
		var failure *gateb.Failure
		if !errors.As(outcome.err, &failure) || !outcome.result.CredentialBurned ||
			!outcome.result.FinishRecorded || outcome.result.CampaignLedger == nil ||
			!outcome.result.CampaignLedger.ExplicitResetRequired {
			t.Fatalf("side %d resource terminal = %+v/%v", index, outcome.result, outcome.err)
		}
		if outcome.result.SafetyTrip.BlocksActiveWork {
			tripped++
			if failure.Class != gateb.ClassResourceBudgetExceeded ||
				outcome.result.SafetyTrip.Record.Reason != governor.SafetyTripResourceExhausted ||
				outcome.result.Emissions.CandidatePackets != 0 {
				t.Fatalf("side %d resource witness = %+v/%+v", index, failure, outcome.result)
			}
		} else if failure.Class != gateb.ClassOOBStreamClosed && failure.Class != gateb.ClassAttemptExpired &&
			failure.Class != gateb.ClassCandidateExhausted {
			t.Fatalf("side %d peer terminal = %+v", index, failure)
		}
	}
	if tripped != 1 {
		t.Fatalf("resource safety trips = %d, want 1", tripped)
	}
	for label, side := range map[string]*gateB3Side{"left": left, "right": right} {
		snapshot := side.machine.Snapshot()
		if snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 || snapshot.Reserved != (governor.Resources{}) {
			t.Fatalf("%s resource-trip residue = %+v", label, snapshot)
		}
	}
}

func TestGateB3Hard16FIREAndCarrierTerminalStopAllCandidates(t *testing.T) {
	for _, mode := range []string{"stale_at_fire", "carrier_closed_at_candidates", "cancel_at_candidates"} {
		t.Run(mode, func(t *testing.T) {
			outcomes := runGateB3SafetyRegression(t, mode)
			drifted := 0
			for index, outcome := range outcomes {
				var failure *gateb.Failure
				if !errors.As(outcome.err, &failure) {
					t.Fatalf("side %d error=%v", index, outcome.err)
				}
				switch mode {
				case "stale_at_fire":
					if failure.Class == gateb.ClassEvidenceDrifted {
						drifted++
					} else if failure.Class != gateb.ClassOOBStreamClosed && failure.Class != gateb.ClassAttemptExpired {
						t.Fatalf("side %d stale failure=%+v", index, failure)
					}
				case "carrier_closed_at_candidates":
					if failure.Class != gateb.ClassOOBStreamClosed {
						t.Fatalf("side %d carrier failure=%+v", index, failure)
					}
				case "cancel_at_candidates":
					if failure.Class != gateb.ClassAttemptExpired && failure.Class != gateb.ClassOOBStreamClosed {
						t.Fatalf("side %d cancel failure=%+v cause=%v", index, failure, errors.Unwrap(failure))
					}
				}
				if outcome.result.Emissions.CandidatePackets != 0 || outcome.result.Emissions.WinnerPackets != 0 ||
					outcome.result.Emissions.DataPacketsRead != 0 || outcome.result.Emissions.DataPacketsWritten != 0 ||
					!outcome.result.CredentialBurned || !outcome.result.FinishRecorded ||
					outcome.result.CampaignLedger == nil || !outcome.result.CampaignLedger.ExplicitResetRequired ||
					outcome.result.SafetyTrip.BlocksActiveWork {
					t.Fatalf("side %d emitted after terminal barrier: %+v", index, outcome.result)
				}
			}
			if mode == "stale_at_fire" && drifted == 0 {
				t.Fatal("stale Gate B3 FIRE lacked a local evidence-drift witness")
			}
		})
	}
}

func TestGateB3Hard16NATSimFreshTopology100(t *testing.T) {
	if os.Getenv("WINKYOU_GATE_B3_REPEAT_REQUIRED") != "1" {
		t.Skip("100 full-shape campaigns run only in the required Gate B3 proof job")
	}
	started := time.Now()
	var successes, exhaustions atomic.Int64
	const repetitions, batchSize = 100, 4
	for batchStart := 0; batchStart < repetitions; batchStart += batchSize {
		batchStart := batchStart
		t.Run(fmt.Sprintf("batch-%03d", batchStart/batchSize), func(t *testing.T) {
			batchEnd := min(batchStart+batchSize, repetitions)
			for iteration := batchStart; iteration < batchEnd; iteration++ {
				iteration := iteration
				t.Run(fmt.Sprintf("fresh-%03d", iteration), func(t *testing.T) {
					t.Parallel()
					label := fmt.Sprintf("fresh-%03d", iteration)
					left, right, closeFixture := newGateB3NATSimFixtureFor(t, label, 11, 29)
					defer closeFixture()
					// The repeat gate measures the complete fixed schedule, not the random
					// position of an early hit. Drop every candidate after accounting so all
					// 100 fresh keys/topologies exercise exactly 16,384 emissions per side.
					left.factory = &gateB3CandidateFaultFactory{base: left.factory, dropEvery: 1}
					right.factory = &gateB3CandidateFaultFactory{base: right.factory, dropEvery: 1}
					outcomes := runGateB3Pair(t, left, right, 12*time.Second, 2*time.Second)
					for index, outcome := range outcomes {
						var failure *gateb.Failure
						boundedExhaustion := errors.As(outcome.err, &failure) && failure.Class == gateb.ClassCandidateExhausted
						if outcome.err != nil && !boundedExhaustion ||
							outcome.result.Terminal != "success" && !boundedExhaustion ||
							outcome.result.Emissions.CandidatePackets != hardnatbudget.Hard16CandidatePackets ||
							outcome.result.Emissions.SocketsOpened != 16 || outcome.result.Emissions.EvidencePackets != 13 {
							t.Fatalf("fresh topology %d side %d = %+v/%v", iteration, index, outcome.result, outcome.err)
						}
					}
					leftSuccess, rightSuccess := outcomes[0].result.Terminal == "success", outcomes[1].result.Terminal == "success"
					if leftSuccess != rightSuccess {
						t.Fatalf("fresh topology %d reached asymmetric terminal", iteration)
					}
					if leftSuccess {
						successes.Add(1)
					} else {
						exhaustions.Add(1)
					}
					winnerPackets := outcomes[0].result.Emissions.WinnerPackets + outcomes[1].result.Emissions.WinnerPackets
					if winnerPackets != 0 && winnerPackets != 1 {
						t.Fatalf("fresh topology %d winner count drifted", iteration)
					}
				})
			}
		})
	}
	t.Logf("Gate B3 natsim repeat witness: fresh_keys=100 fresh_topologies=100 successes=%d exhaustions=%d full_candidates_per_side=16384 residue=0 wall_ms=%d",
		successes.Load(), exhaustions.Load(), time.Since(started).Milliseconds())
}

type gateB3Outcome struct {
	result gateb.Result
	err    error
	stages []string
	role   string
}

func runGateB3SafetyRegression(t testing.TB, mode string) []gateB3Outcome {
	t.Helper()
	left, right, closeFixture := newGateB3NATSimFixtureFor(t, "safety-"+mode, 11, 29)
	t.Cleanup(closeFixture)
	leftClock, rightClock := newGateB2ManualClock(left.now), newGateB2ManualClock(right.now)
	baseContext, cancelAll := context.WithCancel(context.Background())
	defer cancelAll()
	results := make(chan gateB3Outcome, 2)
	var readySides, candidateSides atomic.Int32
	readyBarrier, candidateBarrier := make(chan struct{}), make(chan struct{})
	var terminal sync.Once
	progress := func(clock *gateB2ManualClock) gateb.ProgressReporter {
		return func(stage string, _ bool) error {
			if mode == "stale_at_fire" && stage == gateb.StageReady {
				if readySides.Add(1) == 2 {
					leftClock.Advance(6 * time.Second)
					rightClock.Advance(6 * time.Second)
					close(readyBarrier)
				}
				select {
				case <-readyBarrier:
				case <-time.After(time.Second):
					return errors.New("Gate B3 READY barrier timed out")
				}
			}
			if (mode == "carrier_closed_at_candidates" || mode == "cancel_at_candidates") && stage == gateb.StageCandidates {
				if candidateSides.Add(1) == 2 {
					terminal.Do(func() {
						if mode == "carrier_closed_at_candidates" {
							_ = left.stream.Close()
							_ = right.stream.Close()
						} else {
							cancelAll()
						}
						close(candidateBarrier)
					})
				}
				select {
				case <-candidateBarrier:
				case <-time.After(time.Second):
					return errors.New("Gate B3 candidate barrier timed out")
				}
				time.Sleep(20 * time.Millisecond)
			}
			return nil
		}
	}
	run := func(side *gateB3Side, clock *gateB2ManualClock, randomSeed byte, role string) {
		result, err := gateb.Run(baseContext, gateb.Config{
			Machine: side.machine, Ledger: side.ledger, Artifact: side.artifact, Stream: side.stream,
			ObserverTopology: side.topology, BuildVersion: "gate-b3-safety", ProbeFactory: side.factory,
			Progress: progress(clock), Harness: &gateb.HarnessHooks{
				NoiseRandom: gateB2ObservationRandom(randomSeed + 40), ObservationRandom: gateB2ObservationRandom(randomSeed),
				Now: clock.Now, NewTimer: clock.NewTimer, Wait: clock.Wait, ActiveEnvelope: 6 * time.Second, CandidateWindow: 2 * time.Second,
			},
		})
		results <- gateB3Outcome{result: result, err: err, role: role}
	}
	go run(left, leftClock, 3, "initiator")
	go run(right, rightClock, 97, "responder")
	outcomes := make([]gateB3Outcome, 0, 2)
	for range 2 {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-time.After(15 * time.Second):
			t.Fatal("Gate B3 safety regression exceeded bounded lifetime")
		}
	}
	return outcomes
}

type gateB3Side struct {
	machine  *governor.Governor
	ledger   *governor.PairingAdmissionLedger
	artifact []byte
	factory  probeio.Factory
	stream   net.Conn
	topology hardnatobserve.Topology
	witness  *candidateWitness
	now      time.Time
}

func newGateB3NATSimFixture(t testing.TB, leftSeed, rightSeed uint64) (*gateB3Side, *gateB3Side, func()) {
	return newGateB3NATSimFixtureFor(t, "", leftSeed, rightSeed)
}

func newGateB3NATSimFixtureFor(t testing.TB, label string, leftSeed, rightSeed uint64) (*gateB3Side, *gateB3Side, func()) {
	t.Helper()
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	namespaces := []string{t.TempDir(), t.TempDir()}
	for _, namespace := range namespaces {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			t.Fatal(err)
		}
	}
	leftMachine, err := governor.AcquireHardNATCampaignTestGovernor(namespaces[0], "gate-b3-natsim")
	if err != nil {
		t.Fatal(err)
	}
	rightMachine, err := governor.AcquireHardNATCampaignTestGovernor(namespaces[1], "gate-b3-natsim")
	if err != nil {
		_ = leftMachine.Close()
		t.Fatal(err)
	}
	leftLedger, _ := governor.LoopbackCarrierTestLedger(leftMachine)
	rightLedger, _ := governor.LoopbackCarrierTestLedger(rightMachine)
	if err := governor.SetCarrierTestLedgerTime(leftMachine, now); err != nil {
		t.Fatal(err)
	}
	if err := governor.SetCarrierTestLedgerTime(rightMachine, now); err != nil {
		t.Fatal(err)
	}

	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 40, MaxMappings: 40_000, QueueCapacity: 65_536, MaxDatagram: 2048})
	if err != nil {
		t.Fatal(err)
	}
	model := func(seed uint64) natsim.Model {
		return natsim.Model{Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortRandom,
			Filtering: natsim.FilterAddressPortDependent, EndpointDependentPortReuse: true,
			PortMin: hardnatplan.DynamicPortMin, PortMax: hardnatplan.DynamicPortMax, RandomSeed: seed}
	}
	leftName, rightName := "gate-b3-left", "gate-b3-right"
	if label != "" {
		leftName += "-" + label
		rightName += "-" + label
	}
	leftNAT, err := network.NewNAT(natsim.NATConfig{Name: leftName, PublicAddr: netip.MustParseAddr("198.51.100.60"), Model: model(leftSeed)})
	if err != nil {
		t.Fatal(err)
	}
	rightNAT, err := network.NewNAT(natsim.NATConfig{Name: rightName, PublicAddr: netip.MustParseAddr("198.51.100.70"), Model: model(rightSeed)})
	if err != nil {
		t.Fatal(err)
	}
	topology := hardnatobserve.Topology{Primary: netip.MustParseAddrPort("203.0.113.10:3478"), Other: netip.MustParseAddrPort("203.0.113.11:3479")}
	responders := startNATSimRFC5780Responders(t, network, topology)
	credentialSuffix := ""
	psk := [32]byte{2, 3, 5, 7, 11, 13, 17, 19}
	if label != "" {
		credentialSuffix = "-" + label
		psk = sha256.Sum256([]byte("gate-b3-natsim-psk-" + label))
	}
	set, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: gateB2OpaqueID("gate-b3-credential" + credentialSuffix), AttemptID: gateB2OpaqueID("gate-b3-attempt" + credentialSuffix),
		InitiatorParticipantID: gateB2OpaqueID("gate-b3-initiator" + credentialSuffix), ResponderParticipantID: gateB2OpaqueID("gate-b3-responder" + credentialSuffix),
		OOBChannelID: gateB2OpaqueID("gate-b3-channel" + credentialSuffix), PlannerProfile: hardnatplan.ProfileHardBirthday,
		ResourceClass: hardnatplan.ResourceHard16KLab, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, psk)
	clear(psk[:])
	if err != nil {
		t.Fatal(err)
	}
	leftStream, rightStream := net.Pipe()
	leftWitness, rightWitness := newCandidateWitness(), newCandidateWitness()
	left := &gateB3Side{machine: leftMachine, ledger: leftLedger, artifact: set.Initiator, stream: leftStream, topology: topology, witness: leftWitness, now: now,
		factory: &natSimProbeFactory{network: network, nat: leftNAT, localAddress: netip.MustParseAddr("192.0.2.60"), basePort: 30000, plannerRole: hardnatplan.RoleInitiator, witness: leftWitness}}
	right := &gateB3Side{machine: rightMachine, ledger: rightLedger, artifact: set.Responder, stream: rightStream, topology: topology, witness: rightWitness, now: now,
		factory: &natSimProbeFactory{network: network, nat: rightNAT, localAddress: netip.MustParseAddr("192.0.2.70"), basePort: 31000, plannerRole: hardnatplan.RoleResponder, witness: rightWitness}}
	closeFixture := func() {
		_ = leftStream.Close()
		_ = rightStream.Close()
		for _, responder := range responders {
			_ = responder.Close()
		}
		_ = network.Close()
		_ = leftMachine.Close()
		_ = rightMachine.Close()
		set.Close()
		if counters := network.Snapshot(); counters.ActivePacketConns != 0 || counters.ActiveMappings != 0 || counters.QueuedPackets != 0 {
			t.Errorf("Gate B3 natsim residue=%+v", counters)
		}
	}
	return left, right, closeFixture
}

func runGateB3Pair(t testing.TB, left, right *gateB3Side, active, candidates time.Duration) []gateB3Outcome {
	t.Helper()
	results := make(chan gateB3Outcome, 2)
	run := func(side *gateB3Side, randomSeed byte, role string) {
		clock := newGateB2ManualClock(side.now)
		var stages []string
		result, err := gateb.Run(context.Background(), gateb.Config{
			Machine: side.machine, Ledger: side.ledger, Artifact: side.artifact, Stream: side.stream,
			ObserverTopology: side.topology, BuildVersion: "gate-b3-natsim", ProbeFactory: side.factory,
			Progress: func(stage string, _ bool) error { stages = append(stages, stage); return nil },
			Harness: &gateb.HarnessHooks{NoiseRandom: gateB2ObservationRandom(randomSeed + 40), ObservationRandom: gateB2ObservationRandom(randomSeed),
				Now: clock.Now, NewTimer: clock.NewTimer, Wait: clock.Wait, ActiveEnvelope: active, CandidateWindow: candidates},
		})
		results <- gateB3Outcome{result: result, err: err, stages: stages, role: role}
	}
	go run(left, 3, "initiator")
	go run(right, 97, "responder")
	outcomes := make([]gateB3Outcome, 0, 2)
	for range 2 {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-time.After(15 * time.Second):
			t.Fatal("Gate B3 natsim run exceeded bounded envelope")
		}
	}
	return outcomes
}

func gateB3AttemptCost() governor.AttemptCost {
	envelope, _ := hardnatbudget.For(hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab)
	return envelope.Cost
}

type gateB3CandidateFaultFactory struct {
	base      probeio.Factory
	dropEvery uint64
	writeErr  error
	writes    atomic.Uint64
}

func (factory *gateB3CandidateFaultFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	datagram, err := factory.base.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &gateB3CandidateFaultDatagram{Datagram: datagram, owner: factory}, nil
}

type gateB3CandidateFaultDatagram struct {
	probeio.Datagram
	owner *gateB3CandidateFaultFactory
}

func (datagram *gateB3CandidateFaultDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	metadata, inspectErr := hardnatcontrol.InspectFrame(packet)
	if inspectErr == nil && metadata.Type == hardnatcontrol.FrameCandidate && datagram.owner.dropEvery > 0 {
		writes := datagram.owner.writes.Add(1)
		if writes%datagram.owner.dropEvery == 0 {
			if datagram.owner.writeErr != nil {
				return 0, datagram.owner.writeErr
			}
			return len(packet), nil
		}
	}
	return datagram.Datagram.WriteTo(ctx, packet, target)
}
