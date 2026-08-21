package testpairing_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/natsim"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/punchsim"
	"winkyou/internal/v2/testpairing"
)

func TestGovernedSynchronizedEIMEIMPunchPromotesSameSocket100Times(t *testing.T) {
	scenario := natsim.Scenario{
		Name:        "governed-synchronized-eim-eim-punch",
		Repetitions: 100,
		Network: natsim.Config{
			MaxPacketConns: 2,
			MaxMappings:    2,
			QueueCapacity:  4,
			MaxDatagram:    512,
		},
		Resources: natsim.ResourceLimits{PacketConns: 2, Mappings: 2, QueuedPackets: 2},
		Execute: func(ctx context.Context, network *natsim.Network) error {
			run, err := runPair(ctx, network, natsim.MappingEndpointIndependent, nil, 250*time.Millisecond)
			if err != nil {
				return err
			}
			defer run.close()
			if run.initiator.err != nil || run.responder.err != nil {
				return fmt.Errorf("outcomes: initiator=%v responder=%v", run.initiator.err, run.responder.err)
			}
			for _, outcome := range []endpointOutcome{run.initiator, run.responder} {
				if outcome.result.Secure ||
					outcome.result.OutboundPackets < 1 || outcome.result.OutboundPackets > punchsim.MaxOutboundPackets ||
					outcome.result.InboundPackets < 1 || outcome.result.InboundPackets > punchsim.MaxInboundPackets {
					return fmt.Errorf("unexpected plaintext punch result: %+v", outcome.result)
				}
			}
			if !run.initiatorChannel.Status().Success || !run.responderChannel.Status().Success {
				return errors.New("pairing VERIFY did not reach success")
			}
			if err := exchangeApplicationPayload(ctx, run); err != nil {
				return err
			}
			return run.close()
		},
	}

	report, err := natsim.RunScenario(context.Background(), scenario)
	if err != nil {
		t.Fatalf("run governed EIM x EIM punch scenario: %v", err)
	}
	if report.CompletedRepetitions != 100 || report.PeakPacketConns != 2 || report.PeakMappings != 2 {
		t.Fatalf("scenario report = %+v", report)
	}
}

func TestObservedCandidateReuseOnEDMEDMFailsWithinPunchWindow(t *testing.T) {
	scenario := natsim.Scenario{
		Name:        "observed-candidate-reuse-edm-edm-bounded-failure",
		Repetitions: 1,
		Network: natsim.Config{
			MaxPacketConns: 2,
			MaxMappings:    4,
			QueueCapacity:  2,
			MaxDatagram:    512,
		},
		Resources: natsim.ResourceLimits{PacketConns: 2, Mappings: 4, QueuedPackets: 0},
		Execute: func(ctx context.Context, network *natsim.Network) error {
			run, err := runPair(ctx, network, natsim.MappingEndpointDependent, nil, 40*time.Millisecond)
			if err != nil {
				return err
			}
			defer run.close()
			if !errors.Is(run.initiator.err, punchsim.ErrPunchTimeout) || !errors.Is(run.responder.err, punchsim.ErrPunchTimeout) {
				return fmt.Errorf("EDM outcomes = initiator:%v responder:%v", run.initiator.err, run.responder.err)
			}
			if run.initiator.result.Promotion.Transport != nil || run.responder.result.Promotion.Transport != nil {
				return errors.New("EDM baseline promoted an unverified path")
			}
			if run.initiatorLease.tripCount() != 0 || run.responderLease.tripCount() != 0 {
				return errors.New("ordinary silent drop caused a persistent safety trip")
			}
			if counters := network.Snapshot(); counters.PacketsWritten > 4 {
				return fmt.Errorf("EDM baseline exceeded total packet envelope: %+v", counters)
			}
			return nil
		},
	}

	if _, err := natsim.RunScenario(context.Background(), scenario); err != nil {
		t.Fatalf("run EDM x EDM bounded-failure scenario: %v", err)
	}
}

func TestTamperedSimulationPacketCannotPromote(t *testing.T) {
	mutate := func(packet []byte) []byte {
		if bytes.HasPrefix(packet, []byte(punchsim.SimulationPacketProtocol+"|")) {
			return []byte(punchsim.SimulationPacketProtocol + "|tampered")
		}
		return packet
	}
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 2, MaxMappings: 2, QueueCapacity: 2, MaxDatagram: 512})
	if err != nil {
		t.Fatalf("new network: %v", err)
	}
	defer network.Close()
	run, err := runPair(context.Background(), network, natsim.MappingEndpointIndependent, mutate, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("run tampered pair: %v", err)
	}
	defer run.close()
	if !errors.Is(run.initiator.err, punchsim.ErrProbeRejected) && !errors.Is(run.responder.err, punchsim.ErrProbeRejected) {
		t.Fatalf("tampered outcomes = initiator:%v responder:%v", run.initiator.err, run.responder.err)
	}
	if run.initiator.result.Promotion.Transport != nil || run.responder.result.Promotion.Transport != nil {
		t.Fatal("tampered packet promoted a path")
	}
}

func TestPunchWorstCaseCostIsFixed(t *testing.T) {
	cost := punchsim.PunchWorstCaseCost()
	want := governor.Resources{Sockets: 1, Targets: 1, PacketsPerSecond: 2, Packets: 2, FiveTuples: 1}
	if cost.Resources != want || cost.Duration != time.Second || cost.Heavyweight {
		t.Fatalf("punch cost = %+v, want resources=%+v duration=1s non-heavyweight", cost, want)
	}
}

func TestGovernedSecureEIMEIMPunchPromotesSameSocket100Times(t *testing.T) {
	scenario := natsim.Scenario{
		Name:        "governed-secure-eim-eim-punch",
		Repetitions: 100,
		Network: natsim.Config{
			MaxPacketConns: 2,
			MaxMappings:    2,
			QueueCapacity:  8,
			MaxDatagram:    512,
		},
		Resources: natsim.ResourceLimits{PacketConns: 2, Mappings: 2, QueuedPackets: 4},
		Execute: func(ctx context.Context, network *natsim.Network) error {
			initiatorSecure, responderSecure := securePairConfigs(t, repeatedPSK(0x61), repeatedPSK(0x61), nil, nil)
			run, err := runPairWithOptions(ctx, network, pairOptions{
				mapping:         natsim.MappingEndpointIndependent,
				window:          300 * time.Millisecond,
				initiatorSecure: initiatorSecure,
				responderSecure: responderSecure,
			})
			if err != nil {
				return err
			}
			defer run.close()
			if run.initiator.err != nil || run.responder.err != nil {
				return fmt.Errorf("secure outcomes: initiator=%v responder=%v", run.initiator.err, run.responder.err)
			}
			for _, outcome := range []endpointOutcome{run.initiator, run.responder} {
				if !outcome.result.Secure ||
					outcome.result.OutboundPackets < 1 || outcome.result.OutboundPackets > punchsim.MaxOutboundPackets ||
					outcome.result.InboundPackets < 1 || outcome.result.InboundPackets > punchsim.MaxInboundPackets {
					return fmt.Errorf("unexpected secure counters: %+v", outcome.result)
				}
			}
			if !run.initiatorChannel.Status().Success || !run.responderChannel.Status().Success {
				return errors.New("secure pairing VERIFY did not reach success")
			}
			if err := exchangeApplicationPayload(ctx, run); err != nil {
				return err
			}
			return run.close()
		},
	}

	report, err := natsim.RunScenario(context.Background(), scenario)
	if err != nil {
		t.Fatalf("run governed secure EIM x EIM punch scenario: %v", err)
	}
	if report.CompletedRepetitions != 100 || report.PeakPacketConns != 2 || report.PeakMappings != 2 {
		t.Fatalf("secure scenario report = %+v", report)
	}
}

func TestSecurePunchWrongPSKNeverPromotesAndStaysWithinBudget(t *testing.T) {
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 2, MaxMappings: 2, QueueCapacity: 4, MaxDatagram: 512})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	initiatorSecure, responderSecure := securePairConfigs(t, repeatedPSK(0x71), repeatedPSK(0x70), fixedRandom(0x11), fixedRandom(0x22))
	run, err := runPairWithOptions(context.Background(), network, pairOptions{
		mapping:         natsim.MappingEndpointIndependent,
		window:          100 * time.Millisecond,
		initiatorSecure: initiatorSecure,
		responderSecure: responderSecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer run.close()
	for _, outcome := range []endpointOutcome{run.initiator, run.responder} {
		if outcome.err == nil {
			t.Fatal("wrong-PSK endpoint unexpectedly succeeded")
		}
		if outcome.result.Promotion.Transport != nil {
			t.Fatal("wrong PSK promoted a path")
		}
	}
	if run.initiatorChannel.Status().Success || run.responderChannel.Status().Success {
		t.Fatal("wrong PSK reached pairing success")
	}
	if run.initiatorLease.tripCount() != 0 || run.responderLease.tripCount() != 0 {
		t.Fatal("ordinary authentication failure caused a persistent safety trip")
	}
	if counters := network.Snapshot(); counters.PacketsWritten > 2 {
		t.Fatalf("wrong-PSK path emitted UDP punch traffic before authentication: %+v", counters)
	}
}

func TestEverySecurePunchPacketByteIsAuthenticated(t *testing.T) {
	const securePunchPacketSize = len(punchsim.SecurePacketPrefix) + 1 + 8 + 16 + 8 + 1 + 1 + noisecore.TagSize
	for byteIndex := 0; byteIndex < securePunchPacketSize; byteIndex++ {
		t.Run(fmt.Sprintf("byte_%02d", byteIndex), func(t *testing.T) {
			network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 2, MaxMappings: 2, QueueCapacity: 4, MaxDatagram: 512})
			if err != nil {
				t.Fatal(err)
			}
			defer network.Close()
			mutate := func(packet []byte) []byte {
				if !isSecurePunchPacket(packet) {
					return packet
				}
				mutated := append([]byte(nil), packet...)
				mutated[byteIndex] ^= 1
				return mutated
			}
			initiatorSecure, responderSecure := securePairConfigs(t, repeatedPSK(0x72), repeatedPSK(0x72), fixedRandom(0x31), fixedRandom(0x41))
			run, err := runPairWithOptions(context.Background(), network, pairOptions{
				mapping:         natsim.MappingEndpointIndependent,
				responderMutate: mutate,
				window:          80 * time.Millisecond,
				initiatorSecure: initiatorSecure,
				responderSecure: responderSecure,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer run.close()
			if run.initiator.err == nil && run.responder.err == nil {
				t.Fatal("tampered secure packet completed both endpoints")
			}
			if run.initiator.result.Promotion.Transport != nil || run.responder.result.Promotion.Transport != nil {
				t.Fatal("tampered secure packet promoted a path")
			}
			if run.initiatorLease.tripCount() != 0 || run.responderLease.tripCount() != 0 {
				t.Fatal("authenticated packet rejection caused a persistent safety trip")
			}
		})
	}
}

func TestReplayedPriorSecureHandshakeAndPunchSequenceCannotPromote(t *testing.T) {
	initiatorRecorder := &securePacketRecorder{}
	responderRecorder := &securePacketRecorder{}
	initiatorHandshakeRecorder := &byteSequenceRecorder{}
	responderHandshakeRecorder := &byteSequenceRecorder{}
	firstNetwork, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 2, MaxMappings: 2, QueueCapacity: 8, MaxDatagram: 512})
	if err != nil {
		t.Fatal(err)
	}
	firstInitiatorSecure, firstResponderSecure := securePairConfigs(t, repeatedPSK(0x73), repeatedPSK(0x73), fixedRandom(0x51), fixedRandom(0x61))
	firstInitiatorSecure.handshakeMutate = initiatorHandshakeRecorder.record
	firstResponderSecure.handshakeMutate = responderHandshakeRecorder.record
	first, err := runPairWithOptions(context.Background(), firstNetwork, pairOptions{
		mapping:         natsim.MappingEndpointIndependent,
		initiatorMutate: initiatorRecorder.record,
		responderMutate: responderRecorder.record,
		window:          200 * time.Millisecond,
		initiatorSecure: firstInitiatorSecure,
		responderSecure: firstResponderSecure,
	})
	if err != nil {
		_ = firstNetwork.Close()
		t.Fatal(err)
	}
	if first.initiator.err != nil || first.responder.err != nil {
		_ = first.close()
		_ = firstNetwork.Close()
		t.Fatalf("recording run failed: initiator=%v responder=%v", first.initiator.err, first.responder.err)
	}
	if err := first.close(); err != nil {
		_ = firstNetwork.Close()
		t.Fatal(err)
	}
	if err := firstNetwork.Close(); err != nil {
		t.Fatal(err)
	}
	initiatorSequence := initiatorRecorder.snapshot()
	responderSequence := responderRecorder.snapshot()
	initiatorHandshake := initiatorHandshakeRecorder.snapshot()
	responderHandshake := responderHandshakeRecorder.snapshot()
	if len(initiatorHandshake) != 1 || len(responderHandshake) != 1 ||
		len(initiatorSequence) < 1 || len(responderSequence) < 1 ||
		!containsSecurePunchPacket(initiatorSequence) || !containsSecurePunchPacket(responderSequence) {
		t.Fatalf("recorded sequences do not contain handshake plus punch: handshake=%d/%d punch=%d/%d", len(initiatorHandshake), len(responderHandshake), len(initiatorSequence), len(responderSequence))
	}

	secondNetwork, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 2, MaxMappings: 2, QueueCapacity: 8, MaxDatagram: 512})
	if err != nil {
		t.Fatal(err)
	}
	defer secondNetwork.Close()
	initiatorReplay := newSecurePacketReplayer(initiatorSequence)
	responderReplay := newSecurePacketReplayer(responderSequence)
	initiatorHandshakeReplay := newByteSequenceReplayer(initiatorHandshake)
	responderHandshakeReplay := newByteSequenceReplayer(responderHandshake)
	secondInitiatorSecure, secondResponderSecure := securePairConfigs(t, repeatedPSK(0x73), repeatedPSK(0x73), fixedRandom(0x52), fixedRandom(0x62))
	secondInitiatorSecure.handshakeMutate = initiatorHandshakeReplay.replay
	secondResponderSecure.handshakeMutate = responderHandshakeReplay.replay
	second, err := runPairWithOptions(context.Background(), secondNetwork, pairOptions{
		mapping:         natsim.MappingEndpointIndependent,
		initiatorMutate: initiatorReplay.replay,
		responderMutate: responderReplay.replay,
		window:          100 * time.Millisecond,
		initiatorSecure: secondInitiatorSecure,
		responderSecure: secondResponderSecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	if second.initiator.err == nil && second.responder.err == nil {
		t.Fatal("replayed prior sequence completed both fresh sessions")
	}
	if second.initiator.result.Promotion.Transport != nil || second.responder.result.Promotion.Transport != nil {
		t.Fatal("replayed prior sequence promoted a path")
	}
	if initiatorHandshakeReplay.used() != 1 || responderHandshakeReplay.used() != 1 {
		t.Fatal("replay injectors did not replace both fresh handshake messages")
	}
	if initiatorReplay.used() != 0 || responderReplay.used() != 0 {
		t.Fatal("replayed handshake unexpectedly reached UDP punch replay")
	}
}

type pairRunResult struct {
	initiator endpointOutcome
	responder endpointOutcome

	initiatorChannel *testpairing.SimulatedChannel
	responderChannel *testpairing.SimulatedChannel
	initiatorLease   *simulationLease
	responderLease   *simulationLease
	controllers      []*probeio.Controller

	closeOnce sync.Once
	closeErr  error
}

type endpointOutcome struct {
	role   testpairing.Role
	result punchsim.Result
	err    error
}

func (run *pairRunResult) close() error {
	if run == nil {
		return nil
	}
	run.closeOnce.Do(func() {
		if run.initiator.result.Promotion.Transport != nil {
			run.closeErr = errors.Join(run.closeErr, run.initiator.result.Promotion.Transport.Close())
		}
		if run.responder.result.Promotion.Transport != nil {
			run.closeErr = errors.Join(run.closeErr, run.responder.result.Promotion.Transport.Close())
		}
		for _, controller := range run.controllers {
			run.closeErr = errors.Join(run.closeErr, controller.Close())
		}
	})
	return run.closeErr
}

func runPair(
	parent context.Context,
	network *natsim.Network,
	mapping natsim.MappingBehavior,
	responderMutate func([]byte) []byte,
	window time.Duration,
) (*pairRunResult, error) {
	return runPairWithOptions(parent, network, pairOptions{
		mapping:         mapping,
		responderMutate: responderMutate,
		window:          window,
	})
}

type pairOptions struct {
	mapping         natsim.MappingBehavior
	initiatorMutate func([]byte) []byte
	responderMutate func([]byte) []byte
	window          time.Duration
	initiatorSecure *secureEndpointConfig
	responderSecure *secureEndpointConfig
}

func runPairWithOptions(
	parent context.Context,
	network *natsim.Network,
	options pairOptions,
) (*pairRunResult, error) {
	if (options.initiatorSecure == nil) != (options.responderSecure == nil) {
		return nil, errors.New("secure simulation must be configured at both endpoints")
	}
	model := natsim.Model{
		Mapping:    options.mapping,
		Allocation: natsim.PortPreserving,
		Filtering:  natsim.FilterAddressPortDependent,
	}
	natA, err := network.NewNAT(natsim.NATConfig{Name: "nat-a", PublicAddr: netip.MustParseAddr("203.0.113.10"), Model: model})
	if err != nil {
		return nil, err
	}
	natB, err := network.NewNAT(natsim.NATConfig{Name: "nat-b", PublicAddr: netip.MustParseAddr("203.0.113.20"), Model: model})
	if err != nil {
		return nil, err
	}

	resources := governor.Resources{Sockets: 1, Targets: 2, PacketsPerSecond: 3, Packets: 3, FiveTuples: 2}
	attemptID := simulationID(2)
	initiatorLease := newSimulationLease(attemptID, "peer-initiator", resources)
	responderLease := newSimulationLease(attemptID, "peer-responder", resources)
	initiatorFactory := &simulationFactory{
		network: network,
		endpoint: natsim.EndpointConfig{
			LocalAddr: netip.MustParseAddrPort("192.0.2.10:45010"),
			NATChain:  []*natsim.NAT{natA},
		},
		mutateWrite: options.initiatorMutate,
	}
	responderFactory := &simulationFactory{
		network: network,
		endpoint: natsim.EndpointConfig{
			LocalAddr: netip.MustParseAddrPort("198.51.100.20:45020"),
			NATChain:  []*natsim.NAT{natB},
		},
		mutateWrite: options.responderMutate,
	}
	initiatorController, err := newSimulationController(initiatorLease, initiatorFactory)
	if err != nil {
		return nil, err
	}
	responderController, err := newSimulationController(responderLease, responderFactory)
	if err != nil {
		_ = initiatorController.Close()
		return nil, err
	}

	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	attempt := testpairing.AttemptContext{
		Protocol:               testpairing.ProtocolVersion,
		AuthScope:              testpairing.AuthScope,
		CredentialID:           simulationID(1),
		AttemptID:              attemptID,
		ObservationGeneration:  1,
		SecureChannelProfile:   testpairing.SimulationSecureChannelProfile,
		InitiatorParticipantID: simulationID(3),
		ResponderParticipantID: simulationID(4),
		InitiatorGovernorScope: testpairing.GovernorScopeMachine,
		ResponderGovernorScope: testpairing.GovernorScopeMachine,
		IssuedAt:               now.Add(-time.Second),
		ExpiresAt:              now.Add(5 * time.Minute),
	}
	initiatorChannel, responderChannel, err := testpairing.NewSimulatedPair(
		attempt,
		testpairing.NewMemoryLedger(),
		testpairing.NewMemoryLedger(),
		func() time.Time { return now },
	)
	if err != nil {
		_ = initiatorController.Close()
		_ = responderController.Close()
		return nil, err
	}

	exchange := newCandidateExchange()
	observer := netip.MustParseAddrPort("203.0.113.250:3478")
	initiatorPreparer := &simulationPreparer{
		role:     testpairing.RoleInitiator,
		network:  network,
		factory:  initiatorFactory,
		observer: observer,
		exchange: exchange,
	}
	responderPreparer := &simulationPreparer{
		role:     testpairing.RoleResponder,
		network:  network,
		factory:  responderFactory,
		observer: observer,
		exchange: exchange,
	}

	run := &pairRunResult{
		initiatorChannel: initiatorChannel,
		responderChannel: responderChannel,
		initiatorLease:   initiatorLease,
		responderLease:   responderLease,
		controllers:      []*probeio.Controller{initiatorController, responderController},
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	results := make(chan endpointOutcome, 2)
	go func() {
		result, runErr := runEndpoint(ctx, initiatorController, initiatorPreparer, initiatorChannel, testpairing.RoleInitiator, attemptID, options.window, options.initiatorSecure)
		results <- endpointOutcome{role: testpairing.RoleInitiator, result: result, err: runErr}
	}()
	go func() {
		result, runErr := runEndpoint(ctx, responderController, responderPreparer, responderChannel, testpairing.RoleResponder, attemptID, options.window, options.responderSecure)
		results <- endpointOutcome{role: testpairing.RoleResponder, result: result, err: runErr}
	}()
	for index := 0; index < 2; index++ {
		outcome := <-results
		if outcome.role == testpairing.RoleInitiator {
			run.initiator = outcome
		} else {
			run.responder = outcome
		}
	}
	return run, nil
}

func runEndpoint(
	ctx context.Context,
	controller *probeio.Controller,
	preparer *simulationPreparer,
	channel *testpairing.SimulatedChannel,
	role testpairing.Role,
	attemptID string,
	window time.Duration,
	secure *secureEndpointConfig,
) (result punchsim.Result, err error) {
	handedToPunch := false
	cryptoHandedToPunch := false
	var securePackets *noisecore.PacketCipher
	defer func() {
		if !handedToPunch {
			err = errors.Join(err, controller.Close())
		}
		if securePackets != nil && !cryptoHandedToPunch {
			err = errors.Join(err, securePackets.Close())
		}
		if err != nil {
			cancelControl(channel)
		}
	}()

	socket, err := controller.OpenProbeSocket(ctx)
	if err != nil {
		return punchsim.Result{}, err
	}
	peer, err := preparer.Prepare(ctx, socket)
	if err != nil {
		return punchsim.Result{}, err
	}
	securePackets, err = runControlPrelude(ctx, channel, role, attemptID, secure)
	if err != nil {
		return punchsim.Result{}, err
	}
	handedToPunch = true
	coreRole := punchsim.RoleInitiator
	if role == testpairing.RoleResponder {
		coreRole = punchsim.RoleResponder
	}
	var securePunch *punchsim.SecureConfig
	if securePackets != nil {
		securePunch = &punchsim.SecureConfig{Packets: securePackets}
		cryptoHandedToPunch = true
	}
	result, err = punchsim.Run(ctx, punchsim.Config{
		Socket:                &governedPunchSocket{controller: controller, socket: socket},
		PeerEndpoint:          peer,
		Role:                  coreRole,
		AttemptID:             attemptID,
		ObservationGeneration: 1,
		PunchWindow:           window,
		Secure:                securePunch,
	})
	if err != nil {
		return punchsim.Result{}, err
	}
	if err := runControlVerify(ctx, channel, attemptID); err != nil {
		_ = result.Promotion.Transport.Close()
		return punchsim.Result{}, err
	}
	return result, nil
}

func runControlPrelude(
	ctx context.Context,
	channel *testpairing.SimulatedChannel,
	role testpairing.Role,
	attemptID string,
	secure *secureEndpointConfig,
) (*noisecore.PacketCipher, error) {
	var session *noisecore.Session
	var err error
	if secure == nil {
		if err := channel.Send(ctx, testpairing.MessagePrepare, nil); err != nil {
			return nil, err
		}
		if err := receiveControl(ctx, channel, attemptID, testpairing.MessagePrepare); err != nil {
			return nil, err
		}
	} else {
		session, err = runSecureHandshakeOverControl(ctx, channel, role, attemptID, secure)
		if err != nil {
			return nil, err
		}
	}
	var readyPayload []byte
	if session != nil {
		hash, err := session.HandshakeHash()
		if err != nil {
			_ = session.Close()
			return nil, err
		}
		readyPayload = append(readyPayload, hash[:]...)
	}
	if err := channel.Send(ctx, testpairing.MessageReady, readyPayload); err != nil {
		clear(readyPayload)
		_ = session.Close()
		return nil, err
	}
	peerReady, err := receiveControlPayload(ctx, channel, attemptID, testpairing.MessageReady)
	if err != nil {
		clear(readyPayload)
		_ = session.Close()
		return nil, err
	}
	if session == nil && len(peerReady) != 0 {
		clear(peerReady)
		clear(readyPayload)
		_ = session.Close()
		return nil, errors.New("plaintext control payload mismatch")
	}
	if session != nil {
		if len(peerReady) != noisecore.HashSize || !bytes.Equal(peerReady, readyPayload) {
			clear(peerReady)
			clear(readyPayload)
			_ = session.Close()
			return nil, errors.New("secure handshake hash mismatch")
		}
	}
	clear(peerReady)
	clear(readyPayload)
	var packets *noisecore.PacketCipher
	if session != nil {
		packets, err = session.TakePacketCipher(punchsim.MaxSecurePacketSequence)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
	}
	if role == testpairing.RoleInitiator {
		if err := channel.Send(ctx, testpairing.MessageFire, nil); err != nil {
			_ = packets.Close()
			return nil, err
		}
		return packets, nil
	}
	if err := receiveControl(ctx, channel, attemptID, testpairing.MessageFire); err != nil {
		_ = packets.Close()
		return nil, err
	}
	return packets, nil
}

func runSecureHandshakeOverControl(
	ctx context.Context,
	channel *testpairing.SimulatedChannel,
	role testpairing.Role,
	attemptID string,
	secure *secureEndpointConfig,
) (*noisecore.Session, error) {
	noiseConfig := noisecore.Config{Prologue: secure.prologue, PSK: secure.psk, Random: secure.random}
	if role == testpairing.RoleInitiator {
		session, err := noisecore.NewInitiator(noiseConfig)
		if err != nil {
			return nil, err
		}
		first, err := session.WriteMessage(nil)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
		first = mutateHandshake(first, secure.handshakeMutate)
		if len(first) != noisecore.PublicKeySize+noisecore.TagSize {
			clear(first)
			_ = session.Close()
			return nil, errors.New("secure control handshake message size mismatch")
		}
		if err := channel.Send(ctx, testpairing.MessagePrepare, first); err != nil {
			clear(first)
			_ = session.Close()
			return nil, err
		}
		clear(first)
		second, err := receiveControlPayload(ctx, channel, attemptID, testpairing.MessagePrepare)
		if err != nil {
			_ = session.Close()
			return nil, err
		}
		payload, err := session.ReadMessage(second)
		clear(second)
		if err != nil || len(payload) != 0 || !session.Complete() {
			clear(payload)
			_ = session.Close()
			if err != nil {
				return nil, err
			}
			return nil, errors.New("secure control handshake incomplete")
		}
		clear(payload)
		return session, nil
	}

	session, err := noisecore.NewResponder(noiseConfig)
	if err != nil {
		return nil, err
	}
	first, err := receiveControlPayload(ctx, channel, attemptID, testpairing.MessagePrepare)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	payload, err := session.ReadMessage(first)
	clear(first)
	if err != nil || len(payload) != 0 {
		clear(payload)
		_ = session.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("secure control handshake payload was not empty")
	}
	clear(payload)
	second, err := session.WriteMessage(nil)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	second = mutateHandshake(second, secure.handshakeMutate)
	if len(second) != noisecore.PublicKeySize+noisecore.TagSize {
		clear(second)
		_ = session.Close()
		return nil, errors.New("secure control handshake message size mismatch")
	}
	if err := channel.Send(ctx, testpairing.MessagePrepare, second); err != nil {
		clear(second)
		_ = session.Close()
		return nil, err
	}
	clear(second)
	if !session.Complete() {
		_ = session.Close()
		return nil, errors.New("secure control handshake incomplete")
	}
	return session, nil
}

func mutateHandshake(message []byte, mutate func([]byte) []byte) []byte {
	if mutate == nil {
		return message
	}
	return mutate(message)
}

func runControlVerify(ctx context.Context, channel *testpairing.SimulatedChannel, attemptID string) error {
	if err := channel.Send(ctx, testpairing.MessageVerify, nil); err != nil {
		return err
	}
	if err := receiveControl(ctx, channel, attemptID, testpairing.MessageVerify); err != nil {
		return err
	}
	status := channel.Status()
	if !status.Terminal || !status.Success || status.Reason != testpairing.TerminalSuccess {
		return errors.New("pairing channel did not reach terminal success")
	}
	return nil
}

func receiveControl(ctx context.Context, channel *testpairing.SimulatedChannel, attemptID string, expected testpairing.MessageType) error {
	payload, err := receiveControlPayload(ctx, channel, attemptID, expected)
	if err != nil {
		return err
	}
	defer clear(payload)
	if len(payload) != 0 {
		return errors.New("pairing control payload mismatch")
	}
	return nil
}

func receiveControlPayload(ctx context.Context, channel *testpairing.SimulatedChannel, attemptID string, expected testpairing.MessageType) ([]byte, error) {
	message, err := channel.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if message.Type != expected || message.AttemptID != attemptID || message.ObservationGeneration != 1 {
		clear(message.Payload)
		return nil, errors.New("pairing control context mismatch")
	}
	return message.Payload, nil
}

func cancelControl(channel *testpairing.SimulatedChannel) {
	if channel == nil || channel.Status().Terminal {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = channel.Send(ctx, testpairing.MessageCancel, nil)
}

type governedPunchSocket struct {
	controller *probeio.Controller
	socket     *probeio.ProbeSocket
}

func (socket *governedPunchSocket) RegisterTarget(target netip.AddrPort) error {
	return socket.socket.RegisterTarget(target)
}

func (socket *governedPunchSocket) SendProbe(ctx context.Context, target netip.AddrPort, packet []byte) error {
	return socket.socket.SendProbe(ctx, target, packet)
}

func (socket *governedPunchSocket) ReceiveReply(ctx context.Context, dst []byte, verify punchsim.ReplyVerifier) (int, netip.AddrPort, error) {
	return socket.socket.ReceiveReply(ctx, dst, func(packet []byte, from netip.AddrPort) error {
		return verify(packet, from)
	})
}

func (socket *governedPunchSocket) Promote(target netip.AddrPort, pathID string) (punchsim.Promotion, error) {
	promotion, err := socket.socket.Promote(target, pathID)
	if err != nil {
		return punchsim.Promotion{}, err
	}
	return punchsim.Promotion{
		AttemptID:  promotion.AttemptID,
		Generation: promotion.Generation,
		Target:     promotion.Target,
		Transport:  promotion.Transport,
	}, nil
}

func (socket *governedPunchSocket) Close() error {
	return socket.controller.Close()
}

func exchangeApplicationPayload(parent context.Context, run *pairRunResult) error {
	ctx, cancel := context.WithTimeout(parent, 250*time.Millisecond)
	defer cancel()
	if err := run.initiator.result.Promotion.Transport.WritePacket(ctx, []byte("application-from-initiator")); err != nil {
		return fmt.Errorf("write initiator application payload: %w", err)
	}
	buffer := make([]byte, 128)
	n, meta, err := run.responder.result.Promotion.Transport.ReadPacket(ctx, buffer)
	if err != nil {
		return fmt.Errorf("read responder application payload: %w", err)
	}
	if string(buffer[:n]) != "application-from-initiator" || meta.PathID != punchsim.PathID {
		return fmt.Errorf("responder application packet = %q/%+v", buffer[:n], meta)
	}
	if err := run.responder.result.Promotion.Transport.WritePacket(ctx, []byte("application-from-responder")); err != nil {
		return fmt.Errorf("write responder application payload: %w", err)
	}
	n, meta, err = run.initiator.result.Promotion.Transport.ReadPacket(ctx, buffer)
	if err != nil {
		return fmt.Errorf("read initiator application payload: %w", err)
	}
	if string(buffer[:n]) != "application-from-responder" || meta.PathID != punchsim.PathID {
		return fmt.Errorf("initiator application packet = %q/%+v", buffer[:n], meta)
	}
	return nil
}

func simulationID(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 16))
}

type fixedTestPSK struct {
	key [noisecore.PSKSize]byte
}

type secureEndpointConfig struct {
	prologue        []byte
	psk             noisecore.PSKSource
	random          io.Reader
	handshakeMutate func([]byte) []byte
}

func (source fixedTestPSK) LoadPSK() ([noisecore.PSKSize]byte, error) {
	return source.key, nil
}

func repeatedPSK(value byte) [noisecore.PSKSize]byte {
	var key [noisecore.PSKSize]byte
	for index := range key {
		key[index] = value
	}
	return key
}

func fixedRandom(value byte) []byte {
	return bytes.Repeat([]byte{value}, 32)
}

func securePairConfigs(
	t *testing.T,
	initiatorPSK, responderPSK [noisecore.PSKSize]byte,
	initiatorRandom, responderRandom []byte,
) (*secureEndpointConfig, *secureEndpointConfig) {
	t.Helper()
	prologue := securePairingPrologue(t)
	initiator := &secureEndpointConfig{
		prologue: append([]byte(nil), prologue...),
		psk:      fixedTestPSK{key: initiatorPSK},
	}
	responder := &secureEndpointConfig{
		prologue: append([]byte(nil), prologue...),
		psk:      fixedTestPSK{key: responderPSK},
	}
	if initiatorRandom != nil {
		initiator.random = bytes.NewReader(append([]byte(nil), initiatorRandom...))
	}
	if responderRandom != nil {
		responder.random = bytes.NewReader(append([]byte(nil), responderRandom...))
	}
	return initiator, responder
}

func securePairingPrologue(t *testing.T) []byte {
	t.Helper()
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	context := testpairing.PairingContext{
		Artifact:               testpairing.PairingArtifactAcceptance,
		Protocol:               testpairing.ProtocolVersion,
		AuthScope:              testpairing.AuthScope,
		CredentialID:           simulationID(1),
		AttemptID:              simulationID(2),
		ObservationGeneration:  "1",
		InitiatorParticipantID: simulationID(3),
		ResponderParticipantID: simulationID(4),
		InitiatorGovernorScope: string(testpairing.GovernorScopeMachine),
		ResponderGovernorScope: string(testpairing.GovernorScopeMachine),
		SecureChannelProfile:   testpairing.SelectedSecureChannelProfile,
		IssuedAt:               now.Add(-time.Second).Format(time.RFC3339),
		ExpiresAt:              now.Add(5 * time.Minute).Format(time.RFC3339),
		OfferFingerprint:       base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)),
		InitiatorChannelRole:   testpairing.ChannelRoleInitiator,
		ResponderChannelRole:   testpairing.ChannelRoleResponder,
		EarlyData:              testpairing.FeatureDisabled,
		Resumption:             testpairing.FeatureDisabled,
		RuntimeFallback:        testpairing.FeatureDisabled,
	}
	prologue, err := testpairing.BuildNoisePrologue(context)
	if err != nil {
		t.Fatalf("build secure pairing prologue: %v", err)
	}
	return prologue
}

func isSecurePacket(packet []byte) bool {
	return len(packet) > len(punchsim.SecurePacketPrefix) && bytes.HasPrefix(packet, []byte(punchsim.SecurePacketPrefix))
}

func isSecurePunchPacket(packet []byte) bool {
	if !isSecurePacket(packet) {
		return false
	}
	frameType := packet[len(punchsim.SecurePacketPrefix)]
	return frameType >= 0x11 && frameType <= 0x13
}

func containsSecurePunchPacket(packets [][]byte) bool {
	for _, packet := range packets {
		if isSecurePunchPacket(packet) {
			return true
		}
	}
	return false
}

type securePacketRecorder struct {
	mu      sync.Mutex
	packets [][]byte
}

type byteSequenceRecorder struct {
	mu      sync.Mutex
	entries [][]byte
}

func (recorder *byteSequenceRecorder) record(value []byte) []byte {
	recorder.mu.Lock()
	recorder.entries = append(recorder.entries, append([]byte(nil), value...))
	recorder.mu.Unlock()
	return value
}

func (recorder *byteSequenceRecorder) snapshot() [][]byte {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	result := make([][]byte, len(recorder.entries))
	for index := range recorder.entries {
		result[index] = append([]byte(nil), recorder.entries[index]...)
	}
	return result
}

type byteSequenceReplayer struct {
	mu      sync.Mutex
	entries [][]byte
	index   int
}

func newByteSequenceReplayer(entries [][]byte) *byteSequenceReplayer {
	result := &byteSequenceReplayer{entries: make([][]byte, len(entries))}
	for index := range entries {
		result.entries[index] = append([]byte(nil), entries[index]...)
	}
	return result
}

func (replayer *byteSequenceReplayer) replay(value []byte) []byte {
	replayer.mu.Lock()
	defer replayer.mu.Unlock()
	if replayer.index >= len(replayer.entries) {
		return value
	}
	replacement := append([]byte(nil), replayer.entries[replayer.index]...)
	replayer.index++
	clear(value)
	return replacement
}

func (replayer *byteSequenceReplayer) used() int {
	replayer.mu.Lock()
	defer replayer.mu.Unlock()
	return replayer.index
}

func (recorder *securePacketRecorder) record(packet []byte) []byte {
	if !isSecurePacket(packet) {
		return packet
	}
	recorder.mu.Lock()
	recorder.packets = append(recorder.packets, append([]byte(nil), packet...))
	recorder.mu.Unlock()
	return packet
}

func (recorder *securePacketRecorder) snapshot() [][]byte {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	result := make([][]byte, len(recorder.packets))
	for index := range recorder.packets {
		result[index] = append([]byte(nil), recorder.packets[index]...)
	}
	return result
}

type securePacketReplayer struct {
	mu      sync.Mutex
	packets [][]byte
	index   int
}

func newSecurePacketReplayer(packets [][]byte) *securePacketReplayer {
	result := &securePacketReplayer{packets: make([][]byte, len(packets))}
	for index := range packets {
		result.packets[index] = append([]byte(nil), packets[index]...)
	}
	return result
}

func (replayer *securePacketReplayer) replay(packet []byte) []byte {
	if !isSecurePacket(packet) {
		return packet
	}
	replayer.mu.Lock()
	defer replayer.mu.Unlock()
	if replayer.index >= len(replayer.packets) {
		return packet
	}
	replacement := append([]byte(nil), replayer.packets[replayer.index]...)
	replayer.index++
	clear(packet)
	return replacement
}

func (replayer *securePacketReplayer) used() int {
	replayer.mu.Lock()
	defer replayer.mu.Unlock()
	return replayer.index
}

type candidateExchange struct {
	mu         sync.Mutex
	candidates map[testpairing.Role]netip.AddrPort
	ready      chan struct{}
	readyOnce  sync.Once
}

func newCandidateExchange() *candidateExchange {
	return &candidateExchange{
		candidates: make(map[testpairing.Role]netip.AddrPort, 2),
		ready:      make(chan struct{}),
	}
}

func (exchange *candidateExchange) publish(ctx context.Context, role testpairing.Role, candidate netip.AddrPort) (netip.AddrPort, error) {
	exchange.mu.Lock()
	if _, exists := exchange.candidates[role]; exists {
		exchange.mu.Unlock()
		return netip.AddrPort{}, errors.New("duplicate candidate role")
	}
	exchange.candidates[role] = candidate
	if len(exchange.candidates) == 2 {
		exchange.readyOnce.Do(func() { close(exchange.ready) })
	}
	exchange.mu.Unlock()
	select {
	case <-ctx.Done():
		return netip.AddrPort{}, ctx.Err()
	case <-exchange.ready:
	}
	peerRole := testpairing.RoleInitiator
	if role == testpairing.RoleInitiator {
		peerRole = testpairing.RoleResponder
	}
	exchange.mu.Lock()
	peer := exchange.candidates[peerRole]
	exchange.mu.Unlock()
	return peer, nil
}

type simulationPreparer struct {
	role     testpairing.Role
	network  *natsim.Network
	factory  *simulationFactory
	observer netip.AddrPort
	exchange *candidateExchange
}

func (preparer *simulationPreparer) Prepare(ctx context.Context, socket *probeio.ProbeSocket) (netip.AddrPort, error) {
	if err := socket.RegisterTarget(preparer.observer); err != nil {
		return netip.AddrPort{}, err
	}
	if err := socket.SendProbe(ctx, preparer.observer, []byte("simulation-candidate-observation")); err != nil {
		return netip.AddrPort{}, err
	}
	connection := preparer.factory.connection()
	if connection == nil {
		return netip.AddrPort{}, errors.New("candidate factory has no connection")
	}
	mapped, err := preparer.network.MappedAddr(connection, preparer.observer)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return preparer.exchange.publish(ctx, preparer.role, mapped)
}

type simulationFactory struct {
	network     *natsim.Network
	endpoint    natsim.EndpointConfig
	mutateWrite func([]byte) []byte

	mu     sync.Mutex
	opened bool
	conn   *natsim.PacketConn
}

func (factory *simulationFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.opened {
		return nil, errors.New("simulation factory opened more than once")
	}
	connection, err := factory.network.NewPacketConn(factory.endpoint)
	if err != nil {
		return nil, err
	}
	factory.opened = true
	factory.conn = connection
	return &simulationDatagram{connection: connection, mutateWrite: factory.mutateWrite}, nil
}

func (factory *simulationFactory) connection() *natsim.PacketConn {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.conn
}

type simulationDatagram struct {
	connection  *natsim.PacketConn
	mutateWrite func([]byte) []byte
}

func (datagram *simulationDatagram) ReadFrom(ctx context.Context, dst []byte) (int, netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return 0, netip.AddrPort{}, err
	}
	stop := context.AfterFunc(ctx, func() {
		_ = datagram.connection.SetReadDeadline(time.Now())
	})
	n, address, err := datagram.connection.ReadFrom(dst)
	stop()
	_ = datagram.connection.SetReadDeadline(time.Time{})
	if contextErr := ctx.Err(); contextErr != nil {
		return 0, netip.AddrPort{}, contextErr
	}
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok || udpAddress == nil {
		return 0, netip.AddrPort{}, errors.New("simulation returned a non-UDP source")
	}
	return n, udpAddress.AddrPort(), nil
}

func (datagram *simulationDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	toWrite := append([]byte(nil), packet...)
	if datagram.mutateWrite != nil {
		toWrite = datagram.mutateWrite(toWrite)
	}
	n, err := datagram.connection.WriteTo(toWrite, net.UDPAddrFromAddrPort(target))
	if err != nil || datagram.mutateWrite == nil {
		return n, err
	}
	// The fault injector models mutation after the sender's successful write;
	// probeio must therefore see the original caller-visible byte count.
	return len(packet), nil
}

func (datagram *simulationDatagram) SetDeadline(deadline time.Time) error {
	return datagram.connection.SetDeadline(deadline)
}

func (datagram *simulationDatagram) LocalAddr() net.Addr {
	return datagram.connection.LocalAddr()
}

func (datagram *simulationDatagram) Close() error {
	return datagram.connection.Close()
}

func newSimulationController(lease *simulationLease, factory *simulationFactory) (*probeio.Controller, error) {
	return probeio.New(probeio.Config{
		Lease:              lease,
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "test",
	})
}

type simulationLease struct {
	request  governor.AttemptRequest
	peerID   string
	stopping chan struct{}
	done     chan struct{}

	mu             sync.Mutex
	drains         int
	trips          int
	stoppingClosed bool
	doneClosed     bool
}

func newSimulationLease(attemptID, peerID string, resources governor.Resources) *simulationLease {
	return &simulationLease{
		request: governor.AttemptRequest{
			ID:        attemptID,
			Operation: governor.OperationConnectTest,
			Cost: governor.AttemptCost{
				Resources: resources,
				Duration:  2 * time.Second,
			},
		},
		peerID:   peerID,
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (lease *simulationLease) Request() governor.AttemptRequest { return lease.request }
func (lease *simulationLease) PeerID() string                   { return lease.peerID }
func (lease *simulationLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *simulationLease) Done() <-chan struct{}            { return lease.done }

func (lease *simulationLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.stoppingClosed {
		return nil, governor.ErrLeaseClosed
	}
	lease.drains++
	return &simulationDrain{lease: lease}, nil
}

func (lease *simulationLease) Close() error {
	lease.mu.Lock()
	lease.beginStoppingLocked()
	if lease.drains == 0 {
		lease.finishLocked()
	}
	done := lease.done
	lease.mu.Unlock()
	<-done
	return nil
}

func (lease *simulationLease) Trip(event governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	lease.mu.Lock()
	lease.trips++
	lease.beginStoppingLocked()
	sequence := uint64(lease.trips)
	lease.mu.Unlock()
	return governor.SafetyTripStatus{
		State:            governor.SafetyTripTripped,
		BlocksActiveWork: true,
		Record: governor.SafetyTripRecord{
			SchemaVersion: 1,
			State:         governor.SafetyTripTripped,
			Sequence:      sequence,
			Reason:        event.Reason,
		},
	}, nil
}

func (lease *simulationLease) tripCount() int {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.trips
}

func (lease *simulationLease) beginStoppingLocked() {
	if !lease.stoppingClosed {
		lease.stoppingClosed = true
		close(lease.stopping)
	}
}

func (lease *simulationLease) finishLocked() {
	if !lease.doneClosed {
		lease.doneClosed = true
		close(lease.done)
	}
}

type simulationDrain struct {
	lease *simulationLease
	once  sync.Once
}

func (drain *simulationDrain) Complete() error {
	drain.once.Do(func() {
		drain.lease.mu.Lock()
		if drain.lease.drains > 0 {
			drain.lease.drains--
		}
		if drain.lease.stoppingClosed && drain.lease.drains == 0 {
			drain.lease.finishLocked()
		}
		drain.lease.mu.Unlock()
	})
	return nil
}
