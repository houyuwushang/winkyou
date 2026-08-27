package governor_test

import (
	"context"
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
	"winkyou/internal/stunwire"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gatea"
	"winkyou/internal/v2/oobattempt"
)

func TestGateANATSimulationEIMEIMFreshRun100Times(t *testing.T) {
	repetition := 0
	report, err := natsim.RunScenario(context.Background(), natsim.Scenario{
		Name:        "gate-a-eim-eim-handoff",
		Repetitions: 100,
		Network: natsim.Config{
			MaxPacketConns: 4,
			MaxMappings:    4,
			QueueCapacity:  16,
			MaxDatagram:    2048,
		},
		Resources: natsim.ResourceLimits{PacketConns: 4, Mappings: 2, QueuedPackets: 6},
		Execute: func(ctx context.Context, network *natsim.Network) error {
			repetition++
			outcomes, err := runGateANATSimulation(t, ctx, network, repetition,
				natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, nil, nil)
			if err != nil {
				return err
			}
			if len(outcomes) != 2 {
				return fmt.Errorf("outcomes=%d want=2", len(outcomes))
			}
			direct, udp := 0, 0
			for _, outcome := range outcomes {
				if outcome.err != nil || outcome.result.Terminal != "success" || !outcome.result.Bidirectional ||
					!outcome.result.FinishRecorded || !outcome.result.TransportDrained ||
					outcome.result.MappingBehavior != "consistent_same_address" ||
					outcome.result.Emissions.STUNPackets != 2 || outcome.result.Emissions.DataPacketsRead != 3 ||
					outcome.result.Emissions.DataPacketsWritten != 3 ||
					!reflect.DeepEqual(outcome.stages, gatea.ProgressSequence) {
					return fmt.Errorf("successful outcome mismatch: err=%v result=%+v stages=%v", outcome.err, outcome.result, outcome.stages)
				}
				direct += outcome.result.Emissions.DirectPackets
				udp += outcome.result.Emissions.UDPPacketsTotal
			}
			if direct != 3 || udp != 7 {
				return fmt.Errorf("direct/UDP packets=%d/%d want=3/7", direct, udp)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Gate A EIM x EIM matrix: %v", err)
	}
	if report.CompletedRepetitions != 100 || report.PeakPacketConns != 4 || report.PeakMappings != 2 {
		t.Fatalf("Gate A EIM x EIM report=%+v", report)
	}
	t.Logf("Gate A EIM x EIM witness: completed=%d peak_packet_conns=%d peak_mappings=%d direct=3 establishment_udp=7 data=3/3 residue=0",
		report.CompletedRepetitions, report.PeakPacketConns, report.PeakMappings)
}

func TestGateANATSimulationEDMStopsBeforeREADYInEitherRole(t *testing.T) {
	for _, test := range []struct {
		name      string
		initiator natsim.MappingBehavior
		responder natsim.MappingBehavior
	}{
		{"initiator-edm", natsim.MappingEndpointDependent, natsim.MappingEndpointIndependent},
		{"responder-edm", natsim.MappingEndpointIndependent, natsim.MappingEndpointDependent},
	} {
		t.Run(test.name, func(t *testing.T) {
			repetition := 0
			report, err := natsim.RunScenario(context.Background(), natsim.Scenario{
				Name:        "gate-a-" + test.name,
				Repetitions: 20,
				Network:     natsim.Config{MaxPacketConns: 4, MaxMappings: 4, QueueCapacity: 8, MaxDatagram: 2048},
				Resources:   natsim.ResourceLimits{PacketConns: 4, Mappings: 3, QueuedPackets: 2},
				Execute: func(ctx context.Context, network *natsim.Network) error {
					repetition++
					outcomes, runErr := runGateANATSimulation(t, ctx, network, repetition, test.initiator, test.responder, nil, nil)
					if runErr != nil {
						return runErr
					}
					mappingFailures := 0
					peerTerminals := 0
					for _, outcome := range outcomes {
						var failure *gatea.Failure
						if !errors.As(outcome.err, &failure) || !failure.CredentialBurned || failure.Retryable ||
							outcome.result.Emissions.DirectPackets != 0 || !outcome.result.FinishRecorded || outcome.result.SafetyTrip.BlocksActiveWork {
							return fmt.Errorf("EDM outcome mismatch: err=%v failure=%+v result=%+v", outcome.err, failure, outcome.result)
						}
						switch failure.Class {
						case gatea.ClassMappingNotDirectlyUsable:
							if failure.Stage != gatea.StageSTUN || outcome.result.MappingBehavior != "port_dependent" {
								return fmt.Errorf("EDM mapping terminal mismatch: failure=%+v result=%+v", failure, outcome.result)
							}
							mappingFailures++
						case gatea.ClassOOBStreamClosed:
							peerTerminals++
						default:
							return fmt.Errorf("unexpected EDM peer class: failure=%+v", failure)
						}
					}
					if mappingFailures != 1 || peerTerminals != 1 {
						return fmt.Errorf("EDM terminals mapping/peer=%d/%d want=1/1", mappingFailures, peerTerminals)
					}
					return nil
				},
			})
			if err != nil {
				t.Fatalf("Gate A EDM matrix: %v", err)
			}
			if report.CompletedRepetitions != 20 || report.PeakPacketConns != 4 || report.PeakMappings != 3 {
				t.Fatalf("Gate A EDM report=%+v", report)
			}
		})
	}
}

func TestGateANATSimulationMappingChangeInvalidatesEasyEvidence(t *testing.T) {
	changed := gateANATModel(natsim.MappingEndpointDependent)
	change := []natsim.BehaviorChange{{
		AfterOutboundPackets: 1,
		Model:                changed,
		PublicAddr:           netip.MustParseAddr("198.51.100.11"),
	}}
	outcomes, err := runGateANATOneShot(t, context.Background(), 1,
		natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, change, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer outcomes.close()
	mappingFailures := 0
	peerTerminals := 0
	for _, outcome := range outcomes.items {
		var failure *gatea.Failure
		if !errors.As(outcome.err, &failure) || outcome.result.Emissions.DirectPackets != 0 || !outcome.result.FinishRecorded {
			t.Fatalf("mapping-change outcome: err=%v failure=%+v result=%+v", outcome.err, failure, outcome.result)
		}
		switch failure.Class {
		case gatea.ClassMappingNotDirectlyUsable:
			mappingFailures++
		case gatea.ClassOOBStreamClosed:
			peerTerminals++
		default:
			t.Fatalf("mapping-change class=%s", failure.Class)
		}
	}
	if mappingFailures != 1 || peerTerminals != 1 {
		t.Fatalf("mapping-change terminals mapping/peer=%d/%d", mappingFailures, peerTerminals)
	}
}

func TestGateANATSimulationSTUNFaultsAreTerminalWithoutDirectEmission(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		mode    gateANATSTUNMode
		class   string
		minimum int
		maximum int
	}{
		{"silent", gateANATSTUNSilent, gatea.ClassSTUNSilent, 1, 3},
		{"wrong_source", gateANATSTUNWrongSource, gatea.ClassSTUNSourceMismatch, 1, 1},
		{"protocol", gateANATSTUNProtocolError, gatea.ClassSTUNProtocol, 1, 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			run, err := runGateANATOneShotWithSTUN(t, context.Background(), 1, testCase.mode)
			if err != nil {
				t.Fatal(err)
			}
			defer run.close()
			if len(run.items) != 2 {
				t.Fatalf("outcomes=%d want=2", len(run.items))
			}
			for _, outcome := range run.items {
				var failure *gatea.Failure
				if !errors.As(outcome.err, &failure) || failure.Class != testCase.class ||
					failure.Stage != gatea.StageSTUN || !failure.CredentialBurned || failure.Retryable ||
					outcome.result.Emissions.STUNPackets < testCase.minimum || outcome.result.Emissions.STUNPackets > testCase.maximum ||
					outcome.result.Emissions.DirectPackets != 0 || !outcome.result.FinishRecorded ||
					outcome.result.PairingLedger.Sequence != 3 || outcome.result.SafetyTrip.BlocksActiveWork {
					t.Fatalf("STUN fault outcome: failure=%+v cause=%v result=%+v", failure, failure.Cause, outcome.result)
				}
			}
		})
	}
}

func TestGateANATSimulationDirectFaultsRemainSingleAttemptAndBounded(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		initiatorFault gateANATInboundFault
		responderFault gateANATInboundFault
		wantTerminal   bool
	}{
		{"drop", gateANATInboundDrop, gateANATInboundNone, true},
		{"duplicate", gateANATInboundNone, gateANATInboundDuplicate, true},
		{"reorder", gateANATInboundNone, gateANATInboundReorder, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			run, err := runGateANATOneShotWithInboundFault(t, context.Background(), 1, testCase.initiatorFault, testCase.responderFault)
			if err != nil {
				t.Fatal(err)
			}
			defer run.close()
			directTerminals := 0
			for _, outcome := range run.items {
				if !outcome.result.CredentialBurned || !outcome.result.FinishRecorded ||
					outcome.result.PairingLedger.TwentyFourHourAdmissions != 1 ||
					outcome.result.PairingLedger.Sequence != 3 || outcome.result.SafetyTrip.BlocksActiveWork ||
					outcome.result.Emissions.STUNPackets != 2 || outcome.result.Emissions.DirectPackets > 2 ||
					outcome.result.Emissions.UDPPacketsTotal > 4 {
					t.Fatalf("direct fault escaped bounds: err=%v result=%+v", outcome.err, outcome.result)
				}
				if outcome.err == nil {
					if outcome.result.Terminal != "success" || !outcome.result.TransportDrained {
						t.Fatalf("reordered success lacked drain: %+v", outcome.result)
					}
					continue
				}
				var failure *gatea.Failure
				if !errors.As(outcome.err, &failure) || !failure.CredentialBurned || failure.Retryable {
					t.Fatalf("direct fault error = %v", outcome.err)
				}
				switch failure.Class {
				case gatea.ClassDirectPacketRejected:
					directTerminals++
				case gatea.ClassOOBStreamClosed, gatea.ClassOOBProtocolViolation, gatea.ClassDataPlaneChallengeFailed:
					directTerminals++
				default:
					t.Fatalf("direct fault class=%q", failure.Class)
				}
			}
			if testCase.wantTerminal && directTerminals == 0 {
				t.Fatal("direct fault did not terminate the direct protocol")
			}
		})
	}
}

type gateANATOutcome struct {
	result gatea.Result
	err    error
	stages []string
}

type gateANATOneShot struct {
	items   []gateANATOutcome
	network *natsim.Network
}

type gateANATSTUNMode uint8

const (
	gateANATSTUNSuccess gateANATSTUNMode = iota
	gateANATSTUNSilent
	gateANATSTUNWrongSource
	gateANATSTUNProtocolError
)

type gateANATInboundFault uint8

const (
	gateANATInboundNone gateANATInboundFault = iota
	gateANATInboundDrop
	gateANATInboundDuplicate
	gateANATInboundReorder
)

func (run *gateANATOneShot) close() {
	if run != nil && run.network != nil {
		_ = run.network.Close()
	}
}

func runGateANATOneShot(t testing.TB, ctx context.Context, repetition int,
	initiatorMapping, responderMapping natsim.MappingBehavior,
	initiatorChanges, responderChanges []natsim.BehaviorChange,
) (*gateANATOneShot, error) {
	t.Helper()
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 4, MaxMappings: 4, QueueCapacity: 16, MaxDatagram: 2048})
	if err != nil {
		return nil, err
	}
	items, err := runGateANATSimulation(t, ctx, network, repetition, initiatorMapping, responderMapping, initiatorChanges, responderChanges)
	if err != nil {
		_ = network.Close()
		return nil, err
	}
	return &gateANATOneShot{items: items, network: network}, nil
}

func runGateANATOneShotWithSTUN(t testing.TB, ctx context.Context, repetition int, mode gateANATSTUNMode) (*gateANATOneShot, error) {
	t.Helper()
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 4, MaxMappings: 4, QueueCapacity: 16, MaxDatagram: 2048})
	if err != nil {
		return nil, err
	}
	items, err := runGateANATSimulationWithSTUN(t, ctx, network, repetition,
		natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, nil, nil, mode)
	if err != nil {
		_ = network.Close()
		return nil, err
	}
	return &gateANATOneShot{items: items, network: network}, nil
}

func runGateANATOneShotWithInboundFault(t testing.TB, ctx context.Context, repetition int,
	initiatorFault, responderFault gateANATInboundFault,
) (*gateANATOneShot, error) {
	t.Helper()
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 4, MaxMappings: 4, QueueCapacity: 16, MaxDatagram: 2048})
	if err != nil {
		return nil, err
	}
	items, err := runGateANATSimulationWithFaults(t, ctx, network, repetition,
		natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, nil, nil,
		gateANATSTUNSuccess, initiatorFault, responderFault)
	if err != nil {
		_ = network.Close()
		return nil, err
	}
	return &gateANATOneShot{items: items, network: network}, nil
}

func runGateANATSimulation(t testing.TB, ctx context.Context, network *natsim.Network, repetition int,
	initiatorMapping, responderMapping natsim.MappingBehavior,
	initiatorChanges, responderChanges []natsim.BehaviorChange,
) ([]gateANATOutcome, error) {
	return runGateANATSimulationWithSTUN(t, ctx, network, repetition, initiatorMapping, responderMapping,
		initiatorChanges, responderChanges, gateANATSTUNSuccess)
}

func runGateANATSimulationWithSTUN(t testing.TB, ctx context.Context, network *natsim.Network, repetition int,
	initiatorMapping, responderMapping natsim.MappingBehavior,
	initiatorChanges, responderChanges []natsim.BehaviorChange, stunMode gateANATSTUNMode,
) ([]gateANATOutcome, error) {
	return runGateANATSimulationWithFaults(t, ctx, network, repetition, initiatorMapping, responderMapping,
		initiatorChanges, responderChanges, stunMode, gateANATInboundNone, gateANATInboundNone)
}

func runGateANATSimulationWithFaults(t testing.TB, ctx context.Context, network *natsim.Network, repetition int,
	initiatorMapping, responderMapping natsim.MappingBehavior,
	initiatorChanges, responderChanges []natsim.BehaviorChange, stunMode gateANATSTUNMode,
	initiatorFault, responderFault gateANATInboundFault,
) ([]gateANATOutcome, error) {
	t.Helper()
	leftNAT, err := network.NewNAT(natsim.NATConfig{
		Name: "left", PublicAddr: netip.MustParseAddr("198.51.100.10"),
		Model: gateANATModel(initiatorMapping), Changes: initiatorChanges,
	})
	if err != nil {
		return nil, err
	}
	rightNAT, err := network.NewNAT(natsim.NATConfig{
		Name: "right", PublicAddr: netip.MustParseAddr("198.51.100.20"),
		Model: gateANATModel(responderMapping), Changes: responderChanges,
	})
	if err != nil {
		return nil, err
	}
	firstSTUN := netip.MustParseAddrPort("203.0.113.1:3478")
	secondSTUN := netip.MustParseAddrPort("203.0.113.1:3479")
	firstServer, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: firstSTUN})
	if err != nil {
		return nil, err
	}
	secondServer, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: secondSTUN})
	if err != nil {
		_ = firstServer.Close()
		return nil, err
	}
	serverErrors := make(chan error, 2)
	go func() { serverErrors <- serveGateANATSTUN(firstServer, stunMode, secondServer) }()
	go func() { serverErrors <- serveGateANATSTUN(secondServer, gateANATSTUNSuccess, nil) }()

	leftFactory := &gateANATFactory{network: network, config: natsim.EndpointConfig{
		LocalAddr: netip.MustParseAddrPort("192.0.2.10:31001"), NATChain: []*natsim.NAT{leftNAT},
	}, inboundFault: initiatorFault}
	rightFactory := &gateANATFactory{network: network, config: natsim.EndpointConfig{
		LocalAddr: netip.MustParseAddrPort("192.0.2.20:31002"), NATChain: []*natsim.NAT{rightNAT},
	}, inboundFault: responderFault}

	now := time.Now().UTC().Truncate(time.Second)
	leftNamespace, rightNamespace := t.TempDir(), t.TempDir()
	for _, namespace := range []string{leftNamespace, rightNamespace} {
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, now); err != nil {
			return nil, err
		}
	}
	leftMachine, err := governor.AcquireLoopbackCarrierTestGovernor(leftNamespace, "gate-a-natsim")
	if err != nil {
		return nil, err
	}
	rightMachine, err := governor.AcquireLoopbackCarrierTestGovernor(rightNamespace, "gate-a-natsim")
	if err != nil {
		_ = leftMachine.Close()
		return nil, err
	}
	leftLedger, err := governor.LoopbackCarrierTestLedger(leftMachine)
	if err != nil {
		_ = rightMachine.Close()
		_ = leftMachine.Close()
		return nil, err
	}
	rightLedger, err := governor.LoopbackCarrierTestLedger(rightMachine)
	if err != nil {
		_ = rightMachine.Close()
		_ = leftMachine.Close()
		return nil, err
	}
	set, err := oobattempt.EncodeArtifactSet(oobattempt.ArtifactMaterial{
		CredentialID:           gateAOpaqueID(fmt.Sprintf("natsim-credential-%d", repetition)),
		AttemptID:              gateAOpaqueID(fmt.Sprintf("natsim-attempt-%d", repetition)),
		InitiatorParticipantID: gateAOpaqueID(fmt.Sprintf("natsim-initiator-%d", repetition)),
		ResponderParticipantID: gateAOpaqueID(fmt.Sprintf("natsim-responder-%d", repetition)),
		OOBChannelID:           gateAOpaqueID(fmt.Sprintf("natsim-channel-%d", repetition)),
		IssuedAt:               now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{1, 4, 9, 16, 25})
	if err != nil {
		_ = rightMachine.Close()
		_ = leftMachine.Close()
		return nil, err
	}
	leftStream, rightStream := net.Pipe()
	results := make(chan gateANATOutcome, 2)
	runSide := func(machine *governor.Governor, ledger *governor.PairingAdmissionLedger, artifact []byte,
		stream net.Conn, factory probeio.Factory,
	) {
		var stages []string
		result, runErr := gatea.Run(ctx, gatea.Config{
			Machine: machine, Ledger: ledger, Artifact: artifact, Stream: stream,
			STUNTargets: []netip.AddrPort{firstSTUN, secondSTUN}, AllowNonLoopback: true,
			BuildVersion: "gate-a-natsim", ProbeFactory: factory,
			Progress: func(stage string, _ bool) error {
				stages = append(stages, stage)
				return nil
			},
		})
		results <- gateANATOutcome{result: result, err: runErr, stages: stages}
	}
	go runSide(leftMachine, leftLedger, set.Initiator, leftStream, leftFactory)
	go runSide(rightMachine, rightLedger, set.Responder, rightStream, rightFactory)

	outcomes := make([]gateANATOutcome, 0, 2)
	for range 2 {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-time.After(5 * time.Second):
			_ = leftStream.Close()
			_ = rightStream.Close()
			return nil, errors.New("Gate A natsim attempt exceeded five seconds")
		}
	}
	set.Close()
	_ = leftFactory.Close()
	_ = rightFactory.Close()
	_ = firstServer.Close()
	_ = secondServer.Close()
	for range 2 {
		if serverErr := <-serverErrors; serverErr != nil {
			return nil, serverErr
		}
	}
	for label, machine := range map[string]*governor.Governor{"left": leftMachine, "right": rightMachine} {
		snapshot := machine.Snapshot()
		if snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 || snapshot.Reserved != (governor.Resources{}) ||
			snapshot.SafetyTrip.BlocksActiveWork {
			return nil, fmt.Errorf("%s governor residue=%+v", label, snapshot)
		}
	}
	if err := rightMachine.Close(); err != nil {
		return nil, err
	}
	if err := leftMachine.Close(); err != nil {
		return nil, err
	}
	if counters := network.Snapshot(); counters.ActivePacketConns != 0 || counters.ActiveMappings != 0 || counters.QueuedPackets != 0 {
		return nil, fmt.Errorf("natsim residue=%+v", counters)
	}
	return outcomes, nil
}

func gateANATModel(mapping natsim.MappingBehavior) natsim.Model {
	return natsim.Model{
		Mapping: mapping, Allocation: natsim.PortIncrement,
		Filtering: natsim.FilterEndpointIndependent,
		PortMin:   40000, PortMax: 40100, RandomSeed: 7,
	}
}

type gateANATFactory struct {
	network      *natsim.Network
	config       natsim.EndpointConfig
	inboundFault gateANATInboundFault
	opened       atomic.Bool
	mu           sync.Mutex
	conn         *natsim.PacketConn
}

func (factory *gateANATFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	if factory == nil || factory.network == nil || ctx == nil || ctx.Err() != nil || !factory.opened.CompareAndSwap(false, true) {
		return nil, probeio.ErrFactoryUnauthorized
	}
	connection, err := factory.network.NewPacketConn(factory.config)
	if err != nil {
		return nil, err
	}
	factory.mu.Lock()
	factory.conn = connection
	factory.mu.Unlock()
	return &gateANATDatagram{connection: connection, inboundFault: factory.inboundFault}, nil
}

func (factory *gateANATFactory) Close() error {
	if factory == nil {
		return nil
	}
	factory.mu.Lock()
	connection := factory.conn
	factory.mu.Unlock()
	if connection != nil {
		return connection.Close()
	}
	return nil
}

type gateANATDatagram struct {
	connection   *natsim.PacketConn
	readMu       sync.Mutex
	writeMu      sync.Mutex
	inboundFault gateANATInboundFault
	faultUsed    bool
	pending      []byte
	pendingFrom  netip.AddrPort
}

func (datagram *gateANATDatagram) ReadFrom(ctx context.Context, dst []byte) (int, netip.AddrPort, error) {
	if datagram == nil || datagram.connection == nil || ctx == nil {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	datagram.readMu.Lock()
	defer datagram.readMu.Unlock()
	if len(datagram.pending) != 0 {
		if len(datagram.pending) > len(dst) {
			return 0, netip.AddrPort{}, probeio.ErrDatagramContract
		}
		n := copy(dst, datagram.pending)
		from := datagram.pendingFrom
		clear(datagram.pending)
		datagram.pending = nil
		datagram.pendingFrom = netip.AddrPort{}
		return n, from, nil
	}
	for {
		n, from, err := datagram.readOne(ctx, dst)
		if err != nil || datagram.faultUsed || !gateANATDirectPacket(dst[:n]) {
			return n, from, err
		}
		datagram.faultUsed = true
		switch datagram.inboundFault {
		case gateANATInboundDrop:
			continue
		case gateANATInboundDuplicate:
			datagram.pending = append([]byte(nil), dst[:n]...)
			datagram.pendingFrom = from
			return n, from, nil
		case gateANATInboundReorder:
			first := append([]byte(nil), dst[:n]...)
			firstFrom := from
			second := make([]byte, len(dst))
			secondN, secondFrom, secondErr := datagram.readOne(ctx, second)
			if secondErr != nil {
				clear(first)
				clear(second)
				return 0, netip.AddrPort{}, secondErr
			}
			datagram.pending = first
			datagram.pendingFrom = firstFrom
			copy(dst, second[:secondN])
			clear(second)
			return secondN, secondFrom, nil
		default:
			return n, from, nil
		}
	}
}

func (datagram *gateANATDatagram) readOne(ctx context.Context, dst []byte) (int, netip.AddrPort, error) {
	if err := ctx.Err(); err != nil {
		return 0, netip.AddrPort{}, err
	}
	deadline := time.Time{}
	if value, ok := ctx.Deadline(); ok {
		deadline = value
	}
	if err := datagram.connection.SetReadDeadline(deadline); err != nil {
		return 0, netip.AddrPort{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = datagram.connection.SetReadDeadline(time.Now()) })
	n, source, err := datagram.connection.ReadFrom(dst)
	stop()
	_ = datagram.connection.SetReadDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, netip.AddrPort{}, ctxErr
	}
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() && !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, netip.AddrPort{}, context.DeadlineExceeded
		}
		return 0, netip.AddrPort{}, err
	}
	udpSource, ok := source.(*net.UDPAddr)
	if !ok || udpSource == nil {
		return 0, netip.AddrPort{}, probeio.ErrDatagramContract
	}
	return n, udpSource.AddrPort(), nil
}

func gateANATDirectPacket(packet []byte) bool {
	metadata, err := directattempt.InspectFrame(packet)
	return err == nil && metadata.Domain == directattempt.DomainDirectPunch
}

func (datagram *gateANATDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if datagram == nil || datagram.connection == nil || ctx == nil {
		return 0, net.ErrClosed
	}
	datagram.writeMu.Lock()
	defer datagram.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return datagram.connection.WriteToAddrPort(packet, target)
}

func (datagram *gateANATDatagram) SetDeadline(deadline time.Time) error {
	if datagram == nil || datagram.connection == nil {
		return net.ErrClosed
	}
	return datagram.connection.SetDeadline(deadline)
}

func (datagram *gateANATDatagram) LocalAddr() net.Addr {
	if datagram == nil || datagram.connection == nil {
		return nil
	}
	return datagram.connection.LocalAddr()
}

func (datagram *gateANATDatagram) Close() error {
	if datagram == nil || datagram.connection == nil {
		return nil
	}
	err := datagram.connection.Close()
	datagram.readMu.Lock()
	clear(datagram.pending)
	datagram.pending = nil
	datagram.pendingFrom = netip.AddrPort{}
	datagram.readMu.Unlock()
	return err
}

func serveGateANATSTUN(connection *natsim.PacketConn, mode gateANATSTUNMode, alternate *natsim.PacketConn) error {
	buffer := make([]byte, stunwire.MaxRequestBytes)
	for {
		n, source, err := connection.ReadFrom(buffer)
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			return err
		}
		udpSource, ok := source.(*net.UDPAddr)
		if !ok || udpSource == nil {
			return errors.New("natsim STUN source is not UDP")
		}
		transaction, err := stunwire.ParseBindingRequest(buffer[:n])
		if err != nil {
			return err
		}
		if mode == gateANATSTUNSilent {
			continue
		}
		response, err := stunwire.BindingSuccess(transaction, udpSource.AddrPort())
		if err != nil {
			return err
		}
		writer := connection
		if mode == gateANATSTUNWrongSource {
			if alternate == nil {
				return errors.New("natsim STUN alternate source unavailable")
			}
			writer = alternate
		}
		if mode == gateANATSTUNProtocolError {
			response[4] ^= 1
		}
		if _, err := writer.WriteToAddrPort(response, udpSource.AddrPort()); err != nil {
			return err
		}
	}
}
