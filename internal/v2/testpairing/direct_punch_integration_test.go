package testpairing_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/natsim"
	"winkyou/internal/probeio"
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
			for _, outcome := range []endpointOutcome{run.initiator, run.responder} {
				if outcome.err != nil {
					return outcome.err
				}
				if outcome.result.OutboundPackets < 1 || outcome.result.OutboundPackets > punchsim.MaxOutboundPackets ||
					outcome.result.InboundPackets < 1 || outcome.result.InboundPackets > punchsim.MaxInboundPackets {
					return fmt.Errorf("unexpected punch counters: %+v", outcome.result)
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
	model := natsim.Model{
		Mapping:    mapping,
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
	}
	responderFactory := &simulationFactory{
		network: network,
		endpoint: natsim.EndpointConfig{
			LocalAddr: netip.MustParseAddrPort("198.51.100.20:45020"),
			NATChain:  []*natsim.NAT{natB},
		},
		mutateWrite: responderMutate,
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
		result, runErr := runEndpoint(ctx, initiatorController, initiatorPreparer, initiatorChannel, testpairing.RoleInitiator, attemptID, window)
		results <- endpointOutcome{role: testpairing.RoleInitiator, result: result, err: runErr}
	}()
	go func() {
		result, runErr := runEndpoint(ctx, responderController, responderPreparer, responderChannel, testpairing.RoleResponder, attemptID, window)
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
) (result punchsim.Result, err error) {
	handedToPunch := false
	defer func() {
		if !handedToPunch {
			err = errors.Join(err, controller.Close())
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
	if err := runControlPrelude(ctx, channel, role, attemptID); err != nil {
		return punchsim.Result{}, err
	}
	handedToPunch = true
	coreRole := punchsim.RoleInitiator
	if role == testpairing.RoleResponder {
		coreRole = punchsim.RoleResponder
	}
	result, err = punchsim.Run(ctx, punchsim.Config{
		Socket:                &governedPunchSocket{controller: controller, socket: socket},
		PeerEndpoint:          peer,
		Role:                  coreRole,
		AttemptID:             attemptID,
		ObservationGeneration: 1,
		PunchWindow:           window,
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

func runControlPrelude(ctx context.Context, channel *testpairing.SimulatedChannel, role testpairing.Role, attemptID string) error {
	if err := channel.Send(ctx, testpairing.MessagePrepare, nil); err != nil {
		return err
	}
	if err := receiveControl(ctx, channel, attemptID, testpairing.MessagePrepare); err != nil {
		return err
	}
	if err := channel.Send(ctx, testpairing.MessageReady, nil); err != nil {
		return err
	}
	if err := receiveControl(ctx, channel, attemptID, testpairing.MessageReady); err != nil {
		return err
	}
	if role == testpairing.RoleInitiator {
		return channel.Send(ctx, testpairing.MessageFire, nil)
	}
	return receiveControl(ctx, channel, attemptID, testpairing.MessageFire)
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
	message, err := channel.Receive(ctx)
	if err != nil {
		return err
	}
	if message.Type != expected || message.AttemptID != attemptID || message.ObservationGeneration != 1 || len(message.Payload) != 0 {
		return errors.New("pairing control context mismatch")
	}
	return nil
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
