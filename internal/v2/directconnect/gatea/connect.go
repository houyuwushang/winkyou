package gatea

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/oobattempt"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/pkg/transport"
)

const (
	directPathID      = "gate-a/easy-direct/1"
	punchDeadline     = 1500 * time.Millisecond
	challengeDeadline = time.Second
	challengePackets  = 3
	challengeMagic    = "WYGC"
)

type staticPSK [noisecore.PSKSize]byte

func (source staticPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

type runtime struct {
	config          Config
	requestContext  context.Context
	artifact        *oobattempt.Artifact
	request         governor.PairingAdmissionRequest
	peer            *governor.PeerLease
	attempt         *governor.AttemptLease
	carrier         *oobcarrier.Carrier
	authorization   *governor.CommittedCarrierAuthorization
	protocol        *directattempt.Protocol
	controller      *probeio.Controller
	socket          *probeio.ProbeSocket
	observer        *stunobserve.GateASameSocketClient
	transportLease  *probeio.TransportLease
	transport       transport.PacketTransport
	binding         directattempt.Binding
	stage           string
	burned          bool
	finishRecorded  bool
	success         bool
	mappingBehavior string
	emissions       Emissions
}

func run(ctx context.Context, config Config) (Result, error) {
	runtime, err := prepare(ctx, config)
	if err != nil {
		_ = terminalProgress(config.Progress)
		return Result{}, err
	}
	defer runtime.artifact.Close()
	runErr := runtime.execute(ctx)
	cleanupErr := runtime.cleanup(terminalReason(runErr))
	if cleanupErr != nil {
		runErr = runtime.failure(ClassDrainFailed, StageTerminal, cleanupErr)
	}
	if err := terminalProgress(config.Progress); err != nil {
		runErr = runtime.failure(ClassDrainFailed, StageTerminal, err)
	}
	result := runtime.result()
	if runErr != nil {
		return result, runErr
	}
	if !result.FinishRecorded || !result.TransportDrained || result.SafetyTrip.BlocksActiveWork {
		return result, runtime.failure(ClassDrainFailed, StageTerminal, errors.New("terminal evidence is incomplete"))
	}
	return result, nil
}

func prepare(ctx context.Context, config Config) (*runtime, error) {
	if ctx == nil {
		return nil, preflightFailure(context.Canceled)
	}
	now := time.Now().UTC()
	artifact, err := oobattempt.ParseArtifact(config.Artifact, now)
	if err != nil {
		return nil, preflightFailure(err)
	}
	fail := func(cause error) (*runtime, error) {
		artifact.Close()
		return nil, preflightFailure(cause)
	}
	if config.Machine == nil || config.Ledger == nil || config.Stream == nil || config.Progress == nil || config.BuildVersion == "" {
		return fail(oobcarrier.ErrInvalidConfig)
	}
	targets, err := validateSTUNTargets(config.STUNTargets, config.AllowNonLoopback)
	if err != nil {
		return fail(err)
	}
	config.STUNTargets = targets
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if trip := config.Machine.Snapshot().SafetyTrip; trip.BlocksActiveWork {
		return fail(governor.ErrSafetyTripped)
	}
	digest, err := artifact.ContextDigest()
	if err != nil {
		return fail(err)
	}
	cost, err := oobcarrier.AttemptCost(artifact.LocalRole)
	if err != nil {
		clear(digest[:])
		return fail(err)
	}
	request := governor.PairingAdmissionRequest{
		CredentialID: artifact.CredentialID, AttemptID: artifact.AttemptID,
		ContextDigest: hex.EncodeToString(digest[:]), Scope: governor.ScopeMachine,
		ExpiresAt: artifact.ExpiresAt, Envelope: governor.PairingEnvelopeFromAttemptCost(cost),
	}
	clear(digest[:])
	if err := config.Ledger.Preflight(request); err != nil {
		return fail(err)
	}
	return &runtime{config: config, artifact: artifact, request: request, stage: StagePreflight}, nil
}

func (runtime *runtime) execute(ctx context.Context) error {
	runtime.requestContext = ctx
	if err := runtime.emit(StagePreflight); err != nil {
		return runtime.failure(ClassOOBStreamInvalid, StagePreflight, err)
	}
	pairingContext, err := runtime.artifact.PairingContext()
	if err != nil {
		return runtime.failure(ClassOOBStreamInvalid, StagePreflight, err)
	}
	peerID := pairingContext.ResponderParticipantID
	if runtime.artifact.LocalRole == directattempt.RoleResponder {
		peerID = pairingContext.InitiatorParticipantID
	}
	runtime.peer, err = runtime.config.Machine.AcquirePeer(peerID)
	if err != nil {
		return runtime.classify(StagePreflight, err)
	}
	cost, _ := oobcarrier.AttemptCost(runtime.artifact.LocalRole)
	runtime.attempt, err = runtime.peer.AcquireAttempt(ctx, governor.AttemptRequest{
		ID: runtime.artifact.AttemptID, Operation: governor.OperationConnectTest, Cost: cost,
	})
	if err != nil {
		return runtime.classify(StagePreflight, err)
	}
	runtime.carrier, err = oobcarrier.Adopt(oobcarrier.Config{
		Lease: runtime.attempt, Stream: runtime.config.Stream,
		OOBChannelID: runtime.artifact.OOBChannelID, Role: runtime.artifact.LocalRole,
	})
	if err != nil {
		return runtime.classify(StageOOBAdopt, err)
	}
	if err := runtime.emit(StageOOBAdopt); err != nil {
		return runtime.failure(ClassOOBStreamInvalid, StageOOBAdopt, err)
	}
	if err := runtime.carrier.AwaitPresence(ctx); err != nil {
		return runtime.classify(StagePresent, err)
	}
	if err := runtime.emit(StagePresent); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StagePresent, err)
	}

	before := runtime.config.Ledger.Status().Sequence
	committed, err := governor.NewPairingAdmissionGate().Commit(ctx, runtime.attempt, runtime.request)
	if err != nil {
		runtime.burned = runtime.config.Ledger.Status().Sequence > before
		return runtime.classify(StageBurned, err)
	}
	runtime.burned = true
	runtime.authorization, err = committed.ConsumeForCarrier(ctx)
	if err != nil {
		return runtime.classify(StageBurned, err)
	}
	if err := runtime.emit(StageBurned); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageBurned, err)
	}
	if err := runtime.carrier.Activate(ctx, runtime.authorization); err != nil {
		return runtime.classify(StageActivated, err)
	}
	if err := runtime.emit(StageActivated); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageActivated, err)
	}
	if err := runtime.handshake(ctx); err != nil {
		return runtime.classify(StageHandshake, err)
	}
	if err := runtime.emit(StageHandshake); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageHandshake, err)
	}
	if err := runtime.exchangeSymmetricControl(ctx, directattempt.FramePrepare); err != nil {
		return runtime.classify(StagePrepare, err)
	}
	if err := runtime.emit(StagePrepare); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StagePrepare, err)
	}

	factory, err := runtime.probeFactory()
	if err != nil {
		return runtime.classify(StageSocket, err)
	}
	generation := probeio.NewGeneration(directattempt.Generation)
	udpCost, _ := stunobserve.GateASameSocketCost(runtime.directOutbound())
	runtime.controller, err = probeio.New(probeio.Config{
		Lease: runtime.attempt, Generation: generation, ExpectedGeneration: directattempt.Generation,
		Factory: factory, EnforcedCost: &udpCost, BuildVersion: runtime.config.BuildVersion,
	})
	if err != nil {
		return runtime.classify(StageSocket, err)
	}
	runtime.socket, err = runtime.controller.OpenProbeSocket(ctx)
	if err != nil {
		return runtime.classify(StageSocket, err)
	}
	if err := runtime.emit(StageSocket); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageSocket, err)
	}
	runtime.observer, err = stunobserve.NewGateASameSocket(stunobserve.GateASameSocketConfig{
		Socket: runtime.socket, Generation: generation, ExpectedGeneration: directattempt.Generation,
		DirectOutbound: runtime.directOutbound(), AllowNonLoopback: runtime.config.AllowNonLoopback,
	})
	if err != nil {
		return runtime.classify(StageSTUN, err)
	}
	observation, err := runtime.observer.Observe(ctx, runtime.config.STUNTargets)
	runtime.emissions.STUNPackets = observation.Transmissions
	runtime.emissions.UDPPacketsTotal += observation.Transmissions
	runtime.mappingBehavior = string(observation.Classification.Behavior)
	if err != nil {
		return runtime.classify(StageSTUN, err)
	}
	if err := runtime.emit(StageSTUN); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageSTUN, err)
	}
	if observation.Classification.Behavior != stunobserve.MappingBehaviorConsistentSameAddress ||
		observation.Classification.SuccessfulTargets != 2 || !observation.MappedEndpoint.IsValid() {
		return runtime.failure(ClassMappingNotDirectlyUsable, StageSTUN, stunobserve.ErrGateAMappingRejected)
	}

	peerReady, err := runtime.exchangeReady(ctx, observation.MappedEndpoint)
	if err != nil {
		return runtime.classify(StageReady, err)
	}
	if err := runtime.observer.RegisterPeerTarget(peerReady.Endpoint, peerReady.Generation); err != nil {
		return runtime.classify(StageReady, err)
	}
	if err := runtime.emit(StageReady); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageReady, err)
	}
	if err := runtime.fire(ctx); err != nil {
		return runtime.classify(StageFire, err)
	}
	if err := runtime.emit(StageFire); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageFire, err)
	}
	if err := runtime.punch(ctx, peerReady.Endpoint); err != nil {
		return runtime.classify(StagePunch, err)
	}
	if err := runtime.emit(StagePunch); err != nil {
		return runtime.failure(ClassDirectPacketRejected, StagePunch, err)
	}
	if err := runtime.exchangeSymmetricControl(ctx, directattempt.FrameVerify); err != nil {
		return runtime.classify(StageVerify, err)
	}
	status := runtime.protocol.Status()
	if !status.Terminal || !status.Success {
		return runtime.failure(ClassOOBProtocolViolation, StageVerify, directattempt.ErrInvalidTransition)
	}
	if err := runtime.emit(StageVerify); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageVerify, err)
	}

	leaseBinding := probeio.TransportLeaseBinding{
		PeerID: runtime.attempt.PeerID(), AttemptID: runtime.attempt.Request().ID,
		Generation: directattempt.Generation, PathID: directPathID, Target: peerReady.Endpoint,
		ConsumerKind: probeio.GateATestConsumer,
	}
	runtime.transportLease, err = probeio.IssueTransportLease(runtime.attempt, leaseBinding)
	if err != nil {
		return runtime.classify(StageTransportLease, err)
	}
	if err := runtime.emit(StageTransportLease); err != nil {
		return runtime.failure(ClassTransportLeaseUnavailable, StageTransportLease, err)
	}
	if err := runtime.socket.PromoteToLease(peerReady.Endpoint, directPathID, runtime.transportLease); err != nil {
		return runtime.classify(StageHandoff, err)
	}
	runtime.transport, err = runtime.transportLease.Adopt(ctx, leaseBinding)
	if err != nil {
		return runtime.classify(StageHandoff, err)
	}
	if err := runtime.transportLease.MarkStandby(); err != nil {
		return runtime.classify(StageHandoff, err)
	}
	if err := runtime.emit(StageHandoff); err != nil {
		return runtime.failure(ClassTransportHandoffFailed, StageHandoff, err)
	}
	if err := runtime.challenge(ctx); err != nil {
		return runtime.classify(StageDataPlaneChallenge, err)
	}
	if err := runtime.transportLease.MarkChallengePassed(); err != nil {
		return runtime.classify(StageDataPlaneChallenge, err)
	}
	if err := runtime.emit(StageDataPlaneChallenge); err != nil {
		return runtime.failure(ClassDataPlaneChallengeFailed, StageDataPlaneChallenge, err)
	}
	runtime.success = true
	return nil
}

func (runtime *runtime) probeFactory() (probeio.Factory, error) {
	if runtime.config.ProbeFactory != nil {
		return runtime.config.ProbeFactory, nil
	}
	address := runtime.config.STUNTargets[0].Addr()
	local := netip.MustParseAddrPort("127.0.0.1:0")
	scope := probeio.AllowedTargetScopeLoopback
	if address.Is6() {
		local = netip.AddrPortFrom(netip.IPv6Loopback(), 0)
	}
	if runtime.config.AllowNonLoopback {
		scope = probeio.AllowedTargetScopeUnicast
		if address.Is4() {
			local = netip.MustParseAddrPort("0.0.0.0:0")
		} else {
			local = netip.MustParseAddrPort("[::]:0")
		}
	}
	return probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: local, AllowedTargetScope: scope})
}

func (runtime *runtime) directOutbound() int {
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		return oobcarrier.MaxInitiatorDirect
	}
	return oobcarrier.MaxResponderDirect
}

func (runtime *runtime) handshake(ctx context.Context) error {
	prologue, err := runtime.artifact.NoisePrologue()
	if err != nil {
		return err
	}
	defer clear(prologue)
	psk, err := runtime.artifact.TakePSK()
	if err != nil {
		return err
	}
	defer clear(psk[:])
	config := noisecore.Config{Prologue: prologue, PSK: staticPSK(psk)}
	var session *noisecore.Session
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		session, err = noisecore.NewInitiator(config)
	} else {
		session, err = noisecore.NewResponder(config)
	}
	if err != nil {
		return err
	}
	defer session.Close()
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		first, err := session.WriteMessage(nil)
		if err != nil {
			return err
		}
		if err := runtime.carrier.SendHandshake(ctx, first); err != nil {
			clear(first)
			return err
		}
		clear(first)
		runtime.emissions.HandshakeFrames++
		second, err := runtime.carrier.ReceiveHandshake(ctx)
		if err != nil {
			return err
		}
		payload, readErr := session.ReadMessage(second)
		clear(second)
		clear(payload)
		if readErr != nil || len(payload) != 0 {
			return errors.Join(readErr, noisecore.ErrInvalidMessage)
		}
	} else {
		first, err := runtime.carrier.ReceiveHandshake(ctx)
		if err != nil {
			return err
		}
		payload, readErr := session.ReadMessage(first)
		clear(first)
		clear(payload)
		if readErr != nil || len(payload) != 0 {
			return errors.Join(readErr, noisecore.ErrInvalidMessage)
		}
		second, err := session.WriteMessage(nil)
		if err != nil {
			return err
		}
		if err := runtime.carrier.SendHandshake(ctx, second); err != nil {
			clear(second)
			return err
		}
		clear(second)
		runtime.emissions.HandshakeFrames++
	}
	hash, err := session.HandshakeHash()
	if err != nil {
		return err
	}
	digest, err := runtime.artifact.ContextDigest()
	if err != nil {
		clear(hash[:])
		return err
	}
	packets, err := session.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		clear(hash[:])
		clear(digest[:])
		return err
	}
	if err := runtime.carrier.MarkHandshakeComplete(); err != nil {
		_ = packets.Close()
		clear(hash[:])
		clear(digest[:])
		return err
	}
	runtime.binding = directattempt.Binding{
		AttemptID: runtime.artifact.AttemptID, ContextDigest: digest,
		HandshakeHash: hash, Generation: directattempt.Generation,
	}
	clear(hash[:])
	clear(digest[:])
	runtime.protocol, err = directattempt.NewProtocolForProfile(
		runtime.artifact.LocalRole, runtime.binding, packets, directattempt.OOBDirectAttemptProfile,
	)
	return err
}

func (runtime *runtime) exchangeSymmetricControl(ctx context.Context, frameType directattempt.FrameType) error {
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		if err := runtime.sendControl(ctx, frameType); err != nil {
			return err
		}
		return runtime.receiveControl(ctx, frameType)
	}
	if err := runtime.receiveControl(ctx, frameType); err != nil {
		return err
	}
	return runtime.sendControl(ctx, frameType)
}

func (runtime *runtime) sendControl(ctx context.Context, frameType directattempt.FrameType) error {
	frame, err := runtime.protocol.Seal(frameType, nil)
	if err != nil {
		return err
	}
	defer clear(frame)
	if err := runtime.carrier.SendControl(ctx, frame); err != nil {
		return err
	}
	runtime.emissions.ControlFrames++
	return nil
}

func (runtime *runtime) receiveControl(ctx context.Context, expected directattempt.FrameType) error {
	opened, err := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
	if err != nil {
		return err
	}
	if opened.Type == directattempt.FrameCancel {
		return directattempt.ErrCancelled
	}
	if opened.Type != expected {
		return directattempt.ErrInvalidTransition
	}
	return nil
}

func (runtime *runtime) exchangeReady(ctx context.Context, endpoint netip.AddrPort) (*directattempt.ReadyPayload, error) {
	ready, err := directattempt.NewReadyPayloadForProfile(runtime.binding, runtime.artifact.LocalRole, endpoint, directattempt.OOBDirectAttemptProfile)
	if err != nil {
		return nil, err
	}
	send := func() error {
		frame, sealErr := runtime.protocol.Seal(directattempt.FrameReady, &ready)
		if sealErr != nil {
			return sealErr
		}
		defer clear(frame)
		if sendErr := runtime.carrier.SendControl(ctx, frame); sendErr != nil {
			return sendErr
		}
		runtime.emissions.ControlFrames++
		return nil
	}
	receive := func() (*directattempt.ReadyPayload, error) {
		opened, receiveErr := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
		if receiveErr != nil {
			return nil, receiveErr
		}
		if opened.Type != directattempt.FrameReady || opened.Ready == nil {
			return nil, directattempt.ErrInvalidReady
		}
		peer := *opened.Ready
		return &peer, nil
	}
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		if err := send(); err != nil {
			return nil, err
		}
		return receive()
	}
	peer, err := receive()
	if err != nil {
		return nil, err
	}
	if err := send(); err != nil {
		return nil, err
	}
	return peer, nil
}

func (runtime *runtime) fire(ctx context.Context) error {
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		return runtime.sendControl(ctx, directattempt.FrameFire)
	}
	return runtime.receiveControl(ctx, directattempt.FrameFire)
}

func (runtime *runtime) punch(ctx context.Context, peer netip.AddrPort) error {
	punchCtx, cancel := context.WithTimeout(ctx, punchDeadline)
	defer cancel()
	firstType := directattempt.FrameSYN
	if runtime.artifact.LocalRole == directattempt.RoleResponder {
		firstType = directattempt.FrameSYNACK
	}
	first, err := runtime.protocol.Seal(firstType, nil)
	if err != nil {
		return err
	}
	if err := runtime.socket.SendProbe(punchCtx, peer, first); err != nil {
		clear(first)
		return err
	}
	clear(first)
	runtime.emissions.DirectPackets++
	runtime.emissions.UDPPacketsTotal++
	if err := runtime.emit(StagePunchSent); err != nil {
		return err
	}
	buffer := make([]byte, directattempt.MaxFrameBytes)
	defer clear(buffer)
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		_, _, err := runtime.socket.ReceiveReply(punchCtx, buffer, func(packet []byte, from netip.AddrPort) error {
			if from != peer {
				return directattempt.ErrInvalidFrame
			}
			opened, openErr := runtime.protocol.Open(packet)
			if openErr != nil || opened.Type != directattempt.FrameSYNACK {
				return errors.Join(openErr, directattempt.ErrInvalidTransition)
			}
			return nil
		})
		if err != nil {
			return err
		}
		ack, err := runtime.protocol.Seal(directattempt.FrameACK, nil)
		if err != nil {
			return err
		}
		if err := runtime.socket.SendProbe(punchCtx, peer, ack); err != nil {
			clear(ack)
			return err
		}
		clear(ack)
		runtime.emissions.DirectPackets++
		runtime.emissions.UDPPacketsTotal++
		return nil
	}
	for received := 0; received < 2; received++ {
		complete := false
		_, _, err := runtime.socket.ReceiveReply(punchCtx, buffer, func(packet []byte, from netip.AddrPort) error {
			if from != peer {
				return directattempt.ErrInvalidFrame
			}
			opened, openErr := runtime.protocol.Open(packet)
			if openErr != nil {
				return openErr
			}
			switch opened.Type {
			case directattempt.FrameSYN:
			case directattempt.FrameACK:
				complete = true
			default:
				return directattempt.ErrInvalidTransition
			}
			return nil
		})
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
	}
	return directattempt.ErrInvalidTransition
}

func (runtime *runtime) challenge(ctx context.Context) error {
	challengeCtx, cancel := context.WithTimeout(ctx, challengeDeadline)
	defer cancel()
	for ordinal := 0; ordinal < challengePackets; ordinal++ {
		packet := challengePacket(runtime.binding, runtime.artifact.LocalRole, uint8(ordinal))
		if err := runtime.transport.WritePacket(challengeCtx, packet); err != nil {
			clear(packet)
			return err
		}
		clear(packet)
		runtime.emissions.DataPacketsWritten++
	}
	seen := [challengePackets]bool{}
	buffer := make([]byte, 64)
	defer clear(buffer)
	for received := 0; received < challengePackets; received++ {
		n, _, err := runtime.transport.ReadPacket(challengeCtx, buffer)
		if err != nil {
			return err
		}
		ordinal, err := validateChallengePacket(buffer[:n], runtime.binding, runtime.artifact.LocalRole.Peer())
		if err != nil || seen[ordinal] {
			return errors.Join(err, errors.New("duplicate data-plane challenge"))
		}
		seen[ordinal] = true
		runtime.emissions.DataPacketsRead++
	}
	return nil
}

func challengePacket(binding directattempt.Binding, role directattempt.Role, ordinal uint8) []byte {
	payload := make([]byte, 0, 4+1+1+sha256.Size)
	payload = append(payload, challengeMagic...)
	payload = append(payload, roleByte(role), ordinal)
	hash := sha256.New()
	_, _ = hash.Write([]byte("winkyou-gate-a-data-plane-challenge/1\n"))
	_, _ = hash.Write([]byte(binding.AttemptID))
	_, _ = hash.Write(binding.ContextDigest[:])
	_, _ = hash.Write(binding.HandshakeHash[:])
	_, _ = hash.Write([]byte{roleByte(role), ordinal})
	payload = append(payload, hash.Sum(nil)...)
	return payload
}

func validateChallengePacket(packet []byte, binding directattempt.Binding, role directattempt.Role) (uint8, error) {
	if len(packet) != 4+1+1+sha256.Size || string(packet[:4]) != challengeMagic || packet[4] != roleByte(role) || packet[5] >= challengePackets {
		return 0, errors.New("invalid data-plane challenge")
	}
	expected := challengePacket(binding, role, packet[5])
	valid := string(expected) == string(packet)
	clear(expected)
	if !valid {
		return 0, errors.New("invalid data-plane challenge")
	}
	return packet[5], nil
}

func roleByte(role directattempt.Role) byte {
	if role == directattempt.RoleInitiator {
		return 1
	}
	if role == directattempt.RoleResponder {
		return 2
	}
	return 0
}

func (runtime *runtime) emit(stage string) error {
	if runtime == nil || runtime.config.Progress == nil {
		return ErrProgressDelivery
	}
	if err := runtime.config.Progress(stage, true); err != nil {
		return errors.Join(ErrProgressDelivery, err)
	}
	runtime.stage = stage
	return nil
}

func terminalProgress(progress ProgressReporter) error {
	if progress == nil {
		return ErrProgressDelivery
	}
	return progress(StageTerminal, false)
}

func (runtime *runtime) cleanup(reason governor.PairingTerminalReason) error {
	if runtime == nil {
		return nil
	}
	var cleanupErr error
	finishOK := !runtime.burned
	if runtime.authorization != nil {
		if err := runtime.authorization.Finish(reason); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			runtime.finishRecorded = true
			finishOK = true
		}
		runtime.authorization = nil
	}
	if runtime.protocol != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.protocol.Close())
		runtime.protocol = nil
	}
	if runtime.carrier != nil {
		_ = runtime.carrier.Close()
		witness := runtime.carrier.Witness()
		runtime.emissions.CarrierFramesRead = witness.FramesRead
		runtime.emissions.CarrierFramesWrite = witness.FramesWritten
		runtime.emissions.CarrierBytesRead = witness.BytesRead
		runtime.emissions.CarrierBytesWrite = witness.BytesWritten
		if !witness.Closed || !witness.Drained {
			cleanupErr = errors.Join(cleanupErr, errors.New("carrier drain incomplete"))
		}
	}
	if runtime.transportLease != nil {
		if runtime.success && finishOK {
			cleanupErr = errors.Join(cleanupErr, runtime.transportLease.DetachAfterFinish())
		} else {
			cleanupErr = errors.Join(cleanupErr, runtime.transportLease.Close())
		}
	} else if runtime.socket != nil {
		if err := runtime.socket.Close(); err != nil && !errors.Is(err, probeio.ErrSocketClosed) && !errors.Is(err, probeio.ErrLeaseClosed) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if finishOK {
		if runtime.controller != nil {
			cleanupErr = errors.Join(cleanupErr, runtime.controller.Close())
			runtime.attempt = nil
		} else if runtime.attempt != nil {
			cleanupErr = errors.Join(cleanupErr, runtime.attempt.Close())
			runtime.attempt = nil
		}
		if runtime.peer != nil {
			cleanupErr = errors.Join(cleanupErr, runtime.peer.Close())
			runtime.peer = nil
		}
	}
	if runtime.transportLease != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.transportLease.Close())
		runtime.transport = nil
	}
	return cleanupErr
}

func (runtime *runtime) result() Result {
	result := Result{
		AttemptKind: "oob_direct_handoff", Terminal: "failed", CredentialBurned: runtime.burned,
		FinishRecorded: runtime.finishRecorded, MappingBehavior: runtime.mappingBehavior,
		Emissions: runtime.emissions, ReservedEnvelope: runtime.request.Envelope,
	}
	if runtime.success {
		result.Terminal = "success"
		result.Bidirectional = true
	}
	if runtime.config.Ledger != nil {
		result.PairingLedger = runtime.config.Ledger.Status()
	}
	if runtime.config.Machine != nil {
		result.SafetyTrip = runtime.config.Machine.Snapshot().SafetyTrip
	}
	if runtime.carrier != nil {
		result.CarrierWitness = runtime.carrier.Witness()
	}
	if runtime.transportLease != nil {
		result.TransportWitness = runtime.transportLease.Witness()
		result.TransportDrained = result.TransportWitness.Drained && result.TransportWitness.Closed
	}
	return result
}

func validateSTUNTargets(targets []netip.AddrPort, allowNonLoopback bool) ([]netip.AddrPort, error) {
	if len(targets) != 2 {
		return nil, oobcarrier.ErrInvalidConfig
	}
	result := make([]netip.AddrPort, 0, 2)
	seen := make(map[netip.AddrPort]struct{}, 2)
	for _, target := range targets {
		if !target.IsValid() || target.Port() == 0 || target.Addr().Zone() != "" || target.Addr().IsUnspecified() || target.Addr().IsMulticast() {
			return nil, oobcarrier.ErrInvalidConfig
		}
		canonical := netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
		if allowNonLoopback {
			if !canonical.Addr().IsGlobalUnicast() || canonical.Addr().IsLoopback() {
				return nil, oobcarrier.ErrInvalidConfig
			}
		} else if !canonical.Addr().IsLoopback() {
			return nil, oobcarrier.ErrInvalidConfig
		}
		if _, duplicate := seen[canonical]; duplicate {
			return nil, oobcarrier.ErrInvalidConfig
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	if result[0].Addr().Is4() != result[1].Addr().Is4() {
		return nil, oobcarrier.ErrInvalidConfig
	}
	return result, nil
}

func preflightFailure(cause error) error {
	class := ClassOOBStreamInvalid
	switch {
	case errors.Is(cause, governor.ErrPairingCredentialUsed):
		class = ClassCredentialUsed
	case errors.Is(cause, governor.ErrPairingAdmissionRejected),
		errors.Is(cause, governor.ErrPairingAdmissionRateLimited),
		errors.Is(cause, governor.ErrPairingAdmissionCircuitOpen),
		errors.Is(cause, governor.ErrPairingLedgerIndeterminate):
		class = ClassAdmissionBlocked
	case errors.Is(cause, governor.ErrSafetyTripped):
		class = ClassResourceBudgetExceeded
	}
	return &Failure{Class: class, Stage: StagePreflight, CredentialBurned: false, Retryable: false, Cause: cause}
}

func (runtime *runtime) failure(class, stage string, cause error) error {
	return &Failure{Class: class, Stage: stage, CredentialBurned: runtime != nil && runtime.burned, Retryable: false, Cause: cause}
}

func (runtime *runtime) classify(stage string, err error) error {
	switch {
	case errors.Is(err, oobcarrier.ErrPresenceTimeout):
		return runtime.failure(ClassOOBPresenceTimeout, StagePresent, err)
	case errors.Is(err, oobcarrier.ErrCarrierTransport), errors.Is(err, io.EOF), errors.Is(err, context.Canceled):
		return runtime.failure(ClassOOBStreamClosed, stage, err)
	case errors.Is(err, oobcarrier.ErrCarrierDomain), errors.Is(err, oobcarrier.ErrPreBurnSecureFrame),
		errors.Is(err, oobcarrier.ErrHandshakeOrder), errors.Is(err, oobcarrier.ErrInvalidFrame),
		errors.Is(err, directattempt.ErrInvalidFrame), errors.Is(err, directattempt.ErrInvalidSequence),
		errors.Is(err, directattempt.ErrInvalidTransition), errors.Is(err, noisecore.ErrAuthentication):
		return runtime.failure(ClassOOBProtocolViolation, stage, err)
	case errors.Is(err, governor.ErrPairingCredentialUsed):
		return runtime.failure(ClassCredentialUsed, stage, err)
	case errors.Is(err, governor.ErrPairingAdmissionRejected), errors.Is(err, governor.ErrPairingAdmissionRateLimited),
		errors.Is(err, governor.ErrPairingAdmissionCircuitOpen), errors.Is(err, governor.ErrPairingLedgerIndeterminate):
		return runtime.failure(ClassAdmissionBlocked, stage, err)
	case errors.Is(err, stunobserve.ErrTimeout), errors.Is(err, context.DeadlineExceeded) && stage == StageSTUN:
		return runtime.failure(ClassSTUNSilent, StageSTUN, err)
	case errors.Is(err, stunobserve.ErrSourceMismatch):
		return runtime.failure(ClassSTUNSourceMismatch, StageSTUN, err)
	case stage == StageSTUN:
		return runtime.failure(ClassSTUNProtocol, StageSTUN, err)
	case errors.Is(err, probeio.ErrTransportBinding), errors.Is(err, probeio.ErrTransportLease):
		if stage == StageTransportLease {
			return runtime.failure(ClassTransportLeaseUnavailable, stage, err)
		}
		return runtime.failure(ClassTransportHandoffFailed, stage, err)
	case stage == StageHandoff:
		return runtime.failure(ClassTransportHandoffFailed, stage, err)
	case stage == StageDataPlaneChallenge:
		return runtime.failure(ClassDataPlaneChallengeFailed, stage, err)
	case errors.Is(err, probeio.ErrHardLimit), errors.Is(err, probeio.ErrResourceExhausted),
		errors.Is(err, probeio.ErrWriteFailures), errors.Is(err, governor.ErrSafetyTripped):
		return runtime.failure(ClassResourceBudgetExceeded, stage, err)
	case stage == StagePunch || stage == StagePunchSent:
		return runtime.failure(ClassDirectPacketRejected, StagePunch, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return runtime.failure(ClassAttemptExpired, stage, err)
	default:
		return runtime.failure(ClassOOBProtocolViolation, stage, err)
	}
}

func terminalReason(err error) governor.PairingTerminalReason {
	if err == nil {
		return governor.PairingTerminalSuccess
	}
	var failure *Failure
	if errors.As(err, &failure) {
		switch failure.Class {
		case ClassOOBStreamClosed, ClassOOBPresenceTimeout:
			return governor.PairingTerminalCarrierError
		case ClassAttemptExpired, ClassSTUNSilent:
			return governor.PairingTerminalExpired
		}
	}
	return governor.PairingTerminalProtocolError
}
