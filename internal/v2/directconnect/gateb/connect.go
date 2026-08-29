package gateb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/hardnatattempt"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatcontrol"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/pkg/transport"
)

const (
	directPathPrefix        = "gate-b2/"
	hardCampaignPathPrefix  = "gate-b3/"
	challengeDeadline       = time.Second
	challengePackets        = 3
	challengeMagic          = "WYGB"
	candidateBatchPeriod    = time.Second
	preFireQuietPeriod      = time.Second + time.Millisecond
	predictiveResponderLead = 250 * time.Millisecond
	asymmetricMappingLead   = 7*time.Second + 250*time.Millisecond
	asymmetricWinnerFloor   = 8*time.Second + time.Millisecond
	candidateDrainSilence   = 250 * time.Millisecond
)

type staticPSK [noisecore.PSKSize]byte

func (source staticPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

type runtime struct {
	config            Config
	activeContext     context.Context
	activeCancel      context.CancelCauseFunc
	deadlineCancel    context.CancelFunc
	carrierWatchDone  chan struct{}
	artifact          *hardnatattempt.Artifact
	request           governor.PairingAdmissionRequest
	peer              *governor.PeerLease
	attempt           *governor.AttemptLease
	carrier           *oobcarrier.Carrier
	authorization     *governor.CommittedCarrierAuthorization
	protocol          *hardnatcontrol.Protocol
	plannerSource     *noisecore.PlannerKeySource
	controller        *probeio.Controller
	sockets           []*probeio.ProbeSocket
	transportLease    *probeio.TransportLease
	transport         transport.PacketTransport
	binding           hardnatcontrol.Binding
	observation       hardnatobserve.Result
	localCommitment   hardnatplan.LocalSourceCommitment
	peerCommitment    hardnatplan.LocalSourceCommitment
	localPlan         hardnatplan.Plan
	peerPlan          hardnatplan.Plan
	joint             hardnatplan.JointPlanCommitment
	executionDigest   [32]byte
	localPublic       hardnatplan.Address
	peerPublic        hardnatplan.Address
	stage             string
	burned            bool
	finishRecorded    bool
	success           bool
	challengeComplete atomic.Bool
	emissionsMu       sync.Mutex
	emissions         Emissions
	candidateStart    time.Time
	candidateLast     time.Time
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
	if config.Harness != nil && config.Harness.Now != nil {
		now = config.Harness.Now().UTC()
	}
	artifact, err := hardnatattempt.ParseArtifact(config.Artifact, now)
	if err != nil {
		return nil, preflightFailure(err)
	}
	fail := func(cause error) (*runtime, error) {
		artifact.Close()
		return nil, preflightFailure(cause)
	}
	envelope, err := hardnatbudget.For(artifact.PlannerProfile, artifact.ResourceClass)
	if err != nil {
		return fail(err)
	}
	activeMaximum, err := hardnatbudget.ActiveDuration(artifact.PlannerProfile, artifact.ResourceClass)
	if err != nil {
		return fail(err)
	}
	candidateMaximum, err := hardnatbudget.CandidateDuration(artifact.PlannerProfile, artifact.ResourceClass)
	if err != nil {
		return fail(err)
	}
	factoryCount := 0
	for _, present := range []bool{config.ProbeFactory != nil, config.NATLabFactory != nil, config.HardNATLabFactory != nil} {
		if present {
			factoryCount++
		}
	}
	if config.Machine == nil || config.Ledger == nil || config.Stream == nil || config.Progress == nil || config.BuildVersion == "" ||
		factoryCount > 1 ||
		(config.Harness != nil && (config.ProbeFactory == nil || config.Harness.ActiveEnvelope < 0 ||
			config.Harness.ActiveEnvelope > activeMaximum || config.Harness.CandidateWindow < 0 ||
			config.Harness.CandidateWindow > candidateMaximum)) {
		return fail(oobcarrier.ErrInvalidConfig)
	}
	if _, rawOSFactory := config.ProbeFactory.(*probeio.UDPFactory); rawOSFactory {
		return fail(oobcarrier.ErrInvalidConfig)
	}
	expectedGovernor, err := hardnatbudget.GovernorProfile(artifact.PlannerProfile, artifact.ResourceClass)
	if err != nil || config.Machine.Snapshot().Profile != expectedGovernor {
		return fail(governor.ErrNotAllowed)
	}
	if hardnatbudget.IsHardCampaign(artifact.PlannerProfile, artifact.ResourceClass) {
		if config.NATLabFactory != nil || (config.ProbeFactory == nil && config.HardNATLabFactory == nil) {
			return fail(oobcarrier.ErrInvalidConfig)
		}
	} else if config.HardNATLabFactory != nil {
		return fail(oobcarrier.ErrInvalidConfig)
	}
	if _, err := validateTopology(config.ObserverTopology, topologyAuthorityFor(config)); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if trip := config.Machine.Snapshot().SafetyTrip; trip.BlocksActiveWork {
		return fail(governor.ErrSafetyTripped)
	}
	contextDigest, err := artifact.ContextDigest()
	if err != nil {
		return fail(err)
	}
	request := governor.PairingAdmissionRequest{
		CredentialID: artifact.CredentialID, AttemptID: artifact.AttemptID,
		ContextDigest: hex.EncodeToString(contextDigest[:]), Scope: governor.ScopeMachine,
		ExpiresAt: artifact.ExpiresAt, Envelope: governor.PairingEnvelopeFromAttemptCost(envelope.Cost),
	}
	if hardnatbudget.IsHardCampaign(artifact.PlannerProfile, artifact.ResourceClass) {
		request.RecordClass = governor.PairingRecordClassHardNATCampaign
	}
	clear(contextDigest[:])
	if err := config.Ledger.Preflight(request); err != nil {
		return fail(err)
	}
	return &runtime{config: config, artifact: artifact, request: request, stage: StagePreflight}, nil
}

func (runtime *runtime) execute(ctx context.Context) error {
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
	envelope, _ := hardnatbudget.For(runtime.artifact.PlannerProfile, runtime.artifact.ResourceClass)
	operation, _ := hardnatbudget.Operation(runtime.artifact.PlannerProfile)
	// The active context below owns cancellation of every emission. Keep the
	// lease alive through cleanup so durable FINISH is recorded before the
	// attempt reservation is released even when the caller cancels.
	runtime.attempt, err = runtime.peer.AcquireAttempt(context.WithoutCancel(ctx), governor.AttemptRequest{
		ID: runtime.artifact.AttemptID, Operation: operation, Cost: envelope.Cost,
	})
	if err != nil {
		return runtime.classify(StagePreflight, err)
	}
	activeDeadline := time.Now().Add(runtime.activeEnvelope())
	activeBase, activeCancel := context.WithCancelCause(ctx)
	activeContext, deadlineCancel := context.WithDeadline(activeBase, activeDeadline)
	runtime.activeContext, runtime.activeCancel, runtime.deadlineCancel = activeContext, activeCancel, deadlineCancel
	ctx = activeContext
	runtime.carrier, err = oobcarrier.AdoptHardNAT(oobcarrier.HardNATConfig{
		Lease: runtime.attempt, Stream: runtime.config.Stream, OOBChannelID: runtime.artifact.OOBChannelID,
		Role: runtime.artifact.LocalRole, PlannerProfile: runtime.artifact.PlannerProfile,
		ResourceClass: runtime.artifact.ResourceClass, ActiveDeadline: activeDeadline,
	})
	if err != nil {
		return runtime.classify(StageOOBAdopt, err)
	}
	runtime.carrierWatchDone = make(chan struct{})
	go func() {
		defer close(runtime.carrierWatchDone)
		select {
		case <-runtime.carrier.Done():
			// Once the data-plane challenge has completed there are no further
			// UDP emissions to cancel. Before that point every carrier terminal
			// event cancels the one absolute active-attempt context immediately.
			if !runtime.challengeComplete.Load() {
				runtime.activeCancel(runtime.carrier.TerminalCause())
			}
		case <-runtime.activeContext.Done():
		}
	}()
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
	// The active I/O context must stop emission immediately, but it must not
	// race the explicit stable terminal reason into the durable journal. FINISH
	// remains owned by cleanup and always precedes attempt release.
	committed, err := governor.NewPairingAdmissionGate().Commit(context.WithoutCancel(ctx), runtime.attempt, runtime.request)
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
	if err := runtime.exchangeControl(ctx, hardnatcontrol.FramePrepare); err != nil {
		return runtime.classify(StagePrepare, err)
	}
	if err := runtime.emit(StagePrepare); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StagePrepare, err)
	}
	if err := runtime.openSockets(ctx, envelope); err != nil {
		return runtime.classify(StageSockets, err)
	}
	if err := runtime.emit(StageSockets); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageSockets, err)
	}
	trust, err := runtime.trustAnchors(pairingContext)
	if err != nil {
		return runtime.classify(StageEvidence, err)
	}
	runtime.observation, err = hardnatobserve.Collect(ctx, hardnatobserve.Config{
		Profile: runtime.artifact.PlannerProfile, ResourceClass: runtime.artifact.ResourceClass,
		Sockets: runtime.sockets[:hardnatobserve.ObservationSocketCount], Topology: runtime.config.ObserverTopology,
		Trust: trust, Random: runtime.harnessObservationRandom(), Now: runtime.harnessNow(),
	})
	if err != nil {
		return runtime.classify(StageEvidence, err)
	}
	runtime.emissions.EvidencePackets = runtime.observation.PacketsSent
	runtime.emissions.UDPPacketsTotal += runtime.observation.PacketsSent
	runtime.emissions.TargetsRegistered = runtime.observation.Targets
	runtime.emissions.FiveTuples = runtime.observation.FiveTuples
	if err := runtime.validateHardProtocolShape("fresh evidence"); err != nil {
		return runtime.classify(StageEvidence, err)
	}
	if err := runtime.emit(StageEvidence); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageEvidence, err)
	}
	if err := runtime.freezeAndExchangePlan(ctx, envelope); err != nil {
		return runtime.classify(StagePlan, err)
	}
	if err := runtime.emit(StagePlan); err != nil {
		return runtime.failure(ClassPlanMismatch, StagePlan, err)
	}
	if err := runtime.revalidateFreshEvidence(); err != nil {
		return runtime.failure(ClassEvidenceDrifted, StageReady, err)
	}
	if err := runtime.registerCandidateTargets(); err != nil {
		return runtime.classify(StageReady, err)
	}
	if !runtime.isHardCampaign() {
		if err := runtime.exchangeControl(ctx, hardnatcontrol.FrameReady); err != nil {
			return runtime.classify(StageReady, err)
		}
	}
	if err := runtime.emit(StageReady); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageReady, err)
	}
	// Evidence and candidate emissions occupy distinct PPS windows. The
	// chooser also retains one slot for the authenticated winner packet.
	if err := runtime.wait(ctx, preFireQuietPeriod); err != nil {
		return runtime.classify(StageFire, err)
	}
	if err := runtime.fire(ctx); err != nil {
		if errors.Is(err, hardnatplan.ErrEvidenceInsufficient) {
			return runtime.failure(ClassEvidenceDrifted, StageFire, err)
		}
		return runtime.classify(StageFire, err)
	}
	if err := runtime.emit(StageFire); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageFire, err)
	}
	if err := runtime.emit(StageCandidates); err != nil {
		return runtime.failure(ClassPacketRejected, StageCandidates, err)
	}
	winnerSocket, winnerTarget, err := runtime.punch(ctx)
	if err != nil {
		return runtime.classify(StageCandidates, err)
	}
	if err := runtime.drainCandidateResidue(ctx, winnerSocket); err != nil {
		return runtime.classify(StageCandidates, err)
	}
	if err := runtime.emit(StageWinner); err != nil {
		return runtime.failure(ClassPacketRejected, StageWinner, err)
	}
	if err := runtime.exchangeControl(ctx, hardnatcontrol.FrameVerify); err != nil {
		return runtime.classify(StageVerify, err)
	}
	if !runtime.protocol.Success() {
		return runtime.failure(ClassPlanMismatch, StageVerify, hardnatcontrol.ErrInvalidTransition)
	}
	if err := runtime.emit(StageVerify); err != nil {
		return runtime.failure(ClassOOBProtocolViolation, StageVerify, err)
	}
	pathPrefix := directPathPrefix
	consumerKind := probeio.GateB2TestConsumer
	if runtime.isHardCampaign() {
		pathPrefix = hardCampaignPathPrefix
		consumerKind = probeio.GateB3TestConsumer
	}
	pathID := pathPrefix + string(runtime.artifact.PlannerProfile)
	leaseBinding := probeio.TransportLeaseBinding{
		PeerID: runtime.attempt.PeerID(), AttemptID: runtime.attempt.Request().ID,
		Generation: hardnatcontrol.Generation, PathID: pathID, Target: winnerTarget,
		ConsumerKind: consumerKind,
	}
	runtime.transportLease, err = probeio.IssueTransportLease(runtime.attempt, leaseBinding)
	if err != nil {
		return runtime.classify(StageTransportLease, err)
	}
	if err := runtime.emit(StageTransportLease); err != nil {
		return runtime.failure(ClassTransportLeaseUnavailable, StageTransportLease, err)
	}
	if runtime.isHardCampaign() {
		err = winnerSocket.PromoteToHardNATCampaignLease(winnerTarget, pathID, runtime.transportLease)
	} else {
		err = winnerSocket.PromoteToHardNATLease(winnerTarget, pathID, runtime.transportLease)
	}
	if err != nil {
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
	config := noisecore.Config{Prologue: prologue, PSK: staticPSK(psk), Random: runtime.harnessNoiseRandom()}
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
		first, writeErr := session.WriteMessage(nil)
		if writeErr != nil {
			return writeErr
		}
		if err := runtime.carrier.SendHandshake(ctx, first); err != nil {
			clear(first)
			return err
		}
		clear(first)
		runtime.emissions.HandshakeFrames++
		second, receiveErr := runtime.carrier.ReceiveHandshake(ctx)
		if receiveErr != nil {
			return receiveErr
		}
		payload, readErr := session.ReadMessage(second)
		clear(second)
		if readErr != nil || len(payload) != 0 {
			clear(payload)
			return errors.Join(readErr, noisecore.ErrInvalidMessage)
		}
		clear(payload)
	} else {
		first, receiveErr := runtime.carrier.ReceiveHandshake(ctx)
		if receiveErr != nil {
			return receiveErr
		}
		payload, readErr := session.ReadMessage(first)
		clear(first)
		if readErr != nil || len(payload) != 0 {
			clear(payload)
			return errors.Join(readErr, noisecore.ErrInvalidMessage)
		}
		clear(payload)
		second, writeErr := session.WriteMessage(nil)
		if writeErr != nil {
			return writeErr
		}
		if err := runtime.carrier.SendHandshake(ctx, second); err != nil {
			clear(second)
			return err
		}
		clear(second)
		runtime.emissions.HandshakeFrames++
	}
	handshakeHash, err := session.HandshakeHash()
	if err != nil {
		return err
	}
	contextDigest, err := runtime.artifact.ContextDigest()
	if err != nil {
		clear(handshakeHash[:])
		return err
	}
	maxSequence, err := hardnatcontrol.MaxSequenceFor(runtime.artifact.PlannerProfile, runtime.artifact.ResourceClass)
	if err != nil {
		clear(handshakeHash[:])
		clear(contextDigest[:])
		return err
	}
	packets, plannerSource, err := session.TakePacketCipherAndPlannerKeySource(maxSequence)
	if err != nil {
		clear(handshakeHash[:])
		clear(contextDigest[:])
		return err
	}
	if err := runtime.carrier.MarkHandshakeComplete(); err != nil {
		_ = packets.Close()
		plannerSource.Close()
		clear(handshakeHash[:])
		clear(contextDigest[:])
		return err
	}
	envelope, _ := hardnatbudget.For(runtime.artifact.PlannerProfile, runtime.artifact.ResourceClass)
	envelopeDigest, err := hardnatbudget.Digest(envelope)
	if err != nil {
		_ = packets.Close()
		plannerSource.Close()
		return err
	}
	runtime.binding = hardnatcontrol.Binding{
		AttemptID: runtime.artifact.AttemptID, ContextDigest: contextDigest, HandshakeHash: handshakeHash,
		Generation: hardnatcontrol.Generation, Profile: runtime.artifact.PlannerProfile,
		ResourceClass: runtime.artifact.ResourceClass, EnvelopeDigest: envelopeDigest,
	}
	clear(handshakeHash[:])
	clear(contextDigest[:])
	clear(envelopeDigest[:])
	runtime.protocol, err = hardnatcontrol.NewProtocol(runtime.artifact.LocalRole, runtime.artifact.LocalPlannerRole, runtime.binding, packets)
	if err != nil {
		plannerSource.Close()
		return err
	}
	runtime.plannerSource = plannerSource
	return nil
}

func (runtime *runtime) openSockets(ctx context.Context, envelope hardnatbudget.Envelope) error {
	factory, err := runtime.probeFactory()
	if err != nil {
		return err
	}
	runtime.controller, err = probeio.New(probeio.Config{
		Lease: runtime.attempt, Generation: probeio.NewGeneration(hardnatcontrol.Generation),
		ExpectedGeneration: hardnatcontrol.Generation, Factory: factory,
		EnforcedCost: &envelope.Cost, BuildVersion: runtime.config.BuildVersion,
		Now: runtime.harnessNow(), NewTimer: runtime.harnessNewTimer(),
	})
	if err != nil {
		return err
	}
	runtime.sockets = make([]*probeio.ProbeSocket, envelope.Cost.Resources.Sockets)
	for index := range runtime.sockets {
		runtime.sockets[index], err = runtime.controller.OpenProbeSocket(ctx)
		if err != nil {
			return err
		}
		runtime.emissions.SocketsOpened++
	}
	return nil
}

func (runtime *runtime) probeFactory() (probeio.Factory, error) {
	if runtime.config.HardNATLabFactory != nil {
		endpoints, err := validateTopology(runtime.config.ObserverTopology, topologyNATLab)
		if err != nil || runtime.config.HardNATLabFactory.ValidateObserverEndpoints(endpoints) != nil {
			return nil, oobcarrier.ErrInvalidConfig
		}
		return runtime.config.HardNATLabFactory, nil
	}
	if runtime.config.NATLabFactory != nil {
		endpoints, err := validateTopology(runtime.config.ObserverTopology, topologyNATLab)
		if err != nil || runtime.config.NATLabFactory.ValidateObserverEndpoints(endpoints) != nil {
			return nil, oobcarrier.ErrInvalidConfig
		}
		return runtime.config.NATLabFactory, nil
	}
	if runtime.config.ProbeFactory != nil {
		if _, rawOSFactory := runtime.config.ProbeFactory.(*probeio.UDPFactory); rawOSFactory {
			return nil, oobcarrier.ErrInvalidConfig
		}
		return runtime.config.ProbeFactory, nil
	}
	endpoints, err := validateTopology(runtime.config.ObserverTopology, topologyLoopback)
	if err != nil {
		return nil, err
	}
	local := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)
	if endpoints[0].Addr().Is6() {
		local = netip.AddrPortFrom(netip.IPv6Loopback(), 0)
	}
	return probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: local, AllowedTargetScope: probeio.AllowedTargetScopeLoopback})
}

type topologyAuthority uint8

const (
	topologyLoopback topologyAuthority = iota
	topologySimulation
	topologyNATLab
)

func topologyAuthorityFor(config Config) topologyAuthority {
	if config.NATLabFactory != nil || config.HardNATLabFactory != nil {
		return topologyNATLab
	}
	if config.ProbeFactory != nil {
		return topologySimulation
	}
	return topologyLoopback
}

func validateTopology(topology hardnatobserve.Topology, authority topologyAuthority) ([4]netip.AddrPort, error) {
	endpoints, err := topology.Endpoints()
	if err != nil {
		return endpoints, err
	}
	for _, endpoint := range endpoints {
		if endpoint.Addr().Is4() != endpoints[0].Addr().Is4() {
			return [4]netip.AddrPort{}, oobcarrier.ErrInvalidConfig
		}
		if authority == topologyLoopback && !endpoint.Addr().IsLoopback() {
			return [4]netip.AddrPort{}, oobcarrier.ErrInvalidConfig
		}
		if authority != topologyLoopback && (!endpoint.Addr().IsGlobalUnicast() || endpoint.Addr().IsLoopback()) {
			return [4]netip.AddrPort{}, oobcarrier.ErrInvalidConfig
		}
	}
	return endpoints, nil
}

func (runtime *runtime) trustAnchors(pairing pairingcontext.PairingContext) (hardnatobserve.TrustAnchors, error) {
	contextDigest, err := runtime.artifact.ContextDigest()
	if err != nil {
		return hardnatobserve.TrustAnchors{}, err
	}
	defer clear(contextDigest[:])
	localID, peerID := pairing.InitiatorParticipantID, pairing.ResponderParticipantID
	if runtime.artifact.LocalRole == directattempt.RoleResponder {
		localID, peerID = peerID, localID
	}
	endpoints, err := runtime.config.ObserverTopology.Endpoints()
	if err != nil {
		return hardnatobserve.TrustAnchors{}, err
	}
	trust := hardnatobserve.TrustAnchors{Generation: hardnatcontrol.Generation}
	trust.AttemptDigest = digestFields("winkyou-hardnat-attempt-digest-v1\x00", contextDigest[:], []byte(runtime.artifact.AttemptID))
	trust.MachineScopeDigest = digestFields("winkyou-hardnat-machine-scope-v1\x00", []byte(localID))
	trust.PeerDigest = digestFields("winkyou-hardnat-peer-v1\x00", []byte(peerID))
	var observer bytes.Buffer
	observer.WriteString(hardnatattempt.ObservationProfile)
	for _, endpoint := range endpoints {
		appendEndpoint(&observer, endpoint)
	}
	trust.ObservationSetDigest = digestFields("winkyou-hardnat-observer-set-v1\x00", observer.Bytes())
	trust.SocketOwnerDigest = digestFields("winkyou-hardnat-socket-owner-v1\x00", []byte(runtime.artifact.AttemptID), []byte(localID), []byte(runtime.artifact.LocalRole))
	return trust, nil
}

func (runtime *runtime) freezeAndExchangePlan(ctx context.Context, envelope hardnatbudget.Envelope) error {
	active, err := hardnatbudget.ActiveDuration(envelope.Profile, envelope.ResourceClass)
	if err != nil {
		return err
	}
	budget := hardnatplan.Cost{
		Sockets: uint32(envelope.Cost.Resources.Sockets), Targets: uint32(envelope.Cost.Resources.Targets),
		FiveTuples: uint32(envelope.Cost.Resources.FiveTuples), Packets: uint32(envelope.Cost.Resources.Packets),
		PacketsPerSecond: uint32(envelope.Cost.Resources.PacketsPerSecond), ActiveMillis: uint32(active.Milliseconds()),
	}
	local, err := hardnatplan.BuildLocalCommitment(hardnatplan.LocalCommitmentInput{
		Profile: runtime.artifact.PlannerProfile, ResourceClass: runtime.artifact.ResourceClass,
		Context: hardnatplan.AttemptContext{AttemptDigest: runtime.observation.Graph.AttemptDigest,
			Generation: hardnatcontrol.Generation, Role: runtime.artifact.LocalPlannerRole},
		Evidence: runtime.observation.Graph, Validation: runtime.observation.Trusted, Budget: budget,
	})
	if err != nil {
		return err
	}
	localPayload, err := hardnatcontrol.NewSourcePayload(local, runtime.observation.PublicAddress)
	if err != nil {
		return err
	}
	peerPayload, err := runtime.exchangeSource(ctx, localPayload)
	if err != nil {
		return err
	}
	if err := runtime.validateExecutionAddresses(runtime.observation.PublicAddress, peerPayload.PublicAddress); err != nil {
		return err
	}
	peer, err := peerPayload.Commitment(runtime.artifact.PlannerProfile, runtime.artifact.ResourceClass)
	if err != nil || peer.Role != runtime.artifact.PeerPlannerRole {
		return errors.Join(hardnatplan.ErrPlanMismatch, err)
	}
	bilateral, err := hardnatplan.BuildBilateralPlan(hardnatplan.BilateralPlannerInput{
		First: local, Second: peer, KeySource: hardnatcontrol.NoisePlannerKeySource{Source: runtime.plannerSource},
	})
	if err != nil {
		return err
	}
	localPlan, ok := bilateral.PlanForRole(runtime.artifact.LocalPlannerRole)
	if !ok {
		return hardnatplan.ErrPlanMismatch
	}
	peerPlan, ok := bilateral.PlanForRole(runtime.artifact.PeerPlannerRole)
	if !ok {
		return hardnatplan.ErrPlanMismatch
	}
	joint := bilateral.Commitment()
	if err := hardnatplan.VerifyExecutablePlanAgainstCommitment(localPlan, local, joint); err != nil {
		return err
	}
	if err := hardnatplan.VerifyExecutablePlanAgainstCommitment(peerPlan, peer, joint); err != nil {
		return err
	}
	envelopeDigest, err := hardnatbudget.Digest(envelope)
	if err != nil {
		return err
	}
	localExecution := hardnatcontrol.ExecutionSource{CarrierRole: runtime.artifact.LocalRole,
		PlannerRole: local.Role, SourceDigest: local.SourceDigest, PublicAddress: runtime.observation.PublicAddress}
	peerExecution := hardnatcontrol.ExecutionSource{CarrierRole: runtime.artifact.LocalRole.Peer(),
		PlannerRole: peer.Role, SourceDigest: peer.SourceDigest, PublicAddress: peerPayload.PublicAddress}
	executionDigest, err := hardnatcontrol.BuildExecutionDigest(joint, envelopeDigest, localExecution, peerExecution)
	clear(envelopeDigest[:])
	if err != nil {
		return err
	}
	if err := runtime.protocol.BindExecution(localPlan, peerPlan, joint, executionDigest); err != nil {
		return err
	}
	runtime.localCommitment, runtime.peerCommitment = local, peer
	runtime.localPlan, runtime.peerPlan, runtime.joint = localPlan, peerPlan, joint
	runtime.executionDigest = executionDigest
	runtime.localPublic, runtime.peerPublic = runtime.observation.PublicAddress, peerPayload.PublicAddress
	runtime.plannerSource.Close()
	runtime.plannerSource = nil
	return nil
}

func (runtime *runtime) validateExecutionAddresses(localAddress, peerAddress hardnatplan.Address) error {
	local, err := fromPlanAddress(localAddress)
	if err != nil {
		return err
	}
	peer, err := fromPlanAddress(peerAddress)
	if err != nil {
		return err
	}
	if runtime.config.NATLabFactory != nil || runtime.config.HardNATLabFactory != nil {
		var localErr, peerErr error
		if runtime.config.HardNATLabFactory != nil {
			localErr = runtime.config.HardNATLabFactory.ValidateLocalAddress(local)
			peerErr = runtime.config.HardNATLabFactory.ValidatePeerAddress(peer)
		} else {
			localErr = runtime.config.NATLabFactory.ValidateLocalAddress(local)
			peerErr = runtime.config.NATLabFactory.ValidatePeerAddress(peer)
		}
		if localErr != nil || peerErr != nil {
			return oobcarrier.ErrInvalidConfig
		}
		return nil
	}
	if runtime.config.ProbeFactory != nil {
		if !local.IsGlobalUnicast() || local.IsLoopback() || !peer.IsGlobalUnicast() || peer.IsLoopback() {
			return oobcarrier.ErrInvalidConfig
		}
		return nil
	}
	if !local.IsLoopback() || !peer.IsLoopback() {
		return oobcarrier.ErrInvalidConfig
	}
	return nil
}

func (runtime *runtime) exchangeControl(ctx context.Context, frameType hardnatcontrol.FrameType) error {
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

func (runtime *runtime) sendControl(ctx context.Context, frameType hardnatcontrol.FrameType) error {
	var frame []byte
	var err error
	switch frameType {
	case hardnatcontrol.FramePrepare:
		frame, err = runtime.protocol.SealPrepare()
	case hardnatcontrol.FrameReady:
		frame, err = runtime.protocol.SealReady()
	case hardnatcontrol.FrameReadyFire:
		frame, err = runtime.protocol.SealReadyFire()
	case hardnatcontrol.FrameFire:
		frame, err = runtime.protocol.SealFire()
	case hardnatcontrol.FrameVerify:
		frame, err = runtime.protocol.SealVerify()
	default:
		return hardnatcontrol.ErrInvalidTransition
	}
	if err != nil {
		return err
	}
	defer clear(frame)
	if err := runtime.carrier.SendHardNATControl(ctx, frame); err != nil {
		return err
	}
	runtime.emissions.ControlFrames++
	return nil
}

func (runtime *runtime) receiveControl(ctx context.Context, expected hardnatcontrol.FrameType) error {
	opened, err := runtime.carrier.ReceiveHardNATControl(ctx, runtime.protocol)
	if err != nil {
		return err
	}
	if opened.Metadata.Type == hardnatcontrol.FrameCancel {
		return context.Canceled
	}
	if opened.Metadata.Type != expected {
		return hardnatcontrol.ErrInvalidTransition
	}
	return nil
}

func (runtime *runtime) exchangeSource(ctx context.Context, local hardnatcontrol.SourcePayload) (hardnatcontrol.SourcePayload, error) {
	send := func() error {
		frame, err := runtime.protocol.SealSource(local)
		if err != nil {
			return err
		}
		defer clear(frame)
		if err := runtime.carrier.SendHardNATControl(ctx, frame); err != nil {
			return err
		}
		runtime.emissions.ControlFrames++
		return nil
	}
	receive := func() (hardnatcontrol.SourcePayload, error) {
		opened, err := runtime.carrier.ReceiveHardNATControl(ctx, runtime.protocol)
		if err != nil {
			return hardnatcontrol.SourcePayload{}, err
		}
		if opened.Metadata.Type != hardnatcontrol.FrameSource || opened.Source == nil {
			return hardnatcontrol.SourcePayload{}, hardnatcontrol.ErrInvalidTransition
		}
		return *opened.Source, nil
	}
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		if err := send(); err != nil {
			return hardnatcontrol.SourcePayload{}, err
		}
		return receive()
	}
	peer, err := receive()
	if err != nil {
		return hardnatcontrol.SourcePayload{}, err
	}
	if err := send(); err != nil {
		return hardnatcontrol.SourcePayload{}, err
	}
	return peer, nil
}

func (runtime *runtime) fire(ctx context.Context) error {
	// Each endpoint proves it reached the FIRE barrier with the exact evidence,
	// joint plan, and execution envelope already bound into authenticated AD.
	// Candidate sealing remains impossible until both directions of this frame
	// have been observed. Rechecking after the exchange closes the READY-to-FIRE
	// expiry window on both roles before any direct packet can be emitted.
	if err := runtime.revalidateFreshEvidence(); err != nil {
		return err
	}
	frameType := hardnatcontrol.FrameFire
	if runtime.isHardCampaign() {
		// Gate B3 combines the existing READY commitment and bilateral FIRE
		// barrier in one authenticated frame. This preserves the revalidation
		// order while keeping the eight-frame OOB ceiling after winner selection.
		frameType = hardnatcontrol.FrameReadyFire
	}
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		if err := runtime.sendControl(ctx, frameType); err != nil {
			return err
		}
		if err := runtime.receiveControl(ctx, frameType); err != nil {
			return err
		}
	} else {
		if err := runtime.receiveControl(ctx, frameType); err != nil {
			return err
		}
		if err := runtime.revalidateFreshEvidence(); err != nil {
			return err
		}
		if err := runtime.sendControl(ctx, frameType); err != nil {
			return err
		}
	}
	return runtime.revalidateFreshEvidence()
}

func (runtime *runtime) revalidateFreshEvidence() error {
	trusted := runtime.observation.Trusted
	now := runtime.now().UTC().UnixMilli()
	if now < trusted.ExpectedFinishedAtMilli {
		now = trusted.ExpectedFinishedAtMilli
	}
	trusted.NowMilli = now
	model, err := hardnatplan.InferStateModel(runtime.observation.Graph, trusted)
	if err != nil || model.Mapping != runtime.observation.Model.Mapping || model.Filtering != runtime.observation.Model.Filtering ||
		model.Allocation != runtime.observation.Model.Allocation || model.EvidenceDigest != runtime.observation.Model.EvidenceDigest ||
		model.ValidationDigest != runtime.observation.Model.ValidationDigest || model.ReusableEndpoint != runtime.observation.Model.ReusableEndpoint ||
		model.ReusableEndpointSlot != runtime.observation.Model.ReusableEndpointSlot ||
		!slices.Equal(model.PredictedSourcePorts, runtime.observation.Model.PredictedSourcePorts) {
		return errors.Join(hardnatplan.ErrEvidenceInsufficient, err)
	}
	return nil
}

type registeredTuple struct {
	slot     uint16
	endpoint netip.AddrPort
}

func (runtime *runtime) registerCandidateTargets() error {
	peerAddress, err := fromPlanAddress(runtime.peerPublic)
	if err != nil {
		return err
	}
	targets := make(map[netip.AddrPort]struct{})
	tuples := make(map[registeredTuple]struct{})
	observerEndpoints, err := runtime.config.ObserverTopology.Endpoints()
	if err != nil {
		return err
	}
	for _, endpoint := range observerEndpoints {
		targets[endpoint] = struct{}{}
		tuples[registeredTuple{slot: 0, endpoint: endpoint}] = struct{}{}
	}
	for slot := 1; slot < hardnatobserve.ObservationSocketCount; slot++ {
		endpoint := observerEndpoints[slot%len(observerEndpoints)]
		tuples[registeredTuple{slot: uint16(slot), endpoint: endpoint}] = struct{}{}
	}
	for _, candidate := range runtime.localPlan.Candidates {
		if int(candidate.SocketSlot) >= len(runtime.sockets) || candidate.TargetPort == 0 {
			return hardnatplan.ErrPlanMismatch
		}
		endpoint := netip.AddrPortFrom(peerAddress, candidate.TargetPort)
		if err := runtime.sockets[candidate.SocketSlot].RegisterTarget(endpoint); err != nil {
			return err
		}
		targets[endpoint] = struct{}{}
		tuples[registeredTuple{slot: candidate.SocketSlot, endpoint: endpoint}] = struct{}{}
	}
	runtime.emissions.TargetsRegistered = len(targets)
	runtime.emissions.FiveTuples = len(tuples)
	if err := runtime.validateHardProtocolShape("candidate registration"); err != nil {
		return err
	}
	return nil
}

type punchEvent struct {
	socket     *probeio.ProbeSocket
	socketSlot uint16
	from       netip.AddrPort
	opened     hardnatcontrol.OpenedFrame
	err        error
}

func (runtime *runtime) punch(ctx context.Context) (*probeio.ProbeSocket, netip.AddrPort, error) {
	if runtime.isHardCampaign() {
		return runtime.punchHardCampaign(ctx)
	}
	punchCtx, cancel := context.WithTimeout(ctx, runtime.candidateWindow())
	defer cancel()
	runtime.candidateStart = time.Now()
	events := make(chan punchEvent, 1024)
	receiveSlots := make(map[uint16]struct{})
	for _, candidate := range runtime.localPlan.Candidates {
		receiveSlots[candidate.SocketSlot] = struct{}{}
	}
	var readers sync.WaitGroup
	for slot := range receiveSlots {
		if int(slot) >= len(runtime.sockets) {
			return nil, netip.AddrPort{}, hardnatplan.ErrPlanMismatch
		}
		readers.Add(1)
		go runtime.readPunchSocket(punchCtx, &readers, runtime.sockets[slot], slot, events)
	}
	senderDone := make(chan error, 1)
	go func() { senderDone <- runtime.sendCandidates(punchCtx) }()

	chooser := runtime.chooser()
	senderFinished := false
	var senderErr error
	sendWinner := func(event punchEvent) (*probeio.ProbeSocket, netip.AddrPort, error) {
		winner, err := runtime.protocol.ChooseWinner(event.opened, event.socketSlot)
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		if err := runtime.waitForAsymmetricWinnerSlot(punchCtx); err != nil {
			return nil, netip.AddrPort{}, err
		}
		frame, err := runtime.protocol.SealWinner(winner)
		if err == nil {
			err = runtime.validateHardWinnerEmission()
		}
		if err == nil {
			err = event.socket.SendProbe(punchCtx, event.from, frame)
		}
		clear(frame)
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		runtime.emissionsMu.Lock()
		runtime.emissions.WinnerPackets++
		runtime.emissions.UDPPacketsTotal++
		runtime.emissionsMu.Unlock()
		return event.socket, event.from, nil
	}
	for {
		select {
		case err := <-senderDone:
			senderFinished = true
			senderErr = err
			senderDone = nil
			if err != nil && !errors.Is(err, context.Canceled) {
				cancel()
				readers.Wait()
				return nil, netip.AddrPort{}, err
			}
		case event := <-events:
			if event.err != nil {
				if errors.Is(event.err, context.Canceled) || errors.Is(event.err, context.DeadlineExceeded) {
					continue
				}
				cancel()
				readers.Wait()
				return nil, netip.AddrPort{}, event.err
			}
			switch event.opened.Metadata.Type {
			case hardnatcontrol.FrameCandidate:
				if !chooser {
					continue
				}
				// The asymmetric target-set must finish its one-shot 512-packet
				// schedule before sealing a winner. Otherwise a fast peer hit can
				// race the sender and place the ACK in the last 64-packet PPS
				// window. This waits for the already-frozen schedule; it does not
				// add a packet, retry, candidate, or fallback.
				if runtime.artifact.PlannerProfile == hardnatplan.ProfileAsymmetricBirthday &&
					runtime.artifact.LocalPlannerRole == hardnatplan.RoleTargetSet && senderDone != nil {
					sendErr := <-senderDone
					senderFinished = true
					senderDone = nil
					if sendErr != nil {
						cancel()
						readers.Wait()
						return nil, netip.AddrPort{}, sendErr
					}
				}
				winnerSocket, winnerTarget, err := sendWinner(event)
				if err != nil {
					cancel()
					readers.Wait()
					return nil, netip.AddrPort{}, err
				}
				cancel()
				readers.Wait()
				if senderDone != nil {
					<-senderDone
				}
				return winnerSocket, winnerTarget, nil
			case hardnatcontrol.FrameWinner:
				if chooser || event.opened.Winner == nil || int(event.opened.Winner.CandidateOrdinal) >= len(runtime.localPlan.Candidates) {
					cancel()
					readers.Wait()
					return nil, netip.AddrPort{}, hardnatcontrol.ErrPlanMismatch
				}
				candidate := runtime.localPlan.Candidates[event.opened.Winner.CandidateOrdinal]
				if candidate.SocketSlot != event.socketSlot || candidate.TargetPort != event.from.Port() {
					cancel()
					readers.Wait()
					return nil, netip.AddrPort{}, hardnatcontrol.ErrPlanMismatch
				}
				cancel()
				readers.Wait()
				if senderDone != nil {
					<-senderDone
				}
				return event.socket, event.from, nil
			default:
				cancel()
				readers.Wait()
				return nil, netip.AddrPort{}, hardnatcontrol.ErrInvalidTransition
			}
		case <-punchCtx.Done():
			cancel()
			readers.Wait()
			if senderDone != nil {
				senderErr = <-senderDone
				senderFinished = true
				senderDone = nil
			}
			if senderErr != nil && !errors.Is(senderErr, context.Canceled) && !errors.Is(senderErr, context.DeadlineExceeded) {
				return nil, netip.AddrPort{}, senderErr
			}
			if runtime.activeContext != nil && runtime.activeContext.Err() != nil {
				return nil, netip.AddrPort{}, context.Cause(runtime.activeContext)
			}
			if cause := context.Cause(punchCtx); cause != nil &&
				!errors.Is(cause, context.DeadlineExceeded) && !errors.Is(cause, context.Canceled) {
				return nil, netip.AddrPort{}, cause
			}
			if senderFinished || errors.Is(punchCtx.Err(), context.DeadlineExceeded) {
				return nil, netip.AddrPort{}, ErrCandidateExhausted
			}
			return nil, netip.AddrPort{}, punchCtx.Err()
		}
	}
}

// punchHardCampaign completes both frozen 16K schedules before a role-ordered
// OOB selection exchange chooses one winner. This removes the former timer
// race in which both endpoints could emit a winner after a symmetric hit.
// Selection consumes the already-reserved eighth carrier frame per direction;
// it adds no UDP packet, target, tuple, retry, or attempt.
func (runtime *runtime) punchHardCampaign(ctx context.Context) (*probeio.ProbeSocket, netip.AddrPort, error) {
	punchCtx, cancel := context.WithTimeout(ctx, runtime.candidateWindow())
	defer cancel()
	runtime.candidateStart = time.Now()
	events := make(chan punchEvent, 1024)
	receiveSlots := make(map[uint16]struct{})
	for _, candidate := range runtime.localPlan.Candidates {
		receiveSlots[candidate.SocketSlot] = struct{}{}
	}
	var readers sync.WaitGroup
	for slot := range receiveSlots {
		if int(slot) >= len(runtime.sockets) {
			return nil, netip.AddrPort{}, hardnatplan.ErrPlanMismatch
		}
		readers.Add(1)
		go runtime.readPunchSocket(punchCtx, &readers, runtime.sockets[slot], slot, events)
	}
	senderDone := make(chan error, 1)
	go func() { senderDone <- runtime.sendCandidates(punchCtx) }()

	var proposalEvent *punchEvent
	proposalRecorded := false
	recordEvent := func(event punchEvent) error {
		if event.err != nil {
			if errors.Is(event.err, context.Canceled) || errors.Is(event.err, context.DeadlineExceeded) {
				return nil
			}
			return event.err
		}
		if event.opened.Metadata.Type != hardnatcontrol.FrameCandidate {
			return hardnatcontrol.ErrInvalidTransition
		}
		if proposalEvent == nil {
			copyEvent := event
			proposalEvent = &copyEvent
		}
		return nil
	}
	finishReaders := func() {
		cancel()
		readers.Wait()
	}
	contextFailure := func() error {
		if runtime.activeContext != nil && runtime.activeContext.Err() != nil {
			return context.Cause(runtime.activeContext)
		}
		if cause := context.Cause(punchCtx); cause != nil &&
			!errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded) {
			return cause
		}
		return ErrCandidateExhausted
	}

	var senderErr error
	senderFinished := false
	for !senderFinished {
		select {
		case senderErr = <-senderDone:
			senderFinished = true
			if senderErr != nil && !errors.Is(senderErr, context.Canceled) && !errors.Is(senderErr, context.DeadlineExceeded) {
				finishReaders()
				return nil, netip.AddrPort{}, senderErr
			}
		case event := <-events:
			if err := recordEvent(event); err != nil {
				finishReaders()
				return nil, netip.AddrPort{}, err
			}
		case <-punchCtx.Done():
			finishReaders()
			if !senderFinished {
				senderErr = <-senderDone
			}
			if senderErr != nil && !errors.Is(senderErr, context.Canceled) && !errors.Is(senderErr, context.DeadlineExceeded) {
				return nil, netip.AddrPort{}, senderErr
			}
			return nil, netip.AddrPort{}, contextFailure()
		}
	}
	if senderErr != nil || runtime.candidatePackets() != hardnatbudget.Hard16CandidatePackets {
		finishReaders()
		return nil, netip.AddrPort{}, contextFailure()
	}

	// The same interval both drains already-emitted candidates into the reader
	// queue and clears the rolling 512-PPS window before the optional winner.
	if err := runtime.waitForHardWinnerSlot(punchCtx); err != nil {
		finishReaders()
		return nil, netip.AddrPort{}, contextFailure()
	}
	drainQueued := func() error {
		for {
			select {
			case event := <-events:
				if err := recordEvent(event); err != nil {
					return err
				}
			default:
				return nil
			}
		}
	}
	if err := drainQueued(); err != nil {
		finishReaders()
		return nil, netip.AddrPort{}, err
	}
	if proposalEvent != nil {
		if _, err := runtime.protocol.RecordWinnerCandidate(proposalEvent.opened, proposalEvent.socketSlot); err != nil {
			finishReaders()
			return nil, netip.AddrPort{}, err
		}
		proposalRecorded = true
	}

	var selection hardnatcontrol.WinnerSelection
	if runtime.artifact.LocalRole == directattempt.RoleResponder {
		var err error
		selection, err = runtime.sendHardWinnerSelection(punchCtx)
		if err == nil {
			selection, err = runtime.receiveHardWinnerSelection(punchCtx)
		}
		if err != nil {
			finishReaders()
			return nil, netip.AddrPort{}, err
		}
	} else {
		var err error
		selection, err = runtime.receiveHardWinnerSelection(punchCtx)
		if err == nil {
			// Include a candidate that reached the authenticated reader while
			// the responder status crossed the OOB stream, but never alter a
			// decision after the initiator seals it.
			err = drainQueued()
		}
		if err == nil && proposalEvent != nil && !proposalRecorded {
			_, err = runtime.protocol.RecordWinnerCandidate(proposalEvent.opened, proposalEvent.socketSlot)
			proposalRecorded = err == nil
		}
		if err == nil {
			selection, err = runtime.sendHardWinnerSelection(punchCtx)
		}
		if err != nil {
			finishReaders()
			return nil, netip.AddrPort{}, err
		}
	}

	selected, hasWinner, localSends := runtime.protocol.SelectedWinner()
	if selection.HasWinner != hasWinner || hasWinner && selection.Winner != selected {
		finishReaders()
		return nil, netip.AddrPort{}, hardnatcontrol.ErrPlanMismatch
	}
	if !hasWinner {
		finishReaders()
		return nil, netip.AddrPort{}, ErrCandidateExhausted
	}
	if localSends {
		if proposalEvent == nil || selected.CandidateOrdinal != proposalEvent.opened.Metadata.Ordinal ||
			selected.ReceiverSocketSlot != proposalEvent.socketSlot {
			finishReaders()
			return nil, netip.AddrPort{}, hardnatcontrol.ErrPlanMismatch
		}
		frame, err := runtime.protocol.SealWinner(selected)
		if err == nil {
			err = runtime.validateHardWinnerEmission()
		}
		if err == nil {
			err = proposalEvent.socket.SendProbe(punchCtx, proposalEvent.from, frame)
		}
		clear(frame)
		if err != nil {
			finishReaders()
			return nil, netip.AddrPort{}, err
		}
		runtime.emissionsMu.Lock()
		runtime.emissions.WinnerPackets++
		runtime.emissions.UDPPacketsTotal++
		runtime.emissionsMu.Unlock()
		finishReaders()
		return proposalEvent.socket, proposalEvent.from, nil
	}

	for {
		select {
		case event := <-events:
			if event.err != nil {
				if errors.Is(event.err, context.Canceled) || errors.Is(event.err, context.DeadlineExceeded) {
					continue
				}
				finishReaders()
				return nil, netip.AddrPort{}, event.err
			}
			if event.opened.Metadata.Type == hardnatcontrol.FrameCandidate {
				continue
			}
			if event.opened.Metadata.Type != hardnatcontrol.FrameWinner || event.opened.Winner == nil || *event.opened.Winner != selected {
				finishReaders()
				return nil, netip.AddrPort{}, hardnatcontrol.ErrPlanMismatch
			}
			finishReaders()
			return event.socket, event.from, nil
		case <-punchCtx.Done():
			finishReaders()
			return nil, netip.AddrPort{}, contextFailure()
		}
	}
}

func (runtime *runtime) candidatePackets() int {
	runtime.emissionsMu.Lock()
	defer runtime.emissionsMu.Unlock()
	return runtime.emissions.CandidatePackets
}

func (runtime *runtime) waitForHardWinnerSlot(ctx context.Context) error {
	if runtime == nil || !runtime.isHardCampaign() {
		return hardnatcontrol.ErrInvalidTransition
	}
	if runtime.config.Harness != nil {
		return runtime.wait(ctx, candidateBatchPeriod+time.Millisecond)
	}
	runtime.emissionsMu.Lock()
	last := runtime.candidateLast
	runtime.emissionsMu.Unlock()
	if last.IsZero() {
		return hardnatcontrol.ErrInvalidTransition
	}
	remaining := time.Until(last.Add(candidateBatchPeriod + time.Millisecond))
	if remaining <= 0 {
		return nil
	}
	return runtime.wait(ctx, remaining)
}

func (runtime *runtime) sendHardWinnerSelection(ctx context.Context) (hardnatcontrol.WinnerSelection, error) {
	frame, selection, err := runtime.protocol.SealWinnerSelection()
	if err != nil {
		return hardnatcontrol.WinnerSelection{}, err
	}
	defer clear(frame)
	if err := runtime.carrier.SendHardNATControl(ctx, frame); err != nil {
		return hardnatcontrol.WinnerSelection{}, err
	}
	runtime.emissions.ControlFrames++
	return selection, nil
}

func (runtime *runtime) receiveHardWinnerSelection(ctx context.Context) (hardnatcontrol.WinnerSelection, error) {
	opened, err := runtime.carrier.ReceiveHardNATControl(ctx, runtime.protocol)
	if err != nil {
		return hardnatcontrol.WinnerSelection{}, err
	}
	if opened.Metadata.Type != hardnatcontrol.FrameWinnerSelection || opened.Selection == nil {
		return hardnatcontrol.WinnerSelection{}, hardnatcontrol.ErrInvalidTransition
	}
	return *opened.Selection, nil
}

// waitForAsymmetricWinnerSlot keeps the target-set's single winner ACK out of
// the one-second window occupied by its eighth 64-packet target batch. A hit
// from the mapping-set's second batch is already in a fresh PPS window.
func (runtime *runtime) waitForAsymmetricWinnerSlot(ctx context.Context) error {
	if runtime.artifact.PlannerProfile != hardnatplan.ProfileAsymmetricBirthday ||
		runtime.artifact.LocalPlannerRole != hardnatplan.RoleTargetSet {
		return nil
	}
	runtime.emissionsMu.Lock()
	lastCandidate := runtime.candidateLast
	runtime.emissionsMu.Unlock()
	if lastCandidate.IsZero() {
		return hardnatcontrol.ErrInvalidTransition
	}
	readyAt := runtime.candidateStart.Add(asymmetricWinnerFloor)
	// Batches are separated from their *starts*. Account for the actual time
	// spent emitting the final batch so the winner is never the 65th packet in
	// a rolling one-second window on a real OS scheduler.
	if afterLast := lastCandidate.Add(candidateBatchPeriod + time.Millisecond); afterLast.After(readyAt) {
		readyAt = afterLast
	}
	remaining := time.Until(readyAt)
	if remaining <= 0 {
		return nil
	}
	return runtime.wait(ctx, remaining)
}

func (runtime *runtime) readPunchSocket(ctx context.Context, readers *sync.WaitGroup, socket *probeio.ProbeSocket, slot uint16, events chan<- punchEvent) {
	defer readers.Done()
	buffer := make([]byte, hardnatcontrol.MaxFrameBytes)
	defer clear(buffer)
	for {
		var opened hardnatcontrol.OpenedFrame
		n, from, err := socket.ReceiveReply(ctx, buffer, func(packet []byte, source netip.AddrPort) error {
			value, openErr := runtime.protocol.Open(packet)
			if openErr != nil {
				return openErr
			}
			switch value.Metadata.Type {
			case hardnatcontrol.FrameCandidate:
				if err := hardnatcontrol.ValidateCandidateArrival(runtime.localPlan, runtime.peerPlan, value, slot, source.Port()); err != nil {
					return err
				}
			case hardnatcontrol.FrameWinner:
			default:
				return hardnatcontrol.ErrInvalidTransition
			}
			opened = value
			return nil
		})
		_ = n
		event := punchEvent{socket: socket, socketSlot: slot, from: from, opened: opened, err: err}
		select {
		case events <- event:
		case <-ctx.Done():
			return
		}
		if err != nil || opened.Metadata.Type == hardnatcontrol.FrameWinner {
			return
		}
	}
}

// drainCandidateResidue consumes only authenticated, already-planned late
// candidates before VERIFY closes the packet cipher and before promotion turns
// the socket into a fixed-target data plane. One complete silence interval is
// required; no packet is emitted and no new endpoint is registered.
func (runtime *runtime) drainCandidateResidue(ctx context.Context, socket *probeio.ProbeSocket) error {
	if socket == nil {
		return hardnatcontrol.ErrPlanMismatch
	}
	slot, ok := runtime.socketSlot(socket)
	if !ok {
		return hardnatcontrol.ErrPlanMismatch
	}
	buffer := make([]byte, hardnatcontrol.MaxFrameBytes)
	defer clear(buffer)
	for {
		drainCtx, cancel := context.WithTimeout(ctx, candidateDrainSilence)
		_, _, err := socket.ReceiveReply(drainCtx, buffer, func(packet []byte, source netip.AddrPort) error {
			opened, openErr := runtime.protocol.Open(packet)
			if openErr != nil {
				return openErr
			}
			if opened.Metadata.Type != hardnatcontrol.FrameCandidate {
				return hardnatcontrol.ErrInvalidTransition
			}
			return hardnatcontrol.ValidateCandidateArrival(runtime.localPlan, runtime.peerPlan, opened, slot, source.Port())
		})
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (runtime *runtime) socketSlot(socket *probeio.ProbeSocket) (uint16, bool) {
	for slot, candidate := range runtime.sockets {
		if candidate == socket {
			return uint16(slot), true
		}
	}
	return 0, false
}

func (runtime *runtime) sendCandidates(ctx context.Context) error {
	// Predictive APDF uses the ADR's role-separated FIRE order: the initiator
	// opens its reciprocal filters first, then the responder emits once. This
	// removes scheduler-dependent simultaneous one-shot loss without retrying
	// or changing a candidate tuple.
	if runtime.artifact.PlannerProfile == hardnatplan.ProfilePredictiveEdm &&
		runtime.artifact.LocalRole == directattempt.RoleResponder {
		if err := runtime.wait(ctx, predictiveResponderLead); err != nil {
			return err
		}
	}
	// Under APDF the reusable target-set mapping must first record every
	// possible mapping-set source endpoint. The mapping side therefore starts
	// only after the target side has emitted its eight fixed 64-packet batches.
	// This is role-separated scheduling, not retry or fallback.
	if runtime.artifact.PlannerProfile == hardnatplan.ProfileAsymmetricBirthday &&
		runtime.artifact.LocalPlannerRole == hardnatplan.RoleMappingSet {
		if err := runtime.wait(ctx, asymmetricMappingLead); err != nil {
			return err
		}
	}
	pps := runtime.candidateBatchSize()
	for index, candidate := range runtime.localPlan.Candidates {
		if runtime.isHardCampaign() && index >= hardnatbudget.Hard16CandidatePackets {
			return runtime.poisonHardProtocol("candidate schedule exceeded the frozen 16384-packet slice")
		}
		if index > 0 && index%pps == 0 {
			if err := runtime.wait(ctx, candidateBatchPeriod); err != nil {
				return err
			}
		}
		peerAddress, err := fromPlanAddress(runtime.peerPublic)
		if err != nil {
			return err
		}
		target := netip.AddrPortFrom(peerAddress, candidate.TargetPort)
		frame, err := runtime.protocol.SealCandidate(candidate)
		if err == nil {
			err = runtime.sockets[candidate.SocketSlot].SendProbe(ctx, target, frame)
		}
		clear(frame)
		if err != nil {
			return err
		}
		runtime.emissionsMu.Lock()
		runtime.emissions.CandidatePackets++
		runtime.emissions.UDPPacketsTotal++
		runtime.candidateLast = time.Now()
		runtime.emissionsMu.Unlock()
	}
	return nil
}

func (runtime *runtime) validateHardProtocolShape(stage string) error {
	if !runtime.isHardCampaign() {
		return nil
	}
	runtime.emissionsMu.Lock()
	emissions := runtime.emissions
	runtime.emissionsMu.Unlock()
	switch stage {
	case "fresh evidence":
		if emissions.SocketsOpened != 16 || emissions.EvidencePackets != hardnatbudget.FreshEvidencePackets ||
			emissions.TargetsRegistered != 4 || emissions.FiveTuples != 11 || emissions.UDPPacketsTotal != hardnatbudget.FreshEvidencePackets {
			return runtime.poisonHardProtocol("fresh evidence slice differs from its frozen shape")
		}
	case "candidate registration":
		if len(runtime.localPlan.Candidates) != hardnatbudget.Hard16CandidatePackets || emissions.SocketsOpened != 16 ||
			emissions.TargetsRegistered != hardnatbudget.Hard16ActualTargetsMaximum ||
			emissions.FiveTuples != hardnatbudget.Hard16ActualFiveTupleMaximum {
			return runtime.poisonHardProtocol("candidate registration differs from its frozen shape")
		}
	}
	if emissions.CandidatePackets > hardnatbudget.Hard16CandidatePackets || emissions.WinnerPackets > 1 ||
		emissions.UDPPacketsTotal > hardnatbudget.Hard16ActualPacketsMaximum {
		return runtime.poisonHardProtocol("establishment emissions exceeded the non-spendable headroom boundary")
	}
	return nil
}

func (runtime *runtime) validateHardWinnerEmission() error {
	if !runtime.isHardCampaign() {
		return nil
	}
	runtime.emissionsMu.Lock()
	winners, total := runtime.emissions.WinnerPackets, runtime.emissions.UDPPacketsTotal
	runtime.emissionsMu.Unlock()
	if winners >= 1 || total+1 > hardnatbudget.Hard16ActualPacketsMaximum {
		return runtime.poisonHardProtocol("winner ACK exceeded the frozen one-packet slice")
	}
	return nil
}

func (runtime *runtime) poisonHardProtocol(detail string) error {
	cause := probeio.ErrHardLimit
	if runtime != nil && runtime.controller != nil {
		cause = errors.Join(cause, runtime.controller.Poison(governor.SafetyTripHardLimit, detail))
	}
	return cause
}

func hardnatbudgetForPPS(profile hardnatplan.Profile) int {
	if profile == hardnatplan.ProfilePredictiveEdm {
		return 32
	}
	if profile == hardnatplan.ProfileHardBirthday {
		return 512
	}
	return 64
}

func (runtime *runtime) chooser() bool {
	return runtime.artifact.PlannerProfile == hardnatplan.ProfilePredictiveEdm && runtime.artifact.LocalRole == directattempt.RoleInitiator ||
		runtime.artifact.PlannerProfile == hardnatplan.ProfileHardBirthday && runtime.artifact.LocalRole == directattempt.RoleInitiator ||
		runtime.artifact.PlannerProfile == hardnatplan.ProfileAsymmetricBirthday && runtime.artifact.LocalPlannerRole == hardnatplan.RoleTargetSet
}

func (runtime *runtime) candidateBatchSize() int {
	limit := hardnatbudgetForPPS(runtime.artifact.PlannerProfile)
	if runtime.isHardCampaign() {
		// Gate B3 selects its sole winner only after both complete schedules,
		// so all 512 slots belong to candidates. The winner waits for a fresh
		// rolling PPS interval and never borrows a 513th slot.
		return limit
	}
	if (runtime.artifact.PlannerProfile == hardnatplan.ProfilePredictiveEdm || runtime.artifact.PlannerProfile == hardnatplan.ProfileHardBirthday) && runtime.chooser() {
		return limit - 1
	}
	return limit
}

func (runtime *runtime) harnessNoiseRandom() io.Reader {
	if runtime != nil && runtime.config.Harness != nil {
		return runtime.config.Harness.NoiseRandom
	}
	return nil
}

func (runtime *runtime) harnessObservationRandom() io.Reader {
	if runtime != nil && runtime.config.Harness != nil {
		return runtime.config.Harness.ObservationRandom
	}
	return nil
}

func (runtime *runtime) harnessNow() func() time.Time {
	if runtime != nil && runtime.config.Harness != nil {
		return runtime.config.Harness.Now
	}
	return nil
}

func (runtime *runtime) harnessNewTimer() func(time.Duration) probeio.Timer {
	if runtime != nil && runtime.config.Harness != nil {
		return runtime.config.Harness.NewTimer
	}
	return nil
}

func (runtime *runtime) candidateWindow() time.Duration {
	if runtime != nil && runtime.config.Harness != nil && runtime.config.Harness.CandidateWindow > 0 {
		return runtime.config.Harness.CandidateWindow
	}
	duration, err := hardnatbudget.CandidateDuration(runtime.artifact.PlannerProfile, runtime.artifact.ResourceClass)
	if err != nil {
		return 0
	}
	return duration
}

func (runtime *runtime) activeEnvelope() time.Duration {
	if runtime != nil && runtime.config.Harness != nil && runtime.config.Harness.ActiveEnvelope > 0 {
		return runtime.config.Harness.ActiveEnvelope
	}
	duration, err := hardnatbudget.ActiveDuration(runtime.artifact.PlannerProfile, runtime.artifact.ResourceClass)
	if err != nil {
		return 0
	}
	return duration
}

func (runtime *runtime) isHardCampaign() bool {
	return runtime != nil && runtime.artifact != nil &&
		hardnatbudget.IsHardCampaign(runtime.artifact.PlannerProfile, runtime.artifact.ResourceClass)
}

func (runtime *runtime) now() time.Time {
	if now := runtime.harnessNow(); now != nil {
		return now()
	}
	return time.Now()
}

func (runtime *runtime) wait(ctx context.Context, duration time.Duration) error {
	if runtime != nil && runtime.config.Harness != nil && runtime.config.Harness.Wait != nil {
		return runtime.config.Harness.Wait(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (runtime *runtime) challenge(ctx context.Context) error {
	challengeCtx, cancel := context.WithTimeout(ctx, challengeDeadline)
	defer cancel()
	buffer := make([]byte, 64)
	defer clear(buffer)
	write := func(ordinal int) error {
		packet := challengePacket(runtime.binding, runtime.artifact.LocalRole, uint8(ordinal))
		defer clear(packet)
		if err := runtime.transport.WritePacket(challengeCtx, packet); err != nil {
			return err
		}
		runtime.emissions.DataPacketsWritten++
		return nil
	}
	read := func(ordinal int) error {
		n, _, err := runtime.transport.ReadPacket(challengeCtx, buffer)
		if err != nil {
			return err
		}
		actual, err := validateChallengePacket(buffer[:n], runtime.binding, runtime.artifact.LocalRole.Peer())
		if err != nil || int(actual) != ordinal {
			return errors.Join(err, errors.New("out-of-order data-plane challenge"))
		}
		runtime.emissions.DataPacketsRead++
		return nil
	}
	for ordinal := 0; ordinal < challengePackets; ordinal++ {
		if runtime.artifact.LocalRole == directattempt.RoleInitiator {
			if err := write(ordinal); err != nil {
				return err
			}
			if err := read(ordinal); err != nil {
				return err
			}
			continue
		}
		if err := read(ordinal); err != nil {
			return err
		}
		if err := write(ordinal); err != nil {
			return err
		}
	}
	// The alternating order means initiator completion proves responder
	// completion. From this point onward no executor path can emit another UDP
	// packet, so a peer's clean carrier close cannot race queued challenge reads.
	runtime.challengeComplete.Store(true)
	return nil
}

func challengePacket(binding hardnatcontrol.Binding, role directattempt.Role, ordinal uint8) []byte {
	payload := make([]byte, 0, 4+1+1+sha256.Size)
	payload = append(payload, challengeMagic...)
	payload = append(payload, roleByte(role), ordinal)
	hash := sha256.New()
	_, _ = hash.Write([]byte("winkyou-gate-b2-data-plane-challenge/1\n"))
	_, _ = hash.Write([]byte(binding.AttemptID))
	_, _ = hash.Write(binding.ContextDigest[:])
	_, _ = hash.Write(binding.HandshakeHash[:])
	_, _ = hash.Write(executionEnvelopeBytes(binding))
	_, _ = hash.Write([]byte{roleByte(role), ordinal})
	payload = append(payload, hash.Sum(nil)...)
	return payload
}

func validateChallengePacket(packet []byte, binding hardnatcontrol.Binding, role directattempt.Role) (uint8, error) {
	if len(packet) != 4+1+1+sha256.Size || string(packet[:4]) != challengeMagic || packet[4] != roleByte(role) || packet[5] >= challengePackets {
		return 0, errors.New("invalid data-plane challenge")
	}
	expected := challengePacket(binding, role, packet[5])
	valid := bytes.Equal(expected, packet)
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
	if runtime.plannerSource != nil {
		runtime.plannerSource.Close()
		runtime.plannerSource = nil
	}
	if runtime.protocol != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.protocol.Close())
		runtime.protocol = nil
	}
	if runtime.carrier != nil {
		if runtime.success && runtime.challengeComplete.Load() &&
			runtime.artifact.LocalRole == directattempt.RoleResponder {
			// The initiator can complete only after receiving the responder's
			// third challenge packet. It closes the carrier after recording
			// FINISH; the responder waits for that bounded terminal signal before
			// closing its side. This is a rendezvous-free close handshake and
			// emits no network traffic.
			select {
			case <-runtime.carrier.Done():
			case <-runtime.activeContext.Done():
			}
		}
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
	} else {
		for _, socket := range runtime.sockets {
			if socket == nil {
				continue
			}
			if err := socket.Close(); err != nil && !errors.Is(err, probeio.ErrSocketClosed) && !errors.Is(err, probeio.ErrLeaseClosed) {
				cleanupErr = errors.Join(cleanupErr, err)
			}
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
	if runtime.activeCancel != nil {
		runtime.activeCancel(context.Canceled)
	}
	if runtime.deadlineCancel != nil {
		runtime.deadlineCancel()
	}
	if runtime.carrierWatchDone != nil {
		<-runtime.carrierWatchDone
	}
	return cleanupErr
}

func (runtime *runtime) result() Result {
	runtime.emissionsMu.Lock()
	emissions := runtime.emissions
	runtime.emissionsMu.Unlock()
	result := Result{
		AttemptKind: "hard_nat_direct_handoff", Profile: runtime.artifact.PlannerProfile,
		ResourceClass: runtime.artifact.ResourceClass, Terminal: "failed", CredentialBurned: runtime.burned,
		FinishRecorded: runtime.finishRecorded, Emissions: emissions, ReservedEnvelope: runtime.request.Envelope,
	}
	if runtime.localPlan.Probability.Model != "" {
		result.Conditional = runtime.localPlan.Probability.Conditional
		result.ProbabilityFloor = runtime.localPlan.Probability.Primary.FloorPartsPerTrillion
	}
	if runtime.success {
		result.Terminal = "success"
		result.Bidirectional = true
	}
	if runtime.config.Ledger != nil {
		result.PairingLedger = runtime.config.Ledger.Status()
		if runtime.isHardCampaign() {
			campaign := runtime.config.Ledger.CampaignStatus()
			result.CampaignLedger = &campaign
		}
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

func preflightFailure(cause error) error {
	class := ClassOOBStreamInvalid
	switch {
	case errors.Is(cause, hardnatattempt.ErrUnsupportedProfile), errors.Is(cause, hardnatbudget.ErrUnsupportedEnvelope), errors.Is(cause, governor.ErrNotAllowed):
		class = ClassProfileUnsupported
	case errors.Is(cause, governor.ErrPairingCredentialUsed):
		class = ClassCredentialUsed
	case errors.Is(cause, governor.ErrHardNATCampaignRateLimited), errors.Is(cause, governor.ErrPairingAdmissionRateLimited):
		class = ClassCampaignRateLimited
	case errors.Is(cause, governor.ErrHardNATCampaignCircuitOpen), errors.Is(cause, governor.ErrPairingAdmissionCircuitOpen):
		class = ClassCampaignCircuitOpen
	case errors.Is(cause, governor.ErrPairingAdmissionRejected), errors.Is(cause, governor.ErrPairingLedgerIndeterminate):
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
	case errors.Is(err, hardnatplan.ErrUnsupportedProfile), errors.Is(err, hardnatattempt.ErrUnsupportedProfile), errors.Is(err, hardnatbudget.ErrUnsupportedEnvelope):
		return runtime.failure(ClassProfileUnsupported, stage, err)
	case errors.Is(err, hardnatplan.ErrEvidenceInsufficient), errors.Is(err, hardnatobserve.ErrRequiredReplyAbsent):
		return runtime.failure(ClassEvidenceInsufficient, stage, err)
	case errors.Is(err, hardnatplan.ErrInsufficientBudget):
		return runtime.failure(ClassInsufficientBudget, stage, err)
	case errors.Is(err, hardnatplan.ErrPlanMismatch), errors.Is(err, hardnatcontrol.ErrPlanMismatch):
		return runtime.failure(ClassPlanMismatch, stage, err)
	case runtime.resourceSafetyTripActive():
		// A governor trip can close sibling readers before the writer's original
		// ENOBUFS/hard-limit error wins the punch select. The durable machine
		// witness is authoritative and must not be downgraded to packet_rejected.
		return runtime.failure(ClassResourceBudgetExceeded, stage, err)
	case errors.Is(err, ErrCandidateExhausted):
		return runtime.failure(ClassCandidateExhausted, StageCandidates, err)
	case errors.Is(err, oobcarrier.ErrPresenceTimeout):
		return runtime.failure(ClassOOBPresenceTimeout, StagePresent, err)
	case errors.Is(err, oobcarrier.ErrCarrierTransport), errors.Is(err, io.EOF):
		return runtime.failure(ClassOOBStreamClosed, stage, err)
	case errors.Is(err, oobcarrier.ErrCarrierDomain), errors.Is(err, oobcarrier.ErrPreBurnSecureFrame),
		errors.Is(err, oobcarrier.ErrHandshakeOrder), errors.Is(err, oobcarrier.ErrInvalidFrame),
		errors.Is(err, hardnatcontrol.ErrInvalidFrame), errors.Is(err, hardnatcontrol.ErrInvalidSequence),
		errors.Is(err, hardnatcontrol.ErrInvalidTransition), errors.Is(err, noisecore.ErrAuthentication):
		return runtime.failure(ClassOOBProtocolViolation, stage, err)
	case errors.Is(err, governor.ErrPairingCredentialUsed):
		return runtime.failure(ClassCredentialUsed, stage, err)
	case errors.Is(err, governor.ErrHardNATCampaignRateLimited), errors.Is(err, governor.ErrPairingAdmissionRateLimited):
		return runtime.failure(ClassCampaignRateLimited, stage, err)
	case errors.Is(err, governor.ErrHardNATCampaignCircuitOpen), errors.Is(err, governor.ErrPairingAdmissionCircuitOpen):
		return runtime.failure(ClassCampaignCircuitOpen, stage, err)
	case errors.Is(err, governor.ErrPairingAdmissionRejected), errors.Is(err, governor.ErrPairingLedgerIndeterminate):
		return runtime.failure(ClassAdmissionBlocked, stage, err)
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
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return runtime.failure(ClassAttemptExpired, stage, err)
	case stage == StageCandidates || stage == StageWinner:
		return runtime.failure(ClassPacketRejected, stage, err)
	default:
		return runtime.failure(ClassOOBProtocolViolation, stage, err)
	}
}

func (runtime *runtime) resourceSafetyTripActive() bool {
	if runtime == nil || runtime.config.Machine == nil {
		return false
	}
	trip := runtime.config.Machine.Snapshot().SafetyTrip
	if !trip.BlocksActiveWork {
		return false
	}
	switch trip.Record.Reason {
	case governor.SafetyTripResourceExhausted, governor.SafetyTripWriteFailures, governor.SafetyTripHardLimit:
		return true
	default:
		return false
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
		case ClassAttemptExpired:
			if errors.Is(failure.Cause, context.Canceled) {
				return governor.PairingTerminalCancelled
			}
			return governor.PairingTerminalExpired
		case ClassResourceBudgetExceeded:
			// A durable safety trip synchronously closes AttemptLease.Stopping.
			// PairingAdmissionGate's registered drain therefore chooses cancelled
			// as the terminal reason. Use the same reason here so cleanup remains
			// idempotent and FINISH still precedes attempt release regardless of
			// which goroutine observes the trip first.
			return governor.PairingTerminalCancelled
		case ClassCandidateExhausted, ClassEvidenceInsufficient:
			return governor.PairingTerminalExpired
		}
	}
	return governor.PairingTerminalProtocolError
}

func digestFields(label string, fields ...[]byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(label))
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(field)
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func appendEndpoint(target *bytes.Buffer, endpoint netip.AddrPort) {
	address := endpoint.Addr().Unmap()
	if address.Is4() {
		target.WriteByte(4)
		raw := address.As4()
		target.Write(raw[:])
	} else {
		target.WriteByte(6)
		raw := address.As16()
		target.Write(raw[:])
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], endpoint.Port())
	target.Write(port[:])
}

func fromPlanAddress(address hardnatplan.Address) (netip.Addr, error) {
	switch address.Family {
	case hardnatplan.AddressFamilyIPv4:
		var raw [4]byte
		copy(raw[:], address.Bytes[:4])
		value := netip.AddrFrom4(raw)
		if !value.IsValid() {
			return netip.Addr{}, hardnatplan.ErrPlanMismatch
		}
		return value, nil
	case hardnatplan.AddressFamilyIPv6:
		value := netip.AddrFrom16(address.Bytes)
		if !value.IsValid() {
			return netip.Addr{}, hardnatplan.ErrPlanMismatch
		}
		return value, nil
	default:
		return netip.Addr{}, hardnatplan.ErrPlanMismatch
	}
}

func executionEnvelopeBytes(binding hardnatcontrol.Binding) []byte {
	encoded := make([]byte, 0, len(binding.Profile)+len(binding.ResourceClass)+32)
	encoded = append(encoded, binding.Profile...)
	encoded = append(encoded, 0)
	encoded = append(encoded, binding.ResourceClass...)
	encoded = append(encoded, 0)
	encoded = append(encoded, binding.EnvelopeDigest[:]...)
	return encoded
}
