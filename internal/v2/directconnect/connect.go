package directconnect

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/rendezvouscarrier"
)

const punchDeadline = 1500 * time.Millisecond

type staticPSK [noisecore.PSKSize]byte

func (source staticPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

type runtime struct {
	config         Config
	requestContext context.Context
	artifact       *directattempt.Artifact
	stunTarget     netip.AddrPort
	request        governor.PairingAdmissionRequest
	peer           *governor.PeerLease
	attempt        *governor.AttemptLease
	carrier        *rendezvouscarrier.Carrier
	authorization  *governor.CommittedCarrierAuthorization
	protocol       *directattempt.Protocol
	controller     *probeio.Controller
	socket         *probeio.ProbeSocket
	promotion      *probeio.Promotion
	stage          string
	burned         bool
	finishRecorded bool
	emissions      Emissions
}

func connect(ctx context.Context, config Config) (Result, error) {
	runtime, err := prepare(ctx, config)
	if err != nil {
		if progressErr := terminalProgress(config.Progress); progressErr != nil {
			return Result{}, &Failure{
				Class: ClassDirectAttemptFailed, Stage: StageTerminal, CredentialBurned: false,
				TerminalCategory: CategoryPreflightRejected, Cause: progressErr,
			}
		}
		return Result{}, err
	}
	defer runtime.artifact.Close()

	runErr := runtime.run(ctx)
	finishReason := terminalReason(runErr)
	cleanupErr := runtime.cleanup(finishReason)
	if cleanupErr != nil {
		runErr = runtime.failure(ClassDrainFailed, StageTerminal, cleanupErr)
	}
	terminalErr := terminalProgress(config.Progress)
	if terminalErr != nil {
		return Result{}, runtime.failure(ClassDirectAttemptFailed, StageTerminal, terminalErr)
	}
	if runErr != nil {
		return Result{}, runErr
	}
	result := runtime.result()
	if !result.FinishRecorded || result.SafetyTrip.BlocksActiveWork {
		return Result{}, runtime.failure(ClassDrainFailed, StageTerminal, errors.New("terminal evidence is incomplete"))
	}
	return result, nil
}

func prepare(ctx context.Context, config Config) (*runtime, error) {
	if ctx == nil {
		return nil, preflightFailure(ClassDirectAttemptFailed, context.Canceled)
	}
	now := time.Now().UTC()
	artifact, err := directattempt.ParseArtifact(config.Artifact, now)
	if err != nil {
		return nil, artifactFailure(err)
	}
	fail := func(class string, cause error) (*runtime, error) {
		artifact.Close()
		return nil, preflightFailure(class, cause)
	}
	if config.Rendezvous.DeploymentTier != DeploymentSelfHosted &&
		config.Rendezvous.DeploymentTier != DeploymentMinimumTrust {
		return fail(ClassRendezvousEndpointInvalid, rendezvouscarrier.ErrInvalidConfig)
	}
	if err := validateRendezvousInput(config.Rendezvous.Endpoint, config.allowLoopback); err != nil {
		return fail(ClassRendezvousEndpointInvalid, err)
	}
	tlsConfig := rendezvouscarrier.TLSConfig{
		Verification: rendezvouscarrier.TLSVerification(config.Rendezvous.TLS.Verification),
		ServerName:   config.Rendezvous.TLS.ServerName,
		SPKISHA256:   config.Rendezvous.TLS.SPKISHA256,
	}
	if err := rendezvouscarrier.ValidateTLSConfig(tlsConfig); err != nil {
		return fail(ClassRendezvousEndpointInvalid, err)
	}
	stunTarget, err := validateSTUNInput(config.STUNEndpoint, config.allowLoopback)
	if err != nil {
		return fail(ClassSTUNEndpointInvalid, err)
	}
	if config.Machine == nil || config.Ledger == nil || config.Progress == nil || strings.TrimSpace(config.BuildVersion) == "" {
		return fail(ClassDirectAttemptFailed, errors.New("direct attempt dependencies are unavailable"))
	}
	if err := ctx.Err(); err != nil {
		artifact.Close()
		return nil, &Failure{
			Class: ClassAttemptExpired, Stage: StagePreflight, CredentialBurned: false,
			TerminalCategory: CategoryCancelled, Cause: err,
		}
	}
	if trip := config.Machine.Snapshot().SafetyTrip; trip.BlocksActiveWork {
		artifact.Close()
		return nil, &Failure{
			Class: ClassResourceBudgetExceeded, Stage: StagePreflight, CredentialBurned: false,
			TerminalCategory: CategorySafetyTripped, Cause: governor.ErrSafetyTripped,
		}
	}
	digest, err := artifact.ContextDigest()
	if err != nil {
		return fail(ClassInvalidDirectArtifact, err)
	}
	request := governor.PairingAdmissionRequest{
		CredentialID:  artifact.CredentialID,
		AttemptID:     artifact.AttemptID,
		ContextDigest: hex.EncodeToString(digest[:]),
		Scope:         governor.ScopeMachine,
		ExpiresAt:     artifact.ExpiresAt,
		Envelope:      governor.PairingEnvelopeFromAttemptCost(rendezvouscarrier.N2AttemptCost()),
	}
	clear(digest[:])
	if err := config.Ledger.Preflight(request); err != nil {
		class, category := classifyAdmission(err)
		artifact.Close()
		return nil, &Failure{Class: class, Stage: StagePreflight, TerminalCategory: category, Cause: err}
	}
	return &runtime{
		config: config, artifact: artifact, stunTarget: stunTarget, request: request, stage: StagePreflight,
	}, nil
}

func (runtime *runtime) run(ctx context.Context) error {
	runtime.requestContext = ctx
	pairingContext, err := runtime.artifact.PairingContext()
	if err != nil {
		return runtime.failure(ClassInvalidDirectArtifact, StagePreflight, err)
	}
	peerID := pairingContext.ResponderParticipantID
	if runtime.artifact.LocalRole == directattempt.RoleResponder {
		peerID = pairingContext.InitiatorParticipantID
	}
	runtime.peer, err = runtime.config.Machine.AcquirePeer(peerID)
	if err != nil {
		return runtime.classify(StagePreflight, err)
	}
	runtime.attempt, err = runtime.peer.AcquireAttempt(ctx, governor.AttemptRequest{
		ID: runtime.artifact.AttemptID, Operation: governor.OperationConnectTest, Cost: rendezvouscarrier.N2AttemptCost(),
	})
	if err != nil {
		return runtime.classify(StagePreflight, err)
	}

	carrierScope := rendezvouscarrier.AllowedTargetIsolatedUnicast
	if runtime.config.allowLoopback {
		carrierScope = rendezvouscarrier.AllowedTargetLoopback
	}
	runtime.carrier, err = rendezvouscarrier.Preconnect(ctx, rendezvouscarrier.Config{
		Lease:              runtime.attempt,
		Endpoint:           runtime.config.Rendezvous.Endpoint,
		Tier:               rendezvouscarrier.DeploymentTier(runtime.config.Rendezvous.DeploymentTier),
		AssociationID:      runtime.artifact.RendezvousAssociationID,
		Slot:               presenceSlot(runtime.artifact.LocalRole),
		Role:               runtime.artifact.LocalRole,
		AllowedTargetScope: carrierScope,
		PresenceDeadline:   rendezvouscarrier.PresenceTimeout,
		OperationDeadline:  rendezvouscarrier.ActiveEnvelope,
		TLS: &rendezvouscarrier.TLSConfig{
			Verification: rendezvouscarrier.TLSVerification(runtime.config.Rendezvous.TLS.Verification),
			ServerName:   runtime.config.Rendezvous.TLS.ServerName,
			SPKISHA256:   runtime.config.Rendezvous.TLS.SPKISHA256,
		},
	})
	if err != nil {
		return runtime.classify(StagePreflight, err)
	}
	if err := runtime.carrier.AwaitPresence(ctx); err != nil {
		if errors.Is(err, rendezvouscarrier.ErrPresenceTimeout) {
			return runtime.failure(ClassPresenceTimeout, StageTerminal, err)
		}
		return runtime.classify(StagePresent, err)
	}
	if err := runtime.emit(StagePresent); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StagePresent, err)
	}

	before := runtime.config.Ledger.Status().Sequence
	committed, err := governor.NewPairingAdmissionGate().Commit(ctx, runtime.attempt, runtime.request)
	if err != nil {
		after := runtime.config.Ledger.Status().Sequence
		runtime.burned = after > before
		return runtime.classify(StageBurned, err)
	}
	runtime.burned = true
	runtime.authorization, err = committed.ConsumeForCarrier(ctx)
	if err != nil {
		return runtime.classify(StageBurned, err)
	}
	if err := runtime.emit(StageBurned); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageBurned, err)
	}
	if err := runtime.carrier.Activate(ctx, runtime.authorization); err != nil {
		return runtime.classify(StageActivated, err)
	}
	if err := runtime.emit(StageActivated); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageActivated, err)
	}

	binding, err := runtime.handshake(ctx)
	if err != nil {
		return runtime.failure(ClassSecureHandshakeFailed, StageHandshake, err)
	}
	if err := runtime.emit(StageHandshake); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageHandshake, err)
	}
	if err := runtime.exchangeControl(ctx, directattempt.FramePrepare); err != nil {
		return runtime.classify(StagePrepare, err)
	}
	if err := runtime.emit(StagePrepare); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StagePrepare, err)
	}

	generation := probeio.NewGeneration(directattempt.Generation)
	localAddress := netip.MustParseAddrPort("0.0.0.0:0")
	if runtime.stunTarget.Addr().Is6() {
		localAddress = netip.MustParseAddrPort("[::]:0")
	}
	factoryScope := probeio.AllowedTargetScopeUnicast
	if runtime.config.allowLoopback {
		factoryScope = probeio.AllowedTargetScopeLoopback
	}
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: localAddress, AllowedTargetScope: factoryScope,
	})
	if err != nil {
		return runtime.classify(StageSocket, err)
	}
	udpCost := stunobserve.N2SameSocketCost()
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
	local, err := runtime.socket.LocalAddr()
	if err != nil || !local.Addr().IsUnspecified() || local.Port() == 0 {
		return runtime.classify(StageSocket, errors.Join(err, probeio.ErrDatagramContract))
	}
	if err := runtime.emit(StageSocket); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageSocket, err)
	}

	observer, err := stunobserve.NewSameSocket(stunobserve.SameSocketConfig{
		Socket: runtime.socket, Generation: generation, ExpectedGeneration: directattempt.Generation,
		AllowNonLoopback: !runtime.config.allowLoopback,
	})
	if err != nil {
		return runtime.classify(StageSTUN, err)
	}
	observation, err := observer.Observe(ctx, runtime.stunTarget)
	runtime.emissions.STUNPackets = observation.Transmissions
	runtime.emissions.UDPPacketsTotal += observation.Transmissions
	if err != nil {
		return runtime.classify(StageSTUN, err)
	}
	if observation.LocalEndpoint.Port() != local.Port() {
		return runtime.failure(ClassSTUNProtocol, StageSTUN, probeio.ErrDatagramContract)
	}
	if err := runtime.emit(StageSTUN); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageSTUN, err)
	}

	peerReady, err := runtime.exchangeReady(ctx, binding, observation.MappedEndpoint)
	if err != nil {
		return runtime.classify(StageReady, err)
	}
	if peerReady == nil {
		return runtime.classify(StageReady, directattempt.ErrInvalidReady)
	}
	if err := observer.RegisterPeerTarget(peerReady.Endpoint, peerReady.Generation); err != nil {
		return runtime.classify(StageReady, err)
	}
	if err := runtime.emit(StageReady); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageReady, err)
	}

	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		if err := runtime.sendControl(ctx, directattempt.FrameFire); err != nil {
			return runtime.classify(StageFire, err)
		}
	} else {
		opened, err := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
		if err != nil {
			return runtime.classify(StageFire, err)
		}
		if opened.Type == directattempt.FrameCancel {
			return runtime.classify(StageFire, directattempt.ErrCancelled)
		}
		if opened.Type != directattempt.FrameFire {
			return runtime.classify(StageFire, directattempt.ErrInvalidTransition)
		}
	}
	if err := runtime.emit(StageFire); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageFire, err)
	}
	if err := runtime.punch(ctx, peerReady.Endpoint); err != nil {
		return runtime.classify(StagePunch, err)
	}
	if err := runtime.emit(StagePunch); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StagePunch, err)
	}
	if err := runtime.exchangeControl(ctx, directattempt.FrameVerify); err != nil {
		return runtime.classify(StageVerify, err)
	}
	status := runtime.protocol.Status()
	if !status.Terminal || !status.Success {
		return runtime.failure(ClassVerificationFailed, StageVerify, directattempt.ErrInvalidTransition)
	}
	if err := runtime.emit(StageVerify); err != nil {
		return runtime.failure(ClassDirectAttemptFailed, StageVerify, err)
	}
	promotion, err := runtime.socket.PromoteTerminal(peerReady.Endpoint, "n3b-direct-terminal")
	if err != nil {
		return runtime.classify(StageVerify, err)
	}
	runtime.promotion = &promotion
	return nil
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
	if err := progress(StageTerminal, false); err != nil {
		return errors.Join(ErrProgressDelivery, err)
	}
	return nil
}

func validateRendezvousInput(endpoint string, allowLoopback bool) error {
	if endpoint == "" || endpoint != strings.TrimSpace(endpoint) || len(endpoint) > 512 || strings.IndexFunc(endpoint, unicode.IsControl) >= 0 {
		return rendezvouscarrier.ErrInvalidConfig
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" {
		return rendezvouscarrier.ErrInvalidConfig
	}
	parsedPort, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", port))
	if err != nil || parsedPort.Port() == 0 {
		return rendezvouscarrier.ErrInvalidConfig
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Zone() != "" || address.String() != host || address.IsUnspecified() || address.IsMulticast() {
			return rendezvouscarrier.ErrInvalidConfig
		}
		if allowLoopback {
			if !address.IsLoopback() {
				return rendezvouscarrier.ErrTargetForbidden
			}
		} else if !address.IsGlobalUnicast() || address.IsLoopback() {
			return rendezvouscarrier.ErrTargetForbidden
		}
		return nil
	}
	if !validHostname(host) {
		return rendezvouscarrier.ErrInvalidConfig
	}
	return nil
}

func validateSTUNInput(value string, allowLoopback bool) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.String() != value || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" ||
		endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return netip.AddrPort{}, stunobserve.ErrInvalidUnicastTarget
	}
	if allowLoopback {
		if !endpoint.Addr().IsLoopback() {
			return netip.AddrPort{}, stunobserve.ErrInvalidTarget
		}
	} else if !endpoint.Addr().IsGlobalUnicast() || endpoint.Addr().IsLoopback() {
		return netip.AddrPort{}, stunobserve.ErrInvalidUnicastTarget
	}
	return endpoint, nil
}

func validHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func presenceSlot(role directattempt.Role) rendezvouscarrier.PresenceSlot {
	if role == directattempt.RoleInitiator {
		return rendezvouscarrier.PresenceSlotA
	}
	return rendezvouscarrier.PresenceSlotB
}
