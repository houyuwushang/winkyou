package gatecorchestrator

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"reflect"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecchildstream"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/netif"
	"winkyou/pkg/tunnel"
)

const gateCSessionTripDetail = "Gate C foreground session did not drain within its fixed deadline"

func defaultDependencies() dependencies {
	return dependencies{
		now:    time.Now,
		random: rand.Reader,
		openSSH: func(ctx context.Context, cfg sshassembly.Config) (sshProductStream, error) {
			return sshassembly.OpenClient(ctx, cfg)
		},
		claimPending:   gatecstage.ClaimPending,
		acquireMachine: acquireMachine,
		newChildStream: func(input io.Reader, output io.Writer, deadline time.Time) (oobcarrier.BoundedStream, error) {
			return gatecchildstream.New(input, output, deadline)
		},
		newInterface:     netif.NewGateCMemoryInterface,
		newTunnel:        tunnel.NewMemoryWireGuard,
		inspectConflict:  defaultConflictInspector,
		activityInterval: SessionActivityInterval,
	}
}

func runPrepared(ctx context.Context, input preparedInput, deps dependencies) (result Result, runErr error) {
	if ctx == nil || ctx.Err() != nil || deps.now == nil || deps.random == nil || deps.openSSH == nil ||
		deps.newInterface == nil || deps.newTunnel == nil || deps.inspectConflict == nil ||
		deps.activityInterval <= 0 || deps.activityInterval > SessionActivityInterval ||
		input.machine == nil || input.ledger == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	peer, err := resolveTrustedPeer(input)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, profileOf(input), resourceOf(input), err, nil)
	}
	topology, err := observerTopology(input.request)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, profileOf(input), resourceOf(input), err, nil)
	}
	if deps.configureGateB == nil {
		return Result{}, localFailure(ClassPeerUnauthorized, StagePreflight, false, profileOf(input), resourceOf(input), ErrPeerUnauthorized, nil)
	}
	state, err := deps.inspectConflict(ctx, input, peer)
	if err != nil || conflictPresent(state) {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, profileOf(input), resourceOf(input), ErrRequestInvalid, nil)
	}
	releaseOwnership, err := claimLocalOwnership(peer)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, profileOf(input), resourceOf(input), err, nil)
	}
	defer releaseOwnership()

	activeDuration, err := hardnatbudget.ActiveDuration(input.artifact.PlannerProfile, input.artifact.ResourceClass)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, profileOf(input), resourceOf(input), err, nil)
	}
	sequence := newProgressSequence(input.progress, deps.now().Add(activeDuration))
	defer func() { runErr = errors.Join(runErr, sequence.emitTerminal()) }()
	if err := sequence.emit(StagePreflight, true); err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, profileOf(input), resourceOf(input), err, nil)
	}

	var clientConfig sshassembly.ClientConfig
	if input.request.Role == directattempt.RoleInitiator {
		clientConfig, err = sshassembly.BindClientConfig(input.sshAuthority, *input.request.SSH)
		if err != nil {
			return Result{}, classifyLocalFailure(err, StagePreflight, false, input, nil)
		}
	}

	var openedSSH sshProductStream
	defer func() {
		if openedSSH != nil {
			result.Witness.SSH = openedSSH.Witness()
		}
	}()
	gateConfig := gateb.Config{
		Machine: input.machine, Ledger: input.ledger, PreparedArtifact: input.artifact,
		ExpectedPeerAddress: input.request.ExpectedPeerPublicAddress,
		ObserverTopology:    topology, BuildVersion: input.buildVersion,
		Progress: func(stage string, cancellable bool) error {
			if stage == gateb.StagePreflight || stage == gateb.StageTerminal {
				return nil
			}
			return sequence.emit(stage, cancellable)
		},
	}
	deps.configureGateB(&gateConfig)
	gateConfig.OpenProductStream = func(openCtx context.Context, attempt *governor.AttemptLease, deadline time.Time) (stream oobcarrier.BoundedStream, openErr error) {
		if attempt == nil || attempt.Request().ID != input.artifact.AttemptID || !deadline.After(deps.now()) {
			return nil, ErrRequestInvalid
		}
		if err := sequence.emit(StageSSHSpawn, true); err != nil {
			return nil, err
		}
		if input.request.Role == directattempt.RoleResponder {
			if input.stream != nil {
				return input.stream, nil
			}
			if deps.newChildStream == nil {
				return nil, ErrRequestInvalid
			}
			return deps.newChildStream(input.childInput, input.childOutput, deadline)
		}
		openedSSH, openErr = deps.openSSH(openCtx, sshassembly.Config{
			Lease: attempt, Client: clientConfig, PlannerProfile: input.artifact.PlannerProfile,
			ResourceClass: input.artifact.ResourceClass, ActiveDeadline: deadline,
		})
		if openErr != nil {
			return nil, openErr
		}
		return openedSSH, nil
	}

	handoff, gateResult, err := gateb.RunForProduct(ctx, gateConfig)
	result.Witness.GateB = gateResult
	result.CredentialBurned = gateResult.CredentialBurned
	if openedSSH != nil {
		result.Witness.SSH = openedSSH.Witness()
	}
	if err != nil || handoff == nil {
		stage := gateResultStage(err)
		if stage == StagePreflight {
			stage = sequence.lastStage()
		}
		return result, classifyLocalFailure(err, stage, gateResult.CredentialBurned, input, nil)
	}
	finished := false
	defer func() {
		if !finished {
			witness, abortErr := handoff.Abort(runErr)
			result.Witness.Handoff = witness
			runErr = errors.Join(runErr, abortErr)
		}
	}()

	memoryInterface, err := deps.newInterface(peer.interfaceName, peer.mtu)
	if err != nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageHandoff, true, input, nil)
	}
	interfaceClosed := false
	defer func() {
		if closeErr := memoryInterface.Close(); closeErr == nil {
			interfaceClosed = true
		} else {
			runErr = errors.Join(runErr, sessionDrainFailure(input, closeErr))
		}
		result.Witness.InterfaceClosed = interfaceClosed
	}()

	tun, err := deps.newTunnel(tunnel.Config{Interface: memoryInterface, PrivateKey: peer.privateKey, ListenPort: 0})
	if err != nil || tun == nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageHandoff, true, input, nil)
	}
	tunnelStarted := false
	defer func() {
		if !tunnelStarted {
			return
		}
		if stopErr := boundedTunnelStop(tun); stopErr != nil {
			runErr = errors.Join(runErr, sessionDrainFailure(input, stopErr))
		} else {
			result.Witness.TunnelStopped = true
		}
	}()
	if err := tun.Start(); err != nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageHandoff, true, input, nil)
	}
	tunnelStarted = true

	configuredPeer, err := bindingPeer(peer)
	if err != nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageHandoff, true, input, nil)
	}
	if err := handoff.BeginWireGuardChallenge(); err != nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageDataPlaneChallenge, true, input, nil)
	}
	configuredPeer.Transport = handoff.Transport()
	if err := tun.AddPeer(configuredPeer); err != nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageDataPlaneChallenge, true, input, nil)
	}
	if input.request.Role == directattempt.RoleInitiator {
		if err := initiateOneShotHandshake(ctx, tun, peer.publicKey); err != nil {
			return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageDataPlaneChallenge, true, input, nil)
		}
	}
	if err := completeWireGuardChallenge(ctx, handoff); err != nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageDataPlaneChallenge, true, input, nil)
	}

	sessionDeadline := deps.now().Add(peer.sessionCeiling)
	sessionCtx, cancelSession := context.WithDeadline(context.WithoutCancel(ctx), sessionDeadline)
	defer cancelSession()
	handoffWitness, err := handoff.FinishAndDetach(sessionCtx)
	result.Witness.Handoff = handoffWitness
	result.Witness.WireGuard = handoffWitness.Transport
	result.FinishRecorded = handoffWitness.FinishRecorded
	if err != nil {
		return result, classifyLocalFailure(ErrWireGuardBinding, gateb.StageDataPlaneChallenge, true, input, nil)
	}
	finished = true
	if err := sequence.emit(StageFinishRecorded, true); err != nil {
		return result, classifyLocalFailure(err, StageFinishRecorded, true, input, nil)
	}
	if !handoffWitness.OOBDrained || !handoffWitness.AttemptReleased {
		return result, classifyLocalFailure(ErrSessionDrain, StageOOBDrained, true, input, nil)
	}
	if err := sequence.emit(StageOOBDrained, true); err != nil {
		return result, classifyLocalFailure(err, StageOOBDrained, true, input, nil)
	}

	binding := handoff.Binding()
	echoWitness, err := postOOBEcho(sessionCtx, input.request.Role, memoryInterface, echoBinding{
		Role: input.request.Role, Local: peer.localVirtual, Remote: peer.remoteVirtual,
		AttemptID: binding.AttemptID, ContextDigest: binding.ContextDigest,
	}, deps.random)
	result.Witness.Echo = echoWitness
	if err != nil {
		return result, classifyLocalFailure(ErrPostHandoff, StageDataPlaneReady, true, input, map[string]int{
			"echo_requests_written": echoWitness.RequestsWritten,
			"echo_responses_read":   echoWitness.ResponsesRead,
		})
	}
	result.DataPlaneReady = true
	if err := sequence.emit(StageDataPlaneReady, true); err != nil {
		return result, classifyLocalFailure(err, StageDataPlaneReady, true, input, nil)
	}

	sessionEnd, foregroundWitness, err := foregroundSession(ctx, sessionCtx, input.request.Role, memoryInterface, handoff,
		echoBinding{Role: input.request.Role, Local: peer.localVirtual, Remote: peer.remoteVirtual,
			AttemptID: binding.AttemptID, ContextDigest: binding.ContextDigest}, deps.random, deps.activityInterval)
	mergeEchoWitness(&result.Witness.Echo, foregroundWitness)
	result.SessionEnd = sessionEnd
	result.Witness.WireGuard = handoff.Witness().Transport
	result.Witness.Handoff = handoff.Witness()
	result.Witness.GateB = handoff.Result()
	if err != nil {
		return result, classifyLocalFailure(ErrPostHandoff, StageDataPlaneReady, true, input, nil)
	}
	if closeErr := handoff.CloseSession(); closeErr != nil {
		return result, sessionDrainFailure(input, closeErr)
	}
	result.Terminal = "success"
	return result, nil
}

func completeWireGuardChallenge(ctx context.Context, handoff *gateb.ProductHandoff) error {
	deadline := time.NewTimer(probeio.WireGuardChallengeTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		witness := handoff.Witness().Transport
		if challengeTraceComplete(witness) {
			if err := handoff.MarkWireGuardChallengePassed(); err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrWireGuardBinding
		case <-ticker.C:
		}
	}
}

func initiateOneShotHandshake(ctx context.Context, tun tunnel.Tunnel, publicKey tunnel.PublicKey) error {
	if ctx == nil || tun == nil {
		return ErrWireGuardBinding
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	initiator, ok := tun.(tunnel.OneShotHandshakeInitiator)
	if !ok {
		return ErrWireGuardBinding
	}
	if err := initiator.InitiatePeerHandshake(publicKey); err != nil {
		return err
	}
	return ctx.Err()
}

func challengeTraceComplete(witness probeio.WireGuardSessionGateWitness) bool {
	if witness.State != probeio.WireGuardGateChallengeCapped {
		return false
	}
	initiator := reflect.DeepEqual(witness.Outbound, []probeio.WireGuardMessageType{
		probeio.WireGuardHandshakeInitiation, probeio.WireGuardTransportData,
	}) && reflect.DeepEqual(witness.Inbound, []probeio.WireGuardMessageType{probeio.WireGuardHandshakeResponse})
	responder := reflect.DeepEqual(witness.Outbound, []probeio.WireGuardMessageType{probeio.WireGuardHandshakeResponse}) &&
		reflect.DeepEqual(witness.Inbound, []probeio.WireGuardMessageType{
			probeio.WireGuardHandshakeInitiation, probeio.WireGuardTransportData,
		})
	return initiator || responder
}

func boundedTunnelStop(tun tunnel.Tunnel) error {
	done := make(chan error, 1)
	go func() { done <- tun.Stop() }()
	timer := time.NewTimer(SessionDrainTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return ErrSessionDrain
	}
}

func sessionDrainFailure(input preparedInput, cause error) error {
	if input.machine != nil {
		_, _ = input.machine.Trip(governor.SafetyTripEvent{
			Reason: governor.SafetyTripCancellation, Detail: gateCSessionTripDetail,
			AttemptID: input.artifact.AttemptID, BuildVersion: input.buildVersion,
		})
	}
	return localFailure(ClassSessionDrain, StageTerminal, true, profileOf(input), resourceOf(input), cause, nil)
}

func classifyLocalFailure(cause error, stage string, burned bool, input preparedInput, counts map[string]int) error {
	if cause == nil {
		cause = ErrRequestInvalid
	}
	var gateFailure *gateb.Failure
	if errors.As(cause, &gateFailure) {
		return localFailure(gateFailure.Class, gateFailure.Stage, gateFailure.CredentialBurned,
			profileOf(input), resourceOf(input), gateFailure.Cause, counts)
	}
	class := ClassRequestInvalid
	switch {
	case errors.Is(cause, ErrPeerUnauthorized):
		class = ClassPeerUnauthorized
	case errors.Is(cause, sshassembly.ErrHostIdentity):
		class = ClassSSHHostRejected
	case errors.Is(cause, sshassembly.ErrBudgetExceeded):
		class = ClassSSHBudgetExceeded
	case errors.Is(cause, sshassembly.ErrChildTerminated), errors.Is(cause, sshassembly.ErrAssemblyClosed):
		class = ClassSSHChildTerminated
	case errors.Is(cause, sshassembly.ErrTransport), errors.Is(cause, sshassembly.ErrDeadline):
		class = ClassSSHUnavailable
	case errors.Is(cause, sshassembly.ErrProfileInvalid):
		class = ClassSSHProfileInvalid
	case errors.Is(cause, ErrWireGuardBinding), errors.Is(cause, probeio.ErrWireGuardGate),
		errors.Is(cause, probeio.ErrWireGuardGateLimit), errors.Is(cause, probeio.ErrWireGuardGateState):
		class = ClassWireGuardBinding
	case errors.Is(cause, ErrPostHandoff), errors.Is(cause, ErrEchoInvalid):
		class = ClassPostHandoff
	case errors.Is(cause, ErrSessionDrain):
		class = ClassSessionDrain
	}
	return localFailure(class, stage, burned, profileOf(input), resourceOf(input), cause, counts)
}

func localFailure(class, stage string, burned bool, profile, resource string, cause error, counts map[string]int) *Failure {
	return &Failure{Class: class, Stage: stage, CredentialBurned: burned, Retryable: false,
		Profile: profile, ResourceClass: resource, Counts: cloneCounts(counts), Cause: cause}
}

func cloneCounts(source map[string]int) map[string]int {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]int, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func profileOf(input preparedInput) string {
	if input.artifact == nil {
		return ""
	}
	return string(input.artifact.PlannerProfile)
}

func resourceOf(input preparedInput) string {
	if input.artifact == nil {
		return ""
	}
	return string(input.artifact.ResourceClass)
}

func gateResultStage(err error) string {
	var failure *gateb.Failure
	if errors.As(err, &failure) && failure.Stage != "" {
		return failure.Stage
	}
	return StagePreflight
}

func mergeEchoWitness(target *EchoWitness, addition EchoWitness) {
	if target == nil {
		return
	}
	target.RequestsWritten += addition.RequestsWritten
	target.RequestsRead += addition.RequestsRead
	target.ResponsesWritten += addition.ResponsesWritten
	target.ResponsesRead += addition.ResponsesRead
	target.CloseWritten += addition.CloseWritten
	target.CloseRead += addition.CloseRead
	target.ReplaysRejected += addition.ReplaysRejected
	target.Drained = target.Drained || addition.Drained
}
