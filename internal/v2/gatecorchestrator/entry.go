package gatecorchestrator

import (
	"context"
	"errors"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/sshassembly"
)

// RunInitiator executes one foreground Gate C1b attempt. The ordinary build
// has no non-loopback UDP authority, so it completes only under an explicitly
// sealed test topology; a field request is rejected before SSH or UDP I/O.
func RunInitiator(ctx context.Context, options InitiatorOptions) (Result, error) {
	return runInitiator(ctx, options, defaultDependencies())
}

func runInitiator(ctx context.Context, options InitiatorOptions, deps dependencies) (Result, error) {
	if ctx == nil || options.RequestFile == "" || options.Config == nil || options.BuildVersion == "" || options.Progress == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	request, err := gatecrequest.LoadPrivate(options.RequestFile)
	if err != nil || request.Role != gatecattempt.RoleInitiator || request.SSH == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	artifact, err := loadArtifact(request.ArtifactFile, deps.now())
	if err != nil || artifact.LocalRole != gatecattempt.RoleInitiator {
		if artifact != nil {
			artifact.Close()
		}
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	defer artifact.Close()
	authority, err := sshassembly.NewLoopbackAuthority(request.SSH.Endpoint)
	if err != nil {
		return Result{}, localFailure(ClassPeerUnauthorized, StagePreflight, false,
			string(artifact.PlannerProfile), string(artifact.ResourceClass), ErrPeerUnauthorized, nil)
	}
	input := preparedInput{
		request: request, artifact: artifact, configuration: options.Config, configPath: options.ConfigPath,
		buildVersion: options.BuildVersion, sshAuthority: authority, progress: options.Progress,
	}
	if _, err := resolveTrustedPeer(input); err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(artifact.PlannerProfile), string(artifact.ResourceClass), err, nil)
	}
	if err := passiveMachinePreflight(); err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(artifact.PlannerProfile), string(artifact.ResourceClass), err, nil)
	}
	machine, ledger, err := acquireMachine(artifact.PlannerProfile, artifact.ResourceClass, options.BuildVersion)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(artifact.PlannerProfile), string(artifact.ResourceClass), err, nil)
	}
	defer machine.Close()
	input.machine, input.ledger = machine, ledger
	return runPrepared(ctx, input, deps)
}

func runClaimedResponder(ctx context.Context, claimed *gatecstage.Claimed, stream oobcarrier.BoundedStream,
	options ResponderOptions, deps dependencies) (Result, error) {
	if ctx == nil || claimed == nil || claimed.Artifact == nil || stream == nil || options.Config == nil ||
		options.BuildVersion == "" || options.Progress == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	defer claimed.Close()
	if claimed.Request.Role != gatecattempt.RoleResponder || claimed.Request.SSH != nil ||
		claimed.Artifact.LocalRole != gatecattempt.RoleResponder {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	// ClaimPending has already durably consumed the single slot. Compete for
	// the machine owner immediately; the loser cannot reach any UDP path.
	machine, ledger, err := acquireMachine(claimed.Artifact.PlannerProfile, claimed.Artifact.ResourceClass, options.BuildVersion)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(claimed.Artifact.PlannerProfile), string(claimed.Artifact.ResourceClass), err, nil)
	}
	defer machine.Close()
	return runPrepared(ctx, preparedInput{
		request: claimed.Request, artifact: claimed.Artifact, configuration: options.Config,
		configPath: options.ConfigPath, buildVersion: options.BuildVersion, machine: machine,
		ledger: ledger, stream: stream, progress: options.Progress,
	}, deps)
}

func loadArtifact(path string, now time.Time) (*gatecattempt.Artifact, error) {
	payload, err := pairgen.ReadPrivateFile(path, gatecattempt.MaxArtifactBytes)
	if err != nil {
		return nil, ErrRequestInvalid
	}
	defer clear(payload)
	artifact, err := gatecattempt.ParseArtifact(payload, now.UTC())
	if err != nil {
		return nil, ErrRequestInvalid
	}
	return artifact, nil
}

func passiveMachinePreflight() error {
	if status := governor.InspectMachineNamespace(); !status.Ready {
		return ErrRequestInvalid
	}
	if status := governor.InspectMachineSafetyTrip(); status.BlocksActiveWork {
		return governor.ErrSafetyTripped
	}
	ledger := governor.InspectMachinePairingLedger()
	if ledger.State == governor.PairingLedgerIndeterminate {
		return errors.New("gatecorchestrator: pairing ledger is unavailable")
	}
	return nil
}
