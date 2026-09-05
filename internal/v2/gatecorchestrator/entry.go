package gatecorchestrator

import (
	"context"
	"errors"
	"io"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/pairgen"
)

// RunInitiator executes one foreground Gate C1b attempt. The ordinary build
// has no non-loopback UDP authority, so it completes only under an explicitly
// sealed test topology; a field request is rejected before SSH or UDP I/O.
func RunInitiator(ctx context.Context, options InitiatorOptions) (Result, error) {
	return runInitiator(ctx, options, defaultDependencies())
}

func runInitiator(ctx context.Context, options InitiatorOptions, deps dependencies) (Result, error) {
	if ctx == nil || options.RequestFile == "" || options.Config == nil || options.BuildVersion == "" || options.Progress == nil || deps.inspectMachine == nil || deps.artifactNow == nil || deps.newSSHAuthority == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	request, err := gatecrequest.LoadPrivate(options.RequestFile)
	if err != nil || request.Role != gatecattempt.RoleInitiator || request.SSH == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	artifact, err := loadArtifact(request.ArtifactFile, deps.artifactNow())
	if err != nil || artifact.LocalRole != gatecattempt.RoleInitiator {
		if artifact != nil {
			artifact.Close()
		}
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	defer artifact.Close()
	authority, err := deps.newSSHAuthority(request.SSH.Endpoint)
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
	if err := deps.inspectMachine(); err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(artifact.PlannerProfile), string(artifact.ResourceClass), err, nil)
	}
	if deps.acquireMachine == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(artifact.PlannerProfile), string(artifact.ResourceClass), ErrRequestInvalid, nil)
	}
	machine, ledger, err := deps.acquireMachine(artifact.PlannerProfile, artifact.ResourceClass, options.BuildVersion)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(artifact.PlannerProfile), string(artifact.ResourceClass), err, nil)
	}
	defer machine.Close()
	input.machine, input.ledger = machine, ledger
	return runPrepared(ctx, input, deps)
}

// RunResponderStdio consumes the single staged responder slot and adopts the
// forced-command stdin/stdout byte stream. It does not speak JSON-RPC and does
// not create, dial, or listen on an SSH connection.
func RunResponderStdio(ctx context.Context, input io.Reader, output io.Writer, options ResponderOptions) (Result, error) {
	return runResponderStdio(ctx, input, output, options, defaultDependencies())
}

func runResponderStdio(ctx context.Context, input io.Reader, output io.Writer,
	options ResponderOptions, deps dependencies) (Result, error) {
	if ctx == nil || input == nil || output == nil || options.Config == nil || options.BuildVersion == "" ||
		options.Progress == nil || deps.now == nil || deps.artifactNow == nil || deps.claimPending == nil || deps.acquireMachine == nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	claimed, err := deps.claimPending(deps.artifactNow().UTC())
	if err != nil || claimed == nil || claimed.Artifact == nil {
		if claimed != nil {
			claimed.Close()
		}
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	defer claimed.Close()
	if claimed.Request.Role != gatecattempt.RoleResponder || claimed.Request.SSH != nil ||
		claimed.Artifact.LocalRole != gatecattempt.RoleResponder {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false, "", "", ErrRequestInvalid, nil)
	}
	// ClaimPending has already durably consumed the single slot. Compete for
	// the machine owner immediately; the loser cannot reach any UDP path.
	machine, ledger, err := deps.acquireMachine(claimed.Artifact.PlannerProfile, claimed.Artifact.ResourceClass, options.BuildVersion)
	if err != nil {
		return Result{}, localFailure(ClassRequestInvalid, StagePreflight, false,
			string(claimed.Artifact.PlannerProfile), string(claimed.Artifact.ResourceClass), err, nil)
	}
	defer machine.Close()
	return runPrepared(ctx, preparedInput{
		request: claimed.Request, artifact: claimed.Artifact, configuration: options.Config,
		configPath: options.ConfigPath, buildVersion: options.BuildVersion, machine: machine,
		ledger: ledger, childInput: input, childOutput: output, progress: options.Progress,
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
