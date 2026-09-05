//go:build c1bproof

package gatecorchestrator

import (
	"context"
	"io"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/gatecstage"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/sshassembly"
	"winkyou/pkg/config"
)

// MemoryProofOptions exists only in c1bproof-tagged test binaries. It cannot
// grant an ordinary product build a network factory or bypass the local
// request/artifact/config validations exercised by runPrepared.
type MemoryProofOptions struct {
	Request       gatecrequest.Request
	Artifact      *gatecattempt.Artifact
	Config        *config.Config
	Machine       *governor.Governor
	Ledger        *governor.PairingAdmissionLedger
	SSHAuthority  sshassembly.SSHEndpointAuthority
	Stream        oobcarrier.BoundedStream
	ProbeFactory  probeio.Factory
	Harness       *gateb.HarnessHooks
	BuildVersion  string
	Progress      ProgressReporter
	Random        io.Reader
	InactiveEvery time.Duration
	StageRoot     string
}

// RunMemoryProof composes the real Gate C pipeline with a tagged in-memory
// factory. It is intentionally unavailable from an ordinary wink binary.
func RunMemoryProof(ctx context.Context, options MemoryProofOptions) (Result, error) {
	deps := memoryProofDependencies(options)
	stream := options.Stream
	if options.Request.Role == gatecattempt.RoleInitiator {
		stream = nil
	}
	return runPrepared(ctx, preparedInput{
		request: options.Request, artifact: options.Artifact, configuration: options.Config,
		buildVersion: options.BuildVersion, machine: options.Machine, ledger: options.Ledger,
		sshAuthority: options.SSHAuthority, stream: stream, progress: options.Progress,
	}, deps)
}

// RunMemoryInitiator and RunMemoryResponder use the real entry parsers and
// durable responder slot, replacing only the isolated owner/factory/runner.
func RunMemoryInitiator(ctx context.Context, entry InitiatorOptions, proof MemoryProofOptions) (Result, error) {
	return runInitiator(ctx, entry, memoryProofDependencies(proof))
}
func RunMemoryResponder(ctx context.Context, input io.Reader, output io.Writer, entry ResponderOptions, proof MemoryProofOptions) (Result, error) {
	return runResponderStdio(ctx, input, output, entry, memoryProofDependencies(proof))
}

func memoryProofDependencies(options MemoryProofOptions) dependencies {
	deps := defaultDependencies()
	if options.Harness != nil && options.Harness.Now != nil {
		deps.artifactNow = options.Harness.Now
	}
	deps.inspectMachine = func() error {
		if options.Machine == nil || options.Ledger == nil || options.Machine.Snapshot().SafetyTrip.BlocksActiveWork {
			return ErrRequestInvalid
		}
		return nil
	}
	deps.acquireMachine = func(hardnatplan.Profile, hardnatplan.ResourceClass, string) (*governor.Governor, *governor.PairingAdmissionLedger, error) {
		if options.Machine == nil || options.Ledger == nil {
			return nil, nil, ErrRequestInvalid
		}
		return options.Machine, options.Ledger, nil
	}
	deps.claimPending = func(now time.Time) (*gatecstage.Claimed, error) {
		return gatecstage.ClaimMemoryProof(options.StageRoot, now)
	}
	deps.configureGateB = func(configuration *gateb.Config) {
		configuration.ProbeFactory = options.ProbeFactory
		configuration.Harness = options.Harness
	}
	deps.inspectConflict = func(context.Context, preparedInput, trustedPeer) (conflictState, error) {
		return conflictState{}, nil
	}
	deps.openSSH = func(ctx context.Context, configuration sshassembly.Config) (sshProductStream, error) {
		return sshassembly.OpenMemoryProofClient(ctx, configuration, options.Stream)
	}
	if options.Random != nil {
		deps.random = options.Random
	}
	if options.InactiveEvery > 0 {
		deps.activityInterval = options.InactiveEvery
	}
	return deps
}
