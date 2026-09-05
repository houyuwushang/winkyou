//go:build c1bproof

package gatecorchestrator

import (
	"context"
	"io"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
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
}

// RunMemoryProof composes the real Gate C pipeline with a tagged in-memory
// factory. It is intentionally unavailable from an ordinary wink binary.
func RunMemoryProof(ctx context.Context, options MemoryProofOptions) (Result, error) {
	wrapped := &proofSSHStream{BoundedStream: options.Stream}
	deps := defaultDependencies()
	deps.configureGateB = func(configuration *gateb.Config) {
		configuration.ProbeFactory = options.ProbeFactory
		configuration.Harness = options.Harness
	}
	deps.inspectConflict = func(context.Context, preparedInput, trustedPeer) (conflictState, error) {
		return conflictState{}, nil
	}
	deps.openSSH = func(context.Context, sshassembly.Config) (sshProductStream, error) { return wrapped, nil }
	if options.Random != nil {
		deps.random = options.Random
	}
	if options.InactiveEvery > 0 {
		deps.activityInterval = options.InactiveEvery
	}
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

type proofSSHStream struct {
	oobcarrier.BoundedStream
	mu      sync.Mutex
	witness sshassembly.Witness
}

func (stream *proofSSHStream) Close() error {
	if stream == nil || stream.BoundedStream == nil {
		return nil
	}
	err := stream.BoundedStream.Close()
	stream.mu.Lock()
	stream.witness.Spawned = true
	stream.witness.Exited = true
	stream.witness.Drained = err == nil
	stream.mu.Unlock()
	return err
}

func (stream *proofSSHStream) Witness() sshassembly.Witness {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	witness := stream.witness
	witness.Spawned = true
	return witness
}

func (*proofSSHStream) TerminalError() error { return nil }
