//go:build c1bproof

package gatecorchestrator

import (
	"bytes"
	"context"
	"encoding/binary"
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
	LivenessClock LivenessClock
	LivenessArmed func(LivenessMemoryProofControl)
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
	if options.LivenessClock != nil {
		deps.newLivenessClock = func() LivenessClock { return options.LivenessClock }
	}
	if options.LivenessArmed != nil {
		deps.livenessProofHook = func(c *livenessController) { options.LivenessArmed(LivenessMemoryProofControl{controller: c}) }
	}
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

// LivenessMemoryProofControl exists ONLY in c1bproof binaries. It exposes fixed
// proof experiments, not raw streams, endpoints, sockets or keys.
type LivenessMemoryProofControl struct{ controller *livenessController }

func (p LivenessMemoryProofControl) RejectNormalAdmission() (LivenessWitness, error) {
	c := p.controller
	for seq := uint64(1); seq <= 5; seq++ {
		b := c.model.binding
		b.Local, b.Remote = b.Remote, b.Local
		b.Role = b.Role.Peer()
		packet, err := buildLivenessPacket(b, livenessMessage{kind: livenessPing, sequence: seq})
		if err != nil {
			return LivenessWitness{}, err
		}
		e, err := c.model.receive(packet)
		if err != nil {
			return LivenessWitness{}, err
		}
		if e != nil {
			c.model.discard(e)
		}
	}
	return c.model.snapshot(), c.permit()
}

func (p LivenessMemoryProofControl) ExceedAutomaticControl(ctx context.Context) error {
	packet := make([]byte, 32)
	binary.LittleEndian.PutUint32(packet, 4)
	for range 5 {
		if err := p.controller.gate.WritePacket(ctx, packet); err != nil {
			return err
		}
	}
	return nil
}

func (p LivenessMemoryProofControl) BypassAdmission() {
	p.controller.enqueue(&livenessEmission{packet: make([]byte, 92)})
}
func (p LivenessMemoryProofControl) ReportAfterClose() error {
	return p.controller.reportViolation(probeio.SessionAdmissionBypass)
}

// ExchangeBusiness proves exact-once bidirectional delivery on the SAME memory
// interface while the control tap and foreground controller are running. The
// fixture cannot select an address, allocate an interface or expose a raw handle.
func (p LivenessMemoryProofControl) ExchangeBusiness(ctx context.Context, peer LivenessMemoryProofControl) error {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		p.controller.end(ctx.Err())
		peer.controller.end(ctx.Err())
	})
	defer func() {
		if !stop() {
			<-done
		}
	}()
	for ordinal := range 3 {
		for _, pair := range [][2]*livenessController{{p.controller, peer.controller}, {peer.controller, p.controller}} {
			packet := make([]byte, 44)
			packet[0], packet[8], packet[9] = 0x45, 64, 17
			binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
			src, dst := pair[0].model.binding.Local.As4(), pair[0].model.binding.Remote.As4()
			copy(packet[12:16], src[:])
			copy(packet[16:20], dst[:])
			binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
			binary.BigEndian.PutUint16(packet[20:22], 32114)
			binary.BigEndian.PutUint16(packet[22:24], 32114)
			binary.BigEndian.PutUint16(packet[24:26], 24)
			copy(packet[28:], "synthetic-data")
			packet[43] = byte(ordinal + 1)
			checksum := livenessUDPChecksum(packet)
			if checksum == 0 {
				checksum = 0xffff
			}
			binary.BigEndian.PutUint16(packet[26:28], checksum)
			if n, err := pair[0].ni.InjectPacket(packet); err != nil || n != len(packet) {
				return io.ErrShortWrite
			}
			var received [1280]byte
			n, err := pair[1].ni.ReceivePacket(received[:])
			if err != nil || !bytes.Equal(received[:n], packet) {
				return errLivenessProtocol
			}
		}
	}
	return nil
}
