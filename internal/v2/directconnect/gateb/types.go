package gateb

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobcarrier"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/pkg/transport"
)

const (
	StagePreflight          = "preflight"
	StageOOBAdopt           = "oob_adopt"
	StagePresent            = "present"
	StageBurned             = "burned"
	StageActivated          = "activated"
	StageHandshake          = "handshake"
	StagePrepare            = "prepare"
	StageSockets            = "sockets"
	StageEvidence           = "fresh_evidence"
	StagePlan               = "plan_committed"
	StageReady              = "ready"
	StageFire               = "fire"
	StageCandidates         = "candidates"
	StageWinner             = "winner"
	StageVerify             = "verify"
	StageTransportLease     = "transport_lease"
	StageHandoff            = "handoff"
	StageDataPlaneChallenge = "data_plane_challenge"
	StageTerminal           = "terminal"
)

var ProgressSequence = []string{
	StagePreflight, StageOOBAdopt, StagePresent, StageBurned, StageActivated,
	StageHandshake, StagePrepare, StageSockets, StageEvidence, StagePlan,
	StageReady, StageFire, StageCandidates, StageWinner, StageVerify,
	StageTransportLease, StageHandoff, StageDataPlaneChallenge, StageTerminal,
}

const (
	ClassProfileUnsupported        = "hard_nat_profile_unsupported"
	ClassEvidenceInsufficient      = "hard_nat_evidence_insufficient"
	ClassEvidenceDrifted           = "hard_nat_evidence_drifted"
	ClassPlanMismatch              = "hard_nat_plan_mismatch"
	ClassInsufficientBudget        = "insufficient_authorized_search_budget"
	ClassCandidateExhausted        = "hard_nat_candidate_exhausted"
	ClassCampaignRateLimited       = "hard_nat_campaign_rate_limited"
	ClassCampaignCircuitOpen       = "hard_nat_campaign_circuit_open"
	ClassPacketRejected            = "hard_nat_packet_rejected"
	ClassCredentialUsed            = "credential_used"
	ClassAdmissionBlocked          = "pairing_admission_blocked"
	ClassOOBStreamInvalid          = "oob_stream_invalid"
	ClassOOBPresenceTimeout        = "oob_presence_timeout"
	ClassOOBStreamClosed           = "oob_stream_closed"
	ClassOOBProtocolViolation      = "oob_protocol_violation"
	ClassAttemptExpired            = "attempt_expired"
	ClassResourceBudgetExceeded    = "resource_budget_exceeded"
	ClassTransportLeaseUnavailable = "transport_lease_unavailable"
	ClassTransportHandoffFailed    = "transport_handoff_failed"
	ClassDataPlaneChallengeFailed  = "data_plane_challenge_failed"
	ClassDrainFailed               = "drain_failed"
)

var StableFailureClasses = []string{
	ClassProfileUnsupported, ClassEvidenceInsufficient, ClassEvidenceDrifted,
	ClassPlanMismatch, ClassInsufficientBudget, ClassCandidateExhausted,
	ClassCampaignRateLimited, ClassCampaignCircuitOpen, ClassPacketRejected,
}

type Failure struct {
	Class            string `json:"class"`
	Stage            string `json:"stage"`
	CredentialBurned bool   `json:"credential_burned"`
	Retryable        bool   `json:"retryable"`
	Cause            error  `json:"-"`
}

func (failure *Failure) Error() string {
	if failure == nil {
		return "gateb: terminal failure"
	}
	return "gateb: " + failure.Class
}
func (failure *Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

type ProgressReporter func(stage string, cancellable bool) error

// ProductStreamOpener receives the exact Gate B attempt lease and its already
// frozen absolute deadline. Gate C uses this single callback to attach the
// C1a SSH assembly to the same attempt that owns all later UDP work.
type ProductStreamOpener func(
	context.Context,
	*governor.AttemptLease,
	time.Time,
) (oobcarrier.BoundedStream, error)

const (
	ArtifactKindHardNATTest = "hard-nat-test-artifact/1"
	ArtifactKindGateC       = "gate-c-product-artifact/1"
)

// AttemptArtifact is the minimum immutable behavior Gate B needs. The
// package intentionally does not import the Gate C artifact implementation;
// only the orchestrator may inject that implementation through this boundary.
type AttemptArtifact interface {
	GateBArtifactKind() string
	GateBLocalRole() directattempt.Role
	GateBPlannerProfile() hardnatplan.Profile
	GateBResourceClass() hardnatplan.ResourceClass
	GateBLocalPlannerRole() hardnatplan.Role
	GateBPeerPlannerRole() hardnatplan.Role
	GateBOOBChannelID() string
	GateBCredentialID() string
	GateBAttemptID() string
	GateBExpiresAt() time.Time
	PairingContext() (pairingcontext.PairingContext, error)
	ContextDigest() ([32]byte, error)
	NoisePrologue() ([]byte, error)
	TakePSK() ([32]byte, error)
	Close()
}

// HarnessHooks compress deterministic simulation time and randomness. Hooks
// are accepted only together with an injected ProbeFactory; the reviewed OS
// UDP factory can never run with them.
type HarnessHooks struct {
	NoiseRandom       io.Reader
	ObservationRandom io.Reader
	Now               func() time.Time
	NewTimer          func(time.Duration) probeio.Timer
	Wait              func(context.Context, time.Duration) error
	ActiveEnvelope    time.Duration // zero uses 20s; tests may only lower it
	CandidateWindow   time.Duration // zero uses the frozen production window; tests may only lower it
}

type Config struct {
	Machine  *governor.Governor
	Ledger   *governor.PairingAdmissionLedger
	Artifact []byte
	// PreparedArtifact is accepted only by RunForProduct. Run continues to
	// parse Artifact bytes through the frozen hardnatattempt parser.
	PreparedArtifact AttemptArtifact
	Stream           oobcarrier.BoundedStream
	// OpenProductStream is required only by RunForProduct. The legacy Run path
	// continues to consume Stream directly and cannot invoke a product opener.
	OpenProductStream ProductStreamOpener
	// ExpectedPeerAddress is mandatory only for RunForProduct and represents
	// one local, operator-authorized address. No peer frame can replace it.
	ExpectedPeerAddress netip.Addr
	ObserverTopology    hardnatobserve.Topology
	BuildVersion        string
	Progress            ProgressReporter

	// ProbeFactory is an in-memory harness seam. A concrete *probeio.UDPFactory
	// is rejected here; the nil production default remains loopback-only.
	ProbeFactory probeio.Factory

	// NATLabFactory is a sealed linux+natlab capability. No ordinary build can
	// construct a value, and the factory validates the current namespace plus
	// the repository's fixed TEST-NET topology before any socket opens.
	NATLabFactory probeio.IsolatedNATLabFactory

	// HardNATLabFactory is the separately sealed Gate B3 capability. Its
	// linux+natlab implementation admits only the fixed TEST-NET peer and the
	// compiled 49152-65535 target universe.
	HardNATLabFactory probeio.HardNATCampaignNATLabFactory

	Harness *HarnessHooks
}

// ProductHandoff is an opaque, single-owner continuation returned only after
// VERIFY, production lease issuance, Promote, adoption, and standby. The raw
// promoted transport is never exposed; Transport returns the WireGuard gate.
type ProductHandoff struct {
	mu                sync.Mutex
	runtime           *runtime
	gate              *probeio.WireGuardSessionGate
	binding           ProductBinding
	establishmentDone bool
	closed            bool
}

type ProductBinding struct {
	Role          directattempt.Role
	Profile       hardnatplan.Profile
	ResourceClass hardnatplan.ResourceClass
	AttemptID     string
	ContextDigest [32]byte
}

type ProductHandoffWitness struct {
	FinishRecorded  bool
	OOBDrained      bool
	AttemptReleased bool
	Carrier         oobcarrier.Witness
	Transport       probeio.WireGuardSessionGateWitness
}

type Emissions struct {
	HandshakeFrames    int `json:"handshake_frames"`
	ControlFrames      int `json:"control_frames"`
	EvidencePackets    int `json:"evidence_packets"`
	CandidatePackets   int `json:"candidate_packets"`
	WinnerPackets      int `json:"winner_packets"`
	UDPPacketsTotal    int `json:"udp_packets_total"`
	DataPacketsRead    int `json:"data_packets_read"`
	DataPacketsWritten int `json:"data_packets_written"`
	SocketsOpened      int `json:"sockets_opened"`
	TargetsRegistered  int `json:"targets_registered"`
	FiveTuples         int `json:"five_tuples"`
	CarrierFramesRead  int `json:"carrier_frames_read"`
	CarrierFramesWrite int `json:"carrier_frames_written"`
	CarrierBytesRead   int `json:"carrier_bytes_read"`
	CarrierBytesWrite  int `json:"carrier_bytes_written"`
}

type Result struct {
	AttemptKind      string                            `json:"attempt_kind"`
	Profile          hardnatplan.Profile               `json:"profile"`
	ResourceClass    hardnatplan.ResourceClass         `json:"resource_class"`
	Terminal         string                            `json:"terminal"`
	Bidirectional    bool                              `json:"bidirectional"`
	TransportDrained bool                              `json:"transport_drained"`
	CredentialBurned bool                              `json:"credential_burned"`
	FinishRecorded   bool                              `json:"finish_recorded"`
	Conditional      bool                              `json:"conditional"`
	ProbabilityFloor uint64                            `json:"probability_floor_parts_per_trillion"`
	Emissions        Emissions                         `json:"emissions"`
	ReservedEnvelope governor.PairingAdmissionEnvelope `json:"reserved_envelope"`
	PairingLedger    governor.PairingLedgerStatus      `json:"pairing_ledger"`
	CampaignLedger   *governor.HardNATCampaignStatus   `json:"campaign_ledger,omitempty"`
	SafetyTrip       governor.SafetyTripStatus         `json:"safety_trip"`
	CarrierWitness   oobcarrier.Witness                `json:"carrier_witness"`
	TransportWitness probeio.TransportLeaseWitness     `json:"transport_witness"`
}

var (
	ErrProgressDelivery   = errors.New("gateb: progress delivery failed")
	ErrCandidateExhausted = errors.New("gateb: frozen candidate set exhausted")
)

func Run(ctx context.Context, config Config) (Result, error) { return run(ctx, config) }

// RunForProduct stops at the reviewed ownership handoff. The caller must
// complete the bounded WireGuard challenge and then either FinishAndDetach or
// Abort; abandoning the returned object would retain the attempt lease.
func RunForProduct(ctx context.Context, config Config) (*ProductHandoff, Result, error) {
	return runForProduct(ctx, config)
}

func (handoff *ProductHandoff) Binding() ProductBinding {
	if handoff == nil {
		return ProductBinding{}
	}
	return handoff.binding
}

func (handoff *ProductHandoff) Transport() transport.PacketTransport {
	if handoff == nil {
		return nil
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed {
		return nil
	}
	return handoff.gate
}

// Result returns a redacted lifecycle snapshot without changing ownership.
func (handoff *ProductHandoff) Result() Result {
	if handoff == nil {
		return Result{}
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.runtime == nil {
		return Result{}
	}
	return handoff.runtime.result()
}
