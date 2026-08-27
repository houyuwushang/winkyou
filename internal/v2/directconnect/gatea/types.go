package gatea

import (
	"context"
	"errors"
	"net/netip"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/oobcarrier"
)

const (
	StagePreflight          = "preflight"
	StageOOBAdopt           = "oob_adopt"
	StagePresent            = "present"
	StageBurned             = "burned"
	StageActivated          = "activated"
	StageHandshake          = "handshake"
	StagePrepare            = "prepare"
	StageSocket             = "socket"
	StageSTUN               = "stun"
	StageReady              = "ready"
	StageFire               = "fire"
	StagePunchSent          = "punch_sent"
	StagePunch              = "punch"
	StageVerify             = "verify"
	StageTransportLease     = "transport_lease"
	StageHandoff            = "handoff"
	StageDataPlaneChallenge = "data_plane_challenge"
	StageTerminal           = "terminal"
)

var ProgressSequence = []string{
	StagePreflight, StageOOBAdopt, StagePresent, StageBurned, StageActivated,
	StageHandshake, StagePrepare, StageSocket, StageSTUN, StageReady, StageFire,
	StagePunchSent, StagePunch, StageVerify, StageTransportLease, StageHandoff,
	StageDataPlaneChallenge, StageTerminal,
}

const (
	ClassOOBStreamInvalid          = "oob_stream_invalid"
	ClassOOBPresenceTimeout        = "oob_presence_timeout"
	ClassOOBStreamClosed           = "oob_stream_closed"
	ClassOOBProtocolViolation      = "oob_protocol_violation"
	ClassMappingNotDirectlyUsable  = "mapping_not_directly_usable"
	ClassTransportLeaseUnavailable = "transport_lease_unavailable"
	ClassTransportHandoffFailed    = "transport_handoff_failed"
	ClassDataPlaneChallengeFailed  = "data_plane_challenge_failed"

	ClassCredentialUsed         = "credential_used"
	ClassAdmissionBlocked       = "pairing_admission_blocked"
	ClassSTUNSilent             = "stun_silent"
	ClassSTUNProtocol           = "stun_protocol_error"
	ClassSTUNSourceMismatch     = "stun_source_mismatch"
	ClassDirectPacketRejected   = "direct_packet_rejected"
	ClassAttemptExpired         = "attempt_expired"
	ClassResourceBudgetExceeded = "resource_budget_exceeded"
	ClassDrainFailed            = "drain_failed"
)

// StableGateAFailureClasses is the frozen Gate A additive error set.
var StableGateAFailureClasses = []string{
	ClassOOBStreamInvalid,
	ClassOOBPresenceTimeout,
	ClassOOBStreamClosed,
	ClassOOBProtocolViolation,
	ClassMappingNotDirectlyUsable,
	ClassTransportLeaseUnavailable,
	ClassTransportHandoffFailed,
	ClassDataPlaneChallengeFailed,
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
		return "gatea: terminal failure"
	}
	return "gatea: " + failure.Class
}

func (failure *Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

type ProgressReporter func(stage string, cancellable bool) error

type Config struct {
	Machine          *governor.Governor
	Ledger           *governor.PairingAdmissionLedger
	Artifact         []byte
	Stream           oobcarrier.BoundedStream
	STUNTargets      []netip.AddrPort
	AllowNonLoopback bool
	BuildVersion     string
	Progress         ProgressReporter

	// ProbeFactory is a simulation harness seam. When nil, Gate A constructs
	// the reviewed probeio UDP factory. Architecture gates prevent this
	// disconnected package from becoming a product-injectable executor.
	ProbeFactory probeio.Factory
}

type Emissions struct {
	HandshakeFrames    int `json:"handshake_frames"`
	ControlFrames      int `json:"control_frames"`
	STUNPackets        int `json:"stun_packets"`
	DirectPackets      int `json:"direct_packets"`
	UDPPacketsTotal    int `json:"udp_packets_total"`
	DataPacketsRead    int `json:"data_packets_read"`
	DataPacketsWritten int `json:"data_packets_written"`
	CarrierFramesRead  int `json:"carrier_frames_read"`
	CarrierFramesWrite int `json:"carrier_frames_written"`
	CarrierBytesRead   int `json:"carrier_bytes_read"`
	CarrierBytesWrite  int `json:"carrier_bytes_written"`
}

type Result struct {
	AttemptKind      string                            `json:"attempt_kind"`
	Terminal         string                            `json:"terminal"`
	Bidirectional    bool                              `json:"bidirectional"`
	TransportDrained bool                              `json:"transport_drained"`
	CredentialBurned bool                              `json:"credential_burned"`
	FinishRecorded   bool                              `json:"finish_recorded"`
	MappingBehavior  string                            `json:"mapping_behavior"`
	Emissions        Emissions                         `json:"emissions"`
	ReservedEnvelope governor.PairingAdmissionEnvelope `json:"reserved_envelope"`
	PairingLedger    governor.PairingLedgerStatus      `json:"pairing_ledger"`
	SafetyTrip       governor.SafetyTripStatus         `json:"safety_trip"`
	CarrierWitness   oobcarrier.Witness                `json:"carrier_witness"`
	TransportWitness probeio.TransportLeaseWitness     `json:"transport_witness"`
}

var ErrProgressDelivery = errors.New("gatea: progress delivery failed")

func Run(ctx context.Context, config Config) (Result, error) { return run(ctx, config) }
