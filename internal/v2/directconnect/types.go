// Package directconnect composes the reviewed N2 components into the one-shot
// N3b direct connect_test attempt. It is an internal product boundary, not a
// reusable carrier or packet API.
package directconnect

import (
	"context"
	"errors"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
)

const MaxArtifactBytes = directattempt.MaxArtifactBytes

const (
	DeploymentSelfHosted   = "self_hosted"
	DeploymentMinimumTrust = "minimum_trust"
	TLSSystemRoots         = "system_roots"
	TLSSPKISHA256          = "spki_sha256"
)

const (
	StagePreflight = "preflight"
	StagePresent   = "present"
	StageBurned    = "burned"
	StageActivated = "activated"
	StageHandshake = "handshake"
	StagePrepare   = "prepare"
	StageSocket    = "socket"
	StageSTUN      = "stun"
	StageReady     = "ready"
	StageFire      = "fire"
	StagePunchSent = "punch_sent"
	StagePunch     = "punch"
	StageVerify    = "verify"
	StageTerminal  = "terminal"
)

const (
	CategoryPreflightRejected = "preflight_rejected"
	CategoryAdmissionBlocked  = "admission_blocked"
	CategoryAttemptFailed     = "attempt_failed"
	CategorySafetyTripped     = "safety_tripped"
	CategoryCancelled         = "cancelled"
)

const (
	ClassUnsupportedAttemptProfile = "unsupported_attempt_profile"
	ClassInvalidDirectArtifact     = "invalid_direct_artifact"
	ClassArtifactNotYetValid       = "direct_artifact_not_yet_valid"
	ClassArtifactExpired           = "direct_artifact_expired"
	ClassRendezvousEndpointInvalid = "rendezvous_endpoint_invalid"
	ClassSTUNEndpointInvalid       = "stun_endpoint_invalid"
	ClassRendezvousDNSFailed       = "rendezvous_dns_failed"
	ClassRendezvousDNSAmbiguous    = "rendezvous_dns_ambiguous"
	ClassRendezvousTLSFailed       = "rendezvous_tls_failed"
	ClassRendezvousUnreachable     = "rendezvous_unreachable"
	ClassPresenceTimeout           = "presence_timeout"
	ClassPairingScopeChanged       = "pairing_scope_changed"
	ClassLedgerIndeterminate       = "ledger_indeterminate"
	ClassCredentialUsed            = "credential_used"
	ClassPairingRateLimited        = "pairing_rate_limited"
	ClassPairingCircuitOpen        = "pairing_circuit_open"
	ClassActivationFailed          = "activation_failed"
	ClassSecureHandshakeFailed     = "secure_handshake_failed"
	ClassControlAuthentication     = "control_authentication_failed"
	ClassRendezvousProtocol        = "rendezvous_protocol_violation"
	ClassCarrierDomainViolation    = "carrier_domain_violation"
	ClassRendezvousBudgetExceeded  = "rendezvous_budget_exceeded"
	ClassSTUNSilent                = "stun_silent"
	ClassSTUNProtocol              = "stun_protocol_error"
	ClassSTUNSourceMismatch        = "stun_source_mismatch"
	ClassReadyRejected             = "ready_rejected"
	ClassPunchTimeout              = "punch_timeout"
	ClassDirectPacketRejected      = "direct_packet_rejected"
	ClassVerificationFailed        = "verification_failed"
	ClassPeerCancelled             = "peer_cancelled"
	ClassAttemptExpired            = "attempt_expired"
	ClassResourceBudgetExceeded    = "resource_budget_exceeded"
	ClassDrainFailed               = "drain_failed"
	ClassDirectAttemptFailed       = "direct_attempt_failed"
)

var ErrProgressDelivery = errors.New("directconnect: progress delivery failed")

// Failure is the complete stable, redacted N3b direct error data. Cause is
// retained for in-process classification and tests only and must never cross
// the JSON-RPC boundary.
type Failure struct {
	Class            string
	Stage            string
	CredentialBurned bool
	TerminalCategory string
	Cause            error
}

func (failure *Failure) Error() string {
	if failure == nil {
		return "directconnect: terminal failure"
	}
	return "directconnect: " + failure.Class
}

func (failure *Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

type ProgressReporter func(stage string, cancellable bool) error

type RendezvousConfig struct {
	Endpoint       string
	DeploymentTier string
	TLS            TLSConfig
}

type TLSConfig struct {
	Verification string
	ServerName   string
	SPKISHA256   string
}

type Config struct {
	Machine      *governor.Governor
	Ledger       *governor.PairingAdmissionLedger
	Artifact     []byte
	Rendezvous   RendezvousConfig
	STUNEndpoint string
	BuildVersion string
	Progress     ProgressReporter

	// allowLoopback is available only to same-package tests. The product entry
	// never sets it, so the exported configuration remains non-loopback only.
	allowLoopback bool
}

type Emissions struct {
	HandshakeFrames    int `json:"handshake_frames"`
	ControlFrames      int `json:"control_frames"`
	CancelFrames       int `json:"cancel_frames"`
	STUNPackets        int `json:"stun_packets"`
	DirectPackets      int `json:"direct_packets"`
	UDPPacketsTotal    int `json:"udp_packets_total"`
	CarrierFramesRead  int `json:"carrier_frames_read"`
	CarrierFramesWrite int `json:"carrier_frames_written"`
	CarrierBytesRead   int `json:"carrier_bytes_read"`
	CarrierBytesWrite  int `json:"carrier_bytes_written"`
}

type Result struct {
	AttemptKind      string                            `json:"attempt_kind"`
	Terminal         string                            `json:"terminal"`
	Bidirectional    bool                              `json:"bidirectional"`
	PromotedTerminal bool                              `json:"promoted_terminal"`
	CredentialBurned bool                              `json:"credential_burned"`
	FinishRecorded   bool                              `json:"finish_recorded"`
	Emissions        Emissions                         `json:"emissions"`
	ReservedEnvelope governor.PairingAdmissionEnvelope `json:"reserved_envelope"`
	PairingLedger    governor.PairingLedgerStatus      `json:"pairing_ledger"`
	SafetyTrip       governor.SafetyTripStatus         `json:"safety_trip"`
}

// Connect executes one bounded attempt and never retries or returns a
// transport handle. The raw artifact is cleared by the caller and is parsed
// into single-owner secret state here.
func Connect(ctx context.Context, config Config) (Result, error) {
	return connect(ctx, config)
}
