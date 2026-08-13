package solverstdio

import (
	"encoding/json"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
)

const (
	SchemaVersion  = "winkyou.stdio/v1"
	FramingVersion = "lsp-content-length/v1"
)

const (
	MethodHandshake            = "handshake"
	MethodStatus               = "status"
	MethodDiagnose             = "diagnose"
	MethodExportRedactedReport = "export_redacted_report"
	MethodConnectTest          = "connect_test"
	MethodCancel               = stdiojsonrpc.CancelMethod
)

var supportedMethods = []string{
	MethodHandshake,
	MethodStatus,
	MethodDiagnose,
	MethodExportRedactedReport,
	MethodConnectTest,
	MethodCancel,
}

func SupportedMethods() []string {
	return append([]string(nil), supportedMethods...)
}

const (
	CodeSafetyTripActive    = -32010
	CodeHandshakeRequired   = -32011
	CodeNotImplemented      = -32012
	CodeIncompatibleVersion = -32013
	CodeExportFailed        = -32014
)

const (
	ClassSafetyTripActive        = "safety_trip_active"
	ClassHandshakeRequired       = "handshake_required"
	ClassNotImplemented          = "not_implemented"
	ClassIncompatibleVersion     = "incompatible_version"
	ClassExportFailed            = "export_failed"
	ClassGovernorLockUnavailable = "governor_lock_unavailable"
)

type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

type ProtocolLimits struct {
	MaxHeaderBytes    int   `json:"max_header_bytes"`
	MaxRequestBytes   int   `json:"max_request_bytes"`
	MaxResponseBytes  int   `json:"max_response_bytes"`
	MaxConcurrent     int   `json:"max_concurrent"`
	RequestsPerSecond int   `json:"requests_per_second"`
	RateBurst         int   `json:"rate_burst"`
	DefaultDeadlineMS int64 `json:"default_deadline_ms"`
	MaxDeadlineMS     int64 `json:"max_deadline_ms"`
	ShutdownTimeoutMS int64 `json:"shutdown_timeout_ms"`
}

type ResourceLimits struct {
	Sockets          int `json:"sockets"`
	Targets          int `json:"targets"`
	PacketsPerSecond int `json:"packets_per_second"`
	Packets          int `json:"packets"`
	FiveTuples       int `json:"five_tuples"`
}

type GovernorLimits struct {
	MaxActivePeers             int            `json:"max_active_peers"`
	MaxActiveAttempts          int            `json:"max_active_attempts"`
	MaxAttemptsPerPeer         int            `json:"max_attempts_per_peer"`
	MaxHeavyweightAttempts     int            `json:"max_heavyweight_attempts"`
	MaxAttemptDurationMS       int64          `json:"max_attempt_duration_ms"`
	CancellationDrainTimeoutMS int64          `json:"cancellation_drain_timeout_ms"`
	Aggregate                  ResourceLimits `json:"aggregate"`
	PerAttempt                 ResourceLimits `json:"per_attempt"`
}

type RemainingQuota struct {
	ActivePeers         int            `json:"active_peers"`
	ActiveAttempts      int            `json:"active_attempts"`
	HeavyweightAttempts int            `json:"heavyweight_attempts"`
	Aggregate           ResourceLimits `json:"aggregate"`
}

type GovernorHandshake struct {
	Scope          governor.Scope     `json:"scope"`
	Profile        governor.Profile   `json:"profile"`
	Mode           string             `json:"mode"`
	ProxySupported bool               `json:"proxy_supported"`
	Owner          governor.OwnerInfo `json:"owner"`
	HardLimits     GovernorLimits     `json:"hard_limits"`
	Remaining      RemainingQuota     `json:"remaining"`
}

type NotificationCapability struct {
	Method                 string `json:"method"`
	BindsRequestID         bool   `json:"binds_request_id"`
	ReportsStage           bool   `json:"reports_stage"`
	ReportsRemainingBudget bool   `json:"reports_remaining_budget"`
	ReportsCancellable     bool   `json:"reports_cancellable"`
}

type HandshakeResult struct {
	SchemaVersion       string                    `json:"schema_version"`
	FramingVersion      string                    `json:"framing_version"`
	Build               BuildInfo                 `json:"build"`
	ProtocolLimits      ProtocolLimits            `json:"protocol_limits"`
	Governor            GovernorHandshake         `json:"governor"`
	AuthScope           string                    `json:"auth_scope"`
	SupportedAuthScopes []string                  `json:"supported_auth_scopes"`
	SafetyTrip          governor.SafetyTripStatus `json:"safety_trip"`
	Methods             []string                  `json:"methods"`
	Notifications       []NotificationCapability  `json:"notifications"`
}

type StatusResult struct {
	SchemaVersion          string                    `json:"schema_version"`
	GeneratedAt            time.Time                 `json:"generated_at"`
	GovernorScope          governor.Scope            `json:"governor_scope"`
	Namespace              governor.NamespaceStatus  `json:"namespace"`
	MachineNamespace       *governor.NamespaceStatus `json:"machine_namespace,omitempty"`
	Owner                  governor.OwnerStatus      `json:"owner"`
	SafetyTrip             governor.SafetyTripStatus `json:"safety_trip"`
	NetworkActivityStarted bool                      `json:"network_activity_started"`
}

type ExportResult struct {
	Written   bool   `json:"written"`
	Redaction string `json:"redaction"`
	Bytes     int64  `json:"bytes"`
}

type handshakeParams struct {
	SchemaVersion  string `json:"schema_version"`
	FramingVersion string `json:"framing_version"`
	DeadlineMS     *int64 `json:"deadline_ms,omitempty"`
}

type readParams struct {
	DeadlineMS *int64 `json:"deadline_ms,omitempty"`
}

type exportParams struct {
	Path       string `json:"path"`
	Redaction  string `json:"redaction,omitempty"`
	DeadlineMS *int64 `json:"deadline_ms,omitempty"`
}

// connectTestParams freezes the v1 envelope while implementation remains
// blocked. CompleteBundle is intentionally not decoded or reflected by this
// PR; the crypto ADR must freeze and review its exact contents first.
type connectTestParams struct {
	AuthScope      string          `json:"auth_scope"`
	CompleteBundle json.RawMessage `json:"complete_bundle"`
	DeadlineMS     *int64          `json:"deadline_ms,omitempty"`
}

func protocolLimits(limits stdiojsonrpc.Limits) ProtocolLimits {
	return ProtocolLimits{
		MaxHeaderBytes:    limits.MaxHeaderBytes,
		MaxRequestBytes:   limits.MaxRequestBytes,
		MaxResponseBytes:  limits.MaxResponseBytes,
		MaxConcurrent:     limits.MaxConcurrent,
		RequestsPerSecond: limits.RequestsPerSecond,
		RateBurst:         limits.RateBurst,
		DefaultDeadlineMS: limits.DefaultDeadline.Milliseconds(),
		MaxDeadlineMS:     limits.MaxDeadline.Milliseconds(),
		ShutdownTimeoutMS: limits.ShutdownTimeout.Milliseconds(),
	}
}

func governorLimits(limits governor.Limits) GovernorLimits {
	return GovernorLimits{
		MaxActivePeers:             limits.MaxActivePeers,
		MaxActiveAttempts:          limits.MaxActiveAttempts,
		MaxAttemptsPerPeer:         limits.MaxAttemptsPerPeer,
		MaxHeavyweightAttempts:     limits.MaxHeavyweightAttempts,
		MaxAttemptDurationMS:       limits.MaxAttemptDuration.Milliseconds(),
		CancellationDrainTimeoutMS: limits.CancellationDrainTimeout.Milliseconds(),
		Aggregate:                  resourceLimits(limits.Aggregate),
		PerAttempt:                 resourceLimits(limits.PerAttempt),
	}
}

func resourceLimits(resources governor.Resources) ResourceLimits {
	return ResourceLimits{
		Sockets:          resources.Sockets,
		Targets:          resources.Targets,
		PacketsPerSecond: resources.PacketsPerSecond,
		Packets:          resources.Packets,
		FiveTuples:       resources.FiveTuples,
	}
}

func remainingQuota(limits governor.Limits) RemainingQuota {
	return RemainingQuota{
		ActivePeers:         limits.MaxActivePeers,
		ActiveAttempts:      limits.MaxActiveAttempts,
		HeavyweightAttempts: limits.MaxHeavyweightAttempts,
		Aggregate:           resourceLimits(limits.Aggregate),
	}
}
