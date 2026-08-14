// Package diagnose builds a passive, structured first-run diagnostic report
// and its stricter shareable export form. It does not own active connectivity
// probes.
package diagnose

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"winkyou/internal/governor"
)

const SchemaVersion = "winkyou.diagnose/v1alpha1"

const UserAcknowledgedWarning = "WARNING: user-acknowledged scope is per-user/container only, is not machine-wide safety, and must not be used for background runtime, recovery, port mapping, prediction, or birthday punching."

type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type ConfigState string

const (
	ConfigReady       ConfigState = "ready"
	ConfigMissing     ConfigState = "missing"
	ConfigInvalid     ConfigState = "invalid"
	ConfigUnavailable ConfigState = "unavailable"
)

type ConfigStatus struct {
	State        ConfigState `json:"state"`
	Source       string      `json:"source"`
	ExplicitPath bool        `json:"explicit_path"`
	FilePresent  bool        `json:"file_present"`
	Detail       string      `json:"detail,omitempty"`
}

type InterfaceState string

const (
	InterfacesReady       InterfaceState = "ready"
	InterfacesPartial     InterfaceState = "partial"
	InterfacesUnavailable InterfaceState = "unavailable"
)

type InterfaceSummary struct {
	Name                 string   `json:"name"`
	Index                int      `json:"index"`
	MTU                  int      `json:"mtu"`
	Up                   bool     `json:"up"`
	Loopback             bool     `json:"loopback"`
	AddressClasses       []string `json:"address_classes,omitempty"`
	AddressesAreRedacted bool     `json:"addresses_are_redacted"`
}

type InterfaceStatus struct {
	State      InterfaceState     `json:"state"`
	Count      int                `json:"count"`
	UpCount    int                `json:"up_count"`
	Interfaces []InterfaceSummary `json:"interfaces,omitempty"`
	Detail     string             `json:"detail,omitempty"`
}

type RouteState string

const (
	RoutePresent     RouteState = "present"
	RouteAbsent      RouteState = "absent"
	RouteUnavailable RouteState = "unavailable"
)

type DefaultRouteStatus struct {
	State     RouteState `json:"state"`
	Family    string     `json:"family,omitempty"`
	Interface string     `json:"interface,omitempty"`
	Source    string     `json:"source,omitempty"`
	Detail    string     `json:"detail,omitempty"`
}

type ActiveProbeStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
	Action string `json:"action,omitempty"`
}

type ResourceLimitReport struct {
	Sockets          int `json:"sockets"`
	Targets          int `json:"targets"`
	PacketsPerSecond int `json:"packets_per_second"`
	Packets          int `json:"packets"`
	FiveTuples       int `json:"five_tuples"`
}

type GovernorLimitReport struct {
	MaxActivePeers             int                 `json:"max_active_peers"`
	MaxActiveAttempts          int                 `json:"max_active_attempts"`
	MaxAttemptsPerPeer         int                 `json:"max_attempts_per_peer"`
	MaxHeavyweightAttempts     int                 `json:"max_heavyweight_attempts"`
	MaxAttemptDurationMS       int64               `json:"max_attempt_duration_ms"`
	CancellationDrainTimeoutMS int64               `json:"cancellation_drain_timeout_ms"`
	Aggregate                  ResourceLimitReport `json:"aggregate"`
	PerAttempt                 ResourceLimitReport `json:"per_attempt"`
}

type UserAcknowledgedBoundary struct {
	ExplicitAcknowledgement bool                 `json:"explicit_acknowledgement"`
	MachineWide             bool                 `json:"machine_wide"`
	PersistentDefault       bool                 `json:"persistent_default"`
	Acquired                bool                 `json:"acquired"`
	PolicyVerified          bool                 `json:"policy_verified"`
	Released                bool                 `json:"released"`
	Profile                 governor.Profile     `json:"profile"`
	AllowedOperations       []governor.Operation `json:"allowed_operations"`
	DeniedCapabilities      []string             `json:"denied_capabilities"`
	HardLimits              GovernorLimitReport  `json:"hard_limits"`
	Warning                 string               `json:"warning"`
	Detail                  string               `json:"detail,omitempty"`
}

type Report struct {
	SchemaVersion          string                    `json:"schema_version"`
	GeneratedAt            time.Time                 `json:"generated_at"`
	Mode                   string                    `json:"mode"`
	Redaction              string                    `json:"redaction"`
	BuildVersion           string                    `json:"build_version"`
	Platform               Platform                  `json:"platform"`
	GovernorScope          governor.Scope            `json:"governor_scope"`
	Namespace              governor.NamespaceStatus  `json:"namespace"`
	MachineNamespace       *governor.NamespaceStatus `json:"machine_namespace,omitempty"`
	UserAcknowledged       *UserAcknowledgedBoundary `json:"user_acknowledged,omitempty"`
	Owner                  governor.OwnerStatus      `json:"owner"`
	SafetyTrip             governor.SafetyTripStatus `json:"safety_trip"`
	Configuration          ConfigStatus              `json:"configuration"`
	Interfaces             InterfaceStatus           `json:"interfaces"`
	DefaultRoute           DefaultRouteStatus        `json:"default_route"`
	ActiveProbe            ActiveProbeStatus         `json:"active_probe"`
	NetworkActivityStarted bool                      `json:"network_activity_started"`
}

type Options struct {
	ConfigPath    string
	GovernorScope governor.Scope
}

type RestrictedUserAuthority interface {
	Snapshot() governor.Snapshot
	Close() error
}

// Inspector dependencies are explicit so tests can prove that a missing
// machine namespace still returns every passive section.
type Inspector struct {
	Now            func() time.Time
	Namespace      func() governor.NamespaceStatus
	Owner          func() governor.OwnerStatus
	SafetyTrip     func() governor.SafetyTripStatus
	UserNamespace  func() governor.NamespaceStatus
	UserOwner      func() governor.OwnerStatus
	UserSafetyTrip func() governor.SafetyTripStatus
	AcquireUser    func(string) (RestrictedUserAuthority, error)
	Configuration  func(string) ConfigStatus
	Interfaces     func() InterfaceStatus
	DefaultRoute   func(context.Context) DefaultRouteStatus
	Platform       Platform
	BuildVersion   string
}

func SystemInspector(buildVersion string) Inspector {
	return Inspector{
		Now:            time.Now,
		Namespace:      governor.InspectMachineNamespace,
		Owner:          governor.InspectMachineOwner,
		SafetyTrip:     governor.InspectMachineSafetyTrip,
		UserNamespace:  governor.InspectUserAcknowledgedNamespace,
		UserOwner:      governor.InspectUserAcknowledgedOwner,
		UserSafetyTrip: governor.InspectUserAcknowledgedSafetyTrip,
		AcquireUser: func(buildVersion string) (RestrictedUserAuthority, error) {
			return governor.AcquireRestrictedUserGovernor(buildVersion)
		},
		Configuration: inspectConfiguration,
		Interfaces:    inspectInterfaces,
		DefaultRoute:  inspectDefaultRoute,
		Platform:      Platform{OS: runtime.GOOS, Arch: runtime.GOARCH},
		BuildVersion:  buildVersion,
	}
}

// Run always produces a report. Collector failures are represented in their
// section and never cause an active fallback.
func (inspector Inspector) Run(ctx context.Context, options Options) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now
	if inspector.Now != nil {
		now = inspector.Now
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now().UTC(),
		Mode:          "passive_only",
		Redaction:     "partial",
		BuildVersion:  firstNonEmpty(strings.TrimSpace(inspector.BuildVersion), "unknown"),
		Platform:      inspector.Platform,
		GovernorScope: governor.ScopeMachine,
	}
	if options.GovernorScope == governor.ScopeUserAcknowledged {
		report.Mode = "user_acknowledged_passive_only"
		report.GovernorScope = governor.ScopeUserAcknowledged
	}
	if report.Platform.OS == "" {
		report.Platform.OS = runtime.GOOS
	}
	if report.Platform.Arch == "" {
		report.Platform.Arch = runtime.GOARCH
	}

	if report.GovernorScope == governor.ScopeUserAcknowledged {
		inspector.collectUserAcknowledgedBoundary(&report)
	} else {
		inspector.collectMachineBoundary(&report)
	}
	if inspector.Configuration == nil {
		report.Configuration = ConfigStatus{State: ConfigUnavailable, Source: "unknown", Detail: "configuration collector unavailable"}
	} else {
		report.Configuration = inspector.Configuration(options.ConfigPath)
	}
	if inspector.Interfaces == nil {
		report.Interfaces = InterfaceStatus{State: InterfacesUnavailable, Detail: "interface collector unavailable"}
	} else {
		report.Interfaces = inspector.Interfaces()
	}
	if inspector.DefaultRoute == nil {
		report.DefaultRoute = DefaultRouteStatus{State: RouteUnavailable, Detail: "route collector unavailable"}
	} else {
		report.DefaultRoute = inspector.DefaultRoute(ctx)
	}
	report.ActiveProbe = activeProbeStatus(report)
	return report
}

func (inspector Inspector) collectMachineBoundary(report *Report) {
	if inspector.Namespace == nil {
		report.Namespace = governor.NamespaceStatus{Scope: governor.ScopeMachine, State: governor.NamespaceUnavailable, Detail: "namespace collector unavailable"}
	} else {
		report.Namespace = inspector.Namespace()
	}
	if inspector.Owner == nil {
		report.Owner = governor.OwnerStatus{Scope: governor.ScopeMachine, State: governor.OwnerUnavailable, Detail: "owner collector unavailable"}
	} else {
		report.Owner = inspector.Owner()
	}
	if inspector.SafetyTrip == nil {
		report.SafetyTrip = governor.SafetyTripStatus{State: governor.SafetyTripUnavailable, BlocksActiveWork: true, Detail: "safety trip collector unavailable"}
	} else {
		report.SafetyTrip = inspector.SafetyTrip()
	}
}

func (inspector Inspector) collectUserAcknowledgedBoundary(report *Report) {
	hard, hardErr := governor.HardLimits(governor.ProfilePhase1UserAcknowledged)
	boundary := &UserAcknowledgedBoundary{
		ExplicitAcknowledgement: true,
		MachineWide:             false,
		PersistentDefault:       false,
		Profile:                 governor.ProfilePhase1UserAcknowledged,
		AllowedOperations:       []governor.Operation{governor.OperationDiagnose, governor.OperationConnectTest},
		DeniedCapabilities: []string{
			"node_runtime",
			"automatic_recovery",
			"port_mapping",
			"prediction",
			"birthday_punch",
			"background_daemon",
			"parallel_heavyweight_attempt",
		},
		HardLimits: limitReport(hard),
		Warning:    UserAcknowledgedWarning,
	}
	if hardErr != nil {
		boundary.Detail = fmt.Sprintf("load compiled user limits: %v", hardErr)
	}

	if hardErr != nil {
		// A missing compiled profile is a build defect, so no namespace may be
		// acquired under an unknown policy.
	} else if inspector.AcquireUser == nil {
		boundary.Detail = firstNonEmpty(boundary.Detail, "restricted user authority collector unavailable")
	} else {
		authority, err := inspector.AcquireUser(report.BuildVersion)
		if err != nil {
			boundary.Detail = firstNonEmpty(boundary.Detail, err.Error())
		} else if authority == nil {
			boundary.Detail = firstNonEmpty(boundary.Detail, "restricted user authority returned nil")
		} else {
			boundary.Acquired = true
			snapshot := authority.Snapshot()
			if snapshot.Profile != governor.ProfilePhase1UserAcknowledged || snapshot.Scope != governor.ScopeUserAcknowledged {
				boundary.Detail = fmt.Sprintf("restricted authority identity mismatch: profile=%s scope=%s", snapshot.Profile, snapshot.Scope)
			} else if snapshot.Limits != hard {
				boundary.Detail = "restricted authority limits do not match the compiled user ceiling"
			} else if snapshot.Closed || snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 || snapshot.Reserved != (governor.Resources{}) {
				boundary.Detail = "restricted authority was not an idle, newly acquired capability"
			} else {
				boundary.PolicyVerified = true
			}
			if err := authority.Close(); err != nil {
				boundary.Detail = firstNonEmpty(boundary.Detail, fmt.Sprintf("release restricted user authority: %v", err))
			} else {
				boundary.Released = true
			}
		}
	}
	report.UserAcknowledged = boundary
	machine := governor.NamespaceStatus{Scope: governor.ScopeMachine, State: governor.NamespaceUnavailable, Detail: "machine namespace collector unavailable"}
	if inspector.Namespace != nil {
		machine = inspector.Namespace()
	}
	report.MachineNamespace = &machine

	if inspector.UserNamespace == nil {
		report.Namespace = governor.NamespaceStatus{Scope: governor.ScopeUserAcknowledged, State: governor.NamespaceUnavailable, Detail: "user namespace collector unavailable"}
	} else {
		report.Namespace = inspector.UserNamespace()
	}
	if inspector.UserOwner == nil {
		report.Owner = governor.OwnerStatus{Scope: governor.ScopeUserAcknowledged, State: governor.OwnerUnavailable, Detail: "user owner collector unavailable"}
	} else {
		report.Owner = inspector.UserOwner()
	}
	if inspector.UserSafetyTrip == nil {
		report.SafetyTrip = governor.SafetyTripStatus{State: governor.SafetyTripUnavailable, BlocksActiveWork: true, Detail: "user safety trip collector unavailable"}
	} else {
		report.SafetyTrip = inspector.UserSafetyTrip()
	}
}

func limitReport(limits governor.Limits) GovernorLimitReport {
	return GovernorLimitReport{
		MaxActivePeers:             limits.MaxActivePeers,
		MaxActiveAttempts:          limits.MaxActiveAttempts,
		MaxAttemptsPerPeer:         limits.MaxAttemptsPerPeer,
		MaxHeavyweightAttempts:     limits.MaxHeavyweightAttempts,
		MaxAttemptDurationMS:       limits.MaxAttemptDuration.Milliseconds(),
		CancellationDrainTimeoutMS: limits.CancellationDrainTimeout.Milliseconds(),
		Aggregate:                  resourceLimitReport(limits.Aggregate),
		PerAttempt:                 resourceLimitReport(limits.PerAttempt),
	}
}

func resourceLimitReport(resources governor.Resources) ResourceLimitReport {
	return ResourceLimitReport{
		Sockets:          resources.Sockets,
		Targets:          resources.Targets,
		PacketsPerSecond: resources.PacketsPerSecond,
		Packets:          resources.Packets,
		FiveTuples:       resources.FiveTuples,
	}
}

func activeProbeStatus(report Report) ActiveProbeStatus {
	status := ActiveProbeStatus{State: "active_probe_blocked"}
	if report.GovernorScope == governor.ScopeUserAcknowledged {
		if report.MachineNamespace != nil && report.MachineNamespace.Ready {
			status.Reason = "user_acknowledged_scope_not_needed"
			status.Detail = "the machine-wide authority is ready, so the lower per-user authority was rejected"
			status.Action = "rerun wink diagnose without --governor-scope"
			return status
		}
		if report.UserAcknowledged == nil || !report.UserAcknowledged.Acquired || !report.UserAcknowledged.PolicyVerified || !report.UserAcknowledged.Released {
			status.Reason = "user_acknowledged_scope_unavailable"
			status.Detail = "the explicitly requested per-user authority could not be safely acquired and released"
			if report.UserAcknowledged != nil && report.UserAcknowledged.Detail != "" {
				status.Detail = report.UserAcknowledged.Detail
			}
			status.Action = "install the machine scope, or review the reported per-user namespace and owner state"
			return status
		}
		if !report.Namespace.Ready {
			status.Reason = "user_acknowledged_scope_unavailable"
			status.Detail = fmt.Sprintf("user-acknowledged namespace is %s: %s", report.Namespace.State, report.Namespace.Detail)
			status.Action = "review the reported per-user namespace permissions and ownership"
			return status
		}
		if report.Owner.State != governor.OwnerIdle {
			status.Reason = "user_acknowledged_scope_unavailable"
			status.Detail = firstNonEmpty(report.Owner.Detail, fmt.Sprintf("user-acknowledged owner state is %s", report.Owner.State))
			status.Action = "stop or reuse the recorded per-user owner before retrying"
			return status
		}
		if report.SafetyTrip.BlocksActiveWork {
			status.Reason = "user_acknowledged_scope_unavailable"
			status.Detail = fmt.Sprintf("per-user safety state %s blocks active work", report.SafetyTrip.State)
			status.Action = "install machine scope; per-user reset semantics are not exposed in this slice"
			return status
		}
		status.Reason = "user_acknowledged_passive_only"
		status.Detail = "the restricted per-user authority was acquired and released; this slice still performs no STUN, coordinator, DNS, TCP, or UDP activity"
		status.Action = "active diagnostics remain unavailable until the separately reviewed probe path is installed"
		return status
	}
	if !report.Namespace.Ready {
		status.Reason = "machine_scope_not_ready"
		status.Detail = fmt.Sprintf("machine scope is %s; passive diagnostics remain available", report.Namespace.State)
		switch report.Namespace.State {
		case governor.NamespaceMissing:
			status.Action = "wink setup-machine-scope"
		case governor.NamespaceUnsafe:
			status.Action = "wink setup-machine-scope --check; review the reported path as administrator"
		default:
			status.Action = "wink setup-machine-scope --check"
		}
		return status
	}
	if report.Owner.State == governor.OwnerHeld {
		status.Reason = "machine_governor_owned"
		status.Detail = "another official WinkYou authority holds the machine scope"
		if report.Owner.Owner != nil {
			status.Detail = fmt.Sprintf("machine scope is held by pid %d (instance %s, build %s)", report.Owner.Owner.PID, report.Owner.Owner.InstanceID, report.Owner.Owner.BuildVersion)
		}
		status.Action = "reuse or stop the recorded owner before requesting an active diagnostic"
		return status
	}
	if report.Owner.State != governor.OwnerIdle {
		status.Reason = "machine_lock_unavailable"
		status.Detail = firstNonEmpty(report.Owner.Detail, "machine owner state is unavailable")
		status.Action = "wink setup-machine-scope --check"
		return status
	}
	if report.SafetyTrip.BlocksActiveWork {
		status.Reason = "machine_safety_trip"
		status.Detail = fmt.Sprintf("safety state %s blocks active work", report.SafetyTrip.State)
		status.Action = "wink safety status"
		return status
	}
	switch report.Configuration.State {
	case ConfigMissing, ConfigInvalid, ConfigUnavailable:
		status.Reason = "configuration_not_ready"
		status.Detail = fmt.Sprintf("configuration state is %s", report.Configuration.State)
		status.Action = "fix the local configuration, then run wink diagnose again"
		return status
	}
	status.Reason = "passive_only_slice"
	status.Detail = "this reviewed slice performs no STUN, coordinator, DNS, TCP, or UDP activity"
	status.Action = "active diagnostics remain unavailable until the separately reviewed probe path is installed"
	return status
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
