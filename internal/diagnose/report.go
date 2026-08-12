// Package diagnose builds a passive, structured first-run diagnostic report.
// It does not own active connectivity probes or the separately planned
// redacted-report export format.
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

type Report struct {
	SchemaVersion          string                    `json:"schema_version"`
	GeneratedAt            time.Time                 `json:"generated_at"`
	Mode                   string                    `json:"mode"`
	Redaction              string                    `json:"redaction"`
	BuildVersion           string                    `json:"build_version"`
	Platform               Platform                  `json:"platform"`
	GovernorScope          governor.Scope            `json:"governor_scope"`
	Namespace              governor.NamespaceStatus  `json:"namespace"`
	Owner                  governor.OwnerStatus      `json:"owner"`
	SafetyTrip             governor.SafetyTripStatus `json:"safety_trip"`
	Configuration          ConfigStatus              `json:"configuration"`
	Interfaces             InterfaceStatus           `json:"interfaces"`
	DefaultRoute           DefaultRouteStatus        `json:"default_route"`
	ActiveProbe            ActiveProbeStatus         `json:"active_probe"`
	NetworkActivityStarted bool                      `json:"network_activity_started"`
}

type Options struct {
	ConfigPath string
}

// Inspector dependencies are explicit so tests can prove that a missing
// machine namespace still returns every passive section.
type Inspector struct {
	Now           func() time.Time
	Namespace     func() governor.NamespaceStatus
	Owner         func() governor.OwnerStatus
	SafetyTrip    func() governor.SafetyTripStatus
	Configuration func(string) ConfigStatus
	Interfaces    func() InterfaceStatus
	DefaultRoute  func(context.Context) DefaultRouteStatus
	Platform      Platform
	BuildVersion  string
}

func SystemInspector(buildVersion string) Inspector {
	return Inspector{
		Now:           time.Now,
		Namespace:     governor.InspectMachineNamespace,
		Owner:         governor.InspectMachineOwner,
		SafetyTrip:    governor.InspectMachineSafetyTrip,
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
	if report.Platform.OS == "" {
		report.Platform.OS = runtime.GOOS
	}
	if report.Platform.Arch == "" {
		report.Platform.Arch = runtime.GOARCH
	}

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

func activeProbeStatus(report Report) ActiveProbeStatus {
	status := ActiveProbeStatus{State: "active_probe_blocked"}
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
