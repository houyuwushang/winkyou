package solver

import "strings"

type PathRole string

const (
	PathRolePrimaryCandidate PathRole = "primary_candidate"
	PathRoleProtectedDirect  PathRole = "protected_direct"
	PathRoleStandby          PathRole = "standby"
	PathRoleBootstrap        PathRole = "bootstrap"
)

type PathDependencyKind string

const (
	PathDependencyNone        PathDependencyKind = "none"
	PathDependencyCoordinator PathDependencyKind = "coordinator"
	PathDependencyRelay       PathDependencyKind = "relay"
	PathDependencyPeer        PathDependencyKind = "peer"
	PathDependencyUnknown     PathDependencyKind = "unknown"
)

type PathPolicy struct {
	MultipathEnabled      bool
	ProtectDirect         bool
	MaxPaths              int
	ShadowWrite           bool
	DependencyPenalty     int
	DirectProtectionBonus int
}

type PathDependency struct {
	Kind   PathDependencyKind
	NodeID string
	Reason string
}

func IsDirectPath(summary PathSummary) bool {
	return strings.EqualFold(summary.ConnectionType, "direct") ||
		summary.Role == PathRoleProtectedDirect
}

func IsRelayPath(summary PathSummary) bool {
	if strings.EqualFold(summary.ConnectionType, "relay") {
		return true
	}
	return HasDependency(summary, PathDependencyRelay)
}

func HasDependency(summary PathSummary, kind PathDependencyKind) bool {
	if kind == PathDependencyNone && len(summary.Dependencies) == 0 {
		return true
	}
	for _, dependency := range summary.Dependencies {
		if dependency.Kind == kind {
			return true
		}
	}
	return false
}

func ClonePathSummary(summary PathSummary) PathSummary {
	clone := summary
	if summary.Details != nil {
		clone.Details = make(map[string]string, len(summary.Details))
		for key, value := range summary.Details {
			clone.Details[key] = value
		}
	}
	if summary.Metrics != nil {
		clone.Metrics = make(map[string]string, len(summary.Metrics))
		for key, value := range summary.Metrics {
			clone.Metrics[key] = value
		}
	}
	if summary.Dependencies != nil {
		clone.Dependencies = append([]PathDependency(nil), summary.Dependencies...)
	}
	return clone
}
