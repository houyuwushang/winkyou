package diagnose

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/pkg/solver"
)

const (
	MaxActiveSTUNTargets = 3

	ActiveSTUNDisclosure = "WARNING: active STUN sends bounded UDP Binding requests to the listed targets and exposes your source IP address and observation timing to those targets."

	ActiveSTUNStateCompleted         = "completed"
	ActiveSTUNStateCompletedWithErrs = "completed_with_errors"
	ActiveSTUNStateBlocked           = "blocked"
)

var (
	ErrActiveSTUNInvalidRequest = errors.New("diagnose: invalid active STUN request")
	ErrActiveSTUNAuthority      = errors.New("diagnose: active STUN authority unavailable")
	ErrActiveSTUNBudget         = errors.New("diagnose: active STUN worst-case budget rejected")
	ErrActiveSTUNSafetyTrip     = errors.New("diagnose: active STUN blocked by safety trip")
)

// ActiveSTUNReport is present only when the CLI receives at least one explicit
// --active-stun target. Its results are time-windowed observations, never a
// permanent NAT classification.
type ActiveSTUNReport struct {
	State                     string                   `json:"state"`
	ErrorClass                string                   `json:"error_class,omitempty"`
	Reason                    string                   `json:"reason,omitempty"`
	ObservationScope          string                   `json:"observation_scope"`
	TargetCount               int                      `json:"target_count"`
	WorstCaseDurationMS       int64                    `json:"worst_case_duration_ms"`
	WorstCasePackets          int                      `json:"worst_case_packets"`
	MaxTransmissionsPerTarget int                      `json:"max_transmissions_per_target"`
	Results                   []ActiveSTUNTargetReport `json:"results,omitempty"`
	MappingBehavior           *MappingBehaviorReport   `json:"mapping_behavior,omitempty"`
	PortAllocation            *PortAllocationReport    `json:"port_allocation,omitempty"`
	NetworkActivityStarted    bool                     `json:"-"`
}

// MappingBehaviorReport is emitted only for the explicit --map-behavior
// mode. Limitations and per-target results are kept beside the behavior so a
// consumer cannot accidentally detach the classification from its evidence.
type MappingBehaviorReport struct {
	Behavior          stunobserve.MappingBehavior      `json:"behavior"`
	EvidenceScope     stunobserve.MappingEvidenceScope `json:"evidence_scope"`
	Limitations       []stunobserve.MappingLimitation  `json:"limitations"`
	SuccessfulTargets int                              `json:"successful_targets"`
	Results           []ActiveSTUNTargetReport         `json:"results"`
}

// PortAllocationReport is emitted only for --port-allocation. The enum,
// signed deltas, limitations, and per-socket evidence remain one object so the
// bounded sample cannot be mistaken for a permanent NAT property.
type PortAllocationReport struct {
	Behavior          stunobserve.AllocationBehavior      `json:"behavior"`
	EvidenceScope     stunobserve.AllocationEvidenceScope `json:"evidence_scope"`
	Limitations       []stunobserve.AllocationLimitation  `json:"limitations"`
	SuccessfulSockets int                                 `json:"successful_sockets"`
	TotalSockets      int                                 `json:"total_sockets"`
	Deltas            []int                               `json:"deltas"`
	Results           []PortAllocationSocketReport        `json:"results"`
}

type PortAllocationSocketReport struct {
	LocalAddress     string `json:"local_address,omitempty"`
	LocalPrefix      string `json:"local_prefix,omitempty"`
	Target           string `json:"target,omitempty"`
	TargetPrefix     string `json:"target_prefix,omitempty"`
	MappedAddress    string `json:"mapped_address,omitempty"`
	MappedPrefix     string `json:"mapped_prefix,omitempty"`
	PortBehavior     string `json:"port_behavior"`
	ErrorClass       string `json:"error_class,omitempty"`
	Reason           string `json:"reason,omitempty"`
	DurationMS       int64  `json:"duration_ms"`
	Transmissions    int    `json:"transmissions"`
	ObservationScope string `json:"observation_scope"`
}

type ActiveSTUNTargetReport struct {
	Target           string `json:"target,omitempty"`
	TargetPrefix     string `json:"target_prefix,omitempty"`
	MappedAddress    string `json:"mapped_address,omitempty"`
	MappedPrefix     string `json:"mapped_prefix,omitempty"`
	PortBehavior     string `json:"port_behavior"`
	ErrorClass       string `json:"error_class,omitempty"`
	Reason           string `json:"reason,omitempty"`
	DurationMS       int64  `json:"duration_ms"`
	Transmissions    int    `json:"transmissions"`
	ObservationScope string `json:"observation_scope"`
}

type ActiveSTUNOptions struct {
	Targets               []netip.AddrPort
	GovernorScope         governor.Scope
	MapBehavior           bool
	PortAllocationSockets int
}

// ActiveSTUNAuthority is the narrow authority surface used by the explicit
// diagnostic. It deliberately cannot select arbitrary governor operations.
type ActiveSTUNAuthority interface {
	Snapshot() governor.Snapshot
	AcquireDiagnosticPeer(string) (ActiveSTUNPeer, error)
	Close() error
}

type ActiveSTUNPeer interface {
	AcquireDiagnosticAttempt(context.Context, string, governor.AttemptCost) (probeio.AttemptLease, error)
	Close() error
}

type ActiveSTUNObserver interface {
	Observe(context.Context, netip.AddrPort) (solver.Observation, error)
	Close() error
}

type ActiveSTUNMappingObserver interface {
	Observe(context.Context, []netip.AddrPort) (stunobserve.MappingObservation, error)
	Close() error
}

type ActiveSTUNAllocationObserver interface {
	Observe(context.Context, netip.AddrPort) (stunobserve.AllocationObservation, error)
	Close() error
}

// ActiveSTUNInspector has explicit dependencies so tests can prove preflight
// rejection without constructing a socket and can exercise the real loopback
// adapter without acquiring a host-wide namespace.
type ActiveSTUNInspector struct {
	Now                func() time.Time
	AcquireMachine     func(string) (ActiveSTUNAuthority, error)
	AcquireUser        func(string) (ActiveSTUNAuthority, error)
	Factory            func(netip.AddrPort) (probeio.Factory, error)
	Observer           func(stunobserve.Config) (ActiveSTUNObserver, error)
	MappingObserver    func(stunobserve.Config, int) (ActiveSTUNMappingObserver, error)
	AllocationObserver func(stunobserve.Config, int) (ActiveSTUNAllocationObserver, error)
	BuildVersion       string
}

func SystemActiveSTUNInspector(buildVersion string) ActiveSTUNInspector {
	return ActiveSTUNInspector{
		Now:            time.Now,
		AcquireMachine: acquireMachineActiveSTUNAuthority,
		AcquireUser: func(build string) (ActiveSTUNAuthority, error) {
			authority, err := acquireRestrictedUserAuthority(build)
			if err != nil {
				return nil, err
			}
			return restrictedActiveSTUNAuthority{authority: authority}, nil
		},
		Factory:  activeSTUNUDPFactory,
		Observer: func(config stunobserve.Config) (ActiveSTUNObserver, error) { return stunobserve.New(config) },
		MappingObserver: func(config stunobserve.Config, targetCount int) (ActiveSTUNMappingObserver, error) {
			return stunobserve.NewMapping(config, targetCount)
		},
		AllocationObserver: func(config stunobserve.Config, socketCount int) (ActiveSTUNAllocationObserver, error) {
			return stunobserve.NewAllocation(config, socketCount)
		},
		BuildVersion: buildVersion,
	}
}

func (inspector ActiveSTUNInspector) Run(ctx context.Context, options ActiveSTUNOptions) (ActiveSTUNReport, error) {
	report := ActiveSTUNReport{
		State:                     ActiveSTUNStateBlocked,
		ObservationScope:          "time_window_only",
		TargetCount:               len(options.Targets),
		MaxTransmissionsPerTarget: stunobserve.MaxTransmissions,
	}
	if ctx == nil {
		return blockActiveSTUN(report, "invalid_request", "nil_context", ErrActiveSTUNInvalidRequest)
	}
	targets, err := canonicalActiveSTUNTargets(options.Targets)
	if err != nil {
		return blockActiveSTUN(report, "invalid_request", "invalid_target_list", err)
	}
	if options.MapBehavior && options.PortAllocationSockets != 0 {
		return blockActiveSTUN(report, "invalid_request", "active_stun_modes_conflict", fmt.Errorf("%w: --map-behavior and --port-allocation are mutually exclusive", ErrActiveSTUNInvalidRequest))
	}
	cost := stunobserve.WorstCaseCost()
	attemptCount := len(targets)
	if options.MapBehavior {
		if err := ValidateMappingBehaviorTargets(targets); err != nil {
			return blockActiveSTUN(report, "invalid_request", "invalid_mapping_target_list", err)
		}
		cost, err = stunobserve.MappingWorstCaseCost(len(targets))
		if err != nil {
			return blockActiveSTUN(report, "invalid_request", "invalid_mapping_target_list", errors.Join(ErrActiveSTUNInvalidRequest, err))
		}
		attemptCount = 1
		report.MappingBehavior = emptyMappingBehaviorReport(targets)
	}
	if options.PortAllocationSockets != 0 {
		if err := ValidatePortAllocationRequest(targets, options.PortAllocationSockets); err != nil {
			return blockActiveSTUN(report, "invalid_request", "invalid_port_allocation_request", err)
		}
		cost, err = stunobserve.AllocationWorstCaseCost(options.PortAllocationSockets)
		if err != nil {
			return blockActiveSTUN(report, "invalid_request", "invalid_port_allocation_request", errors.Join(ErrActiveSTUNInvalidRequest, err))
		}
		attemptCount = 1
		report.PortAllocation = emptyPortAllocationReport(targets[0], options.PortAllocationSockets)
	}
	report.WorstCaseDurationMS = (cost.Duration * time.Duration(attemptCount)).Milliseconds()
	report.WorstCasePackets = cost.Resources.Packets * attemptCount
	if inspector.Now == nil {
		inspector.Now = time.Now
	}
	if inspector.Factory == nil {
		inspector.Factory = activeSTUNUDPFactory
	}
	if inspector.Observer == nil {
		inspector.Observer = func(config stunobserve.Config) (ActiveSTUNObserver, error) { return stunobserve.New(config) }
	}
	if inspector.MappingObserver == nil {
		inspector.MappingObserver = func(config stunobserve.Config, targetCount int) (ActiveSTUNMappingObserver, error) {
			return stunobserve.NewMapping(config, targetCount)
		}
	}
	if inspector.AllocationObserver == nil {
		inspector.AllocationObserver = func(config stunobserve.Config, socketCount int) (ActiveSTUNAllocationObserver, error) {
			return stunobserve.NewAllocation(config, socketCount)
		}
	}
	build := firstNonEmpty(strings.TrimSpace(inspector.BuildVersion), "unknown")

	var acquire func(string) (ActiveSTUNAuthority, error)
	switch options.GovernorScope {
	case governor.ScopeMachine:
		acquire = inspector.AcquireMachine
	case governor.ScopeUserAcknowledged:
		acquire = inspector.AcquireUser
	default:
		return blockActiveSTUN(report, "invalid_request", "invalid_governor_scope", fmt.Errorf("%w: unsupported governor scope %q", ErrActiveSTUNInvalidRequest, options.GovernorScope))
	}
	if acquire == nil {
		return blockActiveSTUN(report, "authority_unavailable", "authority_collector_unavailable", ErrActiveSTUNAuthority)
	}
	authority, err := acquire(build)
	if err != nil {
		return blockActiveSTUN(report, "authority_unavailable", "governor_lock_unavailable", fmt.Errorf("%w: %v", ErrActiveSTUNAuthority, err))
	}
	if authority == nil {
		return blockActiveSTUN(report, "authority_unavailable", "nil_authority", ErrActiveSTUNAuthority)
	}
	closeAuthority := true
	defer func() {
		if closeAuthority {
			_ = authority.Close()
		}
	}()
	if err := preflightActiveSTUN(authority.Snapshot(), options.GovernorScope, attemptCount, cost); err != nil {
		if errors.Is(err, ErrActiveSTUNSafetyTrip) {
			return blockActiveSTUN(report, "safety_trip", "safety_trip_blocks_active_work", err)
		}
		if errors.Is(err, ErrActiveSTUNAuthority) {
			return blockActiveSTUN(report, "authority_unavailable", "authority_not_idle", err)
		}
		return blockActiveSTUN(report, "budget_rejected", "worst_case_budget_unavailable", err)
	}
	runCtx, cancelRun := context.WithTimeout(ctx, cost.Duration*time.Duration(attemptCount))
	defer cancelRun()

	peer, err := authority.AcquireDiagnosticPeer("diagnose-active-stun")
	if err != nil {
		return blockActiveSTUN(report, "authority_unavailable", "peer_lease_unavailable", fmt.Errorf("%w: %v", ErrActiveSTUNAuthority, err))
	}
	if peer == nil {
		return blockActiveSTUN(report, "authority_unavailable", "nil_peer_lease", ErrActiveSTUNAuthority)
	}
	closePeer := true
	defer func() {
		if closePeer {
			_ = peer.Close()
		}
	}()

	if options.MapBehavior {
		return inspector.runMappingBehavior(runCtx, targets, cost, build, report, peer, authority, &closePeer, &closeAuthority)
	}
	if options.PortAllocationSockets != 0 {
		return inspector.runPortAllocation(runCtx, targets[0], options.PortAllocationSockets, cost, build, report, peer, authority, &closePeer, &closeAuthority)
	}

	report.Results = make([]ActiveSTUNTargetReport, 0, len(targets))
	for index, target := range targets {
		if err := runCtx.Err(); err != nil {
			class, reason := activeSTUNContextFailure(err)
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, class, reason, err)
		}
		attemptID := fmt.Sprintf("diagnose-active-stun-%d", index+1)
		lease, err := peer.AcquireDiagnosticAttempt(runCtx, attemptID, cost)
		if err != nil {
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, "budget_rejected", "attempt_lease_unavailable", err)
		}
		if lease == nil {
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, "authority_unavailable", "nil_attempt_lease", ErrActiveSTUNAuthority)
		}
		factory, err := inspector.Factory(target)
		if err != nil {
			_ = lease.Close()
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, "io_error", "udp_factory_unavailable", err)
		}
		if factory == nil {
			_ = lease.Close()
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, "io_error", "nil_udp_factory", ErrActiveSTUNInvalidRequest)
		}
		generation := probeio.NewGeneration(1)
		observer, err := inspector.Observer(stunobserve.Config{
			Lease:              lease,
			Generation:         generation,
			ExpectedGeneration: 1,
			Factory:            factory,
			BuildVersion:       build,
			AllowNonLoopback:   true,
		})
		if err != nil {
			_ = lease.Close()
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, "io_error", "observer_unavailable", err)
		}
		if observer == nil {
			_ = lease.Close()
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, "io_error", "nil_observer", ErrActiveSTUNInvalidRequest)
		}
		started := inspector.Now()
		report.NetworkActivityStarted = true
		observation, observeErr := observer.Observe(runCtx, target)
		closeErr := observer.Close()
		result := activeSTUNTargetResult(target, observation, inspector.Now().Sub(started), observeErr)
		if closeErr != nil {
			result.ErrorClass = stunobserve.ErrorClassIO
			result.Reason = "probe_cleanup_failed"
			report.Results = append(report.Results, result)
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, stunobserve.ErrorClassIO, "probe_cleanup_failed", closeErr)
		}
		report.Results = append(report.Results, result)
		if err := runCtx.Err(); err != nil {
			class, reason := activeSTUNContextFailure(err)
			return finishActiveSTUNWithSystemError(report, peer, authority, &closePeer, &closeAuthority, class, reason, err)
		}
	}

	return completeActiveSTUN(report, peer, authority, &closePeer, &closeAuthority)
}

func (inspector ActiveSTUNInspector) runPortAllocation(
	ctx context.Context,
	target netip.AddrPort,
	socketCount int,
	cost governor.AttemptCost,
	build string,
	report ActiveSTUNReport,
	peer ActiveSTUNPeer,
	authority ActiveSTUNAuthority,
	closePeer, closeAuthority *bool,
) (ActiveSTUNReport, error) {
	if err := ctx.Err(); err != nil {
		class, reason := activeSTUNContextFailure(err)
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, class, reason, err)
	}
	lease, err := peer.AcquireDiagnosticAttempt(ctx, "diagnose-active-stun-port-allocation", cost)
	if err != nil {
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "budget_rejected", "attempt_lease_unavailable", err)
	}
	if lease == nil {
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "authority_unavailable", "nil_attempt_lease", ErrActiveSTUNAuthority)
	}
	factory, err := inspector.Factory(target)
	if err != nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "udp_factory_unavailable", err)
	}
	if factory == nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "nil_udp_factory", ErrActiveSTUNInvalidRequest)
	}
	observer, err := inspector.AllocationObserver(stunobserve.Config{
		Lease:              lease,
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       build,
		AllowNonLoopback:   true,
	}, socketCount)
	if err != nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "allocation_observer_unavailable", err)
	}
	if observer == nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "nil_allocation_observer", ErrActiveSTUNInvalidRequest)
	}

	report.NetworkActivityStarted = true
	allocation, observeErr := observer.Observe(ctx, target)
	report.PortAllocation = portAllocationReport(allocation, target, socketCount)
	closeErr := observer.Close()
	if observeErr != nil || closeErr != nil {
		class := stunobserve.ErrorClassIO
		reason := "port_allocation_observation_failed"
		if closeErr != nil {
			reason = "probe_cleanup_failed"
		}
		if err := ctx.Err(); err != nil {
			class, reason = activeSTUNContextFailure(err)
		}
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, class, reason, errors.Join(observeErr, closeErr))
	}
	return completeActiveSTUN(report, peer, authority, closePeer, closeAuthority)
}

func (inspector ActiveSTUNInspector) runMappingBehavior(
	ctx context.Context,
	targets []netip.AddrPort,
	cost governor.AttemptCost,
	build string,
	report ActiveSTUNReport,
	peer ActiveSTUNPeer,
	authority ActiveSTUNAuthority,
	closePeer, closeAuthority *bool,
) (ActiveSTUNReport, error) {
	if err := ctx.Err(); err != nil {
		class, reason := activeSTUNContextFailure(err)
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, class, reason, err)
	}
	lease, err := peer.AcquireDiagnosticAttempt(ctx, "diagnose-active-stun-mapping", cost)
	if err != nil {
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "budget_rejected", "attempt_lease_unavailable", err)
	}
	if lease == nil {
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "authority_unavailable", "nil_attempt_lease", ErrActiveSTUNAuthority)
	}
	factory, err := inspector.Factory(targets[0])
	if err != nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "udp_factory_unavailable", err)
	}
	if factory == nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "nil_udp_factory", ErrActiveSTUNInvalidRequest)
	}
	observer, err := inspector.MappingObserver(stunobserve.Config{
		Lease:              lease,
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       build,
		AllowNonLoopback:   true,
	}, len(targets))
	if err != nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "mapping_observer_unavailable", err)
	}
	if observer == nil {
		_ = lease.Close()
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, "io_error", "nil_mapping_observer", ErrActiveSTUNInvalidRequest)
	}

	report.NetworkActivityStarted = true
	mapping, observeErr := observer.Observe(ctx, targets)
	report.MappingBehavior = mappingBehaviorReportForTargets(mapping, targets)
	closeErr := observer.Close()
	if observeErr != nil || closeErr != nil {
		class := stunobserve.ErrorClassIO
		reason := "mapping_observation_failed"
		if closeErr != nil {
			reason = "probe_cleanup_failed"
		}
		if err := ctx.Err(); err != nil {
			class, reason = activeSTUNContextFailure(err)
		}
		return finishActiveSTUNWithSystemError(report, peer, authority, closePeer, closeAuthority, class, reason, errors.Join(observeErr, closeErr))
	}
	return completeActiveSTUN(report, peer, authority, closePeer, closeAuthority)
}

func completeActiveSTUN(report ActiveSTUNReport, peer ActiveSTUNPeer, authority ActiveSTUNAuthority, closePeer, closeAuthority *bool) (ActiveSTUNReport, error) {
	peerErr := peer.Close()
	*closePeer = false
	authorityErr := authority.Close()
	*closeAuthority = false
	if err := errors.Join(peerErr, authorityErr); err != nil {
		report.State = ActiveSTUNStateBlocked
		report.ErrorClass = stunobserve.ErrorClassIO
		report.Reason = "probe_cleanup_failed"
		return report, fmt.Errorf("active STUN cleanup: %w", err)
	}
	report.State = ActiveSTUNStateCompleted
	if activeSTUNReportHasErrors(report) {
		report.State = ActiveSTUNStateCompletedWithErrs
	}
	return report, nil
}

func activeSTUNReportHasErrors(report ActiveSTUNReport) bool {
	for _, result := range activeSTUNReportResults(report) {
		if result.ErrorClass != "" {
			return true
		}
	}
	if report.PortAllocation != nil {
		for _, result := range report.PortAllocation.Results {
			if result.ErrorClass != "" {
				return true
			}
		}
	}
	return false
}

func activeSTUNReportResults(report ActiveSTUNReport) []ActiveSTUNTargetReport {
	if report.MappingBehavior != nil {
		return report.MappingBehavior.Results
	}
	return report.Results
}

// ValidateMappingBehaviorTargets rejects a mapping request before authority
// acquisition or network I/O. One UDP socket cannot safely mix address
// families across platforms.
func ValidateMappingBehaviorTargets(targets []netip.AddrPort) error {
	if len(targets) < stunobserve.MinMappingTargets || len(targets) > stunobserve.MaxMappingTargets {
		return fmt.Errorf("%w: --map-behavior requires two or three targets", ErrActiveSTUNInvalidRequest)
	}
	ipv4 := targets[0].Addr().Is4()
	for _, target := range targets[1:] {
		if target.Addr().Is4() != ipv4 {
			return fmt.Errorf("%w: --map-behavior targets must use one address family", ErrActiveSTUNInvalidRequest)
		}
	}
	return nil
}

// ValidatePortAllocationRequest rejects the mode before authority acquisition
// or network I/O. The mode has one target and a bounded socket count.
func ValidatePortAllocationRequest(targets []netip.AddrPort, socketCount int) error {
	if len(targets) != 1 {
		return fmt.Errorf("%w: --port-allocation requires exactly one --active-stun target", ErrActiveSTUNInvalidRequest)
	}
	if socketCount < stunobserve.MinAllocationSockets || socketCount > stunobserve.MaxAllocationSockets {
		return fmt.Errorf("%w: --port-allocation socket count must be between %d and %d", ErrActiveSTUNInvalidRequest, stunobserve.MinAllocationSockets, stunobserve.MaxAllocationSockets)
	}
	return nil
}

func emptyMappingBehaviorReport(targets []netip.AddrPort) *MappingBehaviorReport {
	return mappingBehaviorReportForTargets(stunobserve.MappingObservation{Results: []stunobserve.MappingTargetObservation{}}, targets)
}

func mappingBehaviorReportForTargets(mapping stunobserve.MappingObservation, targets []netip.AddrPort) *MappingBehaviorReport {
	if mapping.Classification.TotalTargets == 0 {
		endpoints := make([]stunobserve.MappingEndpoint, 0, len(targets))
		for _, target := range targets {
			endpoints = append(endpoints, stunobserve.MappingEndpoint{Target: target})
		}
		mapping.Classification = stunobserve.ClassifyMapping(endpoints)
	}
	return mappingBehaviorReport(mapping)
}

func mappingBehaviorReport(mapping stunobserve.MappingObservation) *MappingBehaviorReport {
	classification := mapping.Classification
	if classification.Behavior == "" {
		classification.Behavior = stunobserve.MappingBehaviorInconclusive
	}
	if classification.EvidenceScope == "" {
		classification.EvidenceScope = stunobserve.MappingEvidenceSameAddressMultiplePorts
	}
	report := &MappingBehaviorReport{
		Behavior:          classification.Behavior,
		EvidenceScope:     classification.EvidenceScope,
		Limitations:       append(make([]stunobserve.MappingLimitation, 0, len(classification.Limitations)), classification.Limitations...),
		SuccessfulTargets: classification.SuccessfulTargets,
		Results:           make([]ActiveSTUNTargetReport, 0, len(mapping.Results)),
	}
	for _, result := range mapping.Results {
		report.Results = append(report.Results, activeSTUNTargetResult(
			result.Target,
			result.Observation,
			activeSTUNObservationDuration(result.Observation),
			result.Err,
		))
	}
	return report
}

func emptyPortAllocationReport(target netip.AddrPort, socketCount int) *PortAllocationReport {
	return portAllocationReport(stunobserve.AllocationObservation{}, target, socketCount)
}

func portAllocationReport(allocation stunobserve.AllocationObservation, target netip.AddrPort, socketCount int) *PortAllocationReport {
	classification := allocation.Classification
	if classification.TotalSockets == 0 {
		classification = stunobserve.ClassifyAllocation(make([]stunobserve.AllocationSample, socketCount))
	}
	report := &PortAllocationReport{
		Behavior:          classification.Behavior,
		EvidenceScope:     classification.EvidenceScope,
		Limitations:       append(make([]stunobserve.AllocationLimitation, 0, len(classification.Limitations)), classification.Limitations...),
		SuccessfulSockets: classification.SuccessfulSockets,
		TotalSockets:      classification.TotalSockets,
		Deltas:            append(make([]int, 0, len(classification.Deltas)), classification.Deltas...),
		Results:           make([]PortAllocationSocketReport, 0, len(allocation.Results)),
	}
	for _, socketResult := range allocation.Results {
		base := activeSTUNTargetResult(target, socketResult.Observation, activeSTUNObservationDuration(socketResult.Observation), socketResult.Err)
		report.Results = append(report.Results, PortAllocationSocketReport{
			LocalAddress:     socketResult.Local.String(),
			Target:           base.Target,
			MappedAddress:    base.MappedAddress,
			PortBehavior:     base.PortBehavior,
			ErrorClass:       base.ErrorClass,
			Reason:           base.Reason,
			DurationMS:       base.DurationMS,
			Transmissions:    base.Transmissions,
			ObservationScope: base.ObservationScope,
		})
	}
	return report
}

func activeSTUNObservationDuration(observation solver.Observation) time.Duration {
	started, startErr := time.Parse(time.RFC3339Nano, observation.Details["window_started_at"])
	finished, finishErr := time.Parse(time.RFC3339Nano, observation.Details["window_finished_at"])
	if startErr != nil || finishErr != nil || finished.Before(started) {
		return 0
	}
	return finished.Sub(started)
}

// ApplyActiveSTUN attaches the CLI-only active section without changing the
// passive default. The stdio diagnose method never calls this function.
func ApplyActiveSTUN(report *Report, active ActiveSTUNReport) {
	if report == nil {
		return
	}
	report.ActiveSTUN = &active
	report.NetworkActivityStarted = active.NetworkActivityStarted
	switch active.State {
	case ActiveSTUNStateCompleted:
		report.Mode = "active_stun"
		report.ActiveProbe = ActiveProbeStatus{State: "active_probe_completed", Reason: "explicit_active_stun", Detail: "bounded STUN observations completed; results describe only their observation windows"}
	case ActiveSTUNStateCompletedWithErrs:
		report.Mode = "active_stun"
		report.ActiveProbe = ActiveProbeStatus{State: "active_probe_completed_with_errors", Reason: "explicit_active_stun_partial", Detail: "bounded STUN observations completed with per-target errors; results describe only their observation windows"}
	default:
		report.ActiveProbe = ActiveProbeStatus{State: "active_probe_blocked", Reason: firstNonEmpty(active.Reason, "active_stun_blocked"), Detail: "the explicit active STUN request was rejected before or during governed execution"}
	}
}

func canonicalActiveSTUNTargets(source []netip.AddrPort) ([]netip.AddrPort, error) {
	if len(source) == 0 || len(source) > MaxActiveSTUNTargets {
		return nil, fmt.Errorf("%w: target count=%d maximum=%d", ErrActiveSTUNInvalidRequest, len(source), MaxActiveSTUNTargets)
	}
	result := make([]netip.AddrPort, 0, len(source))
	seen := make(map[netip.AddrPort]struct{}, len(source))
	for _, target := range source {
		if !target.IsValid() || target.Port() == 0 || target.Addr().Zone() != "" {
			return nil, fmt.Errorf("%w: target must be a literal unicast IP and non-zero UDP port", ErrActiveSTUNInvalidRequest)
		}
		address := target.Addr().Unmap()
		if !address.IsLoopback() && !address.IsGlobalUnicast() {
			return nil, fmt.Errorf("%w: target address must be unicast", ErrActiveSTUNInvalidRequest)
		}
		canonical := netip.AddrPortFrom(address, target.Port())
		if _, exists := seen[canonical]; exists {
			return nil, fmt.Errorf("%w: duplicate target %s", ErrActiveSTUNInvalidRequest, canonical)
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func preflightActiveSTUN(snapshot governor.Snapshot, scope governor.Scope, count int, perTarget governor.AttemptCost) error {
	expectedProfile := governor.ProfilePhase1Machine
	if scope == governor.ScopeUserAcknowledged {
		expectedProfile = governor.ProfilePhase1UserAcknowledged
	}
	if snapshot.SafetyTrip.BlocksActiveWork {
		return ErrActiveSTUNSafetyTrip
	}
	if snapshot.Closed || snapshot.Scope != scope || snapshot.Profile != expectedProfile || snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.HeavyweightAttempts != 0 || snapshot.Reserved != (governor.Resources{}) {
		return fmt.Errorf("%w: authority is not a fresh idle capability", ErrActiveSTUNAuthority)
	}
	if snapshot.Limits.MaxActivePeers < 1 || snapshot.Limits.MaxActiveAttempts < 1 || snapshot.Limits.MaxAttemptsPerPeer < 1 {
		return fmt.Errorf("%w: diagnostic peer or attempt capacity is zero", ErrActiveSTUNBudget)
	}
	if !resourcesFit(perTarget.Resources, snapshot.Limits.PerAttempt) {
		return fmt.Errorf("%w: one observation exceeds the per-attempt ceiling", ErrActiveSTUNBudget)
	}
	total := multiplyResources(perTarget.Resources, count)
	if !resourcesFit(total, snapshot.Limits.Aggregate) {
		return fmt.Errorf("%w: total declared resources exceed the aggregate ceiling", ErrActiveSTUNBudget)
	}
	if totalDuration := perTarget.Duration * time.Duration(count); totalDuration <= 0 || totalDuration > snapshot.Limits.MaxAttemptDuration {
		return fmt.Errorf("%w: total declared duration %s exceeds %s", ErrActiveSTUNBudget, totalDuration, snapshot.Limits.MaxAttemptDuration)
	}
	return nil
}

func resourcesFit(current, maximum governor.Resources) bool {
	return current.Sockets <= maximum.Sockets &&
		current.Targets <= maximum.Targets &&
		current.PacketsPerSecond <= maximum.PacketsPerSecond &&
		current.Packets <= maximum.Packets &&
		current.FiveTuples <= maximum.FiveTuples
}

func multiplyResources(resources governor.Resources, count int) governor.Resources {
	return governor.Resources{
		Sockets:          resources.Sockets * count,
		Targets:          resources.Targets * count,
		PacketsPerSecond: resources.PacketsPerSecond * count,
		Packets:          resources.Packets * count,
		FiveTuples:       resources.FiveTuples * count,
	}
}

func activeSTUNTargetResult(target netip.AddrPort, observation solver.Observation, elapsed time.Duration, observeErr error) ActiveSTUNTargetReport {
	if elapsed < 0 {
		elapsed = 0
	}
	result := ActiveSTUNTargetReport{
		Target:           target.String(),
		PortBehavior:     "unknown",
		ErrorClass:       observation.ErrorClass,
		Reason:           observation.Reason,
		DurationMS:       elapsed.Milliseconds(),
		ObservationScope: firstNonEmpty(observation.Details["observation_scope"], "time_window_only"),
	}
	result.Transmissions, _ = strconv.Atoi(observation.Details["transmissions"])
	if mapped, err := netip.ParseAddrPort(observation.Details["mapped_address"]); err == nil {
		result.MappedAddress = mapped.String()
		if local, localErr := netip.ParseAddrPort(observation.LocalAddr); localErr == nil {
			if mapped.Port() == local.Port() {
				result.PortBehavior = "preserved"
			} else {
				result.PortBehavior = "translated"
			}
		}
	}
	if observeErr != nil && result.ErrorClass == "" {
		result.ErrorClass = stunobserve.ErrorClassIO
		result.Reason = "probe_io_failed"
	}
	return result
}

func activeSTUNUDPFactory(target netip.AddrPort) (probeio.Factory, error) {
	address := netip.IPv6Unspecified()
	if target.Addr().Is4() {
		address = netip.IPv4Unspecified()
	}
	if target.Addr().IsLoopback() {
		address = netip.IPv6Loopback()
		if target.Addr().Is4() {
			address = netip.MustParseAddr("127.0.0.1")
		}
	}
	return probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr:          netip.AddrPortFrom(address, 0),
		AllowedTargetScope: probeio.AllowedTargetScopeUnicast,
	})
}

func blockActiveSTUN(report ActiveSTUNReport, class, reason string, err error) (ActiveSTUNReport, error) {
	report.State = ActiveSTUNStateBlocked
	report.ErrorClass = class
	report.Reason = reason
	return report, err
}

func activeSTUNContextFailure(err error) (string, string) {
	if errors.Is(err, context.DeadlineExceeded) {
		return stunobserve.ErrorClassTimeout, "total_deadline_exceeded"
	}
	return stunobserve.ErrorClassCancelled, "request_cancelled"
}

func finishActiveSTUNWithSystemError(report ActiveSTUNReport, peer ActiveSTUNPeer, authority ActiveSTUNAuthority, closePeer, closeAuthority *bool, class, reason string, cause error) (ActiveSTUNReport, error) {
	peerErr := peer.Close()
	*closePeer = false
	authorityErr := authority.Close()
	*closeAuthority = false
	report.State = ActiveSTUNStateBlocked
	report.ErrorClass = class
	report.Reason = reason
	return report, errors.Join(cause, peerErr, authorityErr)
}

type machineActiveSTUNAuthority struct {
	authority *governor.Governor
}

func acquireMachineActiveSTUNAuthority(buildVersion string) (ActiveSTUNAuthority, error) {
	owner, err := governor.AcquireMachineNamespace(buildVersion)
	if err != nil {
		return nil, err
	}
	authority, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		return nil, errors.Join(err, owner.Close())
	}
	return machineActiveSTUNAuthority{authority: authority}, nil
}

func (authority machineActiveSTUNAuthority) Snapshot() governor.Snapshot {
	return authority.authority.Snapshot()
}

func (authority machineActiveSTUNAuthority) AcquireDiagnosticPeer(peerID string) (ActiveSTUNPeer, error) {
	peer, err := authority.authority.AcquirePeer(peerID)
	if err != nil {
		return nil, err
	}
	return machineActiveSTUNPeer{peer: peer}, nil
}

func (authority machineActiveSTUNAuthority) Close() error { return authority.authority.Close() }

type machineActiveSTUNPeer struct {
	peer *governor.PeerLease
}

func (peer machineActiveSTUNPeer) AcquireDiagnosticAttempt(ctx context.Context, attemptID string, cost governor.AttemptCost) (probeio.AttemptLease, error) {
	return peer.peer.AcquireAttempt(ctx, governor.AttemptRequest{ID: attemptID, Operation: governor.OperationDiagnose, Cost: cost})
}

func (peer machineActiveSTUNPeer) Close() error { return peer.peer.Close() }

type restrictedActiveSTUNAuthority struct {
	authority *governor.RestrictedUserGovernor
}

func (authority restrictedActiveSTUNAuthority) Snapshot() governor.Snapshot {
	return authority.authority.Snapshot()
}

func (authority restrictedActiveSTUNAuthority) AcquireDiagnosticPeer(peerID string) (ActiveSTUNPeer, error) {
	peer, err := authority.authority.AcquirePeer(peerID)
	if err != nil {
		return nil, err
	}
	return restrictedActiveSTUNPeer{peer: peer}, nil
}

func (authority restrictedActiveSTUNAuthority) Close() error { return authority.authority.Close() }

type restrictedActiveSTUNPeer struct {
	peer *governor.RestrictedUserPeerLease
}

func (peer restrictedActiveSTUNPeer) AcquireDiagnosticAttempt(ctx context.Context, attemptID string, cost governor.AttemptCost) (probeio.AttemptLease, error) {
	if cost.Heavyweight {
		return nil, fmt.Errorf("%w: heavyweight diagnostic is not permitted", ErrActiveSTUNBudget)
	}
	return peer.peer.AcquireDiagnosticAttempt(ctx, governor.RestrictedAttemptRequest{ID: attemptID, Resources: cost.Resources, Duration: cost.Duration})
}

func (peer restrictedActiveSTUNPeer) Close() error { return peer.peer.Close() }
