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
	NetworkActivityStarted    bool                     `json:"-"`
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
	Targets       []netip.AddrPort
	GovernorScope governor.Scope
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

// ActiveSTUNInspector has explicit dependencies so tests can prove preflight
// rejection without constructing a socket and can exercise the real loopback
// adapter without acquiring a host-wide namespace.
type ActiveSTUNInspector struct {
	Now            func() time.Time
	AcquireMachine func(string) (ActiveSTUNAuthority, error)
	AcquireUser    func(string) (ActiveSTUNAuthority, error)
	Factory        func(netip.AddrPort) (probeio.Factory, error)
	Observer       func(stunobserve.Config) (ActiveSTUNObserver, error)
	BuildVersion   string
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
		Factory:      activeSTUNUDPFactory,
		Observer:     func(config stunobserve.Config) (ActiveSTUNObserver, error) { return stunobserve.New(config) },
		BuildVersion: buildVersion,
	}
}

func (inspector ActiveSTUNInspector) Run(ctx context.Context, options ActiveSTUNOptions) (ActiveSTUNReport, error) {
	cost := stunobserve.WorstCaseCost()
	report := ActiveSTUNReport{
		State:                     ActiveSTUNStateBlocked,
		ObservationScope:          "time_window_only",
		TargetCount:               len(options.Targets),
		WorstCaseDurationMS:       (cost.Duration * time.Duration(len(options.Targets))).Milliseconds(),
		WorstCasePackets:          cost.Resources.Packets * len(options.Targets),
		MaxTransmissionsPerTarget: stunobserve.MaxTransmissions,
	}
	if ctx == nil {
		return blockActiveSTUN(report, "invalid_request", "nil_context", ErrActiveSTUNInvalidRequest)
	}
	targets, err := canonicalActiveSTUNTargets(options.Targets)
	if err != nil {
		return blockActiveSTUN(report, "invalid_request", "invalid_target_list", err)
	}
	if inspector.Now == nil {
		inspector.Now = time.Now
	}
	if inspector.Factory == nil {
		inspector.Factory = activeSTUNUDPFactory
	}
	if inspector.Observer == nil {
		inspector.Observer = func(config stunobserve.Config) (ActiveSTUNObserver, error) { return stunobserve.New(config) }
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
	if err := preflightActiveSTUN(authority.Snapshot(), options.GovernorScope, len(targets), cost); err != nil {
		if errors.Is(err, ErrActiveSTUNSafetyTrip) {
			return blockActiveSTUN(report, "safety_trip", "safety_trip_blocks_active_work", err)
		}
		if errors.Is(err, ErrActiveSTUNAuthority) {
			return blockActiveSTUN(report, "authority_unavailable", "authority_not_idle", err)
		}
		return blockActiveSTUN(report, "budget_rejected", "worst_case_budget_unavailable", err)
	}
	runCtx, cancelRun := context.WithTimeout(ctx, cost.Duration*time.Duration(len(targets)))
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

	peerErr := peer.Close()
	closePeer = false
	authorityErr := authority.Close()
	closeAuthority = false
	if err := errors.Join(peerErr, authorityErr); err != nil {
		report.State = ActiveSTUNStateBlocked
		report.ErrorClass = stunobserve.ErrorClassIO
		report.Reason = "probe_cleanup_failed"
		return report, fmt.Errorf("active STUN cleanup: %w", err)
	}
	report.State = ActiveSTUNStateCompleted
	for _, result := range report.Results {
		if result.ErrorClass != "" {
			report.State = ActiveSTUNStateCompletedWithErrs
			break
		}
	}
	return report, nil
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
