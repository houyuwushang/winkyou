package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/mesh/shortcut"
)

type recoveryState string

const (
	recoveryStateHealthy       recoveryState = "healthy"
	recoveryStateAttempting    recoveryState = "attempting"
	recoveryStateBackoff       recoveryState = "backoff"
	recoveryStateWaitingRoute  recoveryState = "waiting_route"
	recoveryStateBootstrapOnly recoveryState = "bootstrap_only"
	recoveryStateStandby       recoveryState = "standby_owner"
	recoveryStateQueued        recoveryState = "queued"
	recoveryStateUnknownDirect recoveryState = "unknown_direct"
)

// maintainedPeerView is deliberately operational rather than protocol state.
// It explains why a declared direct edge is healthy, waiting, or being
// repaired without requiring an operator to correlate several shortcut rows.
type maintainedPeerView struct {
	PeerID          string            `json:"peer_id"`
	OwnerID         string            `json:"owner_id"`
	State           recoveryState     `json:"state"`
	NeighborKind    mesh.NeighborKind `json:"neighbor_kind,omitempty"`
	ProtectedDirect bool              `json:"protected_direct"`
	Reachable       bool              `json:"reachable"`
	RoutePath       []string          `json:"route_path,omitempty"`
	RouteHopCount   int               `json:"route_hop_count,omitempty"`
	CoordinatorID   string            `json:"coordinator_id,omitempty"`
	AttemptID       string            `json:"attempt_id,omitempty"`
	AttemptPhase    shortcut.Phase    `json:"attempt_phase,omitempty"`
	Failures        int               `json:"failures"`
	NextRetryAt     time.Time         `json:"next_retry_at,omitempty"`
	LastError       string            `json:"last_error,omitempty"`
	LastTransition  time.Time         `json:"last_transition"`
}

type recoveryEdge struct {
	maintainedPeerView
	healthySince time.Time
}

type recoveryAttemptResult struct {
	peerID    string
	attemptID string
	status    shortcut.Status
	err       error
}

// recoverySupervisor maintains declared protected-direct graph edges. It is
// event driven: topology and shortcut callbacks only coalesce a wake-up, while
// the serialized worker performs route selection, edge promotion, and retry.
type recoverySupervisor struct {
	node      *mesh.Node
	shortcuts *shortcut.Manager
	log       *eventLog
	localID   string

	debounce       time.Duration
	minBackoff     time.Duration
	maxBackoff     time.Duration
	stableReset    time.Duration
	attemptTimeout time.Duration
	startTimeout   time.Duration

	wake    chan struct{}
	results chan recoveryAttemptResult

	mu    sync.Mutex
	edges map[string]*recoveryEdge
	// trustedPacket holds packet-neighbor generations that completed the
	// coordinator-less authenticated self-bootstrap path. Shortcut generations
	// are checked directly against shortcut.Manager so probation cannot be
	// mistaken for stability.
	trustedPacket map[string]mesh.NeighborHandle
	peerIDs       []string
	started       bool
	closed        bool
	ctx           context.Context
	cancel        context.CancelFunc
	unregister    func()
	wg            sync.WaitGroup
}

func newRecoverySupervisor(cfg runtimeConfig, node *mesh.Node, manager *shortcut.Manager, log *eventLog) *recoverySupervisor {
	if node == nil || manager == nil || len(cfg.MaintainedPeers) == 0 {
		return nil
	}
	edges := make(map[string]*recoveryEdge, len(cfg.MaintainedPeers))
	peerIDs := append([]string(nil), cfg.MaintainedPeers...)
	sort.Strings(peerIDs)
	for _, peerID := range peerIDs {
		edges[peerID] = &recoveryEdge{maintainedPeerView: maintainedPeerView{
			PeerID: peerID, OwnerID: directEdgeOwner(cfg.NodeID, peerID),
			State: recoveryStateWaitingRoute, LastTransition: time.Now().UTC(),
		}}
	}
	startTimeout := cfg.HandshakeTimeout
	if startTimeout <= 0 {
		startTimeout = 5 * time.Second
	}
	if cfg.AttemptTimeout > 0 && startTimeout > cfg.AttemptTimeout {
		startTimeout = cfg.AttemptTimeout
	}
	return &recoverySupervisor{
		node: node, shortcuts: manager, log: log, localID: cfg.NodeID,
		debounce: cfg.RecoveryDebounce, minBackoff: cfg.RecoveryMinBackoff,
		maxBackoff: cfg.RecoveryMaxBackoff, stableReset: cfg.RecoveryStableReset,
		attemptTimeout: cfg.AttemptTimeout, startTimeout: startTimeout,
		wake: make(chan struct{}, 1), results: make(chan recoveryAttemptResult, len(peerIDs)),
		edges: edges, trustedPacket: make(map[string]mesh.NeighborHandle), peerIDs: peerIDs,
	}
}

func directEdgeOwner(left, right string) string {
	if strings.Compare(left, right) <= 0 {
		return left
	}
	return right
}

func (s *recoverySupervisor) Start(parent context.Context) error {
	if s == nil {
		return nil
	}
	if parent == nil {
		parent = context.Background()
	}
	if err := parent.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return mesh.ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("direct-edge recovery already started")
	}
	ctx, cancel := context.WithCancel(parent)
	s.ctx, s.cancel, s.started = ctx, cancel, true
	s.mu.Unlock()

	unregister, err := s.node.RegisterTopologyHandler(s.Notify)
	if err != nil {
		cancel()
		return err
	}
	s.mu.Lock()
	s.unregister = unregister
	s.mu.Unlock()
	s.wg.Add(1)
	go s.run(ctx)
	s.Notify()
	return nil
}

func (s *recoverySupervisor) Notify() {
	if s == nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *recoverySupervisor) ObserveShortcut(status shortcut.Status) {
	if s == nil || strings.TrimSpace(status.AttemptID) == "" {
		return
	}
	matched := false
	s.mu.Lock()
	for _, edge := range s.edges {
		if edge.AttemptID == status.AttemptID {
			edge.AttemptPhase = status.Phase
			matched = true
			break
		}
	}
	s.mu.Unlock()
	// A shortcut owned or started elsewhere can be the alternate first hop for
	// one of our maintained edges. Its terminal transition has no topology
	// change, so wake reconciliation even when it is not our active repair.
	terminalDirect := status.DirectPeerID != "" &&
		(status.Phase == shortcut.PhaseStable || status.Phase == shortcut.PhaseFailed)
	if (matched || terminalDirect) &&
		(status.Phase == shortcut.PhaseStable || status.Phase == shortcut.PhaseFailed) {
		s.Notify()
	}
}

// ObserveStablePacket records a packet-neighbor generation that has already
// completed an equivalent stability barrier outside the ordinary shortcut
// manager (currently the authenticated self-bootstrap hello). A later
// replacement under the same peer ID has a different opaque handle and will
// therefore not inherit this trust.
func (s *recoverySupervisor) ObserveStablePacket(peerID string, handle mesh.NeighborHandle) {
	if s == nil {
		return
	}
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return
	}
	s.mu.Lock()
	s.trustedPacket[peerID] = handle
	s.mu.Unlock()
	s.Notify()
}

func (s *recoverySupervisor) stablePacketNeighbor(peerID string, neighbor mesh.NeighborInfo) bool {
	if neighbor.Kind != mesh.NeighborKindPacket || neighbor.PeerID != peerID {
		return false
	}
	if s.shortcuts.IsStableDirectNeighbor(peerID, neighbor.Handle) {
		return true
	}
	s.mu.Lock()
	handle, ok := s.trustedPacket[peerID]
	if ok && handle != neighbor.Handle {
		delete(s.trustedPacket, peerID)
		ok = false
	}
	s.mu.Unlock()
	return ok
}

func (s *recoverySupervisor) Snapshot() []maintainedPeerView {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	views := make([]maintainedPeerView, 0, len(s.peerIDs))
	for _, peerID := range s.peerIDs {
		view := s.edges[peerID].maintainedPeerView
		view.RoutePath = append([]string(nil), view.RoutePath...)
		views = append(views, view)
	}
	return views
}

func (s *recoverySupervisor) run(ctx context.Context) {
	defer s.wg.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	timerC := timer.C
	nextAt := time.Now()
	schedule := func(at time.Time) {
		if at.IsZero() {
			return
		}
		if timerC != nil && !at.Before(nextAt) {
			return
		}
		if !timer.Stop() && timerC != nil {
			select {
			case <-timer.C:
			default:
			}
		}
		delay := time.Until(at)
		if delay < 0 {
			delay = 0
		}
		timer.Reset(delay)
		timerC = timer.C
		nextAt = at
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			schedule(time.Now().Add(s.debounce))
		case result := <-s.results:
			s.handleAttemptResult(result)
			schedule(time.Now())
		case <-timerC:
			timerC = nil
			nextAt = time.Time{}
			schedule(s.reconcile(time.Now().UTC()))
		}
	}
}

type recoveryAction struct {
	peerID string
	route  mesh.Route
	remove *mesh.NeighborHandle
}

func (s *recoverySupervisor) reconcile(now time.Time) time.Time {
	var next time.Time
	actions := make([]recoveryAction, 0, len(s.peerIDs))
	s.mu.Lock()
	automaticBusy := false
	for _, edge := range s.edges {
		if edge.AttemptID != "" {
			automaticBusy = true
			break
		}
	}
	s.mu.Unlock()
	queued := false
	for _, peerID := range s.peerIDs {
		neighbor, attached := s.node.Neighbor(peerID)
		route, routeOK := s.node.Route(peerID)
		alternate, alternateOK := s.node.AlternateRoute(peerID)
		directStable := attached && s.stablePacketNeighbor(peerID, neighbor)
		alternateStable := usableRecoveryRoute(alternate, alternateOK, peerID) && s.stableAlternateFirstHop(alternate)

		s.mu.Lock()
		edge := s.edges[peerID]
		if attached {
			edge.NeighborKind = neighbor.Kind
		} else {
			edge.NeighborKind = ""
		}
		edge.ProtectedDirect = directStable
		edge.Reachable = routeOK || attached
		if routeOK {
			edge.RoutePath = append(edge.RoutePath[:0], route.Path...)
			edge.RouteHopCount = route.HopCount
		} else {
			edge.RoutePath = nil
			edge.RouteHopCount = 0
		}

		if edge.AttemptID != "" {
			edge.healthySince = time.Time{}
			s.setStateLocked(edge, recoveryStateAttempting, now)
			s.mu.Unlock()
			continue
		}
		if attached && neighbor.Kind == mesh.NeighborKindPacket && directStable {
			if edge.healthySince.IsZero() {
				edge.healthySince = now
			}
			s.setStateLocked(edge, recoveryStateHealthy, now)
			resetAt := edge.healthySince.Add(s.stableReset)
			if edge.Failures > 0 && !now.Before(resetAt) {
				edge.Failures = 0
				edge.LastError = ""
				edge.NextRetryAt = time.Time{}
			} else if edge.Failures > 0 {
				next = earlierTime(next, resetAt)
			}
			s.mu.Unlock()
			continue
		}
		edge.healthySince = time.Time{}
		if attached && neighbor.Kind == mesh.NeighborKindPacket {
			s.setStateLocked(edge, recoveryStateUnknownDirect, now)
			s.mu.Unlock()
			continue
		}
		if edge.OwnerID != s.localID {
			s.setStateLocked(edge, recoveryStateStandby, now)
			s.mu.Unlock()
			continue
		}
		if attached && neighbor.Kind != mesh.NeighborKindStream {
			s.setStateLocked(edge, recoveryStateUnknownDirect, now)
			s.mu.Unlock()
			continue
		}
		if edge.NextRetryAt.After(now) {
			s.setStateLocked(edge, recoveryStateBackoff, now)
			next = earlierTime(next, edge.NextRetryAt)
			s.mu.Unlock()
			continue
		}
		edge.NextRetryAt = time.Time{}
		if attached {
			if !alternateStable {
				s.setStateLocked(edge, recoveryStateBootstrapOnly, now)
				s.mu.Unlock()
				continue
			}
			if automaticBusy || len(actions) > 0 {
				s.setStateLocked(edge, recoveryStateQueued, now)
				queued = true
				s.mu.Unlock()
				continue
			}
			handle := neighbor.Handle
			actions = append(actions, recoveryAction{peerID: peerID, route: alternate, remove: &handle})
			s.mu.Unlock()
			continue
		}
		if !usableRecoveryRoute(route, routeOK, peerID) {
			s.setStateLocked(edge, recoveryStateWaitingRoute, now)
			s.mu.Unlock()
			continue
		}
		if automaticBusy || len(actions) > 0 {
			s.setStateLocked(edge, recoveryStateQueued, now)
			queued = true
			s.mu.Unlock()
			continue
		}
		actions = append(actions, recoveryAction{peerID: peerID, route: route})
		s.mu.Unlock()
	}

	for _, action := range actions {
		if action.remove != nil {
			s.log.write("direct_recovery_bootstrap_release", map[string]any{
				"peer_id": action.peerID, "route": action.route.Path,
			})
			if err := s.node.RemoveNeighborHandle(*action.remove); err != nil {
				s.recordStartFailure(action.peerID, fmt.Errorf("release bootstrap edge: %w", err), now)
				continue
			}
		}
		if err := s.startAttempt(action.peerID, action.route, now); err != nil {
			s.recordStartFailure(action.peerID, err, now)
		}
	}
	// An action may have installed a backoff after the first pass.
	s.mu.Lock()
	for _, edge := range s.edges {
		if edge.NextRetryAt.After(now) {
			next = earlierTime(next, edge.NextRetryAt)
		}
	}
	s.mu.Unlock()
	if queued && !automaticBusy {
		next = earlierTime(next, now.Add(s.debounce))
	}
	return next
}

func (s *recoverySupervisor) stableAlternateFirstHop(route mesh.Route) bool {
	if len(route.Path) < 3 {
		return false
	}
	peerID := route.Path[1]
	neighbor, ok := s.node.Neighbor(peerID)
	return ok && s.stablePacketNeighbor(peerID, neighbor)
}

func usableRecoveryRoute(route mesh.Route, ok bool, peerID string) bool {
	return ok && route.Destination == peerID && route.HopCount >= 2 && len(route.Path) >= 3 &&
		route.Path[0] != peerID && route.Path[1] != peerID
}

func (s *recoverySupervisor) startAttempt(peerID string, route mesh.Route, now time.Time) error {
	coordinatorID := route.Path[1]
	s.log.write("direct_recovery_attempt_scheduled", map[string]any{
		"peer_id": peerID, "coordinator": coordinatorID, "route": route.Path,
	})
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	startCtx, cancel := context.WithTimeout(parent, s.startTimeout)
	handle, err := s.shortcuts.Start(startCtx, peerID, coordinatorID)
	cancel()
	if err != nil {
		return fmt.Errorf("start repair through %s: %w", coordinatorID, err)
	}
	status, _ := handle.Status()
	s.mu.Lock()
	edge := s.edges[peerID]
	if edge == nil || edge.AttemptID != "" {
		s.mu.Unlock()
		_ = s.shortcuts.Cancel(handle.ID(), fmt.Errorf("automatic repair superseded"))
		return fmt.Errorf("repair for %s was superseded", peerID)
	}
	edge.AttemptID = handle.ID()
	edge.AttemptPhase = status.Phase
	edge.CoordinatorID = coordinatorID
	edge.RoutePath = append(edge.RoutePath[:0], route.Path...)
	edge.RouteHopCount = route.HopCount
	s.setStateLocked(edge, recoveryStateAttempting, now)
	s.mu.Unlock()
	s.log.write("direct_recovery_attempt_started", map[string]any{
		"peer_id": peerID, "attempt_id": handle.ID(), "coordinator": coordinatorID,
	})
	s.wg.Add(1)
	go s.waitAttempt(peerID, handle)
	return nil
}

func (s *recoverySupervisor) waitAttempt(peerID string, handle *shortcut.Handle) {
	defer s.wg.Done()
	waitCtx, cancel := context.WithTimeout(s.ctx, saturatingPositiveDurationSum(s.attemptTimeout, time.Second))
	status, err := handle.WaitFor(waitCtx, shortcut.PhaseStable)
	cancel()
	if err != nil && s.ctx.Err() == nil && status.Phase != shortcut.PhaseFailed {
		_ = s.shortcuts.Cancel(handle.ID(), fmt.Errorf("automatic repair deadline: %w", err))
		if current, ok := handle.Status(); ok {
			status = current
		}
	}
	result := recoveryAttemptResult{peerID: peerID, attemptID: handle.ID(), status: status, err: err}
	select {
	case s.results <- result:
	case <-s.ctx.Done():
	}
}

func (s *recoverySupervisor) handleAttemptResult(result recoveryAttemptResult) {
	now := time.Now().UTC()
	s.mu.Lock()
	edge := s.edges[result.peerID]
	if edge == nil || edge.AttemptID != result.attemptID {
		s.mu.Unlock()
		return
	}
	edge.AttemptID = ""
	edge.AttemptPhase = result.status.Phase
	edge.CoordinatorID = ""
	if result.err == nil && result.status.Phase == shortcut.PhaseStable {
		edge.healthySince = now
		edge.NextRetryAt = time.Time{}
		s.setStateLocked(edge, recoveryStateHealthy, now)
		s.mu.Unlock()
		s.log.write("direct_recovery_attempt_succeeded", map[string]any{
			"peer_id": result.peerID, "attempt_id": result.attemptID,
		})
		return
	}
	cause := result.err
	if cause == nil {
		cause = fmt.Errorf("shortcut ended in phase %s: %s", result.status.Phase, result.status.Failure)
	}
	s.recordFailureLocked(edge, cause, now)
	s.mu.Unlock()
	s.log.write("direct_recovery_attempt_failed", map[string]any{
		"peer_id": result.peerID, "attempt_id": result.attemptID,
		"error": cause.Error(),
	})
}

func (s *recoverySupervisor) recordStartFailure(peerID string, cause error, now time.Time) {
	s.mu.Lock()
	edge := s.edges[peerID]
	if edge != nil && edge.AttemptID == "" {
		s.recordFailureLocked(edge, cause, now)
	}
	s.mu.Unlock()
	s.log.write("direct_recovery_attempt_failed", map[string]any{
		"peer_id": peerID, "error": cause.Error(),
	})
}

func (s *recoverySupervisor) recordFailureLocked(edge *recoveryEdge, cause error, now time.Time) {
	edge.Failures++
	edge.LastError = cause.Error()
	edge.NextRetryAt = now.Add(s.retryDelay(edge.PeerID, edge.Failures))
	edge.healthySince = time.Time{}
	s.setStateLocked(edge, recoveryStateBackoff, now)
}

func (s *recoverySupervisor) retryDelay(peerID string, failures int) time.Duration {
	limit := s.minBackoff
	for index := 1; index < failures && limit < s.maxBackoff; index++ {
		if limit > s.maxBackoff/2 {
			limit = s.maxBackoff
		} else {
			limit *= 2
		}
	}
	if limit > s.maxBackoff {
		limit = s.maxBackoff
	}
	half := limit / 2
	if half <= 0 {
		return limit
	}
	hash := fnv.New64a()
	_, _ = fmt.Fprintf(hash, "%s/%s/%d", s.localID, peerID, failures)
	return half + time.Duration(hash.Sum64()%uint64(half+1))
}

func (s *recoverySupervisor) setStateLocked(edge *recoveryEdge, state recoveryState, now time.Time) {
	if edge.State == state {
		return
	}
	edge.State = state
	edge.LastTransition = now
}

func earlierTime(current, candidate time.Time) time.Time {
	if candidate.IsZero() || (!current.IsZero() && !candidate.Before(current)) {
		return current
	}
	return candidate
}

func (s *recoverySupervisor) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	cancel := s.cancel
	unregister := s.unregister
	s.mu.Unlock()
	if unregister != nil {
		unregister()
	}
	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}
