package client

import (
	"time"

	"winkyou/pkg/logger"
	"winkyou/pkg/solver"
)

const forcedPeerImprovementDelay = 100 * time.Millisecond

func shouldImproveBoundPath(policy solver.PathPolicy, summary solver.PathSummary) bool {
	if !policy.MultipathEnabled || !policy.ProtectDirect {
		return false
	}
	if solver.IsProtectedDirectPath(summary) {
		return false
	}
	if summary.Details != nil && summary.Details["protected_direct_path_id"] != "" {
		return false
	}
	return true
}

func shouldRequestInbandReICE(policy solver.PathPolicy, peer *PeerStatus) bool {
	if peer == nil || !policy.MultipathEnabled || !policy.ProtectDirect {
		return false
	}
	if peer.ProtectedDirectPathID != "" {
		return false
	}
	if peer.LastPathRole == string(solver.PathRoleProtectedDirect) && len(peer.LastPathDependencies) == 0 {
		return false
	}
	return peerInbandEligible(peer)
}

func (e *engine) schedulePeerImprovementByID(nodeID string) {
	e.schedulePeerImprovementByIDWithForce(nodeID, false)
}

func (e *engine) schedulePeerImprovementByIDWithForce(nodeID string, force bool) {
	e.mu.RLock()
	var session *peerSession
	if e.peerMgr != nil {
		session = e.peerMgr.sessions[nodeID]
	}
	e.mu.RUnlock()
	e.schedulePeerImprovement(nodeID, session, force)
}

func (e *engine) schedulePeerImprovement(nodeID string, session *peerSession, force bool) {
	runCtx, ok := e.runContext()
	if session == nil || !ok || (!force && !shouldImproveBoundPath(e.multipathPathPolicy(), sessionLastPath(session))) {
		return
	}

	session.connectMu.Lock()
	if !session.bound || session.connecting || session.improving || session.improvePending {
		session.connectMu.Unlock()
		return
	}
	delay := nextImprovementDelay(session, e.peerRetryInterval(), e.peerRetryMaxInterval(), force)
	session.improveDelay = delay
	session.improvePending = true
	session.connectMu.Unlock()

	go func(expected *peerSession, wait time.Duration) {
		timer := time.NewTimer(wait)
		defer timer.Stop()

		select {
		case <-runCtx.Done():
			return
		case <-timer.C:
		}

		e.mu.RLock()
		current := (*peerSession)(nil)
		if e.peerMgr != nil {
			current = e.peerMgr.sessions[nodeID]
		}
		e.mu.RUnlock()
		if current != expected {
			return
		}

		expected.connectMu.Lock()
		expected.improvePending = false
		expected.connectMu.Unlock()
		e.startPeerImprovement(nodeID, expected, force)
	}(session, delay)
}

func nextImprovementDelay(session *peerSession, base, max time.Duration, force bool) time.Duration {
	if force {
		return forcedPeerImprovementDelay
	}
	delay := time.Duration(0)
	if session != nil {
		delay = session.improveDelay
	}
	if delay <= 0 {
		delay = base
	} else {
		delay *= 2
	}
	if max > 0 && delay > max {
		delay = max
	}
	return delay
}

func (e *engine) startPeerImprovement(nodeID string, session *peerSession, force bool) {
	runner := peerSessionRunner(session)
	if session == nil || runner == nil || (!force && !shouldImproveBoundPath(e.multipathPathPolicy(), sessionLastPath(session))) {
		return
	}

	session.connectMu.Lock()
	if !session.bound || session.connecting || session.improving {
		session.connectMu.Unlock()
		return
	}
	session.improving = true
	session.connectMu.Unlock()

	go func(expected *peerSession) {
		e.refreshRuntimePublicEndpointHints(e.sessionContext(), "path_improvement")
		found, err := runner.ImproveProtectedDirect(e.sessionContext())

		expected.connectMu.Lock()
		expected.improving = false
		if found {
			expected.improveDelay = 0
			expected.improvePending = false
		}
		expected.connectMu.Unlock()

		if err != nil {
			e.log.Warn("peer path improvement failed", logger.String("node_id", nodeID), logger.Error(err))
		}
		if !found {
			e.schedulePeerImprovement(nodeID, expected, force)
		}
	}(session)
}

func sessionLastPath(session *peerSession) solver.PathSummary {
	if session == nil {
		return solver.PathSummary{}
	}
	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	return solver.ClonePathSummary(session.lastPath)
}
