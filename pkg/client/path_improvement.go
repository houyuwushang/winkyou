package client

import (
	"time"

	"winkyou/pkg/logger"
	"winkyou/pkg/solver"
)

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
	return peer.State == PeerStateConnected &&
		(peer.DataState == PeerDataStateAlive || peer.DataState == PeerDataStateBound)
}

func (e *engine) schedulePeerImprovementByID(nodeID string) {
	e.mu.RLock()
	var session *peerSession
	if e.peerMgr != nil {
		session = e.peerMgr.sessions[nodeID]
	}
	e.mu.RUnlock()
	e.schedulePeerImprovement(nodeID, session)
}

func (e *engine) schedulePeerImprovement(nodeID string, session *peerSession) {
	runCtx, ok := e.runContext()
	if session == nil || !ok || !shouldImproveBoundPath(e.multipathPathPolicy(), sessionLastPath(session)) {
		return
	}

	session.connectMu.Lock()
	if !session.bound || session.connecting || session.improving || session.improvePending {
		session.connectMu.Unlock()
		return
	}
	delay := session.improveDelay
	if delay <= 0 {
		delay = e.peerRetryInterval()
	} else {
		delay *= 2
	}
	if maxDelay := e.peerRetryMaxInterval(); delay > maxDelay {
		delay = maxDelay
	}
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
		e.startPeerImprovement(nodeID, expected)
	}(session, delay)
}

func (e *engine) startPeerImprovement(nodeID string, session *peerSession) {
	runner := peerSessionRunner(session)
	if session == nil || runner == nil || !shouldImproveBoundPath(e.multipathPathPolicy(), sessionLastPath(session)) {
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
			e.schedulePeerImprovement(nodeID, expected)
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
