package client

import "time"

func (e *engine) applyPeerHealthStateLocked(now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}
	for _, peer := range e.peers {
		if peer == nil {
			continue
		}
		if peer.TransportLastError != "" {
			peer.DataState = PeerDataStateFailed
			continue
		}
		if peer.ControlState == PeerControlStateDegraded && !peerInbandHeartbeatHealthyAt(peer, now) {
			peer.ControlState = PeerControlStateDisconnected
		}
		if (peer.ControlState == "" || peer.ControlState == PeerControlStateDisconnected) && peerInbandHeartbeatHealthyAt(peer, now) {
			peer.ControlState = PeerControlStateDegraded
		}
		if peerInbandPathHealthHealthyAt(peer, now) {
			peer.State = PeerStateConnected
			peer.DataState = PeerDataStateAlive
			continue
		}
		if peer.DataState == PeerDataStateAlive && !peerDataPathAlive(peer) {
			peer.DataState = PeerDataStateStale
		}
	}
}

func (e *engine) peerRetainsAfterCoordinatorLoss(nodeID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.updateStatusCountersLocked()
	return peerRetainsAfterCoordinatorLossAt(e.peers[nodeID], time.Now())
}

func peerRetainsAfterCoordinatorLossAt(peer *PeerStatus, now time.Time) bool {
	return peerDataPlaneHealthyAt(peer, now) || peerInbandHeartbeatHealthyAt(peer, now)
}

func peerDataPlaneHealthyAt(peer *PeerStatus, now time.Time) bool {
	if peer == nil || peer.TransportLastError != "" {
		return false
	}
	return peerDataPathAlive(peer) || peerInbandPathHealthHealthyAt(peer, now)
}

func peerInbandHeartbeatHealthyAt(peer *PeerStatus, now time.Time) bool {
	if peer == nil {
		return false
	}
	return timestampFreshAt(peer.LastInbandHeartbeatAt, now, inbandHealthWindow)
}

func peerInbandPathHealthHealthyAt(peer *PeerStatus, now time.Time) bool {
	if peer == nil {
		return false
	}
	return timestampFreshAt(peer.LastInbandPathHealthAt, now, inbandHealthWindow)
}

func timestampFreshAt(ts, now time.Time, window time.Duration) bool {
	if ts.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if window <= 0 {
		return true
	}
	return !ts.After(now) && now.Sub(ts) <= window
}
