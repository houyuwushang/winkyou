package client

import (
	"time"

	coordclient "winkyou/pkg/coordinator/client"
	"winkyou/pkg/logger"
	"winkyou/pkg/tunnel"
)

type peerManager struct {
	sessions map[string]*peerSession
}

func (e *engine) initPeerManager() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.peerMgr == nil {
		e.peerMgr = &peerManager{sessions: make(map[string]*peerSession)}
	}
}

func (e *engine) handlePeerUpdate(peer *coordclient.PeerInfo, event coordclient.PeerEvent) {
	if peer == nil || peer.NodeID == e.currentNodeID() {
		return
	}
	e.upsertPeer(peer, peerEventFromCoordinator(event))
	if peer.Online {
		e.startPeerConnect(peer.NodeID)
		return
	}
	if e.peerDataPathAlive(peer.NodeID) {
		e.persistState()
		return
	}
	e.cleanupPeer(peer.NodeID)
}

func (e *engine) handleSignal(signal *coordclient.SignalNotification) {
	if signal == nil || signal.FromNode == "" {
		return
	}
	// keep last-seen/connecting observable
	e.mu.Lock()
	peer, ok := e.peers[signal.FromNode]
	if !ok {
		peer = &PeerStatus{
			NodeID:         signal.FromNode,
			State:          PeerStateDisconnected,
			ControlState:   PeerControlStateConnected,
			DataState:      PeerDataStateConnecting,
			ConnectionType: ConnectionTypeDirect,
		}
		e.peers[signal.FromNode] = peer
	}
	peer.ControlState = PeerControlStateConnected
	if peer.State == PeerStateDisconnected {
		peer.State = PeerStateConnecting
	}
	if peer.DataState == "" || peer.DataState == PeerDataStateStale {
		peer.DataState = PeerDataStateConnecting
	}
	peer.LastSeen = time.Now()
	e.updateStatusCountersLocked()
	e.mu.Unlock()
	e.persistState()

	msg, ok, err := inboundSolverMessageFromSignal(signal)
	if err != nil {
		e.log.Warn("failed to decode peer signal", logger.String("node_id", signal.FromNode), logger.Error(err))
		return
	}
	if ok {
		go e.handlePeerSolverMessage(signal.FromNode, msg)
	}
}

func (e *engine) cleanupPeer(nodeID string) {
	e.mu.Lock()
	if p := e.peers[nodeID]; p != nil {
		p.State = PeerStateDisconnected
		p.ControlState = PeerControlStateDisconnected
		p.DataState = PeerDataStateFailed
		p.Endpoint = nil
	}
	s := (*peerSession)(nil)
	if e.peerMgr != nil {
		s = e.peerMgr.sessions[nodeID]
		delete(e.peerMgr.sessions, nodeID)
	}
	e.updateStatusCountersLocked()
	e.mu.Unlock()
	if s != nil {
		e.closePeerSession(s)
	}

	e.mu.RLock()
	peer := e.peers[nodeID]
	e.mu.RUnlock()
	if peer != nil {
		if pub, err := tunnel.ParsePublicKey(peer.PublicKey); err == nil && e.tun != nil {
			e.logCleanupError("remove tunnel peer", e.tun.RemovePeer(pub), logger.String("node_id", nodeID))
		}
	}
	e.persistState()
}

func (e *engine) peerDataPathAlive(nodeID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.updateStatusCountersLocked()
	return peerDataPathAlive(e.peers[nodeID])
}

func peerDataPathAlive(peer *PeerStatus) bool {
	if peer == nil || peer.LastHandshake.IsZero() || peer.TransportLastError != "" {
		return false
	}
	return peer.State == PeerStateConnected ||
		peer.TransportTxPackets > 0 ||
		peer.TransportRxPackets > 0 ||
		peer.TxBytes > 0 ||
		peer.RxBytes > 0
}
