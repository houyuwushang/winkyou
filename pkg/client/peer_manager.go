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
		peer = &PeerStatus{NodeID: signal.FromNode, State: PeerStateDisconnected, ConnectionType: ConnectionTypeDirect}
		e.peers[signal.FromNode] = peer
	}
	if peer.State == PeerStateDisconnected {
		peer.State = PeerStateConnecting
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
		closePeerSession(s)
	}

	e.mu.RLock()
	peer := e.peers[nodeID]
	e.mu.RUnlock()
	if peer != nil {
		if pub, err := tunnel.ParsePublicKey(peer.PublicKey); err == nil && e.tun != nil {
			_ = e.tun.RemovePeer(pub)
		}
	}
	e.persistState()
}
