package client

import (
	"context"
	"time"

	coordclient "winkyou/pkg/coordinator/client"
	"winkyou/pkg/nat"
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

	switch signal.Type {
	case coordclient.SIGNAL_ICE_OFFER:
		go e.handleOffer(signal)
	case coordclient.SIGNAL_ICE_ANSWER:
		go e.handleAnswer(signal)
	case coordclient.SIGNAL_ICE_CANDIDATE:
		go e.handleCandidate(signal)
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
		_ = s.agent.Close()
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

func (e *engine) newICEAgent(ctx context.Context) (nat.ICEAgent, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.nat == nil {
		return nil, ErrEngineNotStarted
	}
	return e.nat.NewICEAgent(nat.ICEConfig{ConnectTimeout: 5 * time.Second, STUNServers: e.cfg.NAT.STUNServers, TURNServers: toNATTURNServers(e.cfg.NAT.TURNServers)})
}
