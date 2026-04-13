package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	coordclient "winkyou/pkg/coordinator/client"
	"winkyou/pkg/nat"
	"winkyou/pkg/tunnel"
)

type peerSession struct {
	nodeID    string
	sessionID string
	initiator bool
	agent     nat.ICEAgent
	connected bool
	connectMu sync.Mutex
}

func (e *engine) ensurePeerSession(nodeID string) (*peerSession, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.peerMgr == nil {
		return nil, fmt.Errorf("client: peer manager not ready")
	}
	if s, ok := e.peerMgr.sessions[nodeID]; ok {
		return s, nil
	}
	agent, err := e.newICEAgent(context.Background())
	if err != nil {
		return nil, err
	}
	localID := e.status.NodeID
	s := &peerSession{nodeID: nodeID, sessionID: localID + "->" + nodeID, initiator: localID < nodeID, agent: agent}
	e.peerMgr.sessions[nodeID] = s
	return s, nil
}

func (e *engine) startPeerConnect(nodeID string) {
	s, err := e.ensurePeerSession(nodeID)
	if err != nil {
		return
	}
	if !s.initiator {
		return
	}
	go e.sendOffer(nodeID, s)
}

func (e *engine) sendOffer(nodeID string, s *peerSession) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cands, err := s.agent.GatherCandidates(ctx)
	if err != nil {
		return
	}
	payload, err := marshalOfferPayload(peerOfferPayload{
		SessionID: s.sessionID,
		ICE:       nat.ICESessionDescriptionPayload{Ufrag: s.sessionID, Pwd: s.sessionID + "-pwd", Role: "controlling", Candidates: cands},
		SentAt:    time.Now(),
	})
	if err != nil {
		return
	}
	if e.coord != nil {
		_ = e.coord.SendSignal(ctx, nodeID, coordclient.SIGNAL_ICE_OFFER, payload)
	}
}

func (e *engine) handleOffer(signal *coordclient.SignalNotification) {
	offer, err := unmarshalOfferPayload(signal.Payload)
	if err != nil {
		return
	}
	s, err := e.ensurePeerSession(signal.FromNode)
	if err != nil {
		return
	}
	_ = s.agent.SetRemoteCandidates(offer.ICE.Candidates)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	locals, err := s.agent.GatherCandidates(ctx)
	if err != nil {
		return
	}
	answerPayload, err := marshalAnswerPayload(peerAnswerPayload{SessionID: s.sessionID, ICE: nat.ICESessionDescriptionPayload{Ufrag: s.sessionID, Pwd: s.sessionID + "-pwd", Role: "controlled", Candidates: locals}, SentAt: time.Now()})
	if err != nil {
		return
	}
	if e.coord != nil {
		_ = e.coord.SendSignal(ctx, signal.FromNode, coordclient.SIGNAL_ICE_ANSWER, answerPayload)
	}

	e.tryConnectPeer(signal.FromNode, s)
}

func (e *engine) handleAnswer(signal *coordclient.SignalNotification) {
	ans, err := unmarshalAnswerPayload(signal.Payload)
	if err != nil {
		return
	}
	s, err := e.ensurePeerSession(signal.FromNode)
	if err != nil {
		return
	}
	if ans.SessionID == "" {
		return
	}
	_ = s.agent.SetRemoteCandidates(ans.ICE.Candidates)
	e.tryConnectPeer(signal.FromNode, s)
}

func (e *engine) handleCandidate(signal *coordclient.SignalNotification) {
	cand, err := unmarshalCandidatePayload(signal.Payload)
	if err != nil {
		return
	}
	s, err := e.ensurePeerSession(signal.FromNode)
	if err != nil {
		return
	}
	_ = s.agent.SetRemoteCandidates([]nat.Candidate{cand.ICE.Candidate})
	e.tryConnectPeer(signal.FromNode, s)
}

func (e *engine) tryConnectPeer(nodeID string, s *peerSession) {
	s.connectMu.Lock()
	if s.connected {
		s.connectMu.Unlock()
		return
	}
	s.connectMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, pair, err := s.agent.Connect(ctx)
	if err != nil {
		return
	}
	_ = conn.Close()
	if e.tun == nil {
		return
	}
	if err := e.attachTunnelPeer(nodeID, pair); err != nil {
		return
	}
	s.connectMu.Lock()
	s.connected = true
	s.connectMu.Unlock()
}

func (e *engine) attachTunnelPeer(nodeID string, pair *nat.CandidatePair) error {
	e.mu.RLock()
	peer, ok := e.peers[nodeID]
	e.mu.RUnlock()
	if !ok || peer == nil {
		return ErrPeerNotFound
	}
	pub, err := tunnel.ParsePublicKey(peer.PublicKey)
	if err != nil {
		return err
	}
	_, ipnet, err := net.ParseCIDR(peer.VirtualIP.String() + "/32")
	if err != nil {
		return err
	}
	pcfg := &tunnel.PeerConfig{PublicKey: pub, AllowedIPs: []net.IPNet{*ipnet}}
	if pair != nil && pair.Remote != nil {
		pcfg.Endpoint = pair.Remote.Address
	}
	if err := e.tun.AddPeer(pcfg); err != nil {
		return err
	}

	e.mu.Lock()
	if p := e.peers[nodeID]; p != nil {
		p.State = PeerStateConnected
		if pair != nil && pair.Remote != nil {
			p.Endpoint = cloneUDPAddr(pair.Remote.Address)
			if pair.Local != nil && (pair.Local.Type == nat.CandidateTypeRelay || pair.Remote.Type == nat.CandidateTypeRelay) {
				p.ConnectionType = ConnectionTypeRelay
			} else {
				p.ConnectionType = ConnectionTypeDirect
			}
		}
		p.LastSeen = time.Now()
	}
	e.updateStatusCountersLocked()
	e.mu.Unlock()
	e.persistState()
	return nil
}
