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
	nodeID         string
	sessionID      string
	initiator      bool
	agent          nat.ICEAgent
	transport      nat.SelectedTransport
	selectedPair   *nat.CandidatePair
	tunnelAttached bool
	connected      bool
	connecting     bool
	connectMu      sync.Mutex
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
	localID := e.status.NodeID
	initiator := localID < nodeID
	agent, err := e.newICEAgent(context.Background(), initiator)
	if err != nil {
		return nil, err
	}
	s := &peerSession{
		nodeID:    nodeID,
		sessionID: localID + "->" + nodeID,
		initiator: initiator,
		agent:     agent,
	}
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
	ufrag, pwd, err := s.agent.GetLocalCredentials()
	if err != nil {
		return
	}
	payload, err := marshalOfferPayload(peerOfferPayload{
		SessionID: s.sessionID,
		ICE:       nat.ICESessionDescriptionPayload{Ufrag: ufrag, Pwd: pwd, Role: iceRole(s.initiator), Candidates: cands},
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
	if err := s.agent.SetRemoteCredentials(offer.ICE.Ufrag, offer.ICE.Pwd); err != nil {
		return
	}
	if err := s.agent.SetRemoteCandidates(offer.ICE.Candidates); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	locals, err := s.agent.GatherCandidates(ctx)
	if err != nil {
		return
	}
	ufrag, pwd, err := s.agent.GetLocalCredentials()
	if err != nil {
		return
	}
	answerPayload, err := marshalAnswerPayload(peerAnswerPayload{
		SessionID: s.sessionID,
		ICE:       nat.ICESessionDescriptionPayload{Ufrag: ufrag, Pwd: pwd, Role: iceRole(s.initiator), Candidates: locals},
		SentAt:    time.Now(),
	})
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
	if err := s.agent.SetRemoteCredentials(ans.ICE.Ufrag, ans.ICE.Pwd); err != nil {
		return
	}
	if err := s.agent.SetRemoteCandidates(ans.ICE.Candidates); err != nil {
		return
	}
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
	if err := s.agent.SetRemoteCandidates([]nat.Candidate{cand.ICE.Candidate}); err != nil {
		return
	}
	e.tryConnectPeer(signal.FromNode, s)
}

func (e *engine) tryConnectPeer(nodeID string, s *peerSession) {
	s.connectMu.Lock()
	if s.connected || s.tunnelAttached || s.connecting {
		s.connectMu.Unlock()
		return
	}
	s.connecting = true
	s.connectMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport, pair, err := s.agent.Connect(ctx)
	if err != nil {
		s.connectMu.Lock()
		s.connecting = false
		s.connectMu.Unlock()
		return
	}
	s.connectMu.Lock()
	s.transport = transport
	s.selectedPair = pair
	s.connectMu.Unlock()
	if e.tun == nil {
		s.connectMu.Lock()
		s.connecting = false
		s.connectMu.Unlock()
		return
	}
	if err := e.attachTunnelPeer(nodeID, transport, pair); err != nil {
		s.connectMu.Lock()
		s.connecting = false
		s.connectMu.Unlock()
		return
	}
	s.connectMu.Lock()
	s.tunnelAttached = true
	s.connecting = false
	s.connectMu.Unlock()
}

func (e *engine) attachTunnelPeer(nodeID string, transport nat.SelectedTransport, pair *nat.CandidatePair) error {
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
	pcfg := &tunnel.PeerConfig{
		PublicKey:  pub,
		AllowedIPs: []net.IPNet{*ipnet},
		Transport:  transport,
		Keepalive:  10 * time.Second,
	}
	if pair != nil && pair.Remote != nil {
		pcfg.Endpoint = pair.Remote.Address
	}
	if err := e.tun.AddPeer(pcfg); err != nil {
		return err
	}

	e.mu.Lock()
	if p := e.peers[nodeID]; p != nil {
		p.State = PeerStateConnecting
		if pair != nil && pair.Remote != nil {
			p.Endpoint = cloneUDPAddr(pair.Remote.Address)
			p.ConnectionType = connectionTypeFromCandidatePair(pair)
		}
		p.LastSeen = time.Now()
	}
	e.updateStatusCountersLocked()
	e.mu.Unlock()
	e.persistState()
	return nil
}

func iceRole(controlling bool) string {
	if controlling {
		return "controlling"
	}
	return "controlled"
}

func connectionTypeFromCandidatePair(pair *nat.CandidatePair) ConnectionType {
	if pair != nil && pair.Local != nil && pair.Remote != nil &&
		(pair.Local.Type == nat.CandidateTypeRelay || pair.Remote.Type == nat.CandidateTypeRelay) {
		return ConnectionTypeRelay
	}
	return ConnectionTypeDirect
}
