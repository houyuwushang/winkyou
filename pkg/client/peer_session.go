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
	iceState       nat.ConnectionState
	tunnelAttached bool
	connected      bool
	connecting     bool
	retryDelay     time.Duration
	retryPending   bool
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
	s.connectMu.Lock()
	if s.connected || s.tunnelAttached || s.connecting {
		s.connectMu.Unlock()
		return
	}
	s.connectMu.Unlock()
	go e.sendOffer(nodeID, s)
}

func (e *engine) sendOffer(nodeID string, s *peerSession) {
	ctx, cancel := context.WithTimeout(context.Background(), e.iceGatherTimeout())
	defer cancel()

	cands, err := s.agent.GatherCandidates(ctx)
	if err != nil {
		e.schedulePeerRetry(nodeID, s)
		return
	}
	ufrag, pwd, err := s.agent.GetLocalCredentials()
	if err != nil {
		e.schedulePeerRetry(nodeID, s)
		return
	}
	payload, err := marshalOfferPayload(peerOfferPayload{
		SessionID: s.sessionID,
		ICE:       nat.ICESessionDescriptionPayload{Ufrag: ufrag, Pwd: pwd, Role: iceRole(s.initiator), Candidates: cands},
		SentAt:    time.Now(),
	})
	if err != nil {
		e.schedulePeerRetry(nodeID, s)
		return
	}
	if e.coord != nil {
		if err := e.coord.SendSignal(ctx, nodeID, coordclient.SIGNAL_ICE_OFFER, payload); err != nil {
			e.schedulePeerRetry(nodeID, s)
			return
		}
	}
	e.schedulePeerRetry(nodeID, s)
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

	ctx, cancel := context.WithTimeout(context.Background(), e.iceGatherTimeout())
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
		if err := e.coord.SendSignal(ctx, signal.FromNode, coordclient.SIGNAL_ICE_ANSWER, answerPayload); err != nil {
			return
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), e.iceConnectTimeout())
	defer cancel()
	transport, pair, err := s.agent.Connect(ctx)
	if err != nil {
		s.connectMu.Lock()
		s.connecting = false
		s.connectMu.Unlock()
		e.schedulePeerRetry(nodeID, s)
		return
	}
	s.connectMu.Lock()
	s.transport = transport
	s.selectedPair = pair
	if iceAgent, ok := s.agent.(interface{ GetConnectionState() nat.ConnectionState }); ok {
		s.iceState = iceAgent.GetConnectionState()
	}
	s.connectMu.Unlock()

	e.log.Info("ice connected",
		"node_id", nodeID,
		"local_type", candidateTypeString(pair.Local),
		"remote_type", candidateTypeString(pair.Remote),
		"local_addr", candidateAddrString(pair.Local),
		"remote_addr", candidateAddrString(pair.Remote))

	if e.tun == nil {
		s.connectMu.Lock()
		s.connecting = false
		s.connectMu.Unlock()
		e.schedulePeerRetry(nodeID, s)
		return
	}
	if err := e.attachTunnelPeer(nodeID, transport, pair); err != nil {
		e.log.Warn("ice selected but tunnel attach failed",
			"node_id", nodeID,
			"error", err,
			"local_type", candidateTypeString(pair.Local),
			"remote_type", candidateTypeString(pair.Remote))
		s.connectMu.Lock()
		s.connecting = false
		s.connectMu.Unlock()
		e.schedulePeerRetry(nodeID, s)
		return
	}
	s.connectMu.Lock()
	s.tunnelAttached = true
	s.retryDelay = 0
	s.retryPending = false
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
		if pair != nil {
			p.ICEState = "connected"
			p.LocalCandidate = formatCandidateInfo(pair.Local)
			p.RemoteCandidate = formatCandidateInfo(pair.Remote)
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

func closePeerSession(session *peerSession) {
	if session == nil {
		return
	}

	session.connectMu.Lock()
	transport := session.transport
	session.transport = nil
	session.selectedPair = nil
	session.iceState = nat.ConnectionStateNew
	session.tunnelAttached = false
	session.connected = false
	session.connecting = false
	session.retryPending = false
	session.retryDelay = 0
	session.connectMu.Unlock()

	if transport != nil {
		_ = transport.Close()
	}
	if session.agent != nil {
		_ = session.agent.Close()
	}
}

func candidateTypeString(c *nat.Candidate) string {
	if c == nil {
		return ""
	}
	return c.Type.String()
}

func candidateAddrString(c *nat.Candidate) string {
	if c == nil || c.Address == nil {
		return ""
	}
	return c.Address.String()
}

func formatCandidateInfo(c *nat.Candidate) string {
	if c == nil {
		return ""
	}
	addr := ""
	if c.Address != nil {
		addr = c.Address.String()
	}
	return fmt.Sprintf("%s:%s", c.Type.String(), addr)
}
