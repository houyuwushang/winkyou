package client

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"winkyou/pkg/logger"
	sesspkg "winkyou/pkg/session"
	"winkyou/pkg/solver"
	"winkyou/pkg/tunnel"
)

type peerSession struct {
	nodeID       string
	sessionID    string
	initiator    bool
	runner       *sesspkg.Session
	connected    bool
	bound        bool
	connecting   bool
	retryDelay   time.Duration
	retryPending bool
	lastPath     solver.PathSummary
	connectMu    sync.Mutex
}

type peerMessageSender struct {
	engine *engine
}

func (e *engine) ensurePeerSession(nodeID string) (*peerSession, error) {
	for {
		e.mu.RLock()
		if e.peerMgr == nil {
			e.mu.RUnlock()
			return nil, fmt.Errorf("client: peer manager not ready")
		}
		if existing, ok := e.peerMgr.sessions[nodeID]; ok {
			state := peerSessionState(existing)
			e.mu.RUnlock()
			if state != sesspkg.StateFailed && state != sesspkg.StateClosed {
				return existing, nil
			}
			e.mu.Lock()
			if e.peerMgr != nil && e.peerMgr.sessions[nodeID] == existing {
				delete(e.peerMgr.sessions, nodeID)
			}
			e.mu.Unlock()
			closePeerSession(existing)
			continue
		}

		localID := e.status.NodeID
		e.mu.RUnlock()

		s := &peerSession{
			nodeID:    nodeID,
			sessionID: sessionIDForNodes(localID, nodeID),
			initiator: localID < nodeID,
		}

		runner, err := e.newPeerRunner(s)
		if err != nil {
			return nil, err
		}
		s.runner = runner

		e.mu.Lock()
		if e.peerMgr == nil {
			e.mu.Unlock()
			_ = runner.Close()
			return nil, fmt.Errorf("client: peer manager not ready")
		}
		if existing, ok := e.peerMgr.sessions[nodeID]; ok {
			e.mu.Unlock()
			_ = runner.Close()
			return existing, nil
		}
		e.peerMgr.sessions[nodeID] = s
		e.mu.Unlock()
		return s, nil
	}
}

func (e *engine) startPeerConnect(nodeID string) {
	s, err := e.ensurePeerSession(nodeID)
	if err != nil || !s.initiator {
		return
	}
	e.startPeerSession(s)
}

func (e *engine) startPeerSession(s *peerSession) {
	if s == nil || s.runner == nil {
		return
	}

	s.connectMu.Lock()
	if s.connected || s.bound || s.connecting {
		s.connectMu.Unlock()
		return
	}
	s.connecting = true
	s.connectMu.Unlock()

	if err := s.runner.Start(e.sessionContext()); err != nil {
		e.handlePeerSessionError(s.nodeID, s, err)
	}
}

func (e *engine) newPeerRunner(s *peerSession) (*sesspkg.Session, error) {
	strategy := e.newLegacyICEStrategy()
	return sesspkg.New(sesspkg.Config{
		SessionID:   s.sessionID,
		LocalNodeID: e.currentNodeID(),
		PeerID:      s.nodeID,
		Initiator:   s.initiator,
		Strategy:    strategy,
		Binder:      sesspkg.NewTunnelBinder(e.tun, e),
		Sender:      peerMessageSender{engine: e},
		RunTimeout:  e.legacyICERunTimeout(),
		Hooks: sesspkg.Hooks{
			OnStateChange: func(state sesspkg.State) {
				e.handlePeerSessionState(s.nodeID, s, state)
			},
			OnBound: func(result solver.Result) {
				e.handlePeerSessionBound(s.nodeID, s, result)
			},
			OnError: func(err error) {
				e.handlePeerSessionError(s.nodeID, s, err)
			},
		},
	})
}

func (e *engine) handlePeerSolverMessage(nodeID string, msg solver.Message) {
	s, err := e.ensurePeerSession(nodeID)
	if err != nil {
		return
	}
	e.startPeerSession(s)
	if err := s.runner.HandleMessage(e.sessionContext(), msg); err != nil {
		e.handlePeerSessionError(nodeID, s, err)
	}
}

func (e *engine) handlePeerSessionState(nodeID string, s *peerSession, state sesspkg.State) {
	if s == nil {
		return
	}

	s.connectMu.Lock()
	switch state {
	case sesspkg.StateNew:
		s.connecting = false
	case sesspkg.StatePlanning, sesspkg.StateExecuting, sesspkg.StateBinding:
		s.connecting = true
	case sesspkg.StateBound:
		s.bound = true
		s.connecting = false
	case sesspkg.StateFailed, sesspkg.StateClosed:
		s.bound = false
		s.connecting = false
	}
	s.connectMu.Unlock()

	if state == sesspkg.StatePlanning || state == sesspkg.StateExecuting || state == sesspkg.StateBinding || state == sesspkg.StateBound {
		e.mu.Lock()
		if peer := e.peers[nodeID]; peer != nil && peer.State != PeerStateConnected {
			peer.State = PeerStateConnecting
			peer.LastSeen = time.Now()
			e.updateStatusCountersLocked()
		}
		e.mu.Unlock()
		e.persistState()
	}
}

func (e *engine) handlePeerSessionBound(nodeID string, s *peerSession, result solver.Result) {
	if s == nil {
		return
	}

	s.connectMu.Lock()
	s.bound = true
	s.connecting = false
	s.retryDelay = 0
	s.retryPending = false
	s.lastPath = result.Summary
	s.connectMu.Unlock()

	var (
		snapshot *PeerStatus
		handlers []func(peer *PeerStatus, event PeerEvent)
	)

	e.mu.Lock()
	if peer := e.peers[nodeID]; peer != nil {
		peer.State = PeerStateConnecting
		peer.ConnectionType = connectionTypeFromSummary(result.Summary.ConnectionType)
		peer.Endpoint = udpAddrFromAddr(result.Summary.RemoteAddr)
		peer.ICEState = result.Summary.Details["ice_state"]
		peer.LocalCandidate = result.Summary.Details["local_candidate"]
		peer.RemoteCandidate = result.Summary.Details["remote_candidate"]
		peer.LastSeen = time.Now()
		e.updateStatusCountersLocked()
		snapshot = clonePeerStatus(peer)
		handlers = append([]func(peer *PeerStatus, event PeerEvent){}, e.peerHandlers...)
	}
	e.mu.Unlock()

	for _, handler := range handlers {
		handler(snapshot, PeerEventUpsert)
	}
	e.persistState()
}

func (e *engine) handlePeerSessionError(nodeID string, s *peerSession, err error) {
	if s == nil {
		return
	}

	s.connectMu.Lock()
	s.bound = false
	s.connecting = false
	s.connected = false
	s.lastPath = solver.PathSummary{}
	s.connectMu.Unlock()

	e.mu.Lock()
	if peer := e.peers[nodeID]; peer != nil {
		if peer.State != PeerStateDisconnected {
			peer.State = PeerStateConnecting
		}
		peer.LastSeen = time.Now()
		e.updateStatusCountersLocked()
	}
	e.mu.Unlock()
	e.persistState()

	if err != nil {
		e.log.Warn("peer session failed", logger.String("node_id", nodeID), logger.Error(err))
	}
	e.schedulePeerRetry(nodeID, s)
}

func (e *engine) BindingPeer(ctx context.Context, peerID string) (*sesspkg.BindingPeer, error) {
	e.mu.RLock()
	peer, ok := e.peers[peerID]
	e.mu.RUnlock()
	if !ok || peer == nil {
		return nil, ErrPeerNotFound
	}

	publicKey, err := tunnel.ParsePublicKey(peer.PublicKey)
	if err != nil {
		return nil, err
	}
	_, allowedIP, err := parsePeerAllowedIP(peer.VirtualIP)
	if err != nil {
		return nil, err
	}
	return &sesspkg.BindingPeer{
		PublicKey:  publicKey,
		AllowedIPs: []net.IPNet{*allowedIP},
		Endpoint:   cloneUDPAddr(peer.Endpoint),
		Keepalive:  10 * time.Second,
	}, nil
}

func (s peerMessageSender) Send(ctx context.Context, peerID string, msg solver.Message) error {
	if s.engine == nil || s.engine.coord == nil {
		return ErrEngineNotStarted
	}
	signalType, payload, err := outboundSignalForSolverMessage(msg)
	if err != nil {
		return err
	}
	return s.engine.coord.SendSignal(ctx, peerID, signalType, payload)
}

func peerSessionState(s *peerSession) sesspkg.State {
	if s == nil || s.runner == nil {
		return sesspkg.StateClosed
	}
	return s.runner.State()
}

func connectionTypeFromSummary(value string) ConnectionType {
	if value == "relay" {
		return ConnectionTypeRelay
	}
	return ConnectionTypeDirect
}

func sessionIDForNodes(localNodeID, peerNodeID string) string {
	parts := []string{localNodeID, peerNodeID}
	sort.Strings(parts)
	return fmt.Sprintf("session/%s/%s", parts[0], parts[1])
}

func parsePeerAllowedIP(ip net.IP) (net.IP, *net.IPNet, error) {
	maskBits := 32
	if ip.To4() == nil {
		maskBits = 128
	}
	return net.ParseCIDR(ip.String() + fmt.Sprintf("/%d", maskBits))
}

func udpAddrFromAddr(addr net.Addr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return cloneUDPAddr(udpAddr)
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	port, err := net.LookupPort("udp", portText)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port}
}

func (e *engine) sessionContext() context.Context {
	if e.runCtx != nil {
		return e.runCtx
	}
	return context.Background()
}

func closePeerSession(session *peerSession) {
	if session == nil {
		return
	}

	session.connectMu.Lock()
	runner := session.runner
	session.runner = nil
	session.bound = false
	session.connected = false
	session.connecting = false
	session.retryPending = false
	session.retryDelay = 0
	session.lastPath = solver.PathSummary{}
	session.connectMu.Unlock()

	if runner != nil {
		_ = runner.Close()
	}
}
