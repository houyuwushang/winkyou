package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"winkyou/pkg/peercontrol"
	"winkyou/pkg/solver"
)

const (
	InbandControlPort     = PingPort + 1
	inbandControlInterval = 5 * time.Second
	inbandHealthWindow    = 3 * inbandControlInterval
	inbandSignalReplayTTL = 20 * time.Second
	inbandSignalSeenTTL   = 2 * time.Minute
	maxInbandSignalReplay = 16
)

var errInbandSignalUnavailable = errors.New("client: in-band solver signal unavailable")

type cachedInbandSignal struct {
	Message   peercontrol.Message
	ExpiresAt time.Time
}

func (e *engine) startInbandControl(bindIP net.IP) error {
	conn, err := listenInbandUDP(bindIP)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.inbandConn = conn
	e.mu.Unlock()

	e.wg.Add(2)
	go func() {
		defer e.wg.Done()
		e.runInbandControlReader(conn)
	}()
	go func() {
		defer e.wg.Done()
		e.runInbandControlSender(conn)
	}()
	return nil
}

func listenInbandUDP(bindIP net.IP) (*net.UDPConn, error) {
	candidates := []*net.UDPAddr{}
	if ip4 := bindIP.To4(); ip4 != nil {
		candidates = append(candidates, &net.UDPAddr{IP: append(net.IP(nil), ip4...), Port: InbandControlPort})
	}
	candidates = append(candidates, &net.UDPAddr{IP: net.IPv4zero, Port: InbandControlPort})

	var lastErr error
	for _, candidate := range candidates {
		conn, err := net.ListenUDP("udp4", candidate)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("client: listen in-band peer control udp on port %d: %w", InbandControlPort, lastErr)
}

func (e *engine) runInbandControlSender(conn *net.UDPConn) {
	e.sendInbandControlSnapshot(conn)
	ticker := time.NewTicker(inbandControlInterval)
	defer ticker.Stop()
	done := e.runDone()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			e.sendInbandControlSnapshot(conn)
		}
	}
}

func (e *engine) runInbandControlReader(conn *net.UDPConn) {
	buffer := make([]byte, 8192)
	done := e.runDone()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if done != nil {
					select {
					case <-done:
						return
					default:
					}
				}
				continue
			}
			return
		}
		_ = e.handleInbandControlPacket(buffer[:n])
	}
}

func (e *engine) sendInbandControlSnapshot(conn *net.UDPConn) {
	localNodeID, peers := e.inbandControlSnapshot()
	if localNodeID == "" || len(peers) == 0 {
		return
	}
	for _, peer := range peers {
		if peer == nil || peer.VirtualIP.To4() == nil || peer.NodeID == "" {
			continue
		}
		addr := &net.UDPAddr{IP: append(net.IP(nil), peer.VirtualIP.To4()...), Port: InbandControlPort}
		for _, msg := range e.inbandMessagesForPeer(localNodeID, peer) {
			raw, err := peercontrol.Marshal(msg)
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(raw, addr)
		}
	}
}

func (e *engine) inbandControlSnapshot() (string, []*PeerStatus) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	localNodeID := e.status.NodeID
	peers := make([]*PeerStatus, 0, len(e.peers))
	for _, peer := range e.peers {
		if peer == nil || !peerInbandEligible(peer) {
			continue
		}
		peers = append(peers, clonePeerStatus(peer))
	}
	return localNodeID, peers
}

func (e *engine) inbandMessagesForPeer(localNodeID string, peer *PeerStatus) []peercontrol.Message {
	lastPathID := firstString(peer.ActivePathID, peer.LastPathID)
	heartbeat := peercontrol.NewHeartbeat(localNodeID, peer.NodeID, peercontrol.Heartbeat{
		ControlState: peer.ControlState.String(),
		DataState:    peer.DataState.String(),
		LastPathID:   lastPathID,
	})
	heartbeat.Seq = atomic.AddUint64(&e.inbandSeq, 1)
	pathHealth := peercontrol.NewPathHealth(localNodeID, peer.NodeID, peercontrol.PathHealth{
		PathID:             lastPathID,
		Strategy:           peer.LastPathStrategy,
		ConnectionType:     peer.ConnectionType.String(),
		Endpoint:           udpAddrString(peer.Endpoint),
		LastHandshake:      peer.LastHandshake,
		TransportTxPackets: peer.TransportTxPackets,
		TransportRxPackets: peer.TransportRxPackets,
		LastError:          peer.TransportLastError,
	})
	pathHealth.Seq = atomic.AddUint64(&e.inbandSeq, 1)
	messages := []peercontrol.Message{heartbeat, pathHealth}
	if shouldRequestInbandReICE(e.multipathPathPolicy(), peer) {
		reICE := peercontrol.NewReICERequest(localNodeID, peer.NodeID, peercontrol.ReICERequest{
			PathID: lastPathID,
			Reason: "protected_direct_unavailable",
		})
		reICE.Seq = atomic.AddUint64(&e.inbandSeq, 1)
		messages = append(messages, reICE)
	}
	messages = append(messages, e.cachedInbandSignalsForPeer(peer.NodeID, time.Now())...)
	return messages
}

func (e *engine) handleInbandControlPacket(raw []byte) error {
	msg, err := peercontrol.Unmarshal(raw)
	if err != nil {
		return err
	}
	e.handleInbandControlMessage(msg)
	return nil
}

func (e *engine) handleInbandControlMessage(msg peercontrol.Message) {
	localNodeID := e.currentNodeID()
	if localNodeID != "" && msg.To != localNodeID {
		return
	}
	seenAt := msg.SentAt
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}

	changed := false
	knownPeer := false
	e.mu.Lock()
	peer := e.peers[msg.From]
	if peer != nil {
		knownPeer = true
		if msg.Heartbeat != nil {
			peer.LastInbandHeartbeatAt = seenAt
			if peer.ControlState == "" || peer.ControlState == PeerControlStateDisconnected {
				peer.ControlState = PeerControlStateDegraded
			}
			changed = true
		}
		if msg.PathHealth != nil {
			peer.LastInbandPathHealthAt = seenAt
			if peer.TransportLastError == "" {
				peer.State = PeerStateConnected
				peer.DataState = PeerDataStateAlive
			}
			if peer.ControlState == "" || peer.ControlState == PeerControlStateDisconnected {
				peer.ControlState = PeerControlStateDegraded
			}
			changed = true
		}
		if msg.ReICERequest != nil {
			changed = true
		}
		if changed {
			peer.LastSeen = seenAt
			e.applyPeerHealthStateLocked(seenAt)
		}
	}
	e.mu.Unlock()
	if knownPeer && msg.ReICERequest != nil {
		e.schedulePeerImprovementByID(msg.From)
	}
	if knownPeer && msg.SessionSignal != nil {
		if e.markInbandMessageSeen(msg, time.Now()) {
			return
		}
		if solverMsg, err := solverMessageFromPeerControlSignal(*msg.SessionSignal, seenAt); err == nil {
			go e.handlePeerSolverMessage(msg.From, solverMsg)
		}
	}
	if changed {
		e.persistState()
	}
}

func (e *engine) sendSolverMessageInband(ctx context.Context, peerID string, solverMsg solver.Message) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	signal, err := peerControlSignalForSolverMessage(solverMsg)
	if err != nil {
		return err
	}

	e.mu.RLock()
	conn := e.inbandConn
	localNodeID := e.status.NodeID
	peer := clonePeerStatus(e.peers[peerID])
	e.mu.RUnlock()
	if conn == nil || localNodeID == "" || peer == nil || !peerInbandEligible(peer) || peer.VirtualIP.To4() == nil {
		return errInbandSignalUnavailable
	}

	msg := peercontrol.NewSessionSignal(localNodeID, peer.NodeID, signal)
	msg.Seq = atomic.AddUint64(&e.inbandSeq, 1)
	e.cacheInbandSignal(peerID, msg, time.Now())
	raw, err := peercontrol.Marshal(msg)
	if err != nil {
		return err
	}
	addr := &net.UDPAddr{IP: append(net.IP(nil), peer.VirtualIP.To4()...), Port: InbandControlPort}
	_, err = conn.WriteToUDP(raw, addr)
	return err
}

func (e *engine) cacheInbandSignal(peerID string, msg peercontrol.Message, now time.Time) {
	if e == nil || peerID == "" || msg.Type != peercontrol.TypeSessionSignal || msg.Seq == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inbandSignals == nil {
		e.inbandSignals = map[string][]cachedInbandSignal{}
	}
	e.inbandSignals[peerID] = appendPrunedCachedInbandSignal(e.inbandSignals[peerID], cachedInbandSignal{
		Message:   clonePeerControlMessage(msg),
		ExpiresAt: now.Add(inbandSignalReplayTTL),
	}, now)
}

func (e *engine) cachedInbandSignalsForPeer(peerID string, now time.Time) []peercontrol.Message {
	if e == nil || peerID == "" {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.inbandSignals) == 0 {
		return nil
	}
	cached := pruneCachedInbandSignals(e.inbandSignals[peerID], now)
	if len(cached) == 0 {
		delete(e.inbandSignals, peerID)
		return nil
	}
	e.inbandSignals[peerID] = cached
	out := make([]peercontrol.Message, 0, len(cached))
	for _, item := range cached {
		out = append(out, clonePeerControlMessage(item.Message))
	}
	return out
}

func appendPrunedCachedInbandSignal(existing []cachedInbandSignal, next cachedInbandSignal, now time.Time) []cachedInbandSignal {
	pruned := pruneCachedInbandSignals(existing, now)
	pruned = append(pruned, next)
	if len(pruned) <= maxInbandSignalReplay {
		return pruned
	}
	return append([]cachedInbandSignal(nil), pruned[len(pruned)-maxInbandSignalReplay:]...)
}

func pruneCachedInbandSignals(values []cachedInbandSignal, now time.Time) []cachedInbandSignal {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	for _, item := range values {
		if item.ExpiresAt.After(now) {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (e *engine) markInbandMessageSeen(msg peercontrol.Message, seenAt time.Time) bool {
	if e == nil || msg.Seq == 0 {
		return false
	}
	if seenAt.IsZero() {
		seenAt = time.Now()
	}
	key := inbandSeenKey(msg)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inbandSeen == nil {
		e.inbandSeen = map[string]time.Time{}
	}
	for cachedKey, expiresAt := range e.inbandSeen {
		if !expiresAt.After(seenAt) {
			delete(e.inbandSeen, cachedKey)
		}
	}
	if _, ok := e.inbandSeen[key]; ok {
		return true
	}
	e.inbandSeen[key] = seenAt.Add(inbandSignalSeenTTL)
	return false
}

func inbandSeenKey(msg peercontrol.Message) string {
	return fmt.Sprintf("%s|%s|%d", msg.From, msg.Type, msg.Seq)
}

func clonePeerControlMessage(msg peercontrol.Message) peercontrol.Message {
	out := msg
	if msg.Heartbeat != nil {
		cp := *msg.Heartbeat
		out.Heartbeat = &cp
	}
	if msg.PathHealth != nil {
		cp := *msg.PathHealth
		out.PathHealth = &cp
	}
	if msg.EndpointUpdate != nil {
		cp := *msg.EndpointUpdate
		out.EndpointUpdate = &cp
	}
	if msg.CapabilityRefresh != nil {
		cp := *msg.CapabilityRefresh
		if len(cp.Strategies) > 0 {
			cp.Strategies = append([]string(nil), cp.Strategies...)
		}
		out.CapabilityRefresh = &cp
	}
	if msg.ReICERequest != nil {
		cp := *msg.ReICERequest
		out.ReICERequest = &cp
	}
	if msg.SessionSignal != nil {
		cp := *msg.SessionSignal
		if len(cp.Payload) > 0 {
			cp.Payload = append([]byte(nil), cp.Payload...)
		}
		out.SessionSignal = &cp
	}
	return out
}

func peerInbandEligible(peer *PeerStatus) bool {
	if peer.State != PeerStateConnected {
		return false
	}
	return peer.DataState == PeerDataStateAlive || peer.DataState == PeerDataStateBound
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (e *engine) runDone() <-chan struct{} {
	if e == nil {
		return nil
	}
	runCtx, ok := e.runContext()
	if !ok {
		return nil
	}
	return runCtx.Done()
}
