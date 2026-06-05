package client

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"winkyou/pkg/peercontrol"
)

const (
	InbandControlPort     = PingPort + 1
	inbandControlInterval = 5 * time.Second
	inbandHealthWindow    = 3 * inbandControlInterval
)

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
	e.mu.Lock()
	peer := e.peers[msg.From]
	if peer != nil {
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
	if msg.ReICERequest != nil {
		e.schedulePeerImprovementByID(msg.From)
	}
	if changed {
		e.persistState()
	}
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
