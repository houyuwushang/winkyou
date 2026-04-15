package client

import (
	"time"

	"winkyou/pkg/tunnel"
)

func (e *engine) startTunnelEventLoop() {
	if e.tun == nil || e.runCtx == nil {
		return
	}

	events := e.tun.Events()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-e.runCtx.Done():
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				e.handleTunnelEvent(event)
			}
		}
	}()
}

func (e *engine) handleTunnelEvent(event tunnel.TunnelEvent) {
	switch event.Type {
	case tunnel.EventPeerHandshake:
		e.markPeerConnected(event.PeerKey, event.Timestamp)
	}
}

func (e *engine) markPeerConnected(publicKey tunnel.PublicKey, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}

	publicKeyText := publicKey.String()

	var (
		snapshot *PeerStatus
		handlers []func(peer *PeerStatus, event PeerEvent)
	)
	e.mu.Lock()
	for nodeID, peer := range e.peers {
		if peer == nil || peer.PublicKey != publicKeyText {
			continue
		}

		peer.State = PeerStateConnected
		peer.LastSeen = at

		if e.peerMgr != nil {
			if session := e.peerMgr.sessions[nodeID]; session != nil {
				session.connectMu.Lock()
				session.connected = true
				session.connecting = false
				session.retryDelay = 0
				session.retryPending = false
				path := session.lastPath
				session.connectMu.Unlock()
				if endpoint := udpAddrFromAddr(path.RemoteAddr); endpoint != nil {
					peer.Endpoint = endpoint
				}
				peer.ConnectionType = connectionTypeFromSummary(path.ConnectionType)
			}
		}

		e.updateStatusCountersLocked()
		snapshot = clonePeerStatus(peer)
		handlers = append([]func(peer *PeerStatus, event PeerEvent){}, e.peerHandlers...)
		break
	}
	e.mu.Unlock()

	if snapshot == nil {
		return
	}
	for _, handler := range handlers {
		handler(snapshot, PeerEventUpsert)
	}
	e.persistState()
}
