package client

import "time"

func (e *engine) iceGatherTimeout() time.Duration {
	if e.cfg.NAT.GatherTimeout > 0 {
		return e.cfg.NAT.GatherTimeout
	}
	return 10 * time.Second
}

func (e *engine) iceConnectTimeout() time.Duration {
	if e.cfg.NAT.ConnectTimeout > 0 {
		return e.cfg.NAT.ConnectTimeout
	}
	return 25 * time.Second
}

func (e *engine) iceCheckTimeout() time.Duration {
	if e.cfg.NAT.CheckTimeout > 0 {
		return e.cfg.NAT.CheckTimeout
	}
	return 12 * time.Second
}

func (e *engine) peerRetryInterval() time.Duration {
	if e.cfg.NAT.RetryInterval > 0 {
		return e.cfg.NAT.RetryInterval
	}
	return 2 * time.Second
}

func (e *engine) peerRetryMaxInterval() time.Duration {
	if e.cfg.NAT.RetryMaxInterval > 0 {
		return e.cfg.NAT.RetryMaxInterval
	}
	return 10 * time.Second
}

func (e *engine) schedulePeerRetry(nodeID string, session *peerSession) {
	if session == nil || !session.initiator || e.runCtx == nil {
		return
	}

	session.connectMu.Lock()
	if session.connected || session.tunnelAttached || session.retryPending {
		session.connectMu.Unlock()
		return
	}

	delay := session.retryDelay
	if delay <= 0 {
		delay = e.peerRetryInterval()
	} else {
		delay *= 2
	}
	if maxDelay := e.peerRetryMaxInterval(); delay > maxDelay {
		delay = maxDelay
	}
	session.retryDelay = delay
	session.retryPending = true
	session.connectMu.Unlock()

	go func(expected *peerSession, wait time.Duration) {
		timer := time.NewTimer(wait)
		defer timer.Stop()

		select {
		case <-e.runCtx.Done():
			return
		case <-timer.C:
		}

		e.mu.RLock()
		current := (*peerSession)(nil)
		if e.peerMgr != nil {
			current = e.peerMgr.sessions[nodeID]
		}
		e.mu.RUnlock()
		if current != expected {
			return
		}

		expected.connectMu.Lock()
		expected.retryPending = false
		expected.connectMu.Unlock()
		e.startPeerConnect(nodeID)
	}(session, delay)
}
