package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/solver"
)

func TestSchedulePeerImprovementAllowsConnectedBoundPeerWithoutProtectedDirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Default()
	cfg.NAT.RetryInterval = time.Minute
	cfg.NAT.RetryMaxInterval = time.Minute
	session := &peerSession{
		bound:     true,
		connected: true,
		lastPath: solver.PathSummary{
			PathID:         "relay/path",
			ConnectionType: "relay",
			RemoteAddr:     &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 50000},
			Role:           solver.PathRolePrimaryCandidate,
			Dependencies: []solver.PathDependency{{
				Kind:   solver.PathDependencyRelay,
				Reason: "turn_or_relay_candidate",
			}},
		},
	}
	eng := &engine{
		cfg:    cfg,
		runCtx: ctx,
		peerMgr: &peerManager{sessions: map[string]*peerSession{
			"node-2": session,
		}},
	}

	eng.schedulePeerImprovement("node-2", session, false)

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if !session.improvePending {
		t.Fatal("connected bound peer should schedule protected-direct improvement")
	}
	if session.improveDelay != time.Minute {
		t.Fatalf("improve delay = %v, want %v", session.improveDelay, time.Minute)
	}
}

func TestSchedulePeerImprovementSkipsProtectedDirectPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := &peerSession{
		bound: true,
		lastPath: solver.PathSummary{
			PathID:         "direct/path",
			ConnectionType: "direct",
			Role:           solver.PathRoleProtectedDirect,
		},
	}
	eng := &engine{
		cfg:    config.Default(),
		runCtx: ctx,
		peerMgr: &peerManager{sessions: map[string]*peerSession{
			"node-2": session,
		}},
	}

	eng.schedulePeerImprovement("node-2", session, false)

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if session.improvePending {
		t.Fatal("protected direct path should not schedule improvement")
	}
}

func TestForcedSchedulePeerImprovementAllowsProtectedDirectPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Default()
	cfg.NAT.RetryInterval = time.Minute
	cfg.NAT.RetryMaxInterval = time.Minute
	session := &peerSession{
		bound: true,
		lastPath: solver.PathSummary{
			PathID:         "multipath:relay/path",
			ConnectionType: "relay",
			Role:           solver.PathRolePrimaryCandidate,
			Details: map[string]string{
				"protected_direct_path_id": "direct/path",
			},
		},
	}
	eng := &engine{
		cfg:    cfg,
		runCtx: ctx,
		peerMgr: &peerManager{sessions: map[string]*peerSession{
			"node-2": session,
		}},
	}

	eng.schedulePeerImprovement("node-2", session, true)

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if !session.improvePending {
		t.Fatal("forced re-ice should schedule improvement even when local path is already protected")
	}
	if session.improveDelay != forcedPeerImprovementDelay {
		t.Fatalf("improve delay = %v, want forced delay %v", session.improveDelay, forcedPeerImprovementDelay)
	}
}

func TestPeerSessionHookErrorDuringImprovementPreservesBoundPath(t *testing.T) {
	path := solver.PathSummary{
		PathID:         "signalrelay:path",
		ConnectionType: "relay",
		Role:           solver.PathRolePrimaryCandidate,
	}
	session := &peerSession{
		bound:     true,
		improving: true,
		lastPath:  path,
	}
	eng := &engine{
		peers: map[string]*PeerStatus{
			"node-2": {
				NodeID:       "node-2",
				State:        PeerStateConnected,
				DataState:    PeerDataStateAlive,
				LastPathID:   path.PathID,
				LastPathRole: string(path.Role),
			},
		},
	}

	eng.handlePeerSessionHookError("node-2", session, errors.New("legacyice: executor closed"))

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if !session.bound || !session.improving {
		t.Fatalf("session flags bound=%v improving=%v, want preserved", session.bound, session.improving)
	}
	if session.lastPath.PathID != path.PathID || session.lastPath.ConnectionType != path.ConnectionType {
		t.Fatalf("lastPath = %#v, want preserved %#v", session.lastPath, path)
	}
	peer := eng.peers["node-2"]
	if peer.DataState == PeerDataStateFailed || peer.LastPathID == "" {
		t.Fatalf("peer status = %#v, want bound path preserved", peer)
	}
}

func TestNextImprovementDelay(t *testing.T) {
	base := time.Minute
	max := 5 * time.Minute
	if got := nextImprovementDelay(&peerSession{}, base, max, true); got != forcedPeerImprovementDelay {
		t.Fatalf("forced delay = %v, want %v", got, forcedPeerImprovementDelay)
	}
	if got := nextImprovementDelay(&peerSession{}, base, max, false); got != base {
		t.Fatalf("initial delay = %v, want %v", got, base)
	}
	if got := nextImprovementDelay(&peerSession{improveDelay: base}, base, max, false); got != 2*base {
		t.Fatalf("backoff delay = %v, want %v", got, 2*base)
	}
	if got := nextImprovementDelay(&peerSession{improveDelay: max}, base, max, false); got != max {
		t.Fatalf("max delay = %v, want %v", got, max)
	}
}
