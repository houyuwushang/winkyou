package client

import (
	"context"
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

	eng.schedulePeerImprovement("node-2", session)

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

	eng.schedulePeerImprovement("node-2", session)

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if session.improvePending {
		t.Fatal("protected direct path should not schedule improvement")
	}
}
