package client

import (
	"context"
	"net"
	"testing"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/peercontrol"
	"winkyou/pkg/solver"
)

func TestInbandMessagesForPeer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	eng := &engine{}
	peer := &PeerStatus{
		NodeID:             "node-b",
		State:              PeerStateConnected,
		ControlState:       PeerControlStateConnected,
		DataState:          PeerDataStateAlive,
		Endpoint:           &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 50000},
		LastHandshake:      now,
		TransportTxPackets: 3,
		TransportRxPackets: 4,
		ActivePathID:       "direct/path",
		LastPathID:         "relay/path",
		LastPathStrategy:   "legacy_ice_udp",
		ConnectionType:     ConnectionTypeDirect,
	}

	messages := eng.inbandMessagesForPeer("node-a", peer)
	if len(messages) != 2 {
		t.Fatalf("len(messages) = %d, want 2", len(messages))
	}

	heartbeat := messages[0]
	if heartbeat.Type != peercontrol.TypeHeartbeat || heartbeat.From != "node-a" || heartbeat.To != "node-b" {
		t.Fatalf("heartbeat metadata = %#v", heartbeat)
	}
	if heartbeat.Seq == 0 || heartbeat.Heartbeat == nil {
		t.Fatalf("heartbeat payload = %#v", heartbeat)
	}
	if heartbeat.Heartbeat.ControlState != PeerControlStateConnected.String() || heartbeat.Heartbeat.DataState != PeerDataStateAlive.String() {
		t.Fatalf("heartbeat states = %#v", heartbeat.Heartbeat)
	}
	if heartbeat.Heartbeat.LastPathID != "direct/path" {
		t.Fatalf("heartbeat last path = %q, want active path", heartbeat.Heartbeat.LastPathID)
	}

	health := messages[1]
	if health.Type != peercontrol.TypePathHealth || health.Seq != heartbeat.Seq+1 || health.PathHealth == nil {
		t.Fatalf("path health = %#v", health)
	}
	if health.PathHealth.PathID != "direct/path" || health.PathHealth.Strategy != "legacy_ice_udp" {
		t.Fatalf("path health path = %#v", health.PathHealth)
	}
	if health.PathHealth.Endpoint != "203.0.113.10:50000" {
		t.Fatalf("path health endpoint = %q", health.PathHealth.Endpoint)
	}
	if health.PathHealth.TransportTxPackets != 3 || health.PathHealth.TransportRxPackets != 4 {
		t.Fatalf("path health counters = %#v", health.PathHealth)
	}
	if !health.PathHealth.LastHandshake.Equal(now) {
		t.Fatalf("path health handshake = %v, want %v", health.PathHealth.LastHandshake, now)
	}
}

func TestInbandMessagesRequestReICEWhenProtectedDirectMissing(t *testing.T) {
	cfg := config.Default()
	eng := &engine{cfg: cfg}
	peer := &PeerStatus{
		NodeID:               "node-b",
		State:                PeerStateConnected,
		ControlState:         PeerControlStateConnected,
		DataState:            PeerDataStateAlive,
		ActivePathID:         "relay/path",
		LastPathID:           "relay/path",
		LastPathRole:         string(solver.PathRolePrimaryCandidate),
		LastPathDependencies: []string{"relay:turn_or_relay_candidate"},
		ConnectionType:       ConnectionTypeRelay,
	}

	messages := eng.inbandMessagesForPeer("node-a", peer)
	if len(messages) != 3 {
		t.Fatalf("len(messages) = %d, want 3", len(messages))
	}
	reICE := messages[2]
	if reICE.Type != peercontrol.TypeReICERequest || reICE.ReICERequest == nil {
		t.Fatalf("re-ice message = %#v", reICE)
	}
	if reICE.ReICERequest.PathID != "relay/path" || reICE.ReICERequest.Reason != "protected_direct_unavailable" {
		t.Fatalf("re-ice payload = %#v", reICE.ReICERequest)
	}

	peer.ProtectedDirectPathID = "direct/path"
	messages = eng.inbandMessagesForPeer("node-a", peer)
	if len(messages) != 2 {
		t.Fatalf("len(messages) with protected direct = %d, want 2", len(messages))
	}
}

func TestHandleInbandControlMessageUpdatesPeerTimestamps(t *testing.T) {
	eng := &engine{
		status: EngineStatus{NodeID: "node-a"},
		peers: map[string]*PeerStatus{
			"node-b": {NodeID: "node-b"},
		},
	}
	heartbeatAt := time.Unix(1_700_000_010, 0).UTC()
	ignored := peercontrol.NewHeartbeat("node-b", "node-c", peercontrol.Heartbeat{})
	ignored.SentAt = heartbeatAt
	eng.handleInbandControlMessage(ignored)
	if !eng.peers["node-b"].LastInbandHeartbeatAt.IsZero() {
		t.Fatalf("heartbeat timestamp changed for message to another node: %v", eng.peers["node-b"].LastInbandHeartbeatAt)
	}

	heartbeat := peercontrol.NewHeartbeat("node-b", "node-a", peercontrol.Heartbeat{})
	heartbeat.SentAt = heartbeatAt
	eng.handleInbandControlMessage(heartbeat)
	if !eng.peers["node-b"].LastInbandHeartbeatAt.Equal(heartbeatAt) {
		t.Fatalf("heartbeat timestamp = %v, want %v", eng.peers["node-b"].LastInbandHeartbeatAt, heartbeatAt)
	}
	if eng.peers["node-b"].ControlState != PeerControlStateDegraded {
		t.Fatalf("control state = %s, want degraded after in-band heartbeat", eng.peers["node-b"].ControlState)
	}

	pathHealthAt := heartbeatAt.Add(2 * time.Second)
	pathHealth := peercontrol.NewPathHealth("node-b", "node-a", peercontrol.PathHealth{})
	pathHealth.SentAt = pathHealthAt
	eng.handleInbandControlMessage(pathHealth)
	if !eng.peers["node-b"].LastInbandPathHealthAt.Equal(pathHealthAt) {
		t.Fatalf("path health timestamp = %v, want %v", eng.peers["node-b"].LastInbandPathHealthAt, pathHealthAt)
	}
	if eng.peers["node-b"].DataState != PeerDataStateAlive {
		t.Fatalf("data state = %s, want alive after in-band path_health", eng.peers["node-b"].DataState)
	}
}

func TestHandleInbandReICERequestSchedulesImprovement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Default()
	cfg.NAT.RetryInterval = time.Minute
	cfg.NAT.RetryMaxInterval = time.Minute
	session := &peerSession{
		nodeID: "node-b",
		bound:  true,
		lastPath: solver.PathSummary{
			PathID:         "relay/path",
			ConnectionType: "relay",
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
		status: EngineStatus{NodeID: "node-a"},
		peers: map[string]*PeerStatus{
			"node-b": {
				NodeID:    "node-b",
				State:     PeerStateConnected,
				DataState: PeerDataStateAlive,
			},
		},
		peerMgr: &peerManager{sessions: map[string]*peerSession{
			"node-b": session,
		}},
	}

	msg := peercontrol.NewReICERequest("node-b", "node-a", peercontrol.ReICERequest{
		PathID: "relay/path",
		Reason: "protected_direct_unavailable",
	})
	eng.handleInbandControlMessage(msg)

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if !session.improvePending {
		t.Fatal("re-ice request should schedule protected-direct improvement")
	}
	if session.improveDelay != time.Minute {
		t.Fatalf("improve delay = %v, want %v", session.improveDelay, time.Minute)
	}
}

func TestSendInbandControlSnapshotWritesHeartbeatAndPathHealth(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: InbandControlPort})
	if err != nil {
		t.Skipf("in-band control port unavailable: %v", err)
	}
	defer receiver.Close()

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP sender error = %v", err)
	}
	defer sender.Close()

	eng := &engine{
		status: EngineStatus{NodeID: "node-a"},
		peers: map[string]*PeerStatus{
			"node-b": {
				NodeID:    "node-b",
				VirtualIP: net.ParseIP("127.0.0.1"),
				State:     PeerStateConnected,
				DataState: PeerDataStateAlive,
			},
		},
	}

	eng.sendInbandControlSnapshot(sender)

	got := map[peercontrol.MessageType]bool{}
	buffer := make([]byte, 8192)
	for len(got) < 2 {
		if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		n, _, err := receiver.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("ReadFromUDP() error after receiving %v = %v", got, err)
		}
		msg, err := peercontrol.Unmarshal(buffer[:n])
		if err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		if msg.From != "node-a" || msg.To != "node-b" {
			t.Fatalf("message metadata = %#v", msg)
		}
		got[msg.Type] = true
	}

	if !got[peercontrol.TypeHeartbeat] || !got[peercontrol.TypePathHealth] {
		t.Fatalf("received message types = %#v", got)
	}
}
