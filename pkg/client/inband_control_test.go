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

func TestInbandMessagesAllowBoundConnectingPeer(t *testing.T) {
	cfg := config.Default()
	eng := &engine{cfg: cfg}
	peer := &PeerStatus{
		NodeID:               "node-b",
		State:                PeerStateConnecting,
		ControlState:         PeerControlStateConnected,
		DataState:            PeerDataStateBound,
		ActivePathID:         "relay/path",
		LastPathID:           "relay/path",
		LastPathRole:         string(solver.PathRolePrimaryCandidate),
		LastPathDependencies: []string{"relay:turn_or_relay_candidate"},
		ConnectionType:       ConnectionTypeRelay,
	}

	messages := eng.inbandMessagesForPeer("node-a", peer)
	if len(messages) != 3 {
		t.Fatalf("len(messages) = %d, want heartbeat + path_health + re-ice", len(messages))
	}
	if messages[0].Type != peercontrol.TypeHeartbeat || messages[1].Type != peercontrol.TypePathHealth || messages[2].Type != peercontrol.TypeReICERequest {
		t.Fatalf("messages = %#v, want heartbeat/path_health/re-ice", messages)
	}

	peer.State = PeerStateDisconnected
	if peerInbandEligible(peer) {
		t.Fatal("disconnected peer should not be in-band eligible")
	}
}

func TestInbandMessagesReplayCachedSessionSignal(t *testing.T) {
	now := time.Now().UTC()
	eng := &engine{}
	signal := peercontrol.NewSessionSignal("node-a", "node-b", peercontrol.SessionSignal{
		Kind:      string(solver.MessageKindStrategy),
		Namespace: "test.strategy",
		Type:      "candidate",
		Payload:   []byte("candidate-payload"),
	})
	signal.Seq = 42
	signal.SentAt = now
	eng.cacheInbandSignal("node-b", signal, now)

	peer := &PeerStatus{
		NodeID:    "node-b",
		State:     PeerStateConnected,
		DataState: PeerDataStateAlive,
	}
	messages := eng.inbandMessagesForPeer("node-a", peer)
	var replay *peercontrol.Message
	for i := range messages {
		if messages[i].Type == peercontrol.TypeSessionSignal {
			replay = &messages[i]
			break
		}
	}
	if replay == nil {
		t.Fatalf("messages = %#v, want cached session_signal replay", messages)
	}
	if replay.Seq != 42 || replay.SessionSignal == nil {
		t.Fatalf("replay = %#v, want seq 42 session signal", replay)
	}
	if replay.SessionSignal.Namespace != "test.strategy" || string(replay.SessionSignal.Payload) != "candidate-payload" {
		t.Fatalf("replay session signal = %#v", replay.SessionSignal)
	}

	expired := eng.cachedInbandSignalsForPeer("node-b", now.Add(inbandSignalReplayTTL+time.Millisecond))
	if len(expired) != 0 {
		t.Fatalf("expired cached signals = %#v, want none", expired)
	}
}

func TestInbandMessageSeenDeduplicatesSessionSignalReplay(t *testing.T) {
	now := time.Unix(1_700_000_030, 0).UTC()
	eng := &engine{}
	msg := peercontrol.NewSessionSignal("node-b", "node-a", peercontrol.SessionSignal{
		Kind:      string(solver.MessageKindStrategy),
		Namespace: "test.strategy",
		Type:      "offer",
		Payload:   []byte("payload"),
	})
	msg.Seq = 7

	if eng.markInbandMessageSeen(msg, now) {
		t.Fatal("first signal should not be marked duplicate")
	}
	if !eng.markInbandMessageSeen(msg, now.Add(time.Second)) {
		t.Fatal("replayed signal should be marked duplicate")
	}
	msg.Seq = 8
	if eng.markInbandMessageSeen(msg, now.Add(2*time.Second)) {
		t.Fatal("different sequence should not be marked duplicate")
	}
	msg.Seq = 7
	if eng.markInbandMessageSeen(msg, now.Add(inbandSignalSeenTTL+time.Second)) {
		t.Fatal("expired duplicate marker should allow sequence after TTL")
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

func TestHandleInbandPathHealthLearnsRuntimePublicEndpointHint(t *testing.T) {
	cfg := config.Default()
	eng := &engine{
		cfg:    cfg,
		status: EngineStatus{NodeID: "node-a"},
		peers: map[string]*PeerStatus{
			"node-b": {NodeID: "node-b"},
		},
		runtimePublicEndpointHints: []string{"9.9.9.9:40000"},
	}

	msg := peercontrol.NewPathHealth("node-b", "node-a", peercontrol.PathHealth{
		Endpoint: "8.8.8.8:45678",
	})
	eng.handleInbandControlMessage(msg)

	want := []string{"9.9.9.9:40000", "8.8.8.8:45678"}
	if len(eng.runtimePublicEndpointHints) != len(want) {
		t.Fatalf("runtimePublicEndpointHints = %#v, want %#v", eng.runtimePublicEndpointHints, want)
	}
	for i, hint := range want {
		if eng.runtimePublicEndpointHints[i] != hint {
			t.Fatalf("runtimePublicEndpointHints = %#v, want %#v", eng.runtimePublicEndpointHints, want)
		}
	}

	eng.handleInbandControlMessage(msg)
	if len(eng.runtimePublicEndpointHints) != len(want) {
		t.Fatalf("runtimePublicEndpointHints after duplicate = %#v, want %#v", eng.runtimePublicEndpointHints, want)
	}
}

func TestHandleInbandPathHealthEndpointHintHonorsPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.AutoPublicEndpointHints = false
	eng := &engine{
		cfg:    cfg,
		status: EngineStatus{NodeID: "node-a"},
		peers: map[string]*PeerStatus{
			"node-b": {NodeID: "node-b"},
		},
	}
	eng.handleInbandControlMessage(peercontrol.NewPathHealth("node-b", "node-a", peercontrol.PathHealth{
		Endpoint: "8.8.8.8:45678",
	}))
	if len(eng.runtimePublicEndpointHints) != 0 {
		t.Fatalf("runtimePublicEndpointHints = %#v, want none when auto hints disabled", eng.runtimePublicEndpointHints)
	}

	cfg = config.Default()
	eng = &engine{
		cfg:    cfg,
		status: EngineStatus{NodeID: "node-a"},
		peers: map[string]*PeerStatus{
			"node-b": {NodeID: "node-b"},
		},
	}
	eng.handleInbandControlMessage(peercontrol.NewPathHealth("node-b", "node-a", peercontrol.PathHealth{
		Endpoint: "100.102.17.36:45678",
	}))
	if len(eng.runtimePublicEndpointHints) != 0 {
		t.Fatalf("runtimePublicEndpointHints = %#v, want untrusted CGNAT endpoint rejected", eng.runtimePublicEndpointHints)
	}

	cfg.NAT.DirectTrustedCIDRs = []string{"100.64.0.0/10"}
	eng = &engine{
		cfg:    cfg,
		status: EngineStatus{NodeID: "node-a"},
		peers: map[string]*PeerStatus{
			"node-b": {NodeID: "node-b"},
		},
	}
	eng.handleInbandControlMessage(peercontrol.NewPathHealth("node-b", "node-a", peercontrol.PathHealth{
		Endpoint: "100.102.17.36:45678",
	}))
	if len(eng.runtimePublicEndpointHints) != 1 || eng.runtimePublicEndpointHints[0] != "100.102.17.36:45678" {
		t.Fatalf("runtimePublicEndpointHints = %#v, want trusted CGNAT endpoint", eng.runtimePublicEndpointHints)
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
	if session.improveDelay != forcedPeerImprovementDelay {
		t.Fatalf("improve delay = %v, want forced delay %v", session.improveDelay, forcedPeerImprovementDelay)
	}
}

func TestHandleInbandReICERequestForcesImprovementWhenLocalPathProtected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.Default()
	cfg.NAT.RetryInterval = time.Minute
	cfg.NAT.RetryMaxInterval = time.Minute
	session := &peerSession{
		nodeID: "node-b",
		bound:  true,
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
		Reason: "peer_protected_direct_unavailable",
	})
	eng.handleInbandControlMessage(msg)

	session.connectMu.Lock()
	defer session.connectMu.Unlock()
	if !session.improvePending {
		t.Fatal("re-ice request should force protected-direct improvement even when local path is already protected")
	}
	if session.improveDelay != forcedPeerImprovementDelay {
		t.Fatalf("improve delay = %v, want forced delay %v", session.improveDelay, forcedPeerImprovementDelay)
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

func TestPeerMessageSenderFallsBackToInbandSignal(t *testing.T) {
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
		status:     EngineStatus{NodeID: "node-a"},
		inbandConn: sender,
		peers: map[string]*PeerStatus{
			"node-b": {
				NodeID:    "node-b",
				VirtualIP: net.ParseIP("127.0.0.1"),
				State:     PeerStateConnected,
				DataState: PeerDataStateAlive,
			},
		},
	}
	msg := solver.Message{
		Kind:      solver.MessageKindStrategy,
		Namespace: "test.strategy",
		Type:      "offer",
		Payload:   []byte("payload"),
	}
	if err := (peerMessageSender{engine: eng}).Send(context.Background(), "node-b", msg); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	buffer := make([]byte, 8192)
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	n, _, err := receiver.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("ReadFromUDP() error = %v", err)
	}
	got, err := peercontrol.Unmarshal(buffer[:n])
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Type != peercontrol.TypeSessionSignal || got.SessionSignal == nil {
		t.Fatalf("message = %#v, want session signal", got)
	}
	if got.From != "node-a" || got.To != "node-b" {
		t.Fatalf("message route = %s -> %s, want node-a -> node-b", got.From, got.To)
	}
	if got.SessionSignal.Kind != string(solver.MessageKindStrategy) || got.SessionSignal.Namespace != "test.strategy" || got.SessionSignal.Type != "offer" {
		t.Fatalf("session signal = %#v", got.SessionSignal)
	}
	if string(got.SessionSignal.Payload) != "payload" {
		t.Fatalf("payload = %q, want payload", got.SessionSignal.Payload)
	}
}
