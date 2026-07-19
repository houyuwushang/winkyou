package peercontrol

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestControlEchoRoundTripPreservesRouteHeader(t *testing.T) {
	msg := NewControlEchoRequest("node-a", "node-c", "echo-1", []byte("hello"), 8)
	msg.Seq = 42
	msg.PathVector = append(msg.PathVector, "node-b")
	msg.HopLimit--

	raw, err := Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Type != TypeControlEchoRequest || got.Seq != 42 || got.HopLimit != 7 {
		t.Fatalf("message metadata = %#v", got)
	}
	if !slices.Equal(got.PathVector, []string{"node-a", "node-b"}) {
		t.Fatalf("path vector = %v", got.PathVector)
	}
	if got.ControlEcho == nil || got.ControlEcho.ID != "echo-1" || string(got.ControlEcho.Payload) != "hello" {
		t.Fatalf("control echo = %#v", got.ControlEcho)
	}
}

func TestValidateRoutedHeader(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Message)
		want string
	}{
		{
			name: "hop limit",
			edit: func(msg *Message) { msg.HopLimit = MaxHopLimit + 1 },
			want: "hop_limit",
		},
		{
			name: "empty path member",
			edit: func(msg *Message) { msg.PathVector = []string{"node-a", ""} },
			want: "path_vector[1]",
		},
		{
			name: "wrong origin",
			edit: func(msg *Message) { msg.PathVector = []string{"node-b"} },
			want: "must start with origin",
		},
		{
			name: "missing echo id",
			edit: func(msg *Message) { msg.ControlEcho.ID = "" },
			want: "control_echo.id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewControlEchoRequest("node-a", "node-c", "echo-1", nil, 8)
			tt.edit(&msg)
			err := Validate(msg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want contains %q", err, tt.want)
			}
		})
	}
}

func TestTopologyAnnouncementsRoundTrip(t *testing.T) {
	member := NewMemberAnnounce("node-a", MemberRecord{
		Revision:     3,
		LeaseMillis:  30_000,
		VirtualIP:    "fd00::a",
		Endpoints:    []string{"203.0.113.1:40000"},
		Capabilities: []string{"birthday_punch"},
		NATProfile:   "endpoint_dependent",
	}, 12)
	member.Seq = 21
	raw, err := Marshal(member)
	if err != nil {
		t.Fatalf("Marshal(member) error = %v", err)
	}
	gotMember, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal(member) error = %v", err)
	}
	if gotMember.To != BroadcastNodeID || gotMember.MemberRecord == nil {
		t.Fatalf("member announcement = %#v", gotMember)
	}
	if gotMember.MemberRecord.NodeID != "node-a" || gotMember.MemberRecord.VirtualIP != "fd00::a" {
		t.Fatalf("member record = %#v", gotMember.MemberRecord)
	}

	lsa := NewLinkState("node-a", LinkStateAdvertisement{
		Revision:       4,
		LeaseMillis:    30_000,
		TransitAllowed: true,
		Links: []LinkStateLink{
			{PeerID: "node-b", RTTMillis: 12},
		},
	}, 12)
	lsa.Seq = 22
	raw, err = Marshal(lsa)
	if err != nil {
		t.Fatalf("Marshal(lsa) error = %v", err)
	}
	if strings.Contains(string(raw), "control_only") {
		t.Fatalf("default data-capable link unexpectedly encoded control_only: %s", raw)
	}
	gotLSA, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal(lsa) error = %v", err)
	}
	if gotLSA.To != BroadcastNodeID || gotLSA.LinkState == nil || len(gotLSA.LinkState.Links) != 1 {
		t.Fatalf("link-state announcement = %#v", gotLSA)
	}
	if gotLSA.LinkState.Links[0].PeerID != "node-b" || gotLSA.LinkState.Links[0].RTTMillis != 12 ||
		gotLSA.LinkState.Links[0].ControlOnly {
		t.Fatalf("link state = %#v", gotLSA.LinkState)
	}
}

func TestLinkStateControlOnlyRoundTripIsBackwardCompatible(t *testing.T) {
	message := NewLinkState("node-a", LinkStateAdvertisement{
		Revision: 2, LeaseMillis: 30_000, TransitAllowed: true,
		Links: []LinkStateLink{{PeerID: "node-b", ControlOnly: true}},
	}, 8)
	message.Seq = 1
	raw, err := Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"control_only":true`) {
		t.Fatalf("control-only link was not encoded: %s", raw)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.LinkState == nil || len(got.LinkState.Links) != 1 || !got.LinkState.Links[0].ControlOnly {
		t.Fatalf("decoded control-only link = %#v", got.LinkState)
	}
}

func TestValidateTopologyAnnouncements(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want string
	}{
		{
			name: "member revision",
			msg:  NewMemberAnnounce("node-a", MemberRecord{LeaseMillis: 1_000}, 8),
			want: "revision",
		},
		{
			name: "member lease",
			msg:  NewMemberAnnounce("node-a", MemberRecord{Revision: 1}, 8),
			want: "lease_millis",
		},
		{
			name: "link self",
			msg: NewLinkState("node-a", LinkStateAdvertisement{
				Revision:    1,
				LeaseMillis: 1_000,
				Links:       []LinkStateLink{{PeerID: "node-a"}},
			}, 8),
			want: "self link",
		},
		{
			name: "link duplicate",
			msg: NewLinkState("node-a", LinkStateAdvertisement{
				Revision:    1,
				LeaseMillis: 1_000,
				Links: []LinkStateLink{
					{PeerID: "node-b"},
					{PeerID: "node-b"},
				},
			}, 8),
			want: "repeats peer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.msg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want contains %q", err, tt.want)
			}
		})
	}
}

func TestMarshalUnmarshalHeartbeat(t *testing.T) {
	msg := NewHeartbeat("node-a", "node-b", Heartbeat{
		ControlState: "disconnected",
		DataState:    "alive",
		LastPathID:   "legacyice/direct_prefer",
	})
	msg.Seq = 7

	raw, err := Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Version != Version || got.Type != TypeHeartbeat || got.From != "node-a" || got.To != "node-b" || got.Seq != 7 {
		t.Fatalf("message metadata = %#v", got)
	}
	if got.Heartbeat == nil || got.Heartbeat.DataState != "alive" || got.Heartbeat.LastPathID != "legacyice/direct_prefer" {
		t.Fatalf("heartbeat payload = %#v", got.Heartbeat)
	}
}

func TestValidateEndpointUpdateRequiresEndpoint(t *testing.T) {
	msg := NewEndpointUpdate("node-a", "node-b", EndpointUpdate{PathID: "path/1"})

	err := Validate(msg)
	if err == nil {
		t.Fatal("Validate() should reject endpoint update without endpoint")
	}
	if !strings.Contains(err.Error(), "endpoint_update.endpoint") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEndpointUpdateRoundTrip(t *testing.T) {
	msg := NewEndpointUpdate("node-a", "node-b", EndpointUpdate{
		PathID:   "direct/path",
		Endpoint: "203.0.113.10:50000",
		Reason:   "peer_observed_endpoint",
	})
	msg.Seq = 9

	raw, err := Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Type != TypeEndpointUpdate || got.Seq != 9 || got.EndpointUpdate == nil {
		t.Fatalf("endpoint update message = %#v", got)
	}
	if got.EndpointUpdate.PathID != "direct/path" || got.EndpointUpdate.Endpoint != "203.0.113.10:50000" || got.EndpointUpdate.Reason != "peer_observed_endpoint" {
		t.Fatalf("endpoint update payload = %#v", got.EndpointUpdate)
	}
}

func TestValidateRejectsBootstraplessMetadata(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want string
	}{
		{
			name: "version",
			msg:  Message{Version: 2, Type: TypeHeartbeat, From: "node-a", To: "node-b", SentAt: time.Now(), Heartbeat: &Heartbeat{}},
			want: "unsupported version",
		},
		{
			name: "from",
			msg:  Message{Version: Version, Type: TypeHeartbeat, To: "node-b", SentAt: time.Now(), Heartbeat: &Heartbeat{}},
			want: "from is required",
		},
		{
			name: "payload",
			msg:  Message{Version: Version, Type: TypeHeartbeat, From: "node-a", To: "node-b", SentAt: time.Now()},
			want: "payload is required",
		},
		{
			name: "type",
			msg:  Message{Version: Version, Type: MessageType("unknown"), From: "node-a", To: "node-b", SentAt: time.Now()},
			want: "unsupported message type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.msg)
			if err == nil {
				t.Fatal("Validate() should reject invalid message")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want contains %q", err, tt.want)
			}
		})
	}
}

func TestPathHealthRoundTrip(t *testing.T) {
	lastHandshake := time.Unix(1_700_000_000, 0).UTC()
	msg := NewPathHealth("node-a", "node-b", PathHealth{
		PathID:             "relayonly/turn_relay",
		Strategy:           "relay_only",
		ConnectionType:     "relay",
		Endpoint:           "203.0.113.10:50000",
		LastHandshake:      lastHandshake,
		TransportTxPackets: 3,
		TransportRxPackets: 4,
	})

	raw, err := Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.PathHealth == nil {
		t.Fatal("PathHealth payload is nil")
	}
	if got.PathHealth.Strategy != "relay_only" || got.PathHealth.Endpoint != "203.0.113.10:50000" {
		t.Fatalf("path health = %#v", got.PathHealth)
	}
	if !got.PathHealth.LastHandshake.Equal(lastHandshake) {
		t.Fatalf("last handshake = %v, want %v", got.PathHealth.LastHandshake, lastHandshake)
	}
}

func TestSessionSignalRoundTrip(t *testing.T) {
	msg := NewSessionSignal("node-a", "node-b", SessionSignal{
		Kind:      "strategy_message",
		Namespace: "legacyice",
		Type:      "offer",
		Payload:   []byte("payload"),
	})
	msg.Seq = 11

	raw, err := Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Type != TypeSessionSignal || got.SessionSignal == nil {
		t.Fatalf("message = %#v, want session signal", got)
	}
	if got.SessionSignal.Kind != "strategy_message" || got.SessionSignal.Namespace != "legacyice" || got.SessionSignal.Type != "offer" {
		t.Fatalf("session signal metadata = %#v", got.SessionSignal)
	}
	if string(got.SessionSignal.Payload) != "payload" {
		t.Fatalf("payload = %q, want payload", got.SessionSignal.Payload)
	}
}
