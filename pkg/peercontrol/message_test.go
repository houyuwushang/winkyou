package peercontrol

import (
	"strings"
	"testing"
	"time"
)

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
