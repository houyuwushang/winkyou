package client

import (
	"testing"
	"time"

	coordclient "winkyou/pkg/coordinator/client"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
)

func TestLegacySignalAdaptersRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name       string
		signalType coordclient.SignalType
		msgType    string
	}{
		{name: "offer", signalType: coordclient.SIGNAL_ICE_OFFER, msgType: legacyice.MessageTypeOffer},
		{name: "answer", signalType: coordclient.SIGNAL_ICE_ANSWER, msgType: legacyice.MessageTypeAnswer},
		{name: "candidate", signalType: coordclient.SIGNAL_ICE_CANDIDATE, msgType: legacyice.MessageTypeCandidate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inbound, ok, err := inboundSolverMessageFromSignal(&coordclient.SignalNotification{
				FromNode:  "node-b",
				ToNode:    "node-a",
				Type:      tt.signalType,
				Payload:   []byte("legacy-payload"),
				Timestamp: now.Unix(),
			})
			if err != nil {
				t.Fatalf("inboundSolverMessageFromSignal() error = %v", err)
			}
			if !ok {
				t.Fatal("inboundSolverMessageFromSignal() ok = false, want true")
			}
			if inbound.Kind != solver.MessageKindStrategy || inbound.Namespace != legacyice.Namespace || inbound.Type != tt.msgType {
				t.Fatalf("inbound message = %+v, want strategy/%s/%s", inbound, legacyice.Namespace, tt.msgType)
			}

			signalType, payload, err := outboundSignalForSolverMessage(inbound)
			if err != nil {
				t.Fatalf("outboundSignalForSolverMessage() error = %v", err)
			}
			if signalType != tt.signalType {
				t.Fatalf("signalType = %v, want %v", signalType, tt.signalType)
			}
			if string(payload) != "legacy-payload" {
				t.Fatalf("payload = %q, want legacy-payload", payload)
			}
		})
	}
}

func TestEnvelopeSignalAdaptersRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		msgType string
		payload any
	}{
		{
			name:    "capability",
			msgType: rproto.MsgTypeCapability,
			payload: rproto.Capability{Strategies: []string{"legacy_ice_udp"}},
		},
		{
			name:    "path_commit",
			msgType: rproto.MsgTypePathCommit,
			payload: rproto.PathCommit{Strategy: "legacy_ice_udp", PathID: "legacyice:direct:session/node-a/node-b", ConnectionType: "direct"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := rproto.MarshalEnvelope(rproto.SessionEnvelope{
				SessionID: "session/node-a/node-b",
				FromNode:  "node-a",
				ToNode:    "node-b",
				MsgType:   tt.msgType,
				Seq:       1,
				Payload:   rproto.MustPayload(tt.payload),
			})
			if err != nil {
				t.Fatalf("MarshalEnvelope() error = %v", err)
			}

			msg, ok, err := inboundSolverMessageFromSignal(&coordclient.SignalNotification{
				FromNode:  "node-a",
				ToNode:    "node-b",
				Type:      coordclient.SIGNAL_UNSPECIFIED,
				Payload:   payload,
				Timestamp: time.Now().Unix(),
			})
			if err != nil {
				t.Fatalf("inboundSolverMessageFromSignal() error = %v", err)
			}
			if !ok {
				t.Fatal("inboundSolverMessageFromSignal() ok = false, want true")
			}
			if msg.Kind != solver.MessageKindEnvelope || msg.Namespace != sessionEnvelopeNamespace || msg.Type != tt.msgType {
				t.Fatalf("message = %+v, want envelope/%s/%s", msg, sessionEnvelopeNamespace, tt.msgType)
			}

			signalType, outPayload, err := outboundSignalForSolverMessage(msg)
			if err != nil {
				t.Fatalf("outboundSignalForSolverMessage() error = %v", err)
			}
			if signalType != coordclient.SIGNAL_UNSPECIFIED {
				t.Fatalf("signalType = %v, want SIGNAL_UNSPECIFIED", signalType)
			}
			if string(outPayload) != string(payload) {
				t.Fatalf("payload round trip mismatch")
			}
		})
	}
}
