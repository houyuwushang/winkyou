package client

import (
	"testing"
	"time"

	coordclient "winkyou/pkg/coordinator/client"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
	"winkyou/pkg/solver/strategy/tcpframed"
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
		{
			name:    "probe_script",
			msgType: rproto.MsgTypeProbeScript,
			payload: rproto.ProbeScript{ScriptType: "preflight_v1", PlanID: "probe/preflight", Steps: []rproto.ProbeStep{{Type: "report", Event: "probe_ready"}}},
		},
		{
			name:    "probe_result",
			msgType: rproto.MsgTypeProbeResult,
			payload: rproto.ProbeResult{ScriptType: "preflight_v1", PlanID: "probe/preflight", Success: true},
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

func TestGenericStrategySignalAdapterRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	msg := tcpframed.NewMessage(tcpframed.MessageTypeOffer, []byte(`{"session_id":"session/node-a/node-b"}`), now)

	signalType, payload, err := outboundSignalForSolverMessage(msg)
	if err != nil {
		t.Fatalf("outboundSignalForSolverMessage() error = %v", err)
	}
	if signalType != coordclient.SIGNAL_UNSPECIFIED {
		t.Fatalf("signalType = %v, want SIGNAL_UNSPECIFIED", signalType)
	}

	inbound, ok, err := inboundSolverMessageFromSignal(&coordclient.SignalNotification{
		FromNode:  "node-a",
		ToNode:    "node-b",
		Type:      signalType,
		Payload:   payload,
		Timestamp: now.Unix(),
	})
	if err != nil {
		t.Fatalf("inboundSolverMessageFromSignal() error = %v", err)
	}
	if !ok {
		t.Fatal("inboundSolverMessageFromSignal() ok = false, want true")
	}
	if inbound.Kind != solver.MessageKindStrategy || inbound.Namespace != tcpframed.Namespace || inbound.Type != tcpframed.MessageTypeOffer {
		t.Fatalf("inbound = %#v, want tcpframed offer", inbound)
	}
	if string(inbound.Payload) != string(msg.Payload) {
		t.Fatalf("payload = %q, want %q", inbound.Payload, msg.Payload)
	}
	if !inbound.ReceivedAt.Equal(now) {
		t.Fatalf("ReceivedAt = %s, want %s", inbound.ReceivedAt, now)
	}
}

func TestPeerControlSignalAdapterRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_010, 0).UTC()
	tests := []solver.Message{
		tcpframed.NewMessage(tcpframed.MessageTypeOffer, []byte(`{"session_id":"session/node-a/node-b"}`), now),
	}

	envelopePayload, err := rproto.MarshalEnvelope(rproto.SessionEnvelope{
		SessionID: "session/node-a/node-b",
		FromNode:  "node-a",
		ToNode:    "node-b",
		MsgType:   rproto.MsgTypeCapability,
		Seq:       7,
		Payload:   rproto.MustPayload(rproto.Capability{Strategies: []string{"legacy_ice_udp"}}),
	})
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}
	tests = append(tests, solver.Message{
		Kind:      solver.MessageKindEnvelope,
		Namespace: sessionEnvelopeNamespace,
		Type:      rproto.MsgTypeCapability,
		Payload:   envelopePayload,
	})

	for _, msg := range tests {
		signal, err := peerControlSignalForSolverMessage(msg)
		if err != nil {
			t.Fatalf("peerControlSignalForSolverMessage(%s/%s) error = %v", msg.Namespace, msg.Type, err)
		}
		got, err := solverMessageFromPeerControlSignal(signal, now)
		if err != nil {
			t.Fatalf("solverMessageFromPeerControlSignal(%s/%s) error = %v", signal.Namespace, signal.Type, err)
		}
		if got.Kind != msg.Kind || got.Namespace != msg.Namespace || got.Type != msg.Type {
			t.Fatalf("round trip metadata = %+v, want kind=%s namespace=%s type=%s", got, msg.Kind, msg.Namespace, msg.Type)
		}
		if string(got.Payload) != string(msg.Payload) {
			t.Fatalf("round trip payload mismatch for %s/%s", msg.Namespace, msg.Type)
		}
		if !got.ReceivedAt.Equal(now) {
			t.Fatalf("ReceivedAt = %s, want %s", got.ReceivedAt, now)
		}
	}
}
