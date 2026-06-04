package client

import (
	"encoding/json"
	"fmt"
	"time"

	coordclient "winkyou/pkg/coordinator/client"
	rendezvousclient "winkyou/pkg/rendezvous/client"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
)

const sessionEnvelopeNamespace = "rendezvous.v2"
const strategySignalKind = "strategy_message"

type strategySignalEnvelope struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Payload   []byte `json:"payload,omitempty"`
}

func outboundSignalForSolverMessage(msg solver.Message) (coordclient.SignalType, []byte, error) {
	switch msg.Kind {
	case solver.MessageKindEnvelope:
		if msg.Namespace != sessionEnvelopeNamespace {
			return coordclient.SIGNAL_UNSPECIFIED, nil, fmt.Errorf("client: unsupported envelope namespace %q", msg.Namespace)
		}
		if _, err := rproto.UnmarshalEnvelope(msg.Payload); err != nil {
			return coordclient.SIGNAL_UNSPECIFIED, nil, err
		}
		return coordclient.SIGNAL_UNSPECIFIED, append([]byte(nil), msg.Payload...), nil
	case solver.MessageKindStrategy:
		if msg.Namespace != legacyice.Namespace {
			payload, err := marshalStrategySignal(msg)
			if err != nil {
				return coordclient.SIGNAL_UNSPECIFIED, nil, err
			}
			return coordclient.SIGNAL_UNSPECIFIED, payload, nil
		}
		switch msg.Type {
		case legacyice.MessageTypeOffer:
			return coordclient.SIGNAL_ICE_OFFER, append([]byte(nil), msg.Payload...), nil
		case legacyice.MessageTypeAnswer:
			return coordclient.SIGNAL_ICE_ANSWER, append([]byte(nil), msg.Payload...), nil
		case legacyice.MessageTypeCandidate:
			return coordclient.SIGNAL_ICE_CANDIDATE, append([]byte(nil), msg.Payload...), nil
		default:
			return coordclient.SIGNAL_UNSPECIFIED, nil, fmt.Errorf("client: unsupported legacyice message type %q", msg.Type)
		}
	default:
		return coordclient.SIGNAL_UNSPECIFIED, nil, fmt.Errorf("client: unsupported solver message kind %q", msg.Kind)
	}
}

func inboundSolverMessageFromSignal(signal *coordclient.SignalNotification) (solver.Message, bool, error) {
	if signal == nil {
		return solver.Message{}, false, nil
	}

	switch signal.Type {
	case coordclient.SIGNAL_UNSPECIFIED:
		if msg, ok, err := strategyMessageFromSignal(signal, unixOrZero(signal.Timestamp)); ok || err != nil {
			return msg, ok, err
		}
		envelope, ok, err := rendezvousclient.EnvelopeFromSignal(signal)
		if err != nil || !ok {
			return solver.Message{}, ok, err
		}
		return solver.Message{
			Kind:       solver.MessageKindEnvelope,
			Namespace:  sessionEnvelopeNamespace,
			Type:       envelope.MsgType,
			Payload:    append([]byte(nil), signal.Payload...),
			ReceivedAt: unixOrZero(signal.Timestamp),
		}, true, nil
	case coordclient.SIGNAL_ICE_OFFER:
		return legacyice.NewMessage(legacyice.MessageTypeOffer, signal.Payload, unixOrZero(signal.Timestamp)), true, nil
	case coordclient.SIGNAL_ICE_ANSWER:
		return legacyice.NewMessage(legacyice.MessageTypeAnswer, signal.Payload, unixOrZero(signal.Timestamp)), true, nil
	case coordclient.SIGNAL_ICE_CANDIDATE:
		return legacyice.NewMessage(legacyice.MessageTypeCandidate, signal.Payload, unixOrZero(signal.Timestamp)), true, nil
	default:
		return solver.Message{}, false, nil
	}
}

func marshalStrategySignal(msg solver.Message) ([]byte, error) {
	if msg.Namespace == "" {
		return nil, fmt.Errorf("client: strategy message namespace is required")
	}
	if msg.Type == "" {
		return nil, fmt.Errorf("client: strategy message type is required")
	}
	return json.Marshal(strategySignalEnvelope{
		Kind:      strategySignalKind,
		Namespace: msg.Namespace,
		Type:      msg.Type,
		Payload:   append([]byte(nil), msg.Payload...),
	})
}

func strategyMessageFromSignal(signal *coordclient.SignalNotification, receivedAt time.Time) (solver.Message, bool, error) {
	if signal == nil || signal.Type != coordclient.SIGNAL_UNSPECIFIED || len(signal.Payload) == 0 {
		return solver.Message{}, false, nil
	}
	var envelope strategySignalEnvelope
	if err := json.Unmarshal(signal.Payload, &envelope); err != nil {
		return solver.Message{}, false, nil
	}
	if envelope.Kind == "" {
		return solver.Message{}, false, nil
	}
	if envelope.Kind != strategySignalKind {
		return solver.Message{}, true, fmt.Errorf("client: unsupported unspecified signal kind %q", envelope.Kind)
	}
	if envelope.Namespace == "" || envelope.Type == "" {
		return solver.Message{}, true, fmt.Errorf("client: strategy signal namespace and type are required")
	}
	return solver.Message{
		Kind:       solver.MessageKindStrategy,
		Namespace:  envelope.Namespace,
		Type:       envelope.Type,
		Payload:    append([]byte(nil), envelope.Payload...),
		ReceivedAt: receivedAt,
	}, true, nil
}
