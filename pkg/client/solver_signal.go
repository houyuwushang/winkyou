package client

import (
	"fmt"

	coordclient "winkyou/pkg/coordinator/client"
	rendezvousclient "winkyou/pkg/rendezvous/client"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
)

const sessionEnvelopeNamespace = "rendezvous.v2"

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
			return coordclient.SIGNAL_UNSPECIFIED, nil, fmt.Errorf("client: unsupported strategy namespace %q", msg.Namespace)
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
