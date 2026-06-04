package tcpframed

import (
	"encoding/json"
	"fmt"
	"time"

	"winkyou/pkg/solver"
)

const (
	Namespace            = "tcpframed"
	MessageTypeOffer     = "tcp_offer"
	MessageTypeAnswer    = "tcp_answer"
	MessageTypeCandidate = "tcp_candidate"
)

type endpointPayload struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type offerPayload struct {
	SessionID string          `json:"session_id"`
	PlanID    string          `json:"plan_id,omitempty"`
	Endpoint  endpointPayload `json:"endpoint"`
	SentAt    time.Time       `json:"sent_at"`
}

type answerPayload struct {
	SessionID string    `json:"session_id"`
	PlanID    string    `json:"plan_id,omitempty"`
	Accepted  bool      `json:"accepted"`
	Error     string    `json:"error,omitempty"`
	SentAt    time.Time `json:"sent_at"`
}

type candidatePayload struct {
	SessionID string          `json:"session_id"`
	PlanID    string          `json:"plan_id,omitempty"`
	Endpoint  endpointPayload `json:"endpoint"`
	SentAt    time.Time       `json:"sent_at"`
}

func NewMessage(messageType string, payload []byte, receivedAt time.Time) solver.Message {
	return solver.Message{
		Kind:       solver.MessageKindStrategy,
		Namespace:  Namespace,
		Type:       messageType,
		Payload:    append([]byte(nil), payload...),
		ReceivedAt: receivedAt,
	}
}

func IsMessage(msg solver.Message) bool {
	return msg.Kind == solver.MessageKindStrategy && msg.Namespace == Namespace
}

func marshalOfferPayload(payload offerPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func unmarshalOfferPayload(data []byte) (offerPayload, error) {
	var payload offerPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return offerPayload{}, fmt.Errorf("tcpframed: unmarshal offer payload: %w", err)
	}
	return payload, nil
}

func marshalAnswerPayload(payload answerPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func unmarshalAnswerPayload(data []byte) (answerPayload, error) {
	var payload answerPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return answerPayload{}, fmt.Errorf("tcpframed: unmarshal answer payload: %w", err)
	}
	return payload, nil
}

func marshalCandidatePayload(payload candidatePayload) ([]byte, error) {
	return json.Marshal(payload)
}

func unmarshalCandidatePayload(data []byte) (candidatePayload, error) {
	var payload candidatePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return candidatePayload{}, fmt.Errorf("tcpframed: unmarshal candidate payload: %w", err)
	}
	return payload, nil
}
