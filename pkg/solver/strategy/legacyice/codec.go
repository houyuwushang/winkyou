package legacyice

import (
	"encoding/json"
	"fmt"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

const (
	Namespace            = "legacyice"
	MessageTypeOffer     = "offer"
	MessageTypeAnswer    = "answer"
	MessageTypeCandidate = "candidate"
)

type offerPayload struct {
	SessionID string                           `json:"session_id"`
	PlanID    string                           `json:"plan_id,omitempty"`
	ICE       nat.ICESessionDescriptionPayload `json:"ice"`
	SentAt    time.Time                        `json:"sent_at"`
}

type answerPayload struct {
	SessionID string                           `json:"session_id"`
	PlanID    string                           `json:"plan_id,omitempty"`
	ICE       nat.ICESessionDescriptionPayload `json:"ice"`
	SentAt    time.Time                        `json:"sent_at"`
}

type candidatePayload struct {
	SessionID string                  `json:"session_id"`
	PlanID    string                  `json:"plan_id,omitempty"`
	ICE       nat.ICECandidatePayload `json:"ice"`
	SentAt    time.Time               `json:"sent_at"`
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
	icePayload, err := nat.MarshalICESessionDescriptionPayload(payload.ICE)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SessionID string    `json:"session_id"`
		PlanID    string    `json:"plan_id,omitempty"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: payload.SessionID, PlanID: payload.PlanID, ICE: icePayload, SentAt: payload.SentAt})
}

func unmarshalOfferPayload(data []byte) (offerPayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		PlanID    string    `json:"plan_id,omitempty"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := json.Unmarshal(data, &wrap); err != nil {
		return offerPayload{}, fmt.Errorf("legacyice: unmarshal offer payload: %w", err)
	}
	icePayload, err := nat.UnmarshalICESessionDescriptionPayload(wrap.ICE)
	if err != nil {
		return offerPayload{}, err
	}
	return offerPayload{SessionID: wrap.SessionID, PlanID: wrap.PlanID, ICE: icePayload, SentAt: wrap.SentAt}, nil
}

func marshalAnswerPayload(payload answerPayload) ([]byte, error) {
	icePayload, err := nat.MarshalICESessionDescriptionPayload(payload.ICE)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SessionID string    `json:"session_id"`
		PlanID    string    `json:"plan_id,omitempty"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: payload.SessionID, PlanID: payload.PlanID, ICE: icePayload, SentAt: payload.SentAt})
}

func unmarshalAnswerPayload(data []byte) (answerPayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		PlanID    string    `json:"plan_id,omitempty"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := json.Unmarshal(data, &wrap); err != nil {
		return answerPayload{}, fmt.Errorf("legacyice: unmarshal answer payload: %w", err)
	}
	icePayload, err := nat.UnmarshalICESessionDescriptionPayload(wrap.ICE)
	if err != nil {
		return answerPayload{}, err
	}
	return answerPayload{SessionID: wrap.SessionID, PlanID: wrap.PlanID, ICE: icePayload, SentAt: wrap.SentAt}, nil
}

func marshalCandidatePayload(payload candidatePayload) ([]byte, error) {
	icePayload, err := nat.MarshalICECandidatePayload(payload.ICE)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SessionID string    `json:"session_id"`
		PlanID    string    `json:"plan_id,omitempty"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: payload.SessionID, PlanID: payload.PlanID, ICE: icePayload, SentAt: payload.SentAt})
}

func unmarshalCandidatePayload(data []byte) (candidatePayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		PlanID    string    `json:"plan_id,omitempty"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := json.Unmarshal(data, &wrap); err != nil {
		return candidatePayload{}, fmt.Errorf("legacyice: unmarshal candidate payload: %w", err)
	}
	icePayload, err := nat.UnmarshalICECandidatePayload(wrap.ICE)
	if err != nil {
		return candidatePayload{}, err
	}
	return candidatePayload{SessionID: wrap.SessionID, PlanID: wrap.PlanID, ICE: icePayload, SentAt: wrap.SentAt}, nil
}
