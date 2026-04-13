package client

import (
	"fmt"
	"time"

	"winkyou/pkg/nat"
)

type peerOfferPayload struct {
	SessionID string                           `json:"session_id"`
	ICE       nat.ICESessionDescriptionPayload `json:"ice"`
	SentAt    time.Time                        `json:"sent_at"`
}

type peerAnswerPayload struct {
	SessionID string                           `json:"session_id"`
	ICE       nat.ICESessionDescriptionPayload `json:"ice"`
	SentAt    time.Time                        `json:"sent_at"`
}

type peerCandidatePayload struct {
	SessionID string                  `json:"session_id"`
	ICE       nat.ICECandidatePayload `json:"ice"`
	SentAt    time.Time               `json:"sent_at"`
}

func marshalOfferPayload(p peerOfferPayload) ([]byte, error) {
	b, err := nat.MarshalICESessionDescriptionPayload(p.ICE)
	if err != nil {
		return nil, err
	}
	wrap := struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: p.SessionID, ICE: b, SentAt: p.SentAt}
	return jsonMarshal(wrap)
}

func unmarshalOfferPayload(data []byte) (peerOfferPayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := jsonUnmarshal(data, &wrap); err != nil {
		return peerOfferPayload{}, fmt.Errorf("client: unmarshal offer payload: %w", err)
	}
	ice, err := nat.UnmarshalICESessionDescriptionPayload(wrap.ICE)
	if err != nil {
		return peerOfferPayload{}, err
	}
	return peerOfferPayload{SessionID: wrap.SessionID, ICE: ice, SentAt: wrap.SentAt}, nil
}

func marshalAnswerPayload(p peerAnswerPayload) ([]byte, error) {
	b, err := nat.MarshalICESessionDescriptionPayload(p.ICE)
	if err != nil {
		return nil, err
	}
	wrap := struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: p.SessionID, ICE: b, SentAt: p.SentAt}
	return jsonMarshal(wrap)
}

func unmarshalAnswerPayload(data []byte) (peerAnswerPayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := jsonUnmarshal(data, &wrap); err != nil {
		return peerAnswerPayload{}, fmt.Errorf("client: unmarshal answer payload: %w", err)
	}
	ice, err := nat.UnmarshalICESessionDescriptionPayload(wrap.ICE)
	if err != nil {
		return peerAnswerPayload{}, err
	}
	return peerAnswerPayload{SessionID: wrap.SessionID, ICE: ice, SentAt: wrap.SentAt}, nil
}

func marshalCandidatePayload(p peerCandidatePayload) ([]byte, error) {
	b, err := nat.MarshalICECandidatePayload(p.ICE)
	if err != nil {
		return nil, err
	}
	wrap := struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: p.SessionID, ICE: b, SentAt: p.SentAt}
	return jsonMarshal(wrap)
}

func unmarshalCandidatePayload(data []byte) (peerCandidatePayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := jsonUnmarshal(data, &wrap); err != nil {
		return peerCandidatePayload{}, fmt.Errorf("client: unmarshal candidate payload: %w", err)
	}
	ice, err := nat.UnmarshalICECandidatePayload(wrap.ICE)
	if err != nil {
		return peerCandidatePayload{}, err
	}
	return peerCandidatePayload{SessionID: wrap.SessionID, ICE: ice, SentAt: wrap.SentAt}, nil
}
