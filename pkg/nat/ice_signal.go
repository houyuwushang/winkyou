package nat

import (
	"encoding/json"
	"fmt"
)

// ICESessionDescriptionPayload is used as SIGNAL_ICE_OFFER/SIGNAL_ICE_ANSWER payload.
// It carries minimal ICE parameters required for candidate checks.
type ICESessionDescriptionPayload struct {
	Ufrag      string      `json:"ufrag"`
	Pwd        string      `json:"pwd"`
	Role       string      `json:"role"` // controlling|controlled
	Candidates []Candidate `json:"candidates,omitempty"`
}

// ICECandidatePayload is used as SIGNAL_ICE_CANDIDATE payload (trickle ICE).
type ICECandidatePayload struct {
	Candidate Candidate `json:"candidate"`
}

func MarshalICESessionDescriptionPayload(p ICESessionDescriptionPayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalICESessionDescriptionPayload(data []byte) (ICESessionDescriptionPayload, error) {
	var p ICESessionDescriptionPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return ICESessionDescriptionPayload{}, fmt.Errorf("nat: unmarshal ice session payload: %w", err)
	}
	return p, nil
}

func MarshalICECandidatePayload(p ICECandidatePayload) ([]byte, error) {
	return json.Marshal(p)
}

func UnmarshalICECandidatePayload(data []byte) (ICECandidatePayload, error) {
	var p ICECandidatePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return ICECandidatePayload{}, fmt.Errorf("nat: unmarshal ice candidate payload: %w", err)
	}
	return p, nil
}
