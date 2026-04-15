package proto

import (
	"encoding/json"
	"fmt"
)

const (
	MsgTypeCapability  = "capability"
	MsgTypeObservation = "observation"
	MsgTypeProbeScript = "probe_script"
	MsgTypeProbeResult = "probe_result"
	MsgTypePathCommit  = "path_commit"
)

type SessionEnvelope struct {
	SessionID string          `json:"session_id"`
	FromNode  string          `json:"from_node"`
	ToNode    string          `json:"to_node"`
	MsgType   string          `json:"msg_type"`
	Seq       uint64          `json:"seq"`
	Ack       uint64          `json:"ack"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type Capability struct {
	Strategies []string `json:"strategies,omitempty"`
}

type Observation struct {
	Notes []string `json:"notes,omitempty"`
}

type ProbeScript struct {
	Strategy string `json:"strategy,omitempty"`
}

type ProbeResult struct {
	PathID  string `json:"path_id,omitempty"`
	Success bool   `json:"success"`
}

type PathCommit struct {
	PathID string `json:"path_id,omitempty"`
}

func MarshalEnvelope(envelope SessionEnvelope) ([]byte, error) {
	if envelope.SessionID == "" {
		return nil, fmt.Errorf("rendezvous: session_id is required")
	}
	if envelope.MsgType == "" {
		return nil, fmt.Errorf("rendezvous: msg_type is required")
	}
	return json.Marshal(envelope)
}

func UnmarshalEnvelope(data []byte) (SessionEnvelope, error) {
	var envelope SessionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return SessionEnvelope{}, fmt.Errorf("rendezvous: unmarshal envelope: %w", err)
	}
	if envelope.SessionID == "" {
		return SessionEnvelope{}, fmt.Errorf("rendezvous: session_id is required")
	}
	if envelope.MsgType == "" {
		return SessionEnvelope{}, fmt.Errorf("rendezvous: msg_type is required")
	}
	return envelope, nil
}

func MustPayload(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	raw, _ := json.Marshal(v)
	return raw
}
