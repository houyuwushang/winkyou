package proto

import (
	"encoding/json"
	"fmt"
	"time"
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
	Strategy       string            `json:"strategy,omitempty"`
	PlanID         string            `json:"plan_id,omitempty"`
	Event          string            `json:"event,omitempty"`
	PathID         string            `json:"path_id,omitempty"`
	ConnectionType string            `json:"connection_type,omitempty"`
	LocalAddr      string            `json:"local_addr,omitempty"`
	RemoteAddr     string            `json:"remote_addr,omitempty"`
	LocalKind      string            `json:"local_kind,omitempty"`
	RemoteKind     string            `json:"remote_kind,omitempty"`
	ErrorClass     string            `json:"error_class,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	TimeoutMS      int64             `json:"timeout_ms,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	Timestamp      time.Time         `json:"timestamp,omitempty"`
}

type ProbeScript struct {
	Strategy string   `json:"strategy,omitempty"`
	Steps    []string `json:"steps,omitempty"`
}

type ProbeResult struct {
	PlanID         string `json:"plan_id,omitempty"`
	PathID         string `json:"path_id,omitempty"`
	Success        bool   `json:"success"`
	SelectedPathID string `json:"selected_path_id,omitempty"`
	ErrorClass     string `json:"error_class,omitempty"`
}

type PathCommit struct {
	Strategy       string `json:"strategy,omitempty"`
	PathID         string `json:"path_id,omitempty"`
	ConnectionType string `json:"connection_type,omitempty"`
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
