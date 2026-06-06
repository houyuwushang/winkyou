package signalrelay

import (
	"encoding/json"
	"fmt"
	"time"

	"winkyou/pkg/solver"
)

const (
	Namespace         = "signalrelay"
	MessageTypeReady  = "signal_ready"
	MessageTypePacket = "signal_packet"
	MessageTypeClose  = "signal_close"
)

type readyPayload struct {
	SessionID string    `json:"session_id"`
	PlanID    string    `json:"plan_id,omitempty"`
	SentAt    time.Time `json:"sent_at"`
}

type packetPayload struct {
	SessionID string    `json:"session_id"`
	PlanID    string    `json:"plan_id,omitempty"`
	Seq       uint64    `json:"seq"`
	Data      []byte    `json:"data"`
	SentAt    time.Time `json:"sent_at"`
}

type closePayload struct {
	SessionID string    `json:"session_id"`
	PlanID    string    `json:"plan_id,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	SentAt    time.Time `json:"sent_at"`
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

func marshalReadyPayload(payload readyPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func unmarshalReadyPayload(data []byte) (readyPayload, error) {
	var payload readyPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return readyPayload{}, fmt.Errorf("signalrelay: unmarshal ready payload: %w", err)
	}
	return payload, nil
}

func marshalPacketPayload(payload packetPayload) ([]byte, error) {
	return json.Marshal(payload)
}

func unmarshalPacketPayload(data []byte) (packetPayload, error) {
	var payload packetPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return packetPayload{}, fmt.Errorf("signalrelay: unmarshal packet payload: %w", err)
	}
	return payload, nil
}

func marshalClosePayload(payload closePayload) ([]byte, error) {
	return json.Marshal(payload)
}

func unmarshalClosePayload(data []byte) (closePayload, error) {
	var payload closePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return closePayload{}, fmt.Errorf("signalrelay: unmarshal close payload: %w", err)
	}
	return payload, nil
}
