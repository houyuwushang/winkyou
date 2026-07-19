// Package birthdaypunch is a connectivity strategy that establishes a direct
// UDP path between hard NATs (symmetric/mixed) using multi-socket birthday-
// paradox punching plus port prediction, coordinated over the signaling channel.
// It wraps pkg/nat/puncher and hands the punched path to the data plane through
// the standard net.Conn boundary. See docs/BIRTHDAY-PUNCH-DESIGN.md.
package birthdaypunch

import (
	"encoding/json"
	"fmt"
	"time"

	"winkyou/pkg/solver"
)

const (
	Namespace = "birthdaypunch"
	// MessageTypeEndpoint advertises a node's public endpoint and NAT port model.
	MessageTypeEndpoint = "punch_endpoint"
	// MessageTypeStart triggers synchronized punching at a shared start time.
	MessageTypeStart = "punch_start"
)

// endpointPayload advertises this node's public endpoint and NAT external-port
// allocation model so the peer can predict which ports to punch.
type endpointPayload struct {
	SessionID    string    `json:"session_id"`
	PlanID       string    `json:"plan_id,omitempty"`
	PublicIP     string    `json:"public_ip"`
	ObservedPort int       `json:"observed_port"`
	Pattern      string    `json:"pattern"` // sequential/preserving/random/unknown
	Delta        int       `json:"delta"`
	SentAt       time.Time `json:"sent_at"`
}

// startPayload triggers synchronized punching. Both sides begin at StartAtUnixMs
// and punch for a window long enough to tolerate modest clock skew.
type startPayload struct {
	SessionID     string    `json:"session_id"`
	PlanID        string    `json:"plan_id,omitempty"`
	StartAtUnixMs int64     `json:"start_at_unix_ms"`
	SentAt        time.Time `json:"sent_at"`
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

func marshalEndpoint(p endpointPayload) ([]byte, error) { return json.Marshal(p) }

func unmarshalEndpoint(data []byte) (endpointPayload, error) {
	var p endpointPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return endpointPayload{}, fmt.Errorf("birthdaypunch: unmarshal endpoint: %w", err)
	}
	return p, nil
}

func marshalStart(p startPayload) ([]byte, error) { return json.Marshal(p) }

func unmarshalStart(data []byte) (startPayload, error) {
	var p startPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return startPayload{}, fmt.Errorf("birthdaypunch: unmarshal start: %w", err)
	}
	return p, nil
}
