package peercontrol

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const Version = 1

type MessageType string

const (
	TypeHeartbeat         MessageType = "heartbeat"
	TypePathHealth        MessageType = "path_health"
	TypeEndpointUpdate    MessageType = "endpoint_update"
	TypeCapabilityRefresh MessageType = "capability_refresh"
	TypeReICERequest      MessageType = "re_ice_request"
	TypeSessionSignal     MessageType = "session_signal"
)

type Message struct {
	Version int         `json:"version"`
	Type    MessageType `json:"type"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Seq     uint64      `json:"seq,omitempty"`
	SentAt  time.Time   `json:"sent_at"`

	Heartbeat         *Heartbeat         `json:"heartbeat,omitempty"`
	PathHealth        *PathHealth        `json:"path_health,omitempty"`
	EndpointUpdate    *EndpointUpdate    `json:"endpoint_update,omitempty"`
	CapabilityRefresh *CapabilityRefresh `json:"capability_refresh,omitempty"`
	ReICERequest      *ReICERequest      `json:"re_ice_request,omitempty"`
	SessionSignal     *SessionSignal     `json:"session_signal,omitempty"`
}

type Heartbeat struct {
	ControlState string `json:"control_state,omitempty"`
	DataState    string `json:"data_state,omitempty"`
	LastPathID   string `json:"last_path_id,omitempty"`
}

type PathHealth struct {
	PathID             string    `json:"path_id,omitempty"`
	Strategy           string    `json:"strategy,omitempty"`
	ConnectionType     string    `json:"connection_type,omitempty"`
	Endpoint           string    `json:"endpoint,omitempty"`
	LastHandshake      time.Time `json:"last_handshake,omitempty"`
	TransportTxPackets uint64    `json:"transport_tx_packets,omitempty"`
	TransportRxPackets uint64    `json:"transport_rx_packets,omitempty"`
	LastError          string    `json:"last_error,omitempty"`
}

type EndpointUpdate struct {
	PathID   string `json:"path_id,omitempty"`
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason,omitempty"`
}

type CapabilityRefresh struct {
	Strategies []string `json:"strategies,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

type ReICERequest struct {
	PathID string `json:"path_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type SessionSignal struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"`
	Payload   []byte `json:"payload,omitempty"`
}

func NewHeartbeat(from, to string, heartbeat Heartbeat) Message {
	return baseMessage(TypeHeartbeat, from, to, func(msg *Message) {
		msg.Heartbeat = &heartbeat
	})
}

func NewPathHealth(from, to string, health PathHealth) Message {
	return baseMessage(TypePathHealth, from, to, func(msg *Message) {
		msg.PathHealth = &health
	})
}

func NewEndpointUpdate(from, to string, update EndpointUpdate) Message {
	return baseMessage(TypeEndpointUpdate, from, to, func(msg *Message) {
		msg.EndpointUpdate = &update
	})
}

func NewCapabilityRefresh(from, to string, refresh CapabilityRefresh) Message {
	return baseMessage(TypeCapabilityRefresh, from, to, func(msg *Message) {
		msg.CapabilityRefresh = &refresh
	})
}

func NewReICERequest(from, to string, request ReICERequest) Message {
	return baseMessage(TypeReICERequest, from, to, func(msg *Message) {
		msg.ReICERequest = &request
	})
}

func NewSessionSignal(from, to string, signal SessionSignal) Message {
	return baseMessage(TypeSessionSignal, from, to, func(msg *Message) {
		msg.SessionSignal = &signal
	})
}

func Marshal(msg Message) ([]byte, error) {
	if err := Validate(msg); err != nil {
		return nil, err
	}
	return json.Marshal(msg)
}

func Unmarshal(raw []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Message{}, err
	}
	if err := Validate(msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func Validate(msg Message) error {
	if msg.Version != Version {
		return fmt.Errorf("peercontrol: unsupported version %d", msg.Version)
	}
	if strings.TrimSpace(msg.From) == "" {
		return fmt.Errorf("peercontrol: from is required")
	}
	if strings.TrimSpace(msg.To) == "" {
		return fmt.Errorf("peercontrol: to is required")
	}
	if msg.SentAt.IsZero() {
		return fmt.Errorf("peercontrol: sent_at is required")
	}
	switch msg.Type {
	case TypeHeartbeat:
		return requirePayload(msg.Heartbeat, "heartbeat")
	case TypePathHealth:
		return requirePayload(msg.PathHealth, "path_health")
	case TypeEndpointUpdate:
		if err := requirePayload(msg.EndpointUpdate, "endpoint_update"); err != nil {
			return err
		}
		if strings.TrimSpace(msg.EndpointUpdate.Endpoint) == "" {
			return fmt.Errorf("peercontrol: endpoint_update.endpoint is required")
		}
		return nil
	case TypeCapabilityRefresh:
		return requirePayload(msg.CapabilityRefresh, "capability_refresh")
	case TypeReICERequest:
		return requirePayload(msg.ReICERequest, "re_ice_request")
	case TypeSessionSignal:
		if err := requirePayload(msg.SessionSignal, "session_signal"); err != nil {
			return err
		}
		if strings.TrimSpace(msg.SessionSignal.Kind) == "" {
			return fmt.Errorf("peercontrol: session_signal.kind is required")
		}
		if strings.TrimSpace(msg.SessionSignal.Namespace) == "" {
			return fmt.Errorf("peercontrol: session_signal.namespace is required")
		}
		if strings.TrimSpace(msg.SessionSignal.Type) == "" {
			return fmt.Errorf("peercontrol: session_signal.type is required")
		}
		return nil
	default:
		return fmt.Errorf("peercontrol: unsupported message type %q", msg.Type)
	}
}

func baseMessage(msgType MessageType, from, to string, apply func(*Message)) Message {
	msg := Message{
		Version: Version,
		Type:    msgType,
		From:    from,
		To:      to,
		SentAt:  time.Now().UTC(),
	}
	apply(&msg)
	return msg
}

func requirePayload[T any](payload *T, name string) error {
	if payload == nil {
		return fmt.Errorf("peercontrol: %s payload is required", name)
	}
	return nil
}
