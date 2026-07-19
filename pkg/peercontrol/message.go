package peercontrol

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	Version             = 1
	BroadcastNodeID     = "*"
	DefaultHopLimit     = 16
	MaxHopLimit         = 64
	MaxPathVectorLength = 64
	MaxLeaseMillis      = 24 * 60 * 60 * 1000
)

type MessageType string

const (
	TypeHeartbeat          MessageType = "heartbeat"
	TypePathHealth         MessageType = "path_health"
	TypeEndpointUpdate     MessageType = "endpoint_update"
	TypeCapabilityRefresh  MessageType = "capability_refresh"
	TypeReICERequest       MessageType = "re_ice_request"
	TypeSessionSignal      MessageType = "session_signal"
	TypeControlEchoRequest MessageType = "control_echo_request"
	TypeControlEchoReply   MessageType = "control_echo_reply"
	TypeMemberAnnounce     MessageType = "member_announce"
	TypeLinkState          MessageType = "link_state"
)

type Message struct {
	Version int         `json:"version"`
	Type    MessageType `json:"type"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Seq     uint64      `json:"seq,omitempty"`
	SentAt  time.Time   `json:"sent_at"`
	// HopLimit and PathVector are present only when a logical message may be
	// forwarded across multiple neighbor sessions. From and To remain the
	// logical origin and final destination; the immediate peer is link metadata.
	HopLimit   uint8    `json:"hop_limit,omitempty"`
	PathVector []string `json:"path_vector,omitempty"`

	Heartbeat         *Heartbeat              `json:"heartbeat,omitempty"`
	PathHealth        *PathHealth             `json:"path_health,omitempty"`
	EndpointUpdate    *EndpointUpdate         `json:"endpoint_update,omitempty"`
	CapabilityRefresh *CapabilityRefresh      `json:"capability_refresh,omitempty"`
	ReICERequest      *ReICERequest           `json:"re_ice_request,omitempty"`
	SessionSignal     *SessionSignal          `json:"session_signal,omitempty"`
	ControlEcho       *ControlEcho            `json:"control_echo,omitempty"`
	MemberRecord      *MemberRecord           `json:"member_record,omitempty"`
	LinkState         *LinkStateAdvertisement `json:"link_state,omitempty"`
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

// ControlEcho is a deliberately small diagnostic payload used to prove routed
// control delivery before membership, link-state routing, and user data are
// introduced. RequestPath is populated by the destination in a reply so the
// origin can inspect both directions without an intermediate node decoding the
// payload.
type ControlEcho struct {
	ID          string   `json:"id"`
	Payload     []byte   `json:"payload,omitempty"`
	RequestPath []string `json:"request_path,omitempty"`
}

// MemberRecord describes node identity and edge-solving inputs. Revision is a
// state revision, while Message.Seq remains the unique wire-message sequence
// used for flood deduplication. Equal revisions may refresh the lease.
type MemberRecord struct {
	NodeID       string   `json:"node_id"`
	Revision     uint64   `json:"revision"`
	LeaseMillis  uint32   `json:"lease_millis"`
	VirtualIP    string   `json:"virtual_ip,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	NATProfile   string   `json:"nat_profile,omitempty"`
}

// LinkStateAdvertisement lists the origin's currently usable direct
// neighbors. Removing a link from a newer revision is its withdrawal.
type LinkStateAdvertisement struct {
	NodeID         string          `json:"node_id"`
	Revision       uint64          `json:"revision"`
	LeaseMillis    uint32          `json:"lease_millis"`
	TransitAllowed bool            `json:"transit_allowed"`
	Links          []LinkStateLink `json:"links,omitempty"`
}

type LinkStateLink struct {
	PeerID    string `json:"peer_id"`
	RTTMillis uint32 `json:"rtt_millis,omitempty"`
	// ControlOnly is absent in older messages and therefore defaults to false
	// (data-capable). Either endpoint may set it to remove the undirected edge
	// from the user-data graph while retaining control-plane reachability.
	ControlOnly bool `json:"control_only,omitempty"`
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

func NewControlEchoRequest(from, to, id string, payload []byte, hopLimit uint8) Message {
	if hopLimit == 0 {
		hopLimit = DefaultHopLimit
	}
	msg := baseMessage(TypeControlEchoRequest, from, to, func(msg *Message) {
		msg.ControlEcho = &ControlEcho{ID: id, Payload: append([]byte(nil), payload...)}
	})
	msg.HopLimit = hopLimit
	msg.PathVector = []string{from}
	return msg
}

func NewControlEchoReply(from, to, id string, payload []byte, requestPath []string, hopLimit uint8) Message {
	if hopLimit == 0 {
		hopLimit = DefaultHopLimit
	}
	msg := baseMessage(TypeControlEchoReply, from, to, func(msg *Message) {
		msg.ControlEcho = &ControlEcho{
			ID:          id,
			Payload:     append([]byte(nil), payload...),
			RequestPath: append([]string(nil), requestPath...),
		}
	})
	msg.HopLimit = hopLimit
	msg.PathVector = []string{from}
	return msg
}

func NewMemberAnnounce(from string, record MemberRecord, hopLimit uint8) Message {
	if hopLimit == 0 {
		hopLimit = DefaultHopLimit
	}
	record.NodeID = from
	record.Endpoints = append([]string(nil), record.Endpoints...)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	msg := baseMessage(TypeMemberAnnounce, from, BroadcastNodeID, func(msg *Message) {
		msg.MemberRecord = &record
	})
	msg.HopLimit = hopLimit
	msg.PathVector = []string{from}
	return msg
}

func NewLinkState(from string, state LinkStateAdvertisement, hopLimit uint8) Message {
	if hopLimit == 0 {
		hopLimit = DefaultHopLimit
	}
	state.NodeID = from
	state.Links = append([]LinkStateLink(nil), state.Links...)
	msg := baseMessage(TypeLinkState, from, BroadcastNodeID, func(msg *Message) {
		msg.LinkState = &state
	})
	msg.HopLimit = hopLimit
	msg.PathVector = []string{from}
	return msg
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
	if err := validateRouteHeader(msg); err != nil {
		return err
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
	case TypeControlEchoRequest, TypeControlEchoReply:
		if err := requirePayload(msg.ControlEcho, "control_echo"); err != nil {
			return err
		}
		if strings.TrimSpace(msg.ControlEcho.ID) == "" {
			return fmt.Errorf("peercontrol: control_echo.id is required")
		}
		if msg.HopLimit == 0 {
			return fmt.Errorf("peercontrol: control echo requires hop_limit")
		}
		return nil
	case TypeMemberAnnounce:
		if err := requirePayload(msg.MemberRecord, "member_record"); err != nil {
			return err
		}
		if err := validateFloodHeader(msg); err != nil {
			return err
		}
		return validateMemberRecord(msg.From, *msg.MemberRecord)
	case TypeLinkState:
		if err := requirePayload(msg.LinkState, "link_state"); err != nil {
			return err
		}
		if err := validateFloodHeader(msg); err != nil {
			return err
		}
		return validateLinkState(msg.From, *msg.LinkState)
	default:
		return fmt.Errorf("peercontrol: unsupported message type %q", msg.Type)
	}
}

func validateFloodHeader(msg Message) error {
	if msg.To != BroadcastNodeID {
		return fmt.Errorf("peercontrol: %s must be addressed to broadcast %q", msg.Type, BroadcastNodeID)
	}
	if msg.HopLimit == 0 {
		return fmt.Errorf("peercontrol: %s requires hop_limit", msg.Type)
	}
	return nil
}

func validateMemberRecord(origin string, record MemberRecord) error {
	if record.NodeID != origin {
		return fmt.Errorf("peercontrol: member_record.node_id %q does not match origin %q", record.NodeID, origin)
	}
	if record.Revision == 0 {
		return fmt.Errorf("peercontrol: member_record.revision is required")
	}
	if err := validateLease("member_record", record.LeaseMillis); err != nil {
		return err
	}
	for i, endpoint := range record.Endpoints {
		if strings.TrimSpace(endpoint) == "" {
			return fmt.Errorf("peercontrol: member_record.endpoints[%d] is empty", i)
		}
	}
	for i, capability := range record.Capabilities {
		if strings.TrimSpace(capability) == "" {
			return fmt.Errorf("peercontrol: member_record.capabilities[%d] is empty", i)
		}
	}
	return nil
}

func validateLinkState(origin string, state LinkStateAdvertisement) error {
	if state.NodeID != origin {
		return fmt.Errorf("peercontrol: link_state.node_id %q does not match origin %q", state.NodeID, origin)
	}
	if state.Revision == 0 {
		return fmt.Errorf("peercontrol: link_state.revision is required")
	}
	if err := validateLease("link_state", state.LeaseMillis); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(state.Links))
	for i, link := range state.Links {
		peerID := strings.TrimSpace(link.PeerID)
		if peerID == "" {
			return fmt.Errorf("peercontrol: link_state.links[%d].peer_id is empty", i)
		}
		if peerID == origin {
			return fmt.Errorf("peercontrol: link_state cannot advertise self link %q", peerID)
		}
		if _, exists := seen[peerID]; exists {
			return fmt.Errorf("peercontrol: link_state repeats peer %q", peerID)
		}
		seen[peerID] = struct{}{}
	}
	return nil
}

func validateLease(name string, leaseMillis uint32) error {
	if leaseMillis == 0 {
		return fmt.Errorf("peercontrol: %s.lease_millis is required", name)
	}
	if leaseMillis > MaxLeaseMillis {
		return fmt.Errorf("peercontrol: %s.lease_millis %d exceeds maximum %d", name, leaseMillis, MaxLeaseMillis)
	}
	return nil
}

func validateRouteHeader(msg Message) error {
	if msg.HopLimit > MaxHopLimit {
		return fmt.Errorf("peercontrol: hop_limit %d exceeds maximum %d", msg.HopLimit, MaxHopLimit)
	}
	if len(msg.PathVector) > MaxPathVectorLength {
		return fmt.Errorf("peercontrol: path_vector contains %d nodes, maximum is %d", len(msg.PathVector), MaxPathVectorLength)
	}
	if len(msg.PathVector) > 0 && msg.HopLimit == 0 {
		return fmt.Errorf("peercontrol: path_vector requires hop_limit")
	}
	for i, nodeID := range msg.PathVector {
		if strings.TrimSpace(nodeID) == "" {
			return fmt.Errorf("peercontrol: path_vector[%d] is empty", i)
		}
	}
	if len(msg.PathVector) > 0 && msg.PathVector[0] != msg.From {
		return fmt.Errorf("peercontrol: path_vector must start with origin %q", msg.From)
	}
	return nil
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
