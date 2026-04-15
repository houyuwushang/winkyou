package solver

import (
	"context"
	"net"
	"time"

	"winkyou/pkg/transport"
)

type MessageKind string

const (
	MessageKindEnvelope           MessageKind = "session_envelope"
	MessageKindLegacyICEOffer     MessageKind = "legacyice.offer"
	MessageKindLegacyICEAnswer    MessageKind = "legacyice.answer"
	MessageKindLegacyICECandidate MessageKind = "legacyice.candidate"
)

type Message struct {
	Kind       MessageKind
	Payload    []byte
	ReceivedAt time.Time
}

type SolveInput struct {
	SessionID    string
	LocalNodeID  string
	RemoteNodeID string
	Initiator    bool
}

type Plan struct {
	ID       string
	Strategy string
	Metadata map[string]string
}

type PathSummary struct {
	PathID         string
	ConnectionType string
	RemoteAddr     net.Addr
	Details        map[string]string
}

type Result struct {
	Transport transport.PacketTransport
	Summary   PathSummary
}

type SessionIO interface {
	Send(ctx context.Context, msg Message) error
}

type Strategy interface {
	Name() string
	Plan(ctx context.Context, in SolveInput) ([]Plan, error)
	Execute(ctx context.Context, sess SessionIO, plan Plan) (Result, error)
	Close() error
}

type MessageHandler interface {
	HandleMessage(ctx context.Context, sess SessionIO, msg Message) error
}
