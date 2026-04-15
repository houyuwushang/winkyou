package session

import (
	"context"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type State string

const (
	StateNew       State = "new"
	StatePlanning  State = "planning"
	StateExecuting State = "executing"
	StateBinding   State = "binding"
	StateBound     State = "bound"
	StateFailed    State = "failed"
	StateClosed    State = "closed"
)

type MessageSender interface {
	Send(ctx context.Context, peerID string, msg solver.Message) error
}

type Hooks struct {
	OnStateChange func(state State)
	OnBound       func(result solver.Result)
	OnError       func(error)
}

type Config struct {
	SessionID         string
	LocalNodeID       string
	PeerID            string
	Initiator         bool
	Strategy          solver.Strategy
	Binder            Binder
	Sender            MessageSender
	Hooks             Hooks
	NewLegacyICEAgent func(ctx context.Context, controlling bool) (nat.ICEAgent, error)
	GatherTimeout     time.Duration
	ConnectTimeout    time.Duration
	CheckTimeout      time.Duration
}
