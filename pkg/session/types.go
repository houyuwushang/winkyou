package session

import (
	"context"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
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

const envelopeNamespace = "rendezvous.v2"

type MessageSender interface {
	Send(ctx context.Context, peerID string, msg solver.Message) error
}

type Hooks struct {
	OnStateChange func(state State)
	OnBound       func(result solver.Result)
	OnError       func(error)
}

type Config struct {
	SessionID   string
	LocalNodeID string
	PeerID      string
	Initiator   bool
	Strategy    solver.Strategy
	Binder      Binder
	Sender      MessageSender
	Hooks       Hooks
	RunTimeout  time.Duration
}

type Snapshot struct {
	SessionID        string
	PeerID           string
	State            State
	LocalCapability  rproto.Capability
	RemoteCapability rproto.Capability
	LastEnvelopeType string
	LastEnvelopeAt   time.Time
}
