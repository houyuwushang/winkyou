package session

import (
	"context"
	"time"

	pmodel "winkyou/pkg/probe/model"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type State string

const (
	StateNew                State = "new"
	StateCapabilityExchange State = "capability_exchange"
	StateSelecting          State = "selecting"
	StatePlanning           State = "planning"
	StateExecuting          State = "executing"
	StateBinding            State = "binding"
	StateBound              State = "bound"
	StateFailed             State = "failed"
	StateClosed             State = "closed"
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

type Selection struct {
	StrategyName string
	Negotiated   bool
}

type StrategyResolver interface {
	LocalCapability() rproto.Capability
	Resolve(remote rproto.Capability, initiator bool) (solver.Strategy, Selection, error)
}

type ProbeRunner interface {
	Run(ctx context.Context, script pmodel.Script) (pmodel.Result, error)
}

type Config struct {
	SessionID             string
	LocalNodeID           string
	PeerID                string
	Initiator             bool
	Resolver              StrategyResolver
	Binder                Binder
	Sender                MessageSender
	ProbeRunner           ProbeRunner
	ObservationSink       solver.ObservationSink
	ObservationHistory    solver.ObservationHistory
	Hooks                 Hooks
	RunTimeout            time.Duration
	CapabilityWaitTimeout time.Duration
	PreflightProbeTimeout time.Duration
}

type PathCommitSnapshot struct {
	Strategy       string
	PathID         string
	ConnectionType string
}

type Snapshot struct {
	SessionID               string
	PeerID                  string
	State                   State
	LocalCapability         rproto.Capability
	RemoteCapability        rproto.Capability
	SelectedStrategy        string
	SelectionNegotiated     bool
	CapabilityExchangeAt    time.Time
	LastPathCommit          PathCommitSnapshot
	LastPathCommitAt        time.Time
	LastEnvelopeType        string
	LastEnvelopeAt          time.Time
	LastProbeScriptType     string
	LastProbeScriptAt       time.Time
	LastProbeResult         pmodel.Result
	LastProbeResultAt       time.Time
	LastPlanOrder           []string
	LastPlanOrderReason     string
	PreflightProbeAttempted bool
	PreflightProbeSucceeded bool
}
