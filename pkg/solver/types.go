package solver

import (
	"context"
	"net"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/transport"
)

type MessageKind string

const (
	MessageKindEnvelope MessageKind = "session_envelope"
	MessageKindStrategy MessageKind = "strategy_message"
)

type Message struct {
	Kind       MessageKind
	Namespace  string
	Type       string
	Payload    []byte
	ReceivedAt time.Time
}

type SolveInput struct {
	SessionID          string
	LocalNodeID        string
	RemoteNodeID       string
	Initiator          bool
	LocalCapability    rproto.Capability
	RemoteCapability   rproto.Capability
	LocalObservations  []Observation
	RemoteObservations []Observation
	LastProbeResult    *ProbeResultSummary
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

// ExecutionBudget defines resource limits for candidate execution
type ExecutionBudget struct {
	MaxCandidates int
	TimeBudget    time.Duration
}

// CandidateOutcome represents the result of executing a single candidate plan
type CandidateOutcome struct {
	Plan             Plan
	PlanID           string
	Result           *Result
	PathID           string
	ErrorClass       string
	Err              error
	Score            int
	Selected         bool
	SelectionReason  string
	FinishedAt       time.Time
	ExecutionDur     time.Duration
	ObservationCount int
}

type SessionIO interface {
	Send(ctx context.Context, msg Message) error
	ReportObservation(ctx context.Context, obs Observation) error
}

type ObservationSink interface {
	Record(obs Observation) error
}

type ObservationHistory interface {
	Recent(limit int) []Observation
}

// Observation represents a connectivity observation event
type Observation struct {
	Strategy       string
	PlanID         string
	Event          string
	PathID         string
	ConnectionType string
	LocalAddr      string
	RemoteAddr     string
	LocalKind      string
	RemoteKind     string
	ErrorClass     string
	Reason         string
	TimeoutMS      int64
	Details        map[string]string
	Timestamp      time.Time
}

type ProbeResultSummary struct {
	ScriptType string
	Success    bool
	ErrorClass string
	PathID     string
	Details    map[string]string
	FinishedAt time.Time
}

type RankInput struct {
	SessionID          string
	LocalNodeID        string
	RemoteNodeID       string
	Initiator          bool
	RemoteCapability   rproto.Capability
	LocalObservations  []Observation
	RemoteObservations []Observation
	LastProbeResult    *ProbeResultSummary
}

type RankedPlans struct {
	Plans  []Plan
	Reason string
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

type PlanExecutor interface {
	Execute(ctx context.Context, sess SessionIO) (Result, error)
	HandleMessage(ctx context.Context, sess SessionIO, msg Message) error
	Close() error
}

type ExecutorFactory interface {
	NewExecutor(plan Plan) (PlanExecutor, error)
}

type PlanRanker interface {
	RankPlans(ctx context.Context, input RankInput, plans []Plan) (RankedPlans, error)
}

type ProbeInput struct {
	SessionID          string
	LocalNodeID        string
	RemoteNodeID       string
	Initiator          bool
	LocalCapability    rproto.Capability
	RemoteCapability   rproto.Capability
	LocalObservations  []Observation
	RemoteObservations []Observation
	LastProbeResult    *ProbeResultSummary
}

type ProbePolicy struct {
	Optional bool
	Timeout  time.Duration
	Reason   string
}

type ProbePlanner interface {
	BuildPreflightProbe(ctx context.Context, input ProbeInput) (*ProbeScript, ProbePolicy, error)
}

type ProbeScript struct {
	ScriptType string
	PlanID     string
	Steps      []ProbeStep
}

type ProbeStep struct {
	Action  string
	Params  map[string]string
	Timeout time.Duration
}

type RefinedPlans struct {
	Plans  []Plan
	Reason string
}

type PlanRefiner interface {
	RefinePlans(ctx context.Context, input SolveInput, plans []Plan) (RefinedPlans, error)
}

// DefaultBudget returns a conservative execution budget
func DefaultBudget() ExecutionBudget {
	return ExecutionBudget{
		MaxCandidates: 3,
		TimeBudget:    60 * time.Second,
	}
}

// ScoreOutcome assigns a score to a candidate outcome
// Higher score is better. Generic scoring rules:
// - Success > Failure
// - Direct > Relay (when both succeed)
// - First success wins ties
func ScoreOutcome(outcome CandidateOutcome) int {
	if outcome.Err != nil {
		return 0
	}
	if outcome.Result == nil || outcome.Result.Transport == nil {
		return 0
	}

	score := 100 // base success score

	// Prefer direct over relay
	if outcome.Result.Summary.ConnectionType == "direct" {
		score += 50
	} else if outcome.Result.Summary.ConnectionType == "relay" {
		score += 20
	}

	// Prefer paths with explicit PathID
	if outcome.Result.Summary.PathID != "" {
		score += 10
	}

	return score
}

// SelectBestOutcome picks the highest-scoring outcome from a list
// Returns nil if no successful outcomes exist
func SelectBestOutcome(outcomes []CandidateOutcome) *CandidateOutcome {
	if len(outcomes) == 0 {
		return nil
	}

	var best *CandidateOutcome
	bestScore := -1

	for i := range outcomes {
		outcome := &outcomes[i]
		score := ScoreOutcome(*outcome)
		if score > bestScore {
			bestScore = score
			best = outcome
		}
	}

	if best != nil && bestScore > 0 {
		return best
	}
	return nil
}
