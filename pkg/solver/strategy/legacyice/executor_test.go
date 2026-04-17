package legacyice

import (
	"context"
	"net"
	"testing"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type recordingICEAgent struct {
	gathered         []nat.Candidate
	remoteCandidates []nat.Candidate
	connectErr       error
	connectCalled    chan struct{}
}

func (a *recordingICEAgent) GatherCandidates(context.Context) ([]nat.Candidate, error) {
	return append([]nat.Candidate(nil), a.gathered...), nil
}

func (a *recordingICEAgent) GetLocalCredentials() (string, string, error) {
	return "ufrag", "pwd", nil
}

func (a *recordingICEAgent) SetRemoteCredentials(string, string) error {
	return nil
}

func (a *recordingICEAgent) SetRemoteCandidates(candidates []nat.Candidate) error {
	a.remoteCandidates = append([]nat.Candidate(nil), candidates...)
	return nil
}

func (a *recordingICEAgent) Connect(context.Context) (nat.SelectedTransport, *nat.CandidatePair, error) {
	select {
	case <-a.connectCalled:
	default:
		close(a.connectCalled)
	}
	return nil, nil, a.connectErr
}

func (a *recordingICEAgent) Close() error { return nil }

type recordingSessionIO struct{}

func (recordingSessionIO) Send(context.Context, solver.Message) error { return nil }

func (recordingSessionIO) ReportObservation(context.Context, solver.Observation) error { return nil }

func TestExecutorConfigForPlanProducesDistinctModes(t *testing.T) {
	direct, err := executorConfigForPlan(solver.Plan{ID: "legacyice/direct_prefer", Metadata: map[string]string{"mode": "direct_prefer"}}, Config{})
	if err != nil {
		t.Fatalf("executorConfigForPlan(direct) error = %v", err)
	}
	if direct.Mode != modeDirectPrefer || direct.ForceRelay {
		t.Fatalf("direct config = %+v, want direct_prefer without force relay", direct)
	}

	relay, err := executorConfigForPlan(solver.Plan{ID: "legacyice/relay_only", Metadata: map[string]string{"mode": "relay_only"}}, Config{})
	if err != nil {
		t.Fatalf("executorConfigForPlan(relay) error = %v", err)
	}
	if relay.Mode != modeRelayOnly || !relay.ForceRelay {
		t.Fatalf("relay config = %+v, want relay_only with force relay", relay)
	}
}

func TestStrategyNewExecutorUsesPlanSpecificAgentRequests(t *testing.T) {
	var requests []AgentRequest
	strategy := New(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			requests = append(requests, req)
			return &recordingICEAgent{connectErr: context.Canceled, connectCalled: make(chan struct{})}, nil
		},
	})
	if _, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	}); err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	directExec, err := strategy.NewExecutor(solver.Plan{ID: "legacyice/direct_prefer", Strategy: StrategyName, Metadata: map[string]string{"mode": "direct_prefer"}})
	if err != nil {
		t.Fatalf("NewExecutor(direct) error = %v", err)
	}
	if _, err := directExec.(*executor).ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(direct) error = %v", err)
	}

	relayExec, err := strategy.NewExecutor(solver.Plan{ID: "legacyice/relay_only", Strategy: StrategyName, Metadata: map[string]string{"mode": "relay_only"}})
	if err != nil {
		t.Fatalf("NewExecutor(relay) error = %v", err)
	}
	if _, err := relayExec.(*executor).ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(relay) error = %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("agent requests = %d, want 2", len(requests))
	}
	if requests[0].ForceRelay {
		t.Fatalf("direct request = %+v, want ForceRelay=false", requests[0])
	}
	if !requests[1].ForceRelay {
		t.Fatalf("relay request = %+v, want ForceRelay=true", requests[1])
	}
}

func TestRelayOnlyExecutorFiltersRemoteCandidates(t *testing.T) {
	hostCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}}
	relayCandidate := nat.Candidate{Type: nat.CandidateTypeRelay, Address: &net.UDPAddr{IP: net.IPv4(20, 0, 0, 1), Port: 2001}}
	mixedCandidates := []nat.Candidate{hostCandidate, relayCandidate}

	newExecutorWithAgent := func(planID string, mode executionMode) (*executor, *recordingICEAgent) {
		agent := &recordingICEAgent{
			gathered:      []nat.Candidate{relayCandidate},
			connectErr:    context.Canceled,
			connectCalled: make(chan struct{}),
		}
		exec := newExecutor(Config{
			NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
				_ = ctx
				_ = req
				return agent, nil
			},
			GatherTimeout:  100 * time.Millisecond,
			ConnectTimeout: 100 * time.Millisecond,
		}, solver.SolveInput{
			SessionID:    "session/node-a/node-b",
			LocalNodeID:  "node-a",
			RemoteNodeID: "node-b",
			Initiator:    true,
		}, solver.Plan{
			ID:       planID,
			Strategy: StrategyName,
			Metadata: map[string]string{"mode": string(mode)},
		}, executorConfig{Mode: mode, ForceRelay: mode == modeRelayOnly})
		return exec, agent
	}

	directExec, directAgent := newExecutorWithAgent("legacyice/direct_prefer", modeDirectPrefer)
	directPayload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    "legacyice/direct_prefer",
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: mixedCandidates,
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload(direct) error = %v", err)
	}
	if err := directExec.HandleMessage(context.Background(), recordingSessionIO{}, NewMessage(MessageTypeAnswer, directPayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(direct) error = %v", err)
	}
	<-directAgent.connectCalled
	if got := len(directAgent.remoteCandidates); got != 2 {
		t.Fatalf("direct remote candidates = %d, want 2", got)
	}

	relayExec, relayAgent := newExecutorWithAgent("legacyice/relay_only", modeRelayOnly)
	relayPayload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    "legacyice/relay_only",
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: mixedCandidates,
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload(relay) error = %v", err)
	}
	if err := relayExec.HandleMessage(context.Background(), recordingSessionIO{}, NewMessage(MessageTypeAnswer, relayPayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(relay) error = %v", err)
	}
	<-relayAgent.connectCalled
	if got := len(relayAgent.remoteCandidates); got != 1 {
		t.Fatalf("relay remote candidates = %d, want 1 relay candidate", got)
	}
	if relayAgent.remoteCandidates[0].Type != nat.CandidateTypeRelay {
		t.Fatalf("relay candidate type = %v, want %v", relayAgent.remoteCandidates[0].Type, nat.CandidateTypeRelay)
	}
}
