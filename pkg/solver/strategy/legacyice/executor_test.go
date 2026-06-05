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
	selectedStats    nat.CandidatePairStats
	hasSelectedStats bool
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

func (a *recordingICEAgent) GetSelectedPairStats() (nat.CandidatePairStats, bool) {
	return a.selectedStats, a.hasSelectedStats
}

func (a *recordingICEAgent) Close() error { return nil }

type recordingSessionIO struct{}

func (recordingSessionIO) Send(context.Context, solver.Message) error { return nil }

func (recordingSessionIO) ReportObservation(context.Context, solver.Observation) error { return nil }

type capturingSessionIO struct {
	messages []solver.Message
}

func (c *capturingSessionIO) Send(_ context.Context, msg solver.Message) error {
	c.messages = append(c.messages, msg)
	return nil
}

func (c *capturingSessionIO) ReportObservation(context.Context, solver.Observation) error { return nil }

func TestExecutorConfigForPlanProducesDistinctModes(t *testing.T) {
	direct, err := executorConfigForPlan(solver.Plan{ID: "legacyice/direct_prefer", Metadata: map[string]string{"mode": "direct_prefer"}}, Config{})
	if err != nil {
		t.Fatalf("executorConfigForPlan(direct) error = %v", err)
	}
	if direct.Mode != modeDirectPrefer || direct.ForceRelay {
		t.Fatalf("direct config = %+v, want direct_prefer without force relay", direct)
	}

	publicDirect, err := executorConfigForPlan(solver.Plan{ID: "legacyice/public_direct", Metadata: map[string]string{"mode": "public_direct"}}, Config{})
	if err != nil {
		t.Fatalf("executorConfigForPlan(public_direct) error = %v", err)
	}
	if publicDirect.Mode != modePublicDirect || publicDirect.ForceRelay || !publicDirect.PublicDirectCandidate {
		t.Fatalf("public direct config = %+v, want public_direct without force relay", publicDirect)
	}
	if len(publicDirect.CandidateCIDRExclude) != 0 {
		t.Fatalf("public direct CIDR excludes = %#v, want no agent-level excludes", publicDirect.CandidateCIDRExclude)
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

	publicDirectExec, err := strategy.NewExecutor(solver.Plan{ID: "legacyice/public_direct", Strategy: StrategyName, Metadata: map[string]string{"mode": "public_direct"}})
	if err != nil {
		t.Fatalf("NewExecutor(public_direct) error = %v", err)
	}
	if _, err := publicDirectExec.(*executor).ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(public_direct) error = %v", err)
	}

	relayExec, err := strategy.NewExecutor(solver.Plan{ID: "legacyice/relay_only", Strategy: StrategyName, Metadata: map[string]string{"mode": "relay_only"}})
	if err != nil {
		t.Fatalf("NewExecutor(relay) error = %v", err)
	}
	if _, err := relayExec.(*executor).ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(relay) error = %v", err)
	}

	if len(requests) != 3 {
		t.Fatalf("agent requests = %d, want 3", len(requests))
	}
	if requests[0].ForceRelay {
		t.Fatalf("direct request = %+v, want ForceRelay=false", requests[0])
	}
	if !requests[1].PublicDirectCandidate || len(requests[1].CandidateCIDRExclude) != 0 {
		t.Fatalf("public direct request = %+v, want public direct without agent-level CIDR filters", requests[1])
	}
	if !requests[2].ForceRelay {
		t.Fatalf("relay request = %+v, want ForceRelay=true", requests[2])
	}
}

func TestExecutorPathIDUsesPlanModeForPublicDirect(t *testing.T) {
	input := solver.SolveInput{SessionID: "session/node-a/node-b"}
	directExec := newExecutor(Config{}, input, solver.Plan{ID: planIDDirectPrefer}, executorConfig{Mode: modeDirectPrefer})
	if got := directExec.pathID("direct"); got != "legacyice:direct:session/node-a/node-b" {
		t.Fatalf("direct path id = %q, want legacy format", got)
	}

	publicExec := newExecutor(Config{}, input, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := publicExec.pathID("direct"); got != "legacyice:direct:public_direct:session/node-a/node-b" {
		t.Fatalf("public direct path id = %q, want mode-qualified format", got)
	}
}

func TestSelectedPairMetricsExposeRTT(t *testing.T) {
	agent := &recordingICEAgent{
		selectedStats: nat.CandidatePairStats{
			CurrentRoundTripTime: 42 * time.Millisecond,
		},
		hasSelectedStats: true,
	}

	metrics := selectedPairMetrics(agent)
	if metrics["rtt_ms"] != "42" {
		t.Fatalf("metrics = %#v, want rtt_ms=42", metrics)
	}
}

func TestPublicDirectSendOfferAdvertisesOnlyPublicCandidates(t *testing.T) {
	hostCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}}
	overlayCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(100, 102, 17, 35), Port: 1002}}
	publicCandidate := nat.Candidate{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 1003}}
	relayCandidate := nat.Candidate{Type: nat.CandidateTypeRelay, Address: &net.UDPAddr{IP: net.IPv4(20, 0, 0, 1), Port: 2001}}
	agent := &recordingICEAgent{
		gathered:      []nat.Candidate{hostCandidate, overlayCandidate, publicCandidate, relayCandidate},
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			if !req.PublicDirectCandidate {
				t.Fatalf("agent request = %+v, want public direct marker", req)
			}
			if len(req.CandidateCIDRExclude) != 0 {
				t.Fatalf("agent request CIDR excludes = %#v, want none for srflx gathering", req.CandidateCIDRExclude)
			}
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
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect, PublicDirectCandidate: true})

	io := &capturingSessionIO{}
	if err := exec.sendOffer(context.Background(), io); err != nil {
		t.Fatalf("sendOffer(public_direct) error = %v", err)
	}
	if len(io.messages) != 1 {
		t.Fatalf("sent messages = %d, want 1", len(io.messages))
	}
	offer, err := unmarshalOfferPayload(io.messages[0].Payload)
	if err != nil {
		t.Fatalf("unmarshal offer error = %v", err)
	}
	if len(offer.ICE.Candidates) != 1 {
		t.Fatalf("offer candidates = %#v, want only public srflx candidate", offer.ICE.Candidates)
	}
	if offer.ICE.Candidates[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("offer candidate = %v, want %v", offer.ICE.Candidates[0].Address, publicCandidate.Address)
	}
}

func TestExecutorFiltersRemoteCandidatesByPlanMode(t *testing.T) {
	hostCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}}
	overlayCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(100, 102, 17, 35), Port: 1002}}
	publicCandidate := nat.Candidate{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 1003}}
	relayCandidate := nat.Candidate{Type: nat.CandidateTypeRelay, Address: &net.UDPAddr{IP: net.IPv4(20, 0, 0, 1), Port: 2001}}
	mixedCandidates := []nat.Candidate{hostCandidate, overlayCandidate, publicCandidate, relayCandidate}

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
	if got := len(directAgent.remoteCandidates); got != 4 {
		t.Fatalf("direct remote candidates = %d, want 4", got)
	}
	if got := len(filterLocalCandidates(mixedCandidates, executorConfig{Mode: modeDirectPrefer})); got != 4 {
		t.Fatalf("direct local candidates = %d, want 4", got)
	}

	publicDirectExec, publicDirectAgent := newExecutorWithAgent("legacyice/public_direct", modePublicDirect)
	publicDirectPayload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    "legacyice/public_direct",
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: mixedCandidates,
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload(public_direct) error = %v", err)
	}
	if err := publicDirectExec.HandleMessage(context.Background(), recordingSessionIO{}, NewMessage(MessageTypeAnswer, publicDirectPayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(public_direct) error = %v", err)
	}
	<-publicDirectAgent.connectCalled
	if got := len(publicDirectAgent.remoteCandidates); got != 1 {
		t.Fatalf("public direct remote candidates = %d, want 1 public candidate", got)
	}
	if publicDirectAgent.remoteCandidates[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("public direct candidate = %v, want %v", publicDirectAgent.remoteCandidates[0].Address, publicCandidate.Address)
	}
	publicLocalCandidates := filterLocalCandidates(mixedCandidates, executorConfig{Mode: modePublicDirect})
	if len(publicLocalCandidates) != 1 || publicLocalCandidates[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("public direct local candidates = %#v, want only %v", publicLocalCandidates, publicCandidate.Address)
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

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
