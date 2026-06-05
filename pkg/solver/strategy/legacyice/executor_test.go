package legacyice

import (
	"context"
	"net"
	"strings"
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
	messages     []solver.Message
	observations []solver.Observation
}

func (c *capturingSessionIO) Send(_ context.Context, msg solver.Message) error {
	c.messages = append(c.messages, msg)
	return nil
}

func (c *capturingSessionIO) ReportObservation(_ context.Context, obs solver.Observation) error {
	c.observations = append(c.observations, obs)
	return nil
}

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

func TestPublicDirectSelectedPairDetailsExposePeerReflexiveLearning(t *testing.T) {
	pair := &nat.CandidatePair{
		Local: &nat.Candidate{
			Type:    nat.CandidateTypeHost,
			Address: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000},
		},
		Remote: &nat.Candidate{
			Type:    nat.CandidateTypePrflx,
			Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
		},
	}
	details := selectedPairDetails(pair, modePublicDirect)
	if details["peer_reflexive_pair"] != "true" ||
		details["remote_peer_reflexive"] != "true" ||
		details["public_direct_learned_pair"] != "true" ||
		details["public_direct_remote_learned"] != "true" {
		t.Fatalf("selected pair details = %#v, want peer-reflexive public direct learning markers", details)
	}
	if details["local_candidate_kind"] != "host" || details["remote_candidate_kind"] != "prflx" {
		t.Fatalf("selected pair candidate kinds = %#v, want host/prflx", details)
	}
	if !strings.Contains(details["selected_pair_summary"], "host:192.168.1.20:40000<->prflx:117.48.146.2:41000") {
		t.Fatalf("selected pair summary = %q, want host<->prflx summary", details["selected_pair_summary"])
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
	obs := findObservation(io.observations, "candidate_gathered")
	if obs == nil {
		t.Fatalf("candidate_gathered observation not reported: %#v", io.observations)
	}
	if obs.Details["mode"] != string(modePublicDirect) || obs.Details["message_type"] != MessageTypeOffer {
		t.Fatalf("candidate_gathered details = %#v, want public direct offer", obs.Details)
	}
	if obs.Details["candidate_total"] != "4" || obs.Details["candidate_kept"] != "1" || obs.Details["candidate_rejected"] != "3" {
		t.Fatalf("candidate_gathered counts = %#v, want total=4 kept=1 rejected=3", obs.Details)
	}
	if !strings.Contains(obs.Details["candidate_kept_samples"], "srflx:117.48.146.2:1003") {
		t.Fatalf("candidate_gathered kept samples = %q, want public srflx sample", obs.Details["candidate_kept_samples"])
	}
	for _, want := range []string{"host:10.0.0.1:1001(local_private_candidate)", "host:100.102.17.35:1002(local_cgnat_or_overlay_candidate)", "relay:20.0.0.1:2001(local_relay_candidate)"} {
		if !strings.Contains(obs.Details["candidate_rejected_samples"], want) {
			t.Fatalf("candidate_gathered rejected samples = %q, want %q", obs.Details["candidate_rejected_samples"], want)
		}
	}
	reasons := obs.Details["candidate_reject_reasons"]
	for _, want := range []string{"local_private_candidate=1", "local_cgnat_or_overlay_candidate=1", "local_relay_candidate=1"} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("candidate_gathered reject reasons = %q, want %q", reasons, want)
		}
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
	publicDirectIO := &capturingSessionIO{}
	if err := publicDirectExec.HandleMessage(context.Background(), publicDirectIO, NewMessage(MessageTypeAnswer, publicDirectPayload, time.Now())); err != nil {
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
	obs := findObservation(publicDirectIO.observations, "remote_candidates_filtered")
	if obs == nil {
		t.Fatalf("remote_candidates_filtered observation not reported: %#v", publicDirectIO.observations)
	}
	if obs.Details["mode"] != string(modePublicDirect) || obs.Details["message_type"] != MessageTypeAnswer {
		t.Fatalf("remote_candidates_filtered details = %#v, want public direct answer", obs.Details)
	}
	if obs.Details["candidate_total"] != "4" || obs.Details["candidate_kept"] != "1" || obs.Details["candidate_rejected"] != "3" {
		t.Fatalf("remote_candidates_filtered counts = %#v, want total=4 kept=1 rejected=3", obs.Details)
	}
	if !strings.Contains(obs.Details["candidate_kept_samples"], "srflx:117.48.146.2:1003") {
		t.Fatalf("remote_candidates_filtered kept samples = %q, want public srflx sample", obs.Details["candidate_kept_samples"])
	}
	for _, want := range []string{"host:10.0.0.1:1001(remote_private_candidate)", "host:100.102.17.35:1002(remote_cgnat_or_overlay_candidate)", "relay:20.0.0.1:2001(remote_relay_candidate)"} {
		if !strings.Contains(obs.Details["candidate_rejected_samples"], want) {
			t.Fatalf("remote_candidates_filtered rejected samples = %q, want %q", obs.Details["candidate_rejected_samples"], want)
		}
	}
	remoteReasons := obs.Details["candidate_reject_reasons"]
	for _, want := range []string{"remote_private_candidate=1", "remote_cgnat_or_overlay_candidate=1", "remote_relay_candidate=1"} {
		if !strings.Contains(remoteReasons, want) {
			t.Fatalf("remote_candidates_filtered reject reasons = %q, want %q", remoteReasons, want)
		}
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

func TestPublicDirectEmptyRemoteCandidatesFailsPlanWithoutBubbling(t *testing.T) {
	hostCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}}
	overlayCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(100, 102, 17, 35), Port: 1002}}
	relayCandidate := nat.Candidate{Type: nat.CandidateTypeRelay, Address: &net.UDPAddr{IP: net.IPv4(20, 0, 0, 1), Port: 2001}}

	exec, agent := newExecutorWithRecordingAgent(planIDPublicDirect, modePublicDirect, nil)
	payload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: []nat.Candidate{hostCandidate, overlayCandidate, relayCandidate},
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload(public_direct) error = %v", err)
	}

	io := &capturingSessionIO{}
	if err := exec.HandleMessage(context.Background(), io, NewMessage(MessageTypeAnswer, payload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(public_direct) error = %v, want nil so session can continue fallback", err)
	}
	if len(agent.remoteCandidates) != 0 {
		t.Fatalf("remote candidates = %#v, want none after public direct filtering", agent.remoteCandidates)
	}
	select {
	case err := <-exec.errCh:
		if err == nil || !strings.Contains(err.Error(), "no usable remote candidates") {
			t.Fatalf("executor err = %v, want no usable remote candidates", err)
		}
	default:
		t.Fatal("executor errCh did not receive plan failure")
	}
	if obs := findObservation(io.observations, "remote_candidates_filtered"); obs == nil || obs.Details["candidate_kept"] != "0" {
		t.Fatalf("observations = %#v, want remote_candidates_filtered kept=0", io.observations)
	}
	if obs := findObservation(io.observations, "candidate_failed"); obs == nil || !strings.Contains(obs.Reason, "no usable remote candidates") {
		t.Fatalf("observations = %#v, want candidate_failed no usable remote candidates", io.observations)
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

func newExecutorWithRecordingAgent(planID string, mode executionMode, gathered []nat.Candidate) (*executor, *recordingICEAgent) {
	agent := &recordingICEAgent{
		gathered:      append([]nat.Candidate(nil), gathered...),
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
	}, executorConfig{Mode: mode, ForceRelay: mode == modeRelayOnly, PublicDirectCandidate: mode == modePublicDirect})
	return exec, agent
}

func findObservation(observations []solver.Observation, event string) *solver.Observation {
	for i := range observations {
		if observations[i].Event == event {
			return &observations[i]
		}
	}
	return nil
}
