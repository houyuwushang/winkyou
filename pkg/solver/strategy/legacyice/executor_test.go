package legacyice

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type recordingICEAgent struct {
	gathered          []nat.Candidate
	remoteCandidates  []nat.Candidate
	connectErr        error
	connectCalled     chan struct{}
	selectedPair      *nat.CandidatePair
	selectedStats     nat.CandidatePairStats
	hasSelectedStats  bool
	gatherDeadline    time.Time
	gatherHasDeadline bool
}

func (a *recordingICEAgent) GatherCandidates(ctx context.Context) ([]nat.Candidate, error) {
	a.gatherDeadline, a.gatherHasDeadline = ctx.Deadline()
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

func (a *recordingICEAgent) GetSelectedPair() (*nat.CandidatePair, error) {
	if a.selectedPair == nil {
		return nil, errors.New("no selected pair")
	}
	return a.selectedPair, nil
}

func (a *recordingICEAgent) GetSelectedPairStats() (nat.CandidatePairStats, bool) {
	return a.selectedStats, a.hasSelectedStats
}

func (a *recordingICEAgent) RemoteCandidateCount() int {
	return len(a.remoteCandidates)
}

func (a *recordingICEAgent) Close() error { return nil }

type recordingPunchICEAgent struct {
	recordingICEAgent
	mu       sync.Mutex
	punched  []nat.Candidate
	opts     []nat.PublicDirectPunchOptions
	punchErr error
	local    *net.UDPAddr
}

func (a *recordingPunchICEAgent) PunchCandidates(ctx context.Context, candidates []nat.Candidate, opts nat.PublicDirectPunchOptions) (nat.PublicDirectPunchReport, error) {
	_ = ctx
	limit := opts.Limit
	if limit <= 0 || limit > len(candidates) {
		limit = len(candidates)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.punched = append(a.punched, candidates[:limit]...)
	a.opts = append(a.opts, opts)
	burst := opts.Burst
	if burst <= 0 {
		burst = 1
	}
	return nat.PublicDirectPunchReport{
		CandidateTotal: len(candidates),
		CandidateSent:  limit,
		PacketSent:     limit * burst,
		LocalAddr:      cloneTestUDPAddr(a.local),
	}, a.punchErr
}

func (a *recordingPunchICEAgent) Punched() []nat.Candidate {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]nat.Candidate(nil), a.punched...)
}

func (a *recordingPunchICEAgent) PunchOptions() []nat.PublicDirectPunchOptions {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]nat.PublicDirectPunchOptions(nil), a.opts...)
}

func cloneTestUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

type recordingSessionIO struct{}

func (recordingSessionIO) Send(context.Context, solver.Message) error { return nil }

func (recordingSessionIO) ReportObservation(context.Context, solver.Observation) error { return nil }

type capturingSessionIO struct {
	mu           sync.Mutex
	messages     []solver.Message
	observations []solver.Observation
}

func (c *capturingSessionIO) Send(_ context.Context, msg solver.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.messages = append(c.messages, msg)
	return nil
}

func (c *capturingSessionIO) ReportObservation(_ context.Context, obs solver.Observation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observations = append(c.observations, obs)
	return nil
}

func (c *capturingSessionIO) Messages() []solver.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]solver.Message(nil), c.messages...)
}

func (c *capturingSessionIO) WaitMessages(t *testing.T, count int) []solver.Message {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		messages := c.Messages()
		if len(messages) >= count {
			return messages
		}
		if time.Now().After(deadline) {
			t.Fatalf("messages = %d, want at least %d", len(messages), count)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *capturingSessionIO) Observations() []solver.Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]solver.Observation(nil), c.observations...)
}

func (c *capturingSessionIO) WaitObservations(t *testing.T, count int) []solver.Observation {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		observations := c.Observations()
		if len(observations) >= count {
			return observations
		}
		if time.Now().After(deadline) {
			t.Fatalf("observations = %d, want at least %d", len(observations), count)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type cancelAfterSessionIO struct {
	capturingSessionIO
	cancelAfter int
	cancel      context.CancelFunc
}

func (c *cancelAfterSessionIO) Send(ctx context.Context, msg solver.Message) error {
	if err := c.capturingSessionIO.Send(ctx, msg); err != nil {
		return err
	}
	if c.cancelAfter > 0 && len(c.Messages()) >= c.cancelAfter && c.cancel != nil {
		c.cancel()
	}
	return nil
}

func TestExecutorConfigForPlanProducesDistinctModes(t *testing.T) {
	direct, err := executorConfigForPlan(solver.Plan{ID: "legacyice/direct_prefer", Metadata: map[string]string{"mode": "direct_prefer"}}, Config{DirectTrustedCIDRs: []string{"100.64.0.0/10"}})
	if err != nil {
		t.Fatalf("executorConfigForPlan(direct) error = %v", err)
	}
	if direct.Mode != modeDirectPrefer || direct.ForceRelay {
		t.Fatalf("direct config = %+v, want direct_prefer without force relay", direct)
	}
	if len(direct.DirectTrustedCIDRs) != 1 || direct.DirectTrustedCIDRs[0] != "100.64.0.0/10" {
		t.Fatalf("direct trusted CIDRs = %#v, want 100.64.0.0/10", direct.DirectTrustedCIDRs)
	}

	publicDirect, err := executorConfigForPlan(solver.Plan{ID: "legacyice/public_direct", Metadata: map[string]string{"mode": "public_direct"}}, Config{CandidateCIDRInclude: []string{"10.6.22.0/24"}})
	if err != nil {
		t.Fatalf("executorConfigForPlan(public_direct) error = %v", err)
	}
	if publicDirect.Mode != modePublicDirect || publicDirect.ForceRelay || !publicDirect.PublicDirectCandidate {
		t.Fatalf("public direct config = %+v, want public_direct without force relay", publicDirect)
	}
	if len(publicDirect.CandidateCIDRExclude) != 0 {
		t.Fatalf("public direct CIDR excludes = %#v, want no agent-level excludes", publicDirect.CandidateCIDRExclude)
	}
	if len(publicDirect.CandidateCIDRInclude) != 1 || publicDirect.CandidateCIDRInclude[0] != "10.6.22.0/24" {
		t.Fatalf("public direct CIDR includes = %#v, want configured include", publicDirect.CandidateCIDRInclude)
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
	wantMessages := 1 + publicDirectCandidateSignalRounds
	messages := io.WaitMessages(t, wantMessages)
	if len(messages) != wantMessages {
		t.Fatalf("sent messages = %d, want offer + %d candidate signal rounds", len(messages), publicDirectCandidateSignalRounds)
	}
	offer, err := unmarshalOfferPayload(messages[0].Payload)
	if err != nil {
		t.Fatalf("unmarshal offer error = %v", err)
	}
	if len(offer.ICE.Candidates) != 1 {
		t.Fatalf("offer candidates = %#v, want only public srflx candidate", offer.ICE.Candidates)
	}
	if offer.ICE.Candidates[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("offer candidate = %v, want %v", offer.ICE.Candidates[0].Address, publicCandidate.Address)
	}
	if messages[1].Type != MessageTypeCandidate {
		t.Fatalf("second message type = %q, want candidate", messages[1].Type)
	}
	signaled, err := unmarshalCandidatePayload(messages[1].Payload)
	if err != nil {
		t.Fatalf("unmarshal candidate signal error = %v", err)
	}
	if signaled.PlanID != planIDPublicDirect || signaled.ICE.Candidate.Address.String() != publicCandidate.Address.String() {
		t.Fatalf("candidate signal = %#v, want public_direct %v", signaled, publicCandidate.Address)
	}
	observations := io.Observations()
	obs := findObservation(observations, "candidate_gathered")
	if obs == nil {
		t.Fatalf("candidate_gathered observation not reported: %#v", observations)
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
	signaledObs := findObservation(observations, "candidate_signaled")
	if signaledObs == nil || signaledObs.Details["candidate_sent"] != "1" || signaledObs.Details["candidate_total"] != "1" || signaledObs.Details["candidate_rounds"] != strconv.Itoa(publicDirectCandidateSignalRounds) {
		t.Fatalf("candidate_signaled observation = %#v, want sent=1 total=1 with configured rounds", signaledObs)
	}
}

func TestPublicDirectAdvertisesConfiguredPublicEndpointHints(t *testing.T) {
	hostCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000}}
	unmappedHostCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 21), Port: 40001}}
	agent := &recordingICEAgent{
		gathered:      []nat.Candidate{hostCandidate, unmappedHostCandidate},
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	publicEndpointHint := "117.48.146.2:41000/192.168.1.20:40000"
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			if !req.PublicDirectCandidate {
				t.Fatalf("agent request = %+v, want public direct marker", req)
			}
			return agent, nil
		},
		GatherTimeout:       10 * time.Second,
		ConnectTimeout:      100 * time.Millisecond,
		PublicEndpointHints: []string{publicEndpointHint},
	}, solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{
		Mode:                  modePublicDirect,
		PublicDirectCandidate: true,
		PublicEndpointHints:   []string{publicEndpointHint},
	})

	io := &capturingSessionIO{}
	if err := exec.sendOffer(context.Background(), io); err != nil {
		t.Fatalf("sendOffer(public endpoint hint) error = %v", err)
	}
	if !agent.gatherHasDeadline {
		t.Fatal("GatherCandidates context has no deadline")
	}
	if remaining := time.Until(agent.gatherDeadline); remaining <= 0 || remaining > 2*time.Second {
		t.Fatalf("GatherCandidates deadline remaining = %v, want short public endpoint hint gather timeout", remaining)
	}
	wantMessages := 1 + 2*publicDirectCandidateSignalRounds
	messages := io.WaitMessages(t, wantMessages)
	if len(messages) != wantMessages {
		t.Fatalf("sent messages = %d, want offer + %d candidate signal rounds for two endpoint-hint candidates", len(messages), publicDirectCandidateSignalRounds)
	}
	offer, err := unmarshalOfferPayload(messages[0].Payload)
	if err != nil {
		t.Fatalf("unmarshal offer error = %v", err)
	}
	if len(offer.ICE.Candidates) != 2 {
		t.Fatalf("offer candidates = %#v, want mapped and local-port public endpoint hints", offer.ICE.Candidates)
	}
	hint := offer.ICE.Candidates[0]
	if hint.Type != nat.CandidateTypeSrflx || hint.Address.String() != "117.48.146.2:41000" {
		t.Fatalf("offer hint = %#v, want srflx 117.48.146.2:41000", hint)
	}
	if hint.RelatedAddr == nil || hint.RelatedAddr.String() != "192.168.1.20:40000" {
		t.Fatalf("offer hint related addr = %#v, want 192.168.1.20:40000", hint.RelatedAddr)
	}
	if !strings.HasPrefix(hint.Foundation, "public-hint-") || hint.Priority == 0 {
		t.Fatalf("offer hint foundation/priority = %q/%d, want populated", hint.Foundation, hint.Priority)
	}
	localPortHint := offer.ICE.Candidates[1]
	if localPortHint.Type != nat.CandidateTypeSrflx || localPortHint.Address.String() != "117.48.146.2:40000" {
		t.Fatalf("offer local-port hint = %#v, want srflx 117.48.146.2:40000", localPortHint)
	}
	if localPortHint.RelatedAddr == nil || localPortHint.RelatedAddr.String() != "192.168.1.20:40000" {
		t.Fatalf("offer local-port hint related addr = %#v, want 192.168.1.20:40000", localPortHint.RelatedAddr)
	}
	bases := exec.publicDirectLocalBaseSnapshot()
	if _, ok := bases["192.168.1.20"]; !ok {
		t.Fatalf("public direct local bases = %#v, want host candidate base from public endpoint hint", bases)
	}
	if _, ok := bases["192.168.1.21"]; ok {
		t.Fatalf("public direct local bases = %#v, want only explicitly mapped local base", bases)
	}
	role, deps := pathPolicyMetadata("direct", candidatePairWithTypes(nat.CandidateTypeHost, "192.168.1.20", nat.CandidateTypePrflx, "117.48.146.3"), modePublicDirect, bases, nil)
	if role != solver.PathRoleProtectedDirect || len(deps) != 0 {
		t.Fatalf("path policy with public endpoint hint base = role %q deps %#v, want protected direct", role, deps)
	}
	role, deps = pathPolicyMetadata("direct", candidatePairWithTypes(nat.CandidateTypeHost, "192.168.1.21", nat.CandidateTypePrflx, "117.48.146.3"), modePublicDirect, bases, nil)
	if role != solver.PathRolePrimaryCandidate || len(deps) != 1 || deps[0].Reason != "local_private_candidate" {
		t.Fatalf("path policy with unmapped private base = role %q deps %#v, want dependent direct", role, deps)
	}
	observations := io.Observations()
	obs := findObservation(observations, "candidate_gathered")
	if obs == nil || !strings.Contains(obs.Details["candidate_kept_samples"], "srflx:117.48.146.2:41000<-192.168.1.20:40000") {
		t.Fatalf("observations = %#v, want kept public endpoint hint sample", observations)
	}
	if obs.Details["public_endpoint_hint_count"] != "1" {
		t.Fatalf("candidate_gathered public endpoint hint count = %#v, want 1", obs.Details)
	}
	if obs.Details["public_endpoint_hint_fast_gather"] != "true" || obs.Details["gather_timeout_ms"] != "1000" {
		t.Fatalf("candidate_gathered fast gather details = %#v, want fast gather timeout", obs.Details)
	}
	if obs.Details["public_endpoint_hint_local_base_count"] != "1" ||
		obs.Details["public_endpoint_hint_local_bases"] != "192.168.1.20:40000" ||
		obs.Details["public_endpoint_hint_fixed_local_port"] != "40000" ||
		obs.Details["public_endpoint_hint_fixed_udp_mux_candidate"] != "true" {
		t.Fatalf("candidate_gathered local base details = %#v, want fixed local base diagnostics", obs.Details)
	}
}

func TestPublicDirectGatherTimeoutOnlyShortensWithEndpointHints(t *testing.T) {
	withHint := newExecutor(Config{GatherTimeout: 10 * time.Second}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{
		Mode:                modePublicDirect,
		PublicEndpointHints: []string{"117.48.146.2:41000/192.168.1.20:40000"},
	})
	if got := withHint.gatherTimeout(); got != publicDirectHintGatherTimeout {
		t.Fatalf("gatherTimeout(with hint) = %v, want %v", got, publicDirectHintGatherTimeout)
	}

	withoutHint := newExecutor(Config{GatherTimeout: 10 * time.Second}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{
		Mode: modePublicDirect,
	})
	if got := withoutHint.gatherTimeout(); got != 10*time.Second {
		t.Fatalf("gatherTimeout(without hint) = %v, want configured timeout", got)
	}

	shortConfigured := newExecutor(Config{GatherTimeout: 100 * time.Millisecond}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{
		Mode:                modePublicDirect,
		PublicEndpointHints: []string{"117.48.146.2:41000/192.168.1.20:40000"},
	})
	if got := shortConfigured.gatherTimeout(); got != 100*time.Millisecond {
		t.Fatalf("gatherTimeout(short configured) = %v, want configured timeout", got)
	}
}

func TestPublicDirectExpandsPublicEndpointHintPortWindow(t *testing.T) {
	candidates, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                         modePublicDirect,
		PublicEndpointHints:          []string{"117.48.146.2:41000/192.168.1.20:40000"},
		PublicEndpointHintPortWindow: 2,
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates() error = %v", err)
	}
	got := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Type != nat.CandidateTypeSrflx {
			t.Fatalf("candidate type = %s, want srflx", candidate.Type)
		}
		if candidate.RelatedAddr == nil || candidate.RelatedAddr.String() != "192.168.1.20:40000" {
			t.Fatalf("candidate related addr = %#v, want 192.168.1.20:40000", candidate.RelatedAddr)
		}
		got = append(got, candidate.Address.String())
	}
	want := []string{
		"117.48.146.2:41000",
		"117.48.146.2:40999",
		"117.48.146.2:41001",
		"117.48.146.2:40998",
		"117.48.146.2:41002",
		"117.48.146.2:40000",
		"117.48.146.2:39999",
		"117.48.146.2:40001",
		"117.48.146.2:39998",
		"117.48.146.2:40002",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("expanded hint candidates = %#v, want %#v", got, want)
	}
}

func TestPublicDirectHintPriorityIncludesLocalBasePortCenter(t *testing.T) {
	candidates, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                         modePublicDirect,
		PublicEndpointHints:          []string{"117.48.146.2:41000/192.168.1.20:40000"},
		PublicEndpointHintPortWindow: 2,
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates() error = %v", err)
	}
	ordered := prioritizePublicDirectSignalCandidates(candidates)
	localBaseCenter := candidateAddressIndex(ordered, "117.48.146.2:40000")
	mappedOffsetOne := candidateAddressIndex(ordered, "117.48.146.2:40999")
	if localBaseCenter < 0 || mappedOffsetOne < 0 {
		t.Fatalf("ordered candidates missing expected addresses: %#v", candidateAddresses(ordered))
	}
	if localBaseCenter > mappedOffsetOne {
		t.Fatalf("hint priority order = %#v; want local-base port center before mapped port offset 1", candidateAddresses(ordered))
	}
}

func TestPublicDirectHintPriorityInterleavesMultipleHintsByOffset(t *testing.T) {
	candidates, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode: modePublicDirect,
		PublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:42000/192.168.1.20:40000",
		},
		PublicEndpointHintPortWindow: 2,
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates() error = %v", err)
	}
	ordered := prioritizePublicDirectSignalCandidates(candidates)
	secondHintBase := candidateAddressIndex(ordered, "117.48.146.3:42000")
	firstHintOffsetTwo := candidateAddressIndex(ordered, "117.48.146.2:40998")
	if secondHintBase < 0 || firstHintOffsetTwo < 0 {
		t.Fatalf("ordered candidates missing expected addresses: %#v", candidateAddresses(ordered))
	}
	if secondHintBase > firstHintOffsetTwo {
		t.Fatalf("hint priority order = %#v; want second hint base before first hint offset distance 2", candidateAddresses(ordered))
	}
}

func candidateAddressIndex(candidates []nat.Candidate, address string) int {
	for i, candidate := range candidates {
		if candidate.Address != nil && candidate.Address.String() == address {
			return i
		}
	}
	return -1
}

func candidateAddresses(candidates []nat.Candidate) []string {
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Address == nil {
			continue
		}
		out = append(out, candidate.Address.String())
	}
	return out
}

func TestPublicDirectCandidateObservationReportsEndpointHintPortWindow(t *testing.T) {
	exec := newExecutor(Config{}, solver.SolveInput{}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{
		Mode:                         modePublicDirect,
		PublicEndpointHints:          []string{"117.48.146.2:41000/192.168.1.20:40000"},
		PublicEndpointHintPortWindow: 2,
	})
	summary := newCandidateFilterSummary()
	summary.record(nat.Candidate{
		Type:    nat.CandidateTypeSrflx,
		Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
	}, true, "")
	io := &capturingSessionIO{}

	exec.reportCandidateFilter(io, "candidate_gathered", "local", MessageTypeOffer, summary)

	observations := io.Observations()
	obs := findObservation(observations, "candidate_gathered")
	if obs == nil {
		t.Fatalf("observations = %#v, want candidate_gathered", observations)
	}
	if obs.Details["public_endpoint_hint_count"] != "1" || obs.Details["public_endpoint_hint_port_window"] != "2" {
		t.Fatalf("candidate_gathered details = %#v, want endpoint hint count/window", obs.Details)
	}
	if obs.Details["public_endpoint_hint_local_base_count"] != "1" ||
		obs.Details["public_endpoint_hint_local_bases"] != "192.168.1.20:40000" ||
		obs.Details["public_endpoint_hint_fixed_local_port"] != "40000" ||
		obs.Details["public_endpoint_hint_fixed_udp_mux_candidate"] != "true" {
		t.Fatalf("candidate_gathered local base details = %#v, want fixed local base diagnostics", obs.Details)
	}
}

func TestExecutorPublicDirectSingleCandidatePunchAvoidsObservationNoise(t *testing.T) {
	publicCandidate := nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
		Priority:   100,
		Foundation: "remote-srflx",
	}
	agent := &recordingPunchICEAgent{local: &net.UDPAddr{IP: net.IPv4(172, 29, 7, 111), Port: 64779}}
	exec := newExecutor(Config{}, solver.SolveInput{}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	exec.punchRemoteCandidates(context.Background(), io, agent, []nat.Candidate{publicCandidate}, MessageTypeCandidate)

	punched := agent.Punched()
	if len(punched) != 1 || punched[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("punched candidates = %#v, want single remote candidate", punched)
	}
	if obs := findObservation(io.Observations(), "remote_candidates_punched"); obs != nil {
		t.Fatalf("remote_candidates_punched observation = %#v, want no noisy single-candidate success observation", obs)
	}
}

func TestPublicDirectCandidateSignalsAreBounded(t *testing.T) {
	candidates := make([]nat.Candidate, publicDirectCandidateSignalLimit+16)
	for i := range candidates {
		candidates[i] = nat.Candidate{
			Type:    nat.CandidateTypeSrflx,
			Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000 + i},
		}
	}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	exec.sendCandidateMessages(context.Background(), io, candidates)

	wantMessages := publicDirectCandidateSignalLimit * publicDirectCandidateSignalRounds
	messages := io.WaitMessages(t, wantMessages)
	if len(messages) != wantMessages {
		t.Fatalf("candidate signal messages = %d, want limit %d across %d rounds", len(messages), publicDirectCandidateSignalLimit, publicDirectCandidateSignalRounds)
	}
	for i, msg := range messages {
		if msg.Type != MessageTypeCandidate {
			t.Fatalf("message[%d].Type = %q, want candidate", i, msg.Type)
		}
		payload, err := unmarshalCandidatePayload(msg.Payload)
		if err != nil {
			t.Fatalf("unmarshal candidate[%d] error = %v", i, err)
		}
		if payload.PlanID != planIDPublicDirect {
			t.Fatalf("candidate[%d] plan id = %q, want %q", i, payload.PlanID, planIDPublicDirect)
		}
	}
	observations := io.Observations()
	obs := findObservation(observations, "candidate_signaled")
	if obs == nil {
		t.Fatalf("candidate_signaled observation missing: %#v", observations)
	}
	if obs.Details["candidate_total"] != strconv.Itoa(len(candidates)) || obs.Details["candidate_sent"] != strconv.Itoa(publicDirectCandidateSignalLimit) || obs.Details["candidate_capped"] != "true" || obs.Details["candidate_rounds"] != strconv.Itoa(publicDirectCandidateSignalRounds) {
		t.Fatalf("candidate_signaled details = %#v, want capped %d/%d with configured rounds", obs.Details, len(candidates), publicDirectCandidateSignalLimit)
	}
}

func TestPublicDirectCandidateSignalsPrioritizeEndpointHintsWhenCapped(t *testing.T) {
	candidates := make([]nat.Candidate, publicDirectCandidateSignalLimit)
	for i := range candidates {
		candidates[i] = nat.Candidate{
			Type:       nat.CandidateTypeSrflx,
			Address:    &net.UDPAddr{IP: net.IPv4(117, 48, 146, 3), Port: 42000 + i},
			Priority:   1000 - uint32(i),
			Foundation: "srflx-" + strconv.Itoa(i),
		}
	}
	hintCandidate := nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
		Priority:   1,
		Foundation: "public-hint-1",
		RelatedAddr: &net.UDPAddr{
			IP:   net.IPv4(192, 168, 1, 20),
			Port: 40000,
		},
	}
	candidates = append(candidates, hintCandidate)
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	exec.sendCandidateMessages(context.Background(), io, candidates)

	messages := io.Messages()
	if len(messages) != publicDirectCandidateSignalLimit {
		t.Fatalf("immediate candidate signal messages = %d, want first round limit %d", len(messages), publicDirectCandidateSignalLimit)
	}
	payload, err := unmarshalCandidatePayload(messages[0].Payload)
	if err != nil {
		t.Fatalf("unmarshal first candidate error = %v", err)
	}
	if payload.ICE.Candidate.Address.String() != hintCandidate.Address.String() {
		t.Fatalf("first signaled candidate = %v, want endpoint hint %v", payload.ICE.Candidate.Address, hintCandidate.Address)
	}
	if payload.ICE.Candidate.Foundation != hintCandidate.Foundation {
		t.Fatalf("first signaled foundation = %q, want %q", payload.ICE.Candidate.Foundation, hintCandidate.Foundation)
	}
}

func TestPublicDirectCandidateSignalsCoverEndpointHintWindowWhenCapped(t *testing.T) {
	candidates, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                         modePublicDirect,
		PublicEndpointHints:          []string{"210.30.106.93:50000/172.29.7.111:64779"},
		PublicEndpointHintPortWindow: 512,
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates() error = %v", err)
	}
	candidates = append(candidates, nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: net.IPv4(210, 30, 106, 93), Port: 30000},
		Foundation: "srflx-current",
	})
	if len(candidates) <= publicDirectCandidateSignalLimit {
		t.Fatalf("hint candidates = %d, want more than default signal limit %d", len(candidates), publicDirectCandidateSignalLimit)
	}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	ordered := prioritizePublicDirectSignalCandidates(candidates)
	exec.sendCandidateMessageRound(context.Background(), io, ordered, 1, 1)

	messages := io.Messages()
	if len(messages) != len(candidates) {
		t.Fatalf("candidate signal messages = %d, want full endpoint-hint window %d", len(messages), len(candidates))
	}
	obs := findObservation(io.Observations(), "candidate_signaled")
	if obs == nil {
		t.Fatalf("observations = %#v, want candidate_signaled", io.Observations())
	}
	if obs.Details["candidate_limit"] != strconv.Itoa(len(candidates)) ||
		obs.Details["candidate_sent"] != strconv.Itoa(len(candidates)) ||
		obs.Details["candidate_capped"] != "false" {
		t.Fatalf("candidate_signaled details = %#v, want full endpoint-hint window", obs.Details)
	}
}

func TestPublicDirectCandidateSignalRoundResumesAfterPartialSend(t *testing.T) {
	candidates := []nat.Candidate{
		{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000}, Foundation: "srflx-1"},
		{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41001}, Foundation: "srflx-2"},
		{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41002}, Foundation: "srflx-3"},
		{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41003}, Foundation: "srflx-4"},
		{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41004}, Foundation: "srflx-5"},
	}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	ctx, cancel := context.WithCancel(context.Background())
	io := &cancelAfterSessionIO{cancelAfter: 3, cancel: cancel}

	nextStart := exec.sendCandidateMessageRoundFrom(ctx, io, candidates, 1, 3, 0)

	if nextStart != 3 {
		t.Fatalf("next start = %d, want 3 after partial send", nextStart)
	}
	secondRound := &capturingSessionIO{}
	exec.sendCandidateMessageRoundFrom(context.Background(), secondRound, candidates, 2, 3, nextStart)
	messages := secondRound.Messages()
	if len(messages) == 0 {
		t.Fatal("second round did not send any candidate")
	}
	payload, err := unmarshalCandidatePayload(messages[0].Payload)
	if err != nil {
		t.Fatalf("unmarshal first second-round candidate error = %v", err)
	}
	if payload.ICE.Candidate.Address.String() != "117.48.146.2:41003" {
		t.Fatalf("second round first candidate = %v, want resume at 117.48.146.2:41003", payload.ICE.Candidate.Address)
	}
	obs := findObservation(secondRound.Observations(), "candidate_signaled")
	if obs == nil || obs.Details["candidate_start"] != "3" {
		t.Fatalf("second round observations = %#v, want candidate_start=3", secondRound.Observations())
	}
	if obs.Details["candidate_first"] != "117.48.146.2:41003" ||
		obs.Details["candidate_last"] != "117.48.146.2:41002" ||
		obs.Details["candidate_next_start"] != "3" ||
		obs.Details["candidate_port_min"] != "41000" ||
		obs.Details["candidate_port_max"] != "41004" {
		t.Fatalf("second round coverage details = %#v, want wrapped coverage diagnostics", obs.Details)
	}
}

func TestPublicDirectCandidateSignalsRetryAsynchronously(t *testing.T) {
	candidate := nat.Candidate{
		Type:    nat.CandidateTypeSrflx,
		Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
	}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	start := time.Now()
	exec.sendCandidateMessages(context.Background(), io, []nat.Candidate{candidate})
	if elapsed := time.Since(start); elapsed >= publicDirectCandidateSignalRetryInterval {
		t.Fatalf("sendCandidateMessages elapsed = %v, want return before retry interval", elapsed)
	}
	if messages := io.Messages(); len(messages) != 1 {
		t.Fatalf("immediate candidate signal messages = %d, want first round only", len(messages))
	}

	messages := io.WaitMessages(t, publicDirectCandidateSignalRounds)
	if len(messages) != publicDirectCandidateSignalRounds {
		t.Fatalf("candidate signal messages = %d, want %d rounds", len(messages), publicDirectCandidateSignalRounds)
	}
	observations := io.WaitObservations(t, publicDirectCandidateSignalRounds)
	last := observations[len(observations)-1]
	if last.Event != "candidate_signaled" || last.Details["candidate_round"] != strconv.Itoa(publicDirectCandidateSignalRounds) {
		t.Fatalf("last observation = %#v, want final candidate_signaled round", last)
	}
}

func TestPublicDirectCandidateSignalRoundsScaleWithConnectTimeout(t *testing.T) {
	defaultExec := newExecutor(Config{}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := defaultExec.candidateSignalRounds(); got != publicDirectCandidateSignalRounds {
		t.Fatalf("default candidateSignalRounds() = %d, want %d", got, publicDirectCandidateSignalRounds)
	}

	shortExec := newExecutor(Config{ConnectTimeout: publicDirectCandidateSignalRetryInterval}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := shortExec.candidateSignalRounds(); got != publicDirectCandidateSignalRounds {
		t.Fatalf("short candidateSignalRounds() = %d, want min %d", got, publicDirectCandidateSignalRounds)
	}

	longExec := newExecutor(Config{ConnectTimeout: 25 * time.Second}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := longExec.candidateSignalRounds(); got != publicDirectCandidateSignalMaxRounds {
		t.Fatalf("long candidateSignalRounds() = %d, want capped %d", got, publicDirectCandidateSignalMaxRounds)
	}
}

func TestPublicDirectCandidateSignalRetryIntervalScalesWithConnectTimeout(t *testing.T) {
	defaultExec := newExecutor(Config{}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := defaultExec.candidateSignalRetryInterval(defaultExec.candidateSignalRounds()); got != publicDirectCandidateSignalRetryInterval {
		t.Fatalf("default candidateSignalRetryInterval() = %v, want %v", got, publicDirectCandidateSignalRetryInterval)
	}

	longExec := newExecutor(Config{ConnectTimeout: 25 * time.Second}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := longExec.candidateSignalRetryInterval(longExec.candidateSignalRounds()); got != 1250*time.Millisecond {
		t.Fatalf("long candidateSignalRetryInterval() = %v, want 1.25s", got)
	}

	veryLongExec := newExecutor(Config{ConnectTimeout: 5 * time.Minute}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := veryLongExec.candidateSignalRetryInterval(veryLongExec.candidateSignalRounds()); got != publicDirectCandidateSignalMaxRetryInterval {
		t.Fatalf("very long candidateSignalRetryInterval() = %v, want cap %v", got, publicDirectCandidateSignalMaxRetryInterval)
	}
}

func TestPublicDirectCandidateSignalObservationReportsRetryWindow(t *testing.T) {
	candidate := nat.Candidate{
		Type:    nat.CandidateTypeSrflx,
		Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
	}
	exec := newExecutor(Config{ConnectTimeout: 25 * time.Second}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	rounds := exec.candidateSignalRounds()
	exec.sendCandidateMessageRound(context.Background(), io, []nat.Candidate{candidate}, 1, rounds)

	obs := findObservation(io.Observations(), "candidate_signaled")
	if obs == nil {
		t.Fatalf("observations = %#v, want candidate_signaled", io.Observations())
	}
	if obs.Details["retry_interval_ms"] != "1250" || obs.Details["signal_window_ms"] != "23750" {
		t.Fatalf("candidate_signaled details = %#v, want stretched retry window", obs.Details)
	}
}

func TestPublicDirectRemoteCandidateGraceScalesWithConnectTimeout(t *testing.T) {
	defaultExec := newExecutor(Config{}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := defaultExec.remoteCandidateGraceTimeout(); got != publicDirectRemoteCandidateGraceTimeout {
		t.Fatalf("default remoteCandidateGraceTimeout() = %v, want %v", got, publicDirectRemoteCandidateGraceTimeout)
	}

	shortExec := newExecutor(Config{ConnectTimeout: time.Second}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := shortExec.remoteCandidateGraceTimeout(); got != publicDirectRemoteCandidateGraceTimeout {
		t.Fatalf("short remoteCandidateGraceTimeout() = %v, want min %v", got, publicDirectRemoteCandidateGraceTimeout)
	}

	longExec := newExecutor(Config{ConnectTimeout: 25 * time.Second}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := longExec.remoteCandidateGraceTimeout(); got != publicDirectRemoteCandidateGraceMaxTimeout {
		t.Fatalf("long remoteCandidateGraceTimeout() = %v, want cap %v", got, publicDirectRemoteCandidateGraceMaxTimeout)
	}

	midExec := newExecutor(Config{ConnectTimeout: 8 * time.Second}, solver.SolveInput{}, solver.Plan{ID: planIDPublicDirect}, executorConfig{Mode: modePublicDirect})
	if got := midExec.remoteCandidateGraceTimeout(); got != 4*time.Second {
		t.Fatalf("mid remoteCandidateGraceTimeout() = %v, want half connect timeout", got)
	}
}

func TestPublicDirectRemoteCandidateWaitingReportsScaledGrace(t *testing.T) {
	exec := newExecutor(Config{ConnectTimeout: 25 * time.Second}, solver.SolveInput{}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	t.Cleanup(func() {
		if err := exec.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	io := &capturingSessionIO{}

	if !exec.waitForPublicDirectRemoteCandidates(io, MessageTypeAnswer) {
		t.Fatal("waitForPublicDirectRemoteCandidates() = false, want true")
	}

	obs := findObservation(io.Observations(), "remote_candidates_waiting")
	if obs == nil {
		t.Fatalf("observations = %#v, want remote_candidates_waiting", io.Observations())
	}
	if obs.Details["candidate_grace_ms"] != strconv.FormatInt(publicDirectRemoteCandidateGraceMaxTimeout.Milliseconds(), 10) {
		t.Fatalf("remote_candidates_waiting details = %#v, want scaled grace", obs.Details)
	}
}

func TestPublicDirectCandidateSignalSendTimeoutScalesWithCandidateCount(t *testing.T) {
	if got := candidateSignalSendTimeout(0); got != publicDirectCandidateSignalSendTimeout {
		t.Fatalf("candidateSignalSendTimeout(0) = %v, want base %v", got, publicDirectCandidateSignalSendTimeout)
	}

	tenCandidates := publicDirectCandidateSignalSendTimeout + 10*publicDirectCandidateSignalSendPerCandidateTimeout
	if got := candidateSignalSendTimeout(10); got != tenCandidates {
		t.Fatalf("candidateSignalSendTimeout(10) = %v, want %v", got, tenCandidates)
	}

	if got := candidateSignalSendTimeout(10_000); got != publicDirectCandidateSignalMaxSendTimeout {
		t.Fatalf("candidateSignalSendTimeout(large) = %v, want cap %v", got, publicDirectCandidateSignalMaxSendTimeout)
	}
}

func TestPublicDirectFailureIncludesLastCandidateSignalDetails(t *testing.T) {
	candidate := nat.Candidate{
		Type:    nat.CandidateTypeSrflx,
		Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
	}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	exec.sendCandidateMessageRound(context.Background(), io, []nat.Candidate{candidate}, 1, publicDirectCandidateSignalRounds)
	exec.reportFailure(io, errors.New("public direct timeout"))

	obs := findObservation(io.Observations(), "candidate_failed")
	if obs == nil {
		t.Fatalf("observations = %#v, want candidate_failed", io.Observations())
	}
	if obs.Details["last_signal_candidate_sent"] != "1" ||
		obs.Details["last_signal_candidate_total"] != "1" ||
		obs.Details["last_signal_candidate_round"] != "1" ||
		obs.Details["last_signal_candidate_rounds"] != strconv.Itoa(publicDirectCandidateSignalRounds) {
		t.Fatalf("candidate_failed details = %#v, want last signal details", obs.Details)
	}
}

func TestPublicDirectFailureIncludesLastRemotePunchDetails(t *testing.T) {
	candidates := []nat.Candidate{
		{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000}, Foundation: "srflx-1"},
		{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41001}, Foundation: "srflx-2"},
	}
	agent := &recordingPunchICEAgent{local: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000}}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	exec.punchRemoteCandidateRound(context.Background(), io, agent, candidates, MessageTypeAnswer, 2, 3, 1)
	exec.reportFailure(io, errors.New("public direct timeout"))

	obs := findObservation(io.Observations(), "candidate_failed")
	if obs == nil {
		t.Fatalf("observations = %#v, want candidate_failed", io.Observations())
	}
	if obs.Details["last_punch_punch_local_addr"] != "192.168.1.20:40000" ||
		obs.Details["last_punch_candidate_start"] != "1" ||
		obs.Details["last_punch_candidate_first"] != "117.48.146.2:41001" ||
		obs.Details["last_punch_candidate_port_min"] != "41000" ||
		obs.Details["last_punch_candidate_port_max"] != "41001" ||
		obs.Details["last_punch_packet_sent"] != strconv.Itoa(2*publicDirectRemotePunchBurst) ||
		obs.Details["last_punch_punch_burst"] != strconv.Itoa(publicDirectRemotePunchBurst) ||
		obs.Details["last_punch_punch_round"] != "2" ||
		obs.Details["last_punch_punch_rounds"] != "3" {
		t.Fatalf("candidate_failed details = %#v, want last punch diagnostics", obs.Details)
	}
}

func TestPublicDirectFailureIncludesAgentDiagnostics(t *testing.T) {
	localCandidate := nat.Candidate{
		Type:    nat.CandidateTypeHost,
		Address: &net.UDPAddr{IP: net.IPv4(192, 168, 50, 10), Port: 40000},
	}
	remoteCandidate := nat.Candidate{
		Type:    nat.CandidateTypeSrflx,
		Address: &net.UDPAddr{IP: net.IPv4(210, 30, 106, 93), Port: 18981},
	}
	agent := &recordingICEAgent{
		remoteCandidates: []nat.Candidate{remoteCandidate},
		selectedPair: &nat.CandidatePair{
			Local:  &localCandidate,
			Remote: &remoteCandidate,
		},
	}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	exec.agent = agent
	io := &capturingSessionIO{}

	exec.reportFailure(io, errors.New("public direct timeout"))

	obs := findObservation(io.Observations(), "candidate_failed")
	if obs == nil {
		t.Fatalf("observations = %#v, want candidate_failed", io.Observations())
	}
	if obs.Details["ice_remote_candidate_count"] != "1" ||
		obs.Details["ice_selected_pair"] != "true" ||
		obs.Details["ice_selected_pair_local"] != "host:192.168.50.10:40000" ||
		obs.Details["ice_selected_pair_remote"] != "srflx:210.30.106.93:18981" {
		t.Fatalf("candidate_failed details = %#v, want agent diagnostics", obs.Details)
	}
}

func TestPublicDirectCandidateSignalLimitCoversSymmetricHintWindow(t *testing.T) {
	const symmetricHintWindow = 64
	candidates := make([]nat.Candidate, 1+2*symmetricHintWindow)
	for i := range candidates {
		candidates[i] = nat.Candidate{
			Type:    nat.CandidateTypeSrflx,
			Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000 + i},
		}
	}
	exec := newExecutor(Config{}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	exec.sendCandidateMessages(context.Background(), io, candidates)

	wantMessages := len(candidates) * publicDirectCandidateSignalRounds
	messages := io.WaitMessages(t, wantMessages)
	if len(messages) != wantMessages {
		t.Fatalf("candidate signal messages = %d, want all %d symmetric-window candidates across %d rounds", len(messages), len(candidates), publicDirectCandidateSignalRounds)
	}
	observations := io.Observations()
	obs := findObservation(observations, "candidate_signaled")
	if obs == nil {
		t.Fatalf("candidate_signaled observation missing: %#v", observations)
	}
	if obs.Details["candidate_total"] != strconv.Itoa(len(candidates)) || obs.Details["candidate_sent"] != strconv.Itoa(len(candidates)) || obs.Details["candidate_capped"] != "false" || obs.Details["candidate_rounds"] != strconv.Itoa(publicDirectCandidateSignalRounds) {
		t.Fatalf("candidate_signaled details = %#v, want uncapped full symmetric window", obs.Details)
	}
}

func TestPublicDirectEndpointHintPortWindowClipsPortBounds(t *testing.T) {
	candidates, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                         modePublicDirect,
		PublicEndpointHints:          []string{"117.48.146.2:1"},
		PublicEndpointHintPortWindow: 2,
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates(low port) error = %v", err)
	}
	got := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		got = append(got, candidate.Address.String())
	}
	want := []string{"117.48.146.2:1", "117.48.146.2:2", "117.48.146.2:3"}
	if !slices.Equal(got, want) {
		t.Fatalf("low-port expanded hint candidates = %#v, want %#v", got, want)
	}

	candidates, err = appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                         modePublicDirect,
		PublicEndpointHints:          []string{"117.48.146.2:65535"},
		PublicEndpointHintPortWindow: 2,
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates(high port) error = %v", err)
	}
	got = got[:0]
	for _, candidate := range candidates {
		got = append(got, candidate.Address.String())
	}
	want = []string{"117.48.146.2:65535", "117.48.146.2:65534", "117.48.146.2:65533"}
	if !slices.Equal(got, want) {
		t.Fatalf("high-port expanded hint candidates = %#v, want %#v", got, want)
	}
}

func TestPublicDirectAgentRequestUsesMappedHintLocalPort(t *testing.T) {
	agent := &recordingICEAgent{
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	var got AgentRequest
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			got = req
			return agent, nil
		},
		PublicEndpointHints: []string{"117.48.146.2:41000/192.168.1.20:40000"},
	}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{
		Mode:                  modePublicDirect,
		PublicDirectCandidate: true,
		PublicEndpointHints:   []string{"117.48.146.2:41000/192.168.1.20:40000"},
	})

	if _, err := exec.ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(public direct hint port) error = %v", err)
	}
	if got.CandidatePortMin != 40000 || got.CandidatePortMax != 40000 {
		t.Fatalf("public direct candidate port range = %d-%d, want 40000-40000", got.CandidatePortMin, got.CandidatePortMax)
	}
	if len(got.CandidateCIDRInclude) != 1 || got.CandidateCIDRInclude[0] != "192.168.1.20/32" {
		t.Fatalf("public direct candidate CIDR include = %#v, want mapped local base /32", got.CandidateCIDRInclude)
	}
}

func TestPublicDirectAgentRequestMergesMappedHintAndConfiguredCIDRInclude(t *testing.T) {
	agent := &recordingICEAgent{
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	var got AgentRequest
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			got = req
			return agent, nil
		},
		PublicEndpointHints:  []string{"117.48.146.2:41000/192.168.1.20:40000"},
		CandidateCIDRInclude: []string{"10.6.22.0/24"},
	}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{
		Mode:                  modePublicDirect,
		PublicDirectCandidate: true,
		PublicEndpointHints:   []string{"117.48.146.2:41000/192.168.1.20:40000"},
		CandidateCIDRInclude:  []string{"10.6.22.0/24"},
	})

	if _, err := exec.ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(public direct merged include) error = %v", err)
	}
	want := []string{"10.6.22.0/24", "192.168.1.20/32"}
	if !slices.Equal(got.CandidateCIDRInclude, want) {
		t.Fatalf("public direct candidate CIDR include = %#v, want merged %#v", got.CandidateCIDRInclude, want)
	}
}

func TestPublicDirectAgentRequestUsesConfiguredCIDRIncludeWithoutMappedHint(t *testing.T) {
	agent := &recordingICEAgent{
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	var got AgentRequest
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			got = req
			return agent, nil
		},
		CandidateCIDRInclude: []string{"10.6.22.0/24"},
	}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{
		Mode:                  modePublicDirect,
		PublicDirectCandidate: true,
		CandidateCIDRInclude:  []string{"10.6.22.0/24"},
	})

	if _, err := exec.ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(public direct cidr include) error = %v", err)
	}
	if len(got.CandidateCIDRInclude) != 1 || got.CandidateCIDRInclude[0] != "10.6.22.0/24" {
		t.Fatalf("public direct candidate CIDR include = %#v, want configured include", got.CandidateCIDRInclude)
	}
}

func TestPublicDirectTrustedCIDRAllowsEndpointHint(t *testing.T) {
	const hint = "100.102.17.35:41000/100.102.17.36:40000"
	if _, err := publicEndpointHintCandidate(hint, 0, nil); err == nil {
		t.Fatal("publicEndpointHintCandidate() error = nil, want default rejection for 100.64/10")
	}
	candidate, err := publicEndpointHintCandidate(hint, 0, []string{"100.64.0.0/10"})
	if err != nil {
		t.Fatalf("publicEndpointHintCandidate(trusted) error = %v", err)
	}
	if candidate.Type != nat.CandidateTypeSrflx || candidate.Address.String() != "100.102.17.35:41000" {
		t.Fatalf("trusted hint candidate = %#v, want srflx 100.102.17.35:41000", candidate)
	}
	if candidate.RelatedAddr == nil || candidate.RelatedAddr.String() != "100.102.17.36:40000" {
		t.Fatalf("trusted hint related addr = %#v, want 100.102.17.36:40000", candidate.RelatedAddr)
	}

	if _, err := publicEndpointHintCandidate("117.48.146.2:41000/100.102.17.36:40000", 0, nil); err == nil {
		t.Fatal("publicEndpointHintCandidate() error = nil, want default rejection for 100.64/10 local base")
	}
}

func TestPublicDirectCandidateCIDRIncludeAllowsEndpointHintWithoutTrustingPath(t *testing.T) {
	const hint = "10.6.22.1:41000/10.6.22.3:40000"
	if _, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                modePublicDirect,
		PublicEndpointHints: []string{hint},
	}); err == nil {
		t.Fatal("appendPublicEndpointHintCandidates() error = nil, want default rejection for private hint")
	}

	candidates, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                 modePublicDirect,
		PublicEndpointHints:  []string{hint},
		CandidateCIDRInclude: []string{"10.6.22.1/32", "10.6.22.3/32"},
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates(included) error = %v", err)
	}
	mappedIndex := candidateAddressIndex(candidates, "10.6.22.1:41000")
	if mappedIndex < 0 {
		t.Fatalf("included endpoint hint candidates = %#v, want 10.6.22.1:41000", candidates)
	}
	if localBaseIndex := candidateAddressIndex(candidates, "10.6.22.1:40000"); localBaseIndex < 0 {
		t.Fatalf("included endpoint hint candidates = %#v, want local-base port candidate 10.6.22.1:40000", candidates)
	}
	mapped := candidates[mappedIndex]
	if mapped.RelatedAddr == nil || mapped.RelatedAddr.String() != "10.6.22.3:40000" {
		t.Fatalf("included endpoint hint related addr = %#v, want 10.6.22.3:40000", mapped.RelatedAddr)
	}

	local := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 6, 22, 3), Port: 40000}}
	role, deps := pathPolicyMetadata("direct", &nat.CandidatePair{Local: &local, Remote: &mapped}, modePublicDirect, nil, nil)
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("role = %q, want dependent primary candidate without direct trust", role)
	}
	if len(deps) == 0 || deps[0].Kind != solver.PathDependencyUnknown {
		t.Fatalf("dependencies = %#v, want unknown dependency without direct trust", deps)
	}
}

func TestPublicDirectCandidateCIDRIncludeAllowsNonPublicCandidatesWithoutTrustingPath(t *testing.T) {
	execCfg := executorConfig{
		Mode:                 modePublicDirect,
		CandidateCIDRInclude: []string{"10.6.22.0/24"},
	}
	local := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 6, 22, 3), Port: 40000}}
	remote := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 6, 22, 1), Port: 41000}}

	if reason := localCandidateRejectReason(local, execCfg); reason != "" {
		t.Fatalf("local candidate reject reason = %q, want allowed by candidate CIDR include", reason)
	}
	if reason := remoteCandidateRejectReason(remote, execCfg); reason != "" {
		t.Fatalf("remote candidate reject reason = %q, want allowed by candidate CIDR include", reason)
	}

	role, deps := pathPolicyMetadata("direct", &nat.CandidatePair{Local: &local, Remote: &remote}, modePublicDirect, nil, nil)
	if role != solver.PathRolePrimaryCandidate {
		t.Fatalf("role = %q, want dependent primary candidate without direct trust", role)
	}
	if len(deps) == 0 || deps[0].Kind != solver.PathDependencyUnknown {
		t.Fatalf("dependencies = %#v, want unknown dependency without direct trust", deps)
	}
}

func TestPublicDirectAgentRequestPropagatesTrustedCIDRs(t *testing.T) {
	agent := &recordingICEAgent{
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	var got AgentRequest
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			got = req
			return agent, nil
		},
		DirectTrustedCIDRs:       []string{"100.64.0.0/10"},
		PublicDirectTrustedCIDRs: []string{"198.18.0.0/15"},
	}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{
		Mode:                     modePublicDirect,
		PublicDirectCandidate:    true,
		DirectTrustedCIDRs:       []string{"100.64.0.0/10"},
		PublicDirectTrustedCIDRs: []string{"198.18.0.0/15"},
	})

	if _, err := exec.ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(public direct trusted cidr) error = %v", err)
	}
	if len(got.PublicDirectTrustedCIDRs) != 2 || got.PublicDirectTrustedCIDRs[0] != "100.64.0.0/10" || got.PublicDirectTrustedCIDRs[1] != "198.18.0.0/15" {
		t.Fatalf("trusted CIDRs = %#v, want merged direct/public-direct CIDRs", got.PublicDirectTrustedCIDRs)
	}
}

func TestPublicDirectAgentRequestSkipsAmbiguousMappedHintPorts(t *testing.T) {
	agent := &recordingICEAgent{
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	var got AgentRequest
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			got = req
			return agent, nil
		},
		PublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:41001/192.168.1.20:40001",
		},
	}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{
		Mode:                  modePublicDirect,
		PublicDirectCandidate: true,
		PublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:41001/192.168.1.20:40001",
		},
	})

	if _, err := exec.ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(ambiguous hint ports) error = %v", err)
	}
	if got.CandidatePortMin != 0 || got.CandidatePortMax != 0 {
		t.Fatalf("ambiguous public direct candidate port range = %d-%d, want no override", got.CandidatePortMin, got.CandidatePortMax)
	}
	if len(got.CandidateCIDRInclude) != 1 || got.CandidateCIDRInclude[0] != "192.168.1.20/32" {
		t.Fatalf("ambiguous public direct candidate CIDR include = %#v, want mapped local base /32", got.CandidateCIDRInclude)
	}
}

func TestPublicDirectSplitHintPlanConstrainsMappedHintPort(t *testing.T) {
	agent := &recordingICEAgent{
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	var got AgentRequest
	plan := solver.Plan{
		ID:       "legacyice/public_direct_hint_2",
		Strategy: StrategyName,
		Metadata: map[string]string{
			"mode":                          string(modePublicDirect),
			planMetadataPublicEndpointHints: "117.48.146.3:41001/192.168.1.20:40001",
		},
	}
	execCfg, err := executorConfigForPlan(plan, Config{
		PublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:41001/192.168.1.20:40001",
		},
	})
	if err != nil {
		t.Fatalf("executorConfigForPlan(split hint) error = %v", err)
	}
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			got = req
			return agent, nil
		},
	}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, plan, execCfg)

	if _, err := exec.ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(split public direct hint port) error = %v", err)
	}
	if got.CandidatePortMin != 40001 || got.CandidatePortMax != 40001 {
		t.Fatalf("split hint candidate port range = %d-%d, want 40001-40001", got.CandidatePortMin, got.CandidatePortMax)
	}
	if len(got.CandidateCIDRInclude) != 1 || got.CandidateCIDRInclude[0] != "192.168.1.20/32" {
		t.Fatalf("split hint candidate CIDR include = %#v, want mapped local base /32", got.CandidateCIDRInclude)
	}
	if len(execCfg.PublicEndpointHints) != 1 || execCfg.PublicEndpointHints[0] != "117.48.146.3:41001/192.168.1.20:40001" {
		t.Fatalf("split hint executor hints = %#v, want only selected hint", execCfg.PublicEndpointHints)
	}
}

func TestPublicDirectSplitHintPlanConstrainsMappedHintLocalAddress(t *testing.T) {
	agent := &recordingICEAgent{
		connectErr:    context.Canceled,
		connectCalled: make(chan struct{}),
	}
	var got AgentRequest
	plan := solver.Plan{
		ID:       "legacyice/public_direct_hint_2",
		Strategy: StrategyName,
		Metadata: map[string]string{
			"mode":                          string(modePublicDirect),
			planMetadataPublicEndpointHints: "117.48.146.3:41001/192.168.1.21:40000",
		},
	}
	execCfg, err := executorConfigForPlan(plan, Config{
		PublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:41001/192.168.1.21:40000",
		},
	})
	if err != nil {
		t.Fatalf("executorConfigForPlan(split hint) error = %v", err)
	}
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			got = req
			return agent, nil
		},
	}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, plan, execCfg)

	if _, err := exec.ensureAgent(context.Background()); err != nil {
		t.Fatalf("ensureAgent(split public direct hint local address) error = %v", err)
	}
	if got.CandidatePortMin != 40000 || got.CandidatePortMax != 40000 {
		t.Fatalf("split hint candidate port range = %d-%d, want 40000-40000", got.CandidatePortMin, got.CandidatePortMax)
	}
	if len(got.CandidateCIDRInclude) != 1 || got.CandidateCIDRInclude[0] != "192.168.1.21/32" {
		t.Fatalf("split hint candidate CIDR include = %#v, want selected mapped local base /32", got.CandidateCIDRInclude)
	}
	if len(execCfg.PublicEndpointHints) != 1 || execCfg.PublicEndpointHints[0] != "117.48.146.3:41001/192.168.1.21:40000" {
		t.Fatalf("split hint executor hints = %#v, want only selected hint", execCfg.PublicEndpointHints)
	}
}

func TestPublicDirectHintExecutorAcceptsPublicDirectPlanFamilyMessage(t *testing.T) {
	publicCandidate := nat.Candidate{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000}}
	agent := &recordingICEAgent{
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
		ID:       "legacyice/public_direct_hint_1",
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect})

	payload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: []nat.Candidate{publicCandidate},
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload(public_direct family) error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), recordingSessionIO{}, NewMessage(MessageTypeAnswer, payload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(public_direct family) error = %v", err)
	}
	<-agent.connectCalled
	if len(agent.remoteCandidates) != 1 || agent.remoteCandidates[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("remote candidates = %#v, want public-direct family candidate", agent.remoteCandidates)
	}
}

func TestExecutorCandidateMessageWaitsForRemoteCredentials(t *testing.T) {
	publicCandidate := nat.Candidate{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000}}
	privateCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}}
	agent := &recordingICEAgent{
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
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect})

	candidatePayload, err := marshalCandidatePayload(candidatePayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE:       nat.ICECandidatePayload{Candidate: publicCandidate},
		SentAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalCandidatePayload() error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), recordingSessionIO{}, NewMessage(MessageTypeCandidate, candidatePayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(candidate first) error = %v", err)
	}
	select {
	case <-agent.connectCalled:
		t.Fatal("candidate-only message started ICE connect before remote credentials")
	case <-time.After(50 * time.Millisecond):
	}
	if len(agent.remoteCandidates) != 0 {
		t.Fatalf("candidate-only message set remote candidates = %#v, want buffered until credentials", agent.remoteCandidates)
	}

	answerPayload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: []nat.Candidate{privateCandidate},
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload() error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), recordingSessionIO{}, NewMessage(MessageTypeAnswer, answerPayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(answer after candidate) error = %v", err)
	}
	select {
	case <-agent.connectCalled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICE connect after remote credentials")
	}
	if len(agent.remoteCandidates) != 1 || agent.remoteCandidates[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("remote candidates = %#v, want buffered public candidate after credentials", agent.remoteCandidates)
	}
}

func TestExecutorPublicDirectPunchesEarlyCandidateBeforeCredentials(t *testing.T) {
	publicCandidate := nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
		Priority:   100,
		Foundation: "remote-srflx",
	}
	agent := &recordingPunchICEAgent{
		local: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000},
		recordingICEAgent: recordingICEAgent{
			connectErr:    context.Canceled,
			connectCalled: make(chan struct{}),
		},
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
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect})

	candidatePayload, err := marshalCandidatePayload(candidatePayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE:       nat.ICECandidatePayload{Candidate: publicCandidate},
		SentAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalCandidatePayload() error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), recordingSessionIO{}, NewMessage(MessageTypeCandidate, candidatePayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(candidate first) error = %v", err)
	}
	select {
	case <-agent.connectCalled:
		t.Fatal("candidate-only message started ICE connect before remote credentials")
	case <-time.After(50 * time.Millisecond):
	}
	if len(agent.remoteCandidates) != 0 {
		t.Fatalf("candidate-only message set remote candidates = %#v, want buffered until credentials", agent.remoteCandidates)
	}
	punched := agent.Punched()
	if len(punched) != 1 || punched[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("early punched candidates = %#v, want remote public candidate", punched)
	}
	opts := agent.PunchOptions()
	if len(opts) != 1 || opts[0].Burst != publicDirectRemotePunchBurst {
		t.Fatalf("early punch options = %#v, want burst=%d", opts, publicDirectRemotePunchBurst)
	}
}

func TestExecutorPublicDirectPunchesRemoteCandidatesAfterAnswer(t *testing.T) {
	publicCandidate := nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
		Priority:   100,
		Foundation: "remote-srflx",
	}
	agent := &recordingPunchICEAgent{
		local: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000},
		recordingICEAgent: recordingICEAgent{
			connectErr:    context.Canceled,
			connectCalled: make(chan struct{}),
		},
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
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	answerPayload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: []nat.Candidate{publicCandidate},
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload() error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), io, NewMessage(MessageTypeAnswer, answerPayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(answer) error = %v", err)
	}
	select {
	case <-agent.connectCalled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICE connect")
	}
	punched := agent.Punched()
	if len(punched) != 1 || punched[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("punched candidates = %#v, want remote public candidate", punched)
	}
	opts := agent.PunchOptions()
	if len(opts) != 1 || opts[0].Burst != publicDirectRemotePunchBurst {
		t.Fatalf("punch options = %#v, want burst=%d", opts, publicDirectRemotePunchBurst)
	}
	obs := findObservation(io.Observations(), "remote_candidates_punched")
	if obs == nil {
		t.Fatalf("observations = %#v, want remote_candidates_punched", io.Observations())
	}
	if obs.Details["message_type"] != MessageTypeAnswer ||
		obs.Details["candidate_total"] != "1" ||
		obs.Details["candidate_sent"] != "1" ||
		obs.Details["packet_sent"] != strconv.Itoa(publicDirectRemotePunchBurst) ||
		obs.Details["punch_burst"] != strconv.Itoa(publicDirectRemotePunchBurst) {
		t.Fatalf("remote_candidates_punched details = %#v, want answer total=1 sent=1 burst diagnostics", obs.Details)
	}
	if obs.Details["punch_local_addr"] != "192.168.1.20:40000" || obs.Details["punch_local_port"] != "40000" {
		t.Fatalf("remote_candidates_punched details = %#v, want punch local addr", obs.Details)
	}
}

func TestExecutorPublicDirectRetriesRemoteCandidatePunchesAfterAnswer(t *testing.T) {
	publicCandidate := nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000},
		Priority:   100,
		Foundation: "remote-srflx",
	}
	agent := &recordingPunchICEAgent{
		recordingICEAgent: recordingICEAgent{
			connectErr:    context.Canceled,
			connectCalled: make(chan struct{}),
		},
	}
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			_ = req
			return agent, nil
		},
		GatherTimeout:  100 * time.Millisecond,
		ConnectTimeout: 500 * time.Millisecond,
	}, solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect})
	defer exec.Close()
	io := &capturingSessionIO{}

	answerPayload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: []nat.Candidate{publicCandidate},
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload() error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), io, NewMessage(MessageTypeAnswer, answerPayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(answer) error = %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		if len(agent.Punched()) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("punched candidates = %d, want retries across at least 3 rounds", len(agent.Punched()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	observations := io.Observations()
	var sawRetry bool
	for _, obs := range observations {
		if obs.Event == "remote_candidates_punched" && obs.Details["punch_round"] == "2" {
			sawRetry = true
			break
		}
	}
	if !sawRetry {
		t.Fatalf("observations = %#v, want retry punch observation", observations)
	}
}

func TestExecutorPublicDirectPunchRoundResumesAtCandidateOffset(t *testing.T) {
	candidates := make([]nat.Candidate, publicDirectCandidateSignalLimit+2)
	for i := range candidates {
		candidates[i] = nat.Candidate{
			Type:       nat.CandidateTypeSrflx,
			Address:    &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000 + i},
			Foundation: "srflx-" + strconv.Itoa(i),
		}
	}
	agent := &recordingPunchICEAgent{local: &net.UDPAddr{IP: net.IPv4(172, 29, 7, 111), Port: 64779}}
	exec := newExecutor(Config{}, solver.SolveInput{}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	nextStart := exec.punchRemoteCandidateRound(context.Background(), io, agent, candidates, MessageTypeAnswer, 2, 3, publicDirectCandidateSignalLimit)

	punched := agent.Punched()
	if len(punched) == 0 {
		t.Fatal("punch round did not punch any candidate")
	}
	if punched[0].Address.String() != "117.48.146.2:42024" {
		t.Fatalf("first punched candidate = %v, want resume at offset %d", punched[0].Address, publicDirectCandidateSignalLimit)
	}
	if nextStart != publicDirectCandidateSignalLimit*2%len(candidates) {
		t.Fatalf("next start = %d, want %d", nextStart, publicDirectCandidateSignalLimit*2%len(candidates))
	}
	obs := findObservation(io.Observations(), "remote_candidates_punched")
	if obs == nil || obs.Details["candidate_start"] != strconv.Itoa(publicDirectCandidateSignalLimit) {
		t.Fatalf("observations = %#v, want candidate_start=%d", io.Observations(), publicDirectCandidateSignalLimit)
	}
	if obs.Details["candidate_first"] != "117.48.146.2:42024" ||
		obs.Details["candidate_next_start"] != strconv.Itoa(publicDirectCandidateSignalLimit*2%len(candidates)) ||
		obs.Details["candidate_port_min"] != "41000" ||
		obs.Details["candidate_port_max"] != "42025" {
		t.Fatalf("punch coverage details = %#v, want offset coverage diagnostics", obs.Details)
	}
}

func TestExecutorPublicDirectPunchCoversEndpointHintWindow(t *testing.T) {
	candidates, err := appendPublicEndpointHintCandidates(nil, executorConfig{
		Mode:                         modePublicDirect,
		PublicEndpointHints:          []string{"210.30.106.93:50000/172.29.7.111:64779"},
		PublicEndpointHintPortWindow: 512,
	})
	if err != nil {
		t.Fatalf("appendPublicEndpointHintCandidates() error = %v", err)
	}
	candidates = append(candidates, nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: net.IPv4(210, 30, 106, 93), Port: 30000},
		Foundation: "srflx-current",
	})
	agent := &recordingPunchICEAgent{local: &net.UDPAddr{IP: net.IPv4(172, 29, 7, 111), Port: 64779}}
	exec := newExecutor(Config{}, solver.SolveInput{}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	exec.punchRemoteCandidates(context.Background(), io, agent, candidates, MessageTypeAnswer)

	punched := agent.Punched()
	if len(punched) != len(candidates) {
		t.Fatalf("punched candidates = %d, want full endpoint-hint window %d", len(punched), len(candidates))
	}
	obs := findObservation(io.Observations(), "remote_candidates_punched")
	if obs == nil {
		t.Fatalf("observations = %#v, want remote_candidates_punched", io.Observations())
	}
	if obs.Details["candidate_limit"] != strconv.Itoa(len(candidates)) ||
		obs.Details["candidate_sent"] != strconv.Itoa(len(candidates)) {
		t.Fatalf("remote_candidates_punched details = %#v, want full endpoint-hint window", obs.Details)
	}
	if obs.Details["punch_local_addr"] != "172.29.7.111:64779" || obs.Details["punch_local_port"] != "64779" {
		t.Fatalf("remote_candidates_punched details = %#v, want fixed punch local addr", obs.Details)
	}
}

func TestExecutorAnswerWithoutUsableCandidatesWaitsForCandidateMessage(t *testing.T) {
	publicCandidate := nat.Candidate{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000}}
	privateCandidate := nat.Candidate{Type: nat.CandidateTypeHost, Address: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1001}}
	agent := &recordingICEAgent{
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
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect})
	io := &capturingSessionIO{}

	answerPayload, err := marshalAnswerPayload(answerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: []nat.Candidate{privateCandidate},
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalAnswerPayload() error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), io, NewMessage(MessageTypeAnswer, answerPayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(answer first) error = %v", err)
	}
	select {
	case err := <-exec.errCh:
		t.Fatalf("answer without usable candidates failed before candidate grace: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if obs := findObservation(io.Observations(), "remote_candidates_waiting"); obs == nil {
		t.Fatalf("observations = %#v, want remote_candidates_waiting", io.Observations())
	}
	select {
	case <-agent.connectCalled:
		t.Fatal("answer without usable candidates started ICE connect before candidate message")
	default:
	}

	candidatePayload, err := marshalCandidatePayload(candidatePayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE:       nat.ICECandidatePayload{Candidate: publicCandidate},
		SentAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalCandidatePayload() error = %v", err)
	}
	if err := exec.HandleMessage(context.Background(), io, NewMessage(MessageTypeCandidate, candidatePayload, time.Now())); err != nil {
		t.Fatalf("HandleMessage(candidate after answer) error = %v", err)
	}
	select {
	case <-agent.connectCalled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICE connect after delayed candidate")
	}
	if len(agent.remoteCandidates) != 1 || agent.remoteCandidates[0].Address.String() != publicCandidate.Address.String() {
		t.Fatalf("remote candidates = %#v, want delayed public candidate", agent.remoteCandidates)
	}
}

func TestPublicDirectAgentRequestIncludesMultipleMappedHintLocalBases(t *testing.T) {
	got := publicEndpointHintLocalBaseCIDRs([]string{
		"117.48.146.3:41001/192.168.1.21:40000",
		"117.48.146.2:41000/192.168.1.20:40000",
		"117.48.146.2:41000/192.168.1.20:40000",
	})
	want := []string{"192.168.1.20/32", "192.168.1.21/32"}
	if !slices.Equal(got, want) {
		t.Fatalf("public endpoint hint local base CIDRs = %#v, want %#v", got, want)
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
	publicDirectObservations := publicDirectIO.Observations()
	obs := findObservation(publicDirectObservations, "remote_candidates_filtered")
	if obs == nil {
		t.Fatalf("remote_candidates_filtered observation not reported: %#v", publicDirectObservations)
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
	case <-time.After(exec.remoteCandidateGraceTimeout() + 500*time.Millisecond):
		t.Fatal("executor errCh did not receive plan failure after candidate grace")
	}
	observations := io.Observations()
	if obs := findObservation(observations, "remote_candidates_filtered"); obs == nil || obs.Details["candidate_kept"] != "0" {
		t.Fatalf("observations = %#v, want remote_candidates_filtered kept=0", observations)
	}
	if obs := findObservation(observations, "remote_candidates_waiting"); obs == nil {
		t.Fatalf("observations = %#v, want remote_candidates_waiting", observations)
	}
	if obs := findObservation(observations, "candidate_failed"); obs == nil || !strings.Contains(obs.Reason, "no usable remote candidates") {
		t.Fatalf("observations = %#v, want candidate_failed no usable remote candidates", observations)
	}
	obs := findObservation(observations, "candidate_failed")
	if obs == nil {
		t.Fatalf("observations = %#v, want candidate_failed", observations)
	}
	if obs.Details["last_remote_candidate_total"] != "3" || obs.Details["last_remote_candidate_kept"] != "0" {
		t.Fatalf("candidate_failed details = %#v, want last remote candidate counts", obs.Details)
	}
	if !strings.Contains(obs.Details["last_remote_candidate_reject_reasons"], "remote_private_candidate=1") ||
		!strings.Contains(obs.Details["last_remote_candidate_reject_reasons"], "remote_cgnat_or_overlay_candidate=1") ||
		!strings.Contains(obs.Details["last_remote_candidate_reject_reasons"], "remote_relay_candidate=1") {
		t.Fatalf("candidate_failed reject reasons = %q, want remote filter reasons", obs.Details["last_remote_candidate_reject_reasons"])
	}
}

func TestExecutorSerializesConcurrentOfferHandling(t *testing.T) {
	localCandidate := nat.Candidate{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(117, 48, 146, 2), Port: 41000}}
	remoteCandidate := nat.Candidate{Type: nat.CandidateTypeSrflx, Address: &net.UDPAddr{IP: net.IPv4(210, 30, 106, 93), Port: 18734}}
	agent := &serializedGatherICEAgent{
		gathered:     []nat.Candidate{localCandidate},
		firstRelease: make(chan struct{}),
		entered:      make(chan int, 2),
	}
	exec := newExecutor(Config{
		NewICEAgent: func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error) {
			_ = ctx
			_ = req
			return agent, nil
		},
		GatherTimeout:  time.Second,
		ConnectTimeout: 10 * time.Millisecond,
	}, solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-b",
		RemoteNodeID: "node-a",
		Initiator:    false,
	}, solver.Plan{
		ID:       planIDPublicDirect,
		Strategy: StrategyName,
		Metadata: map[string]string{"mode": string(modePublicDirect)},
	}, executorConfig{Mode: modePublicDirect, PublicDirectCandidate: true})
	payload, err := marshalOfferPayload(offerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    planIDPublicDirect,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      "remote",
			Pwd:        "remote-pwd",
			Candidates: []nat.Candidate{remoteCandidate},
		},
		SentAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalOfferPayload() error = %v", err)
	}

	io := &capturingSessionIO{}
	errs := make(chan error, 2)
	go func() {
		errs <- exec.HandleMessage(context.Background(), io, NewMessage(MessageTypeOffer, payload, time.Now()))
	}()
	select {
	case <-agent.entered:
	case <-time.After(time.Second):
		t.Fatal("first offer did not enter GatherCandidates")
	}
	go func() {
		errs <- exec.HandleMessage(context.Background(), io, NewMessage(MessageTypeOffer, payload, time.Now()))
	}()
	time.Sleep(25 * time.Millisecond)
	close(agent.firstRelease)

	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("HandleMessage(%d) error = %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for HandleMessage(%d)", i)
		}
	}
	calls, concurrent := agent.snapshot()
	if calls != 2 {
		t.Fatalf("GatherCandidates calls = %d, want 2", calls)
	}
	if concurrent {
		t.Fatal("GatherCandidates was entered concurrently")
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

type serializedGatherICEAgent struct {
	mu           sync.Mutex
	gathered     []nat.Candidate
	firstRelease chan struct{}
	entered      chan int
	calls        int
	active       bool
	concurrent   bool
}

func (a *serializedGatherICEAgent) GatherCandidates(ctx context.Context) ([]nat.Candidate, error) {
	a.mu.Lock()
	a.calls++
	call := a.calls
	if a.active {
		a.concurrent = true
		a.mu.Unlock()
		return nil, context.Canceled
	}
	a.active = true
	a.mu.Unlock()

	select {
	case a.entered <- call:
	default:
	}
	if call == 1 {
		select {
		case <-a.firstRelease:
		case <-ctx.Done():
			a.mu.Lock()
			a.active = false
			a.mu.Unlock()
			return nil, ctx.Err()
		}
	}

	a.mu.Lock()
	a.active = false
	a.mu.Unlock()
	return append([]nat.Candidate(nil), a.gathered...), nil
}

func (a *serializedGatherICEAgent) GetLocalCredentials() (string, string, error) {
	return "ufrag", "pwd", nil
}

func (a *serializedGatherICEAgent) SetRemoteCredentials(string, string) error {
	return nil
}

func (a *serializedGatherICEAgent) SetRemoteCandidates([]nat.Candidate) error {
	return nil
}

func (a *serializedGatherICEAgent) Connect(ctx context.Context) (nat.SelectedTransport, *nat.CandidatePair, error) {
	return nil, nil, ctx.Err()
}

func (a *serializedGatherICEAgent) GetSelectedPairStats() (nat.CandidatePairStats, bool) {
	return nat.CandidatePairStats{}, false
}

func (a *serializedGatherICEAgent) Close() error { return nil }

func (a *serializedGatherICEAgent) snapshot() (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls, a.concurrent
}

func findObservation(observations []solver.Observation, event string) *solver.Observation {
	for i := range observations {
		if observations[i].Event == event {
			return &observations[i]
		}
	}
	return nil
}
