package legacyice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
	"winkyou/pkg/transport/iceadapter"
)

type executor struct {
	cfg     Config
	input   solver.SolveInput
	plan    solver.Plan
	execCfg executorConfig

	messageMu               sync.Mutex
	mu                      sync.Mutex
	agent                   nat.ICEAgent
	connecting              bool
	closed                  bool
	remoteCredentialsSet    bool
	remoteCandidatesSet     bool
	pendingRemoteCandidates []nat.Candidate
	publicDirectLocalBases  map[string]struct{}
	lastLocalFilterDetails  map[string]string
	lastRemoteFilterDetails map[string]string
	lastSignalDetails       map[string]string

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	resultCh        chan solver.Result
	errCh           chan error
	failOnce        sync.Once
}

const publicDirectHintGatherTimeout = time.Second

const publicDirectCandidateSignalLimit = 64

const publicDirectCandidateSignalRounds = 3

const publicDirectCandidateSignalMaxRounds = 20

const publicDirectCandidateSignalRetryInterval = 100 * time.Millisecond

const publicDirectCandidateSignalMaxRetryInterval = 2 * time.Second

const publicDirectCandidateSignalSendTimeout = time.Second

const publicDirectCandidateSignalSendPerCandidateTimeout = 75 * time.Millisecond

const publicDirectCandidateSignalMaxSendTimeout = 5 * time.Second

const publicDirectRemoteCandidateGraceTimeout = 750 * time.Millisecond

const publicDirectRemoteCandidateGraceMaxTimeout = 5 * time.Second

func newExecutor(cfg Config, input solver.SolveInput, plan solver.Plan, execCfg executorConfig) *executor {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &executor{
		cfg:             cfg,
		input:           input,
		plan:            plan,
		execCfg:         execCfg,
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		resultCh:        make(chan solver.Result, 1),
		errCh:           make(chan error, 1),
	}
}

func (e *executor) Execute(ctx context.Context, sess solver.SessionIO) (solver.Result, error) {
	e.report(sess, solver.Observation{
		Strategy:  e.strategyName(),
		PlanID:    e.plan.ID,
		Event:     "candidate_started",
		TimeoutMS: e.cfg.ConnectTimeout.Milliseconds(),
		Details: map[string]string{
			"mode":        string(e.execCfg.Mode),
			"force_relay": fmt.Sprintf("%t", e.execCfg.ForceRelay),
		},
	})

	if _, err := e.ensureAgent(ctx); err != nil {
		e.reportFailure(sess, err)
		return solver.Result{}, err
	}

	if e.input.Initiator {
		if err := e.sendOffer(ctx, sess); err != nil {
			e.reportFailure(sess, err)
			return solver.Result{}, err
		}
	}

	select {
	case result := <-e.resultCh:
		return result, nil
	case err := <-e.errCh:
		return solver.Result{}, err
	case <-ctx.Done():
		e.reportFailure(sess, ctx.Err())
		return solver.Result{}, ctx.Err()
	}
}

func (e *executor) HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error {
	if !IsMessage(msg) {
		return nil
	}
	e.messageMu.Lock()
	defer e.messageMu.Unlock()

	agent, err := e.ensureAgent(ctx)
	if err != nil {
		return err
	}

	switch msg.Type {
	case MessageTypeOffer:
		offer, err := unmarshalOfferPayload(msg.Payload)
		if err != nil {
			return err
		}
		if !e.messagePlanMatches(offer.PlanID) {
			return nil
		}
		if err := agent.SetRemoteCredentials(offer.ICE.Ufrag, offer.ICE.Pwd); err != nil {
			return err
		}
		e.markRemoteCredentialsSet()
		candidates, summary := filterRemoteCandidatesWithSummary(offer.ICE.Candidates, e.execCfg)
		e.reportCandidateFilter(sess, "remote_candidates_filtered", "remote", MessageTypeOffer, summary)
		candidates = e.remoteCandidatesWithPending(candidates)
		if len(candidates) == 0 {
			if e.waitForPublicDirectRemoteCandidates(sess, MessageTypeOffer) {
				return nil
			}
			e.failRemoteCandidates(sess, MessageTypeOffer)
			return nil
		}
		if err := agent.SetRemoteCandidates(candidates); err != nil {
			return err
		}
		e.clearPendingRemoteCandidates()
		e.markRemoteCandidatesSet()
		if err := e.sendAnswer(ctx, sess); err != nil {
			return err
		}
		e.startConnect(sess)
		return nil
	case MessageTypeAnswer:
		answer, err := unmarshalAnswerPayload(msg.Payload)
		if err != nil {
			return err
		}
		if !e.messagePlanMatches(answer.PlanID) {
			return nil
		}
		if err := agent.SetRemoteCredentials(answer.ICE.Ufrag, answer.ICE.Pwd); err != nil {
			return err
		}
		e.markRemoteCredentialsSet()
		candidates, summary := filterRemoteCandidatesWithSummary(answer.ICE.Candidates, e.execCfg)
		e.reportCandidateFilter(sess, "remote_candidates_filtered", "remote", MessageTypeAnswer, summary)
		candidates = e.remoteCandidatesWithPending(candidates)
		if len(candidates) == 0 {
			if e.waitForPublicDirectRemoteCandidates(sess, MessageTypeAnswer) {
				return nil
			}
			e.failRemoteCandidates(sess, MessageTypeAnswer)
			return nil
		}
		if err := agent.SetRemoteCandidates(candidates); err != nil {
			return err
		}
		e.clearPendingRemoteCandidates()
		e.markRemoteCandidatesSet()
		e.startConnect(sess)
		return nil
	case MessageTypeCandidate:
		candidate, err := unmarshalCandidatePayload(msg.Payload)
		if err != nil {
			return err
		}
		if !e.messagePlanMatches(candidate.PlanID) {
			return nil
		}
		filtered, summary := filterRemoteCandidatesWithSummary([]nat.Candidate{candidate.ICE.Candidate}, e.execCfg)
		e.reportCandidateFilter(sess, "remote_candidates_filtered", "remote", MessageTypeCandidate, summary)
		if len(filtered) == 0 {
			return nil
		}
		if !e.remoteCredentialsReady() {
			e.queuePendingRemoteCandidates(filtered)
			return nil
		}
		if err := agent.SetRemoteCandidates(filtered); err != nil {
			return err
		}
		e.markRemoteCandidatesSet()
		if e.remoteReadyToConnect() {
			e.startConnect(sess)
		}
		return nil
	default:
		return nil
	}
}

func (e *executor) messagePlanMatches(planID string) bool {
	planID = strings.TrimSpace(planID)
	if planID == "" {
		return true
	}
	return planID == e.plan.ID || legacyICEPlanFamily(planID) == legacyICEPlanFamily(e.plan.ID)
}

func (e *executor) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	agent := e.agent
	e.agent = nil
	e.mu.Unlock()

	e.lifecycleCancel()
	if agent != nil {
		return agent.Close()
	}
	return nil
}

func (e *executor) ensureAgent(ctx context.Context) (nat.ICEAgent, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, fmt.Errorf("legacyice: executor closed")
	}
	if e.agent != nil {
		return e.agent, nil
	}
	if e.cfg.NewICEAgent == nil {
		return nil, fmt.Errorf("legacyice: ice agent factory is nil")
	}
	req := AgentRequest{
		Controlling:              e.input.Initiator,
		ForceRelay:               e.execCfg.ForceRelay,
		CandidateCIDRInclude:     e.agentCandidateCIDRInclude(),
		CandidateCIDRExclude:     append([]string(nil), e.execCfg.CandidateCIDRExclude...),
		PublicDirectTrustedCIDRs: e.trustedDirectCIDRs(),
		PublicDirectCandidate:    e.execCfg.PublicDirectCandidate,
	}
	if minPort, maxPort, ok := publicEndpointHintLocalPortRange(e.execCfg.PublicEndpointHints); ok {
		req.CandidatePortMin = minPort
		req.CandidatePortMax = maxPort
	}
	agent, err := e.cfg.NewICEAgent(ctx, req)
	if err != nil {
		return nil, err
	}
	e.agent = agent
	return agent, nil
}

func (e *executor) agentCandidateCIDRInclude() []string {
	return mergeTrustedCIDRs(
		e.execCfg.CandidateCIDRInclude,
		publicEndpointHintLocalBaseCIDRs(e.execCfg.PublicEndpointHints),
	)
}

func (e *executor) sendOffer(ctx context.Context, sess solver.SessionIO) error {
	agent, err := e.ensureAgent(ctx)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, e.gatherTimeout())
	defer cancel()

	candidates, err := agent.GatherCandidates(gatherCtx)
	if err != nil {
		return err
	}
	candidates, err = appendPublicEndpointHintCandidates(candidates, e.execCfg)
	if err != nil {
		return err
	}
	e.rememberPublicDirectLocalBases(candidates)
	candidates, summary := filterLocalCandidatesWithSummary(candidates, e.execCfg)
	e.reportCandidateFilter(sess, "candidate_gathered", "local", MessageTypeOffer, summary)
	if len(candidates) == 0 {
		return fmt.Errorf("legacyice: no usable local candidates for %s", e.execCfg.Mode)
	}
	ufrag, pwd, err := agent.GetLocalCredentials()
	if err != nil {
		return err
	}
	payload, err := marshalOfferPayload(offerPayload{
		SessionID: e.input.SessionID,
		PlanID:    e.plan.ID,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      ufrag,
			Pwd:        pwd,
			Role:       roleFor(e.input.Initiator),
			Candidates: candidates,
		},
		SentAt: time.Now(),
	})
	if err != nil {
		return err
	}
	if err := sess.Send(ctx, NewMessage(MessageTypeOffer, payload, time.Now())); err != nil {
		return err
	}
	e.sendCandidateMessages(ctx, sess, candidates)
	return nil
}

func (e *executor) sendAnswer(ctx context.Context, sess solver.SessionIO) error {
	agent, err := e.ensureAgent(ctx)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, e.gatherTimeout())
	defer cancel()

	candidates, err := agent.GatherCandidates(gatherCtx)
	if err != nil {
		return err
	}
	candidates, err = appendPublicEndpointHintCandidates(candidates, e.execCfg)
	if err != nil {
		return err
	}
	e.rememberPublicDirectLocalBases(candidates)
	candidates, summary := filterLocalCandidatesWithSummary(candidates, e.execCfg)
	e.reportCandidateFilter(sess, "candidate_gathered", "local", MessageTypeAnswer, summary)
	if len(candidates) == 0 {
		return fmt.Errorf("legacyice: no usable local candidates for %s", e.execCfg.Mode)
	}
	ufrag, pwd, err := agent.GetLocalCredentials()
	if err != nil {
		return err
	}
	payload, err := marshalAnswerPayload(answerPayload{
		SessionID: e.input.SessionID,
		PlanID:    e.plan.ID,
		ICE: nat.ICESessionDescriptionPayload{
			Ufrag:      ufrag,
			Pwd:        pwd,
			Role:       roleFor(e.input.Initiator),
			Candidates: candidates,
		},
		SentAt: time.Now(),
	})
	if err != nil {
		return err
	}
	if err := sess.Send(ctx, NewMessage(MessageTypeAnswer, payload, time.Now())); err != nil {
		return err
	}
	e.sendCandidateMessages(ctx, sess, candidates)
	return nil
}

func (e *executor) sendCandidateMessages(ctx context.Context, sess solver.SessionIO, candidates []nat.Candidate) {
	if e.execCfg.Mode != modePublicDirect || len(candidates) == 0 || sess == nil {
		return
	}
	rounds := e.candidateSignalRounds()
	candidates = prioritizePublicDirectSignalCandidates(candidates)
	roundCtx, cancel := e.candidateSignalRoundContext(ctx, len(candidates))
	e.sendCandidateMessageRound(roundCtx, sess, candidates, 1, rounds)
	cancel()
	if rounds <= 1 {
		return
	}
	go e.sendCandidateMessageRetries(sess, candidates, 2, rounds)
}

func prioritizePublicDirectSignalCandidates(candidates []nat.Candidate) []nat.Candidate {
	out := cloneLegacyCandidates(candidates)
	sort.SliceStable(out, func(i, j int) bool {
		leftRank := publicDirectSignalCandidateRank(out[i])
		rightRank := publicDirectSignalCandidateRank(out[j])
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return candidateAddressKey(out[i]) < candidateAddressKey(out[j])
	})
	return out
}

func publicDirectSignalCandidateRank(candidate nat.Candidate) int {
	if strings.HasPrefix(candidate.Foundation, "public-hint-") {
		return 0
	}
	switch candidate.Type {
	case nat.CandidateTypeSrflx:
		return 1
	case nat.CandidateTypePrflx:
		return 2
	case nat.CandidateTypeHost:
		return 3
	case nat.CandidateTypeRelay:
		return 5
	default:
		return 4
	}
}

func (e *executor) candidateSignalRounds() int {
	connectTimeout := e.cfg.ConnectTimeout
	if connectTimeout <= 0 {
		return publicDirectCandidateSignalRounds
	}
	rounds := int(connectTimeout / publicDirectCandidateSignalRetryInterval)
	if connectTimeout%publicDirectCandidateSignalRetryInterval != 0 {
		rounds++
	}
	if rounds < publicDirectCandidateSignalRounds {
		return publicDirectCandidateSignalRounds
	}
	if rounds > publicDirectCandidateSignalMaxRounds {
		return publicDirectCandidateSignalMaxRounds
	}
	return rounds
}

func (e *executor) sendCandidateMessageRetries(sess solver.SessionIO, candidates []nat.Candidate, startRound int, maxRound int) {
	retryInterval := e.candidateSignalRetryInterval(maxRound)
	for round := startRound; round <= maxRound; round++ {
		timer := time.NewTimer(retryInterval)
		select {
		case <-timer.C:
		case <-e.lifecycleCtx.Done():
			timer.Stop()
			return
		}
		roundCtx, cancel := e.candidateSignalRoundContext(e.lifecycleCtx, len(candidates))
		e.sendCandidateMessageRound(roundCtx, sess, candidates, round, maxRound)
		cancel()
	}
}

func (e *executor) candidateSignalRetryInterval(maxRound int) time.Duration {
	connectTimeout := e.cfg.ConnectTimeout
	if connectTimeout <= 0 || maxRound <= publicDirectCandidateSignalRounds {
		return publicDirectCandidateSignalRetryInterval
	}
	interval := connectTimeout / time.Duration(maxRound)
	if interval < publicDirectCandidateSignalRetryInterval {
		return publicDirectCandidateSignalRetryInterval
	}
	if interval > publicDirectCandidateSignalMaxRetryInterval {
		return publicDirectCandidateSignalMaxRetryInterval
	}
	return interval
}

func (e *executor) candidateSignalRoundContext(parent context.Context, candidateCount int) (context.Context, context.CancelFunc) {
	timeout := candidateSignalSendTimeout(candidateCount)
	if timeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, timeout)
}

func candidateSignalSendTimeout(candidateCount int) time.Duration {
	if candidateCount <= 0 {
		return publicDirectCandidateSignalSendTimeout
	}
	if candidateCount > publicDirectCandidateSignalLimit {
		candidateCount = publicDirectCandidateSignalLimit
	}
	timeout := publicDirectCandidateSignalSendTimeout +
		time.Duration(candidateCount)*publicDirectCandidateSignalSendPerCandidateTimeout
	if timeout > publicDirectCandidateSignalMaxSendTimeout {
		return publicDirectCandidateSignalMaxSendTimeout
	}
	return timeout
}

func (e *executor) remoteCandidateGraceTimeout() time.Duration {
	connectTimeout := e.cfg.ConnectTimeout
	if connectTimeout <= 0 {
		return publicDirectRemoteCandidateGraceTimeout
	}
	grace := connectTimeout / 5
	if grace < publicDirectRemoteCandidateGraceTimeout {
		return publicDirectRemoteCandidateGraceTimeout
	}
	if grace > publicDirectRemoteCandidateGraceMaxTimeout {
		return publicDirectRemoteCandidateGraceMaxTimeout
	}
	return grace
}

func (e *executor) sendCandidateMessageRound(ctx context.Context, sess solver.SessionIO, candidates []nat.Candidate, round int, maxRound int) {
	limit := len(candidates)
	if limit > publicDirectCandidateSignalLimit {
		limit = publicDirectCandidateSignalLimit
	}
	retryInterval := e.candidateSignalRetryInterval(maxRound)
	sent := 0
	var lastErr error
sendLoop:
	for i := 0; i < limit; i++ {
		select {
		case <-ctx.Done():
			lastErr = ctx.Err()
			break sendLoop
		default:
		}
		payload, err := marshalCandidatePayload(candidatePayload{
			SessionID: e.input.SessionID,
			PlanID:    e.plan.ID,
			ICE: nat.ICECandidatePayload{
				Candidate: candidates[i],
			},
			SentAt: time.Now(),
		})
		if err != nil {
			lastErr = err
			continue
		}
		if err := sess.Send(ctx, NewMessage(MessageTypeCandidate, payload, time.Now())); err != nil {
			lastErr = err
			continue
		}
		sent++
	}
	details := map[string]string{
		"mode":              string(e.execCfg.Mode),
		"message_type":      MessageTypeCandidate,
		"candidate_total":   strconv.Itoa(len(candidates)),
		"candidate_sent":    strconv.Itoa(sent),
		"candidate_limit":   strconv.Itoa(publicDirectCandidateSignalLimit),
		"candidate_capped":  fmt.Sprintf("%t", len(candidates) > limit),
		"candidate_round":   strconv.Itoa(round),
		"candidate_rounds":  strconv.Itoa(maxRound),
		"retry_interval_ms": strconv.FormatInt(retryInterval.Milliseconds(), 10),
		"signal_window_ms":  strconv.FormatInt((retryInterval * time.Duration(maxRound-1)).Milliseconds(), 10),
		"send_timeout_ms":   strconv.FormatInt(candidateSignalSendTimeout(len(candidates)).Milliseconds(), 10),
	}
	if lastErr != nil {
		details["last_error"] = lastErr.Error()
	}
	e.rememberCandidateSignalDetails(details)
	e.report(sess, solver.Observation{
		Strategy:  e.strategyName(),
		PlanID:    e.plan.ID,
		Event:     "candidate_signaled",
		Details:   details,
		Timestamp: time.Now(),
	})
}

func (e *executor) markRemoteCredentialsSet() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.remoteCredentialsSet = true
}

func (e *executor) remoteCredentialsReady() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.remoteCredentialsSet
}

func (e *executor) markRemoteCandidatesSet() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.remoteCandidatesSet = true
}

func (e *executor) queuePendingRemoteCandidates(candidates []nat.Candidate) {
	if len(candidates) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := make(map[string]struct{}, len(e.pendingRemoteCandidates)+len(candidates))
	for _, candidate := range e.pendingRemoteCandidates {
		seen[candidateAddressKey(candidate)] = struct{}{}
	}
	for _, candidate := range candidates {
		key := candidateAddressKey(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		e.pendingRemoteCandidates = append(e.pendingRemoteCandidates, cloneLegacyCandidate(candidate))
	}
}

func (e *executor) remoteCandidatesWithPending(candidates []nat.Candidate) []nat.Candidate {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]nat.Candidate, 0, len(e.pendingRemoteCandidates)+len(candidates))
	seen := make(map[string]struct{}, len(e.pendingRemoteCandidates)+len(candidates))
	for _, candidate := range e.pendingRemoteCandidates {
		key := candidateAddressKey(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cloneLegacyCandidate(candidate))
	}
	for _, candidate := range candidates {
		key := candidateAddressKey(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cloneLegacyCandidate(candidate))
	}
	return out
}

func (e *executor) clearPendingRemoteCandidates() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pendingRemoteCandidates = nil
}

func (e *executor) remoteReadyToConnect() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.remoteCredentialsSet && e.remoteCandidatesSet
}

func (e *executor) startConnect(sess solver.SessionIO) {
	e.mu.Lock()
	if e.connecting || e.closed || e.agent == nil {
		e.mu.Unlock()
		return
	}
	e.connecting = true
	agent := e.agent
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			e.connecting = false
			e.mu.Unlock()
		}()

		connectCtx, cancel := context.WithTimeout(e.lifecycleCtx, e.cfg.ConnectTimeout)
		defer cancel()

		conn, pair, err := agent.Connect(connectCtx)
		if err != nil {
			e.reportFailure(sess, err)
			select {
			case e.errCh <- err:
			default:
			}
			return
		}

		connectionType := connectionTypeFromPair(pair)
		pathID := e.pathID(connectionType)
		transport := e.releaseTransport(agent, conn, pathID)
		role, dependencies := pathPolicyMetadata(connectionType, pair, e.execCfg.Mode, e.publicDirectLocalBaseSnapshot(), e.trustedDirectCIDRs())
		metrics := selectedPairMetrics(agent)
		details := selectedPairDetails(pair, e.execCfg.Mode)
		details["ice_state"] = connectionStateString(agent)
		details["plan_mode"] = string(e.execCfg.Mode)
		for key, value := range metrics {
			details[key] = value
		}
		result := solver.Result{
			Transport: transport,
			Summary: solver.PathSummary{
				PathID:         pathID,
				ConnectionType: connectionType,
				RemoteAddr:     remoteAddrFromPair(pair),
				Role:           role,
				Dependencies:   dependencies,
				Metrics:        metrics,
				Details:        details,
			},
		}

		e.report(sess, observationFromPair(e.plan.ID, "selected_pair", pathID, connectionType, pair, nil))
		successDetails := selectedPairDetails(pair, e.execCfg.Mode)
		successDetails["mode"] = string(e.execCfg.Mode)
		e.report(sess, observationFromPair(e.plan.ID, "candidate_succeeded", pathID, connectionType, pair, successDetails))

		select {
		case e.resultCh <- result:
		default:
		}
	}()
}

func (e *executor) pathID(connectionType string) string {
	if e.execCfg.Mode == modePublicDirect {
		return fmt.Sprintf("legacyice:%s:%s:%s", connectionType, e.execCfg.Mode, e.input.SessionID)
	}
	return fmt.Sprintf("legacyice:%s:%s", connectionType, e.input.SessionID)
}

func (e *executor) gatherTimeout() time.Duration {
	timeout := e.cfg.GatherTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if e.publicDirectHintFastGatherEnabled() && timeout > publicDirectHintGatherTimeout {
		return publicDirectHintGatherTimeout
	}
	return timeout
}

func (e *executor) publicDirectHintFastGatherEnabled() bool {
	return e.execCfg.Mode == modePublicDirect && len(e.execCfg.PublicEndpointHints) > 0
}

func (e *executor) rememberPublicDirectLocalBases(candidates []nat.Candidate) {
	if e.execCfg.Mode != modePublicDirect {
		return
	}
	bases := make(map[string]struct{})
	hasExplicitHintBase := publicEndpointHintsHaveLocalBases(e.execCfg.PublicEndpointHints)
	for _, candidate := range candidates {
		if !hasExplicitHintBase && candidate.Type == nat.CandidateTypeHost && len(e.execCfg.PublicEndpointHints) > 0 && candidate.Address != nil && candidate.Address.IP != nil && candidate.Address.IP.IsPrivate() {
			bases[candidate.Address.IP.String()] = struct{}{}
			continue
		}
		if candidate.Type == nat.CandidateTypeRelay || candidate.RelatedAddr == nil || candidate.RelatedAddr.IP == nil {
			continue
		}
		if candidateDependencyReason("local", &candidate) != "" {
			continue
		}
		bases[candidate.RelatedAddr.IP.String()] = struct{}{}
	}
	e.mu.Lock()
	e.publicDirectLocalBases = bases
	e.mu.Unlock()
}

func (e *executor) publicDirectLocalBaseSnapshot() map[string]struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.publicDirectLocalBases) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(e.publicDirectLocalBases))
	for ip := range e.publicDirectLocalBases {
		out[ip] = struct{}{}
	}
	return out
}

func (e *executor) trustedDirectCIDRs() []string {
	return mergeTrustedCIDRs(e.execCfg.DirectTrustedCIDRs, e.execCfg.PublicDirectTrustedCIDRs)
}

func (e *executor) releaseTransport(agent nat.ICEAgent, conn net.Conn, pathID string) transport.PacketTransport {
	e.mu.Lock()
	if e.agent == agent {
		e.agent = nil
	}
	e.mu.Unlock()
	iceTransport := iceadapter.New(conn, pathID)
	return &managedTransport{
		PacketTransport: iceTransport,
		closers: []func() error{
			iceTransport.Close,
			agent.Close,
		},
	}
}

func (e *executor) reportFailure(sess solver.SessionIO, err error) {
	if err == nil {
		return
	}
	e.failOnce.Do(func() {
		details := map[string]string{
			"mode": string(e.execCfg.Mode),
		}
		if e.execCfg.Mode == modePublicDirect {
			e.addPublicDirectFailureDetails(details)
		}
		e.report(sess, solver.Observation{
			Strategy:   e.strategyName(),
			PlanID:     e.plan.ID,
			Event:      "candidate_failed",
			ErrorClass: classifyObservationError(err),
			Reason:     err.Error(),
			Details:    details,
			Timestamp:  time.Now(),
		})
	})
}

func (e *executor) addPublicDirectFailureDetails(details map[string]string) {
	if len(e.execCfg.PublicEndpointHints) > 0 {
		details["public_endpoint_hint_count"] = strconv.Itoa(len(e.execCfg.PublicEndpointHints))
		if e.execCfg.PublicEndpointHintPortWindow > 0 {
			details["public_endpoint_hint_port_window"] = strconv.Itoa(publicEndpointHintPortWindow(e.execCfg.PublicEndpointHintPortWindow))
		}
	}
	local, remote, agent := e.candidateFilterSnapshots()
	for key, value := range local {
		details["last_local_"+key] = value
	}
	for key, value := range remote {
		details["last_remote_"+key] = value
	}
	signal := e.candidateSignalSnapshot()
	for key, value := range signal {
		details["last_signal_"+key] = value
	}
	if agent != nil {
		details["ice_state"] = connectionStateString(agent)
		addPublicDirectAgentFailureDetails(details, agent)
	}
}

func addPublicDirectAgentFailureDetails(details map[string]string, agent nat.ICEAgent) {
	if counter, ok := agent.(interface{ RemoteCandidateCount() int }); ok {
		details["ice_remote_candidate_count"] = strconv.Itoa(counter.RemoteCandidateCount())
	}
	pairReader, ok := agent.(interface {
		GetSelectedPair() (*nat.CandidatePair, error)
	})
	if !ok {
		return
	}
	pair, err := pairReader.GetSelectedPair()
	if err != nil {
		details["ice_selected_pair"] = "false"
		return
	}
	if pair == nil {
		details["ice_selected_pair"] = "false"
		return
	}
	details["ice_selected_pair"] = "true"
	if pair.Local != nil && pair.Local.Address != nil {
		details["ice_selected_pair_local"] = formatCandidate(pair.Local)
	}
	if pair.Remote != nil && pair.Remote.Address != nil {
		details["ice_selected_pair_remote"] = formatCandidate(pair.Remote)
	}
}

func (e *executor) failRemoteCandidates(sess solver.SessionIO, messageType string) {
	err := fmt.Errorf("legacyice: no usable remote candidates for %s in %s", e.execCfg.Mode, messageType)
	e.reportFailure(sess, err)
	select {
	case e.errCh <- err:
	default:
	}
}

func (e *executor) waitForPublicDirectRemoteCandidates(sess solver.SessionIO, messageType string) bool {
	if e.execCfg.Mode != modePublicDirect {
		return false
	}
	grace := e.remoteCandidateGraceTimeout()
	e.report(sess, solver.Observation{
		Strategy: e.strategyName(),
		PlanID:   e.plan.ID,
		Event:    "remote_candidates_waiting",
		Details: map[string]string{
			"mode":         string(e.execCfg.Mode),
			"message_type": messageType,
			"candidate_grace_ms": strconv.FormatInt(
				grace.Milliseconds(),
				10,
			),
		},
		Timestamp: time.Now(),
	})
	go func() {
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-e.lifecycleCtx.Done():
			return
		}
		if e.remoteReadyToConnect() {
			return
		}
		e.failRemoteCandidates(sess, messageType)
	}()
	return true
}

func (e *executor) reportCandidateFilter(sess solver.SessionIO, event, side, messageType string, summary candidateFilterSummary) {
	details := summary.details()
	details["mode"] = string(e.execCfg.Mode)
	details["candidate_side"] = side
	if e.execCfg.Mode == modePublicDirect && side == "local" && len(e.execCfg.PublicEndpointHints) > 0 {
		details["public_endpoint_hint_count"] = strconv.Itoa(len(e.execCfg.PublicEndpointHints))
		if e.execCfg.PublicEndpointHintPortWindow > 0 {
			details["public_endpoint_hint_port_window"] = strconv.Itoa(publicEndpointHintPortWindow(e.execCfg.PublicEndpointHintPortWindow))
		}
		if e.publicDirectHintFastGatherEnabled() {
			details["public_endpoint_hint_fast_gather"] = "true"
			details["gather_timeout_ms"] = strconv.FormatInt(e.gatherTimeout().Milliseconds(), 10)
		}
	}
	if messageType != "" {
		details["message_type"] = messageType
	}
	e.rememberCandidateFilterDetails(side, details)
	e.report(sess, solver.Observation{
		Strategy:  e.strategyName(),
		PlanID:    e.plan.ID,
		Event:     event,
		Details:   details,
		Timestamp: time.Now(),
	})
}

func (e *executor) rememberCandidateFilterDetails(side string, details map[string]string) {
	if e.execCfg.Mode != modePublicDirect {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch side {
	case "local":
		e.lastLocalFilterDetails = cloneStringMap(details)
	case "remote":
		e.lastRemoteFilterDetails = cloneStringMap(details)
	}
}

func (e *executor) candidateFilterSnapshots() (map[string]string, map[string]string, nat.ICEAgent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return cloneStringMap(e.lastLocalFilterDetails), cloneStringMap(e.lastRemoteFilterDetails), e.agent
}

func (e *executor) rememberCandidateSignalDetails(details map[string]string) {
	if e.execCfg.Mode != modePublicDirect {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastSignalDetails = cloneStringMap(details)
}

func (e *executor) candidateSignalSnapshot() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return cloneStringMap(e.lastSignalDetails)
}

func (e *executor) report(sess solver.SessionIO, obs solver.Observation) {
	if sess == nil {
		return
	}
	if obs.Strategy == "" {
		obs.Strategy = e.strategyName()
	}
	if obs.PlanID == "" {
		obs.PlanID = e.plan.ID
	}
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}
	_ = sess.ReportObservation(context.Background(), obs)
}

func (e *executor) strategyName() string {
	if e.plan.Strategy != "" {
		return e.plan.Strategy
	}
	return StrategyName
}

type managedTransport struct {
	transport.PacketTransport
	closeOnce sync.Once
	closers   []func() error
}

func (m *managedTransport) Close() error {
	var result error
	m.closeOnce.Do(func() {
		for _, closer := range m.closers {
			if closer == nil {
				continue
			}
			if err := closer(); err != nil && !errors.Is(err, net.ErrClosed) && result == nil {
				result = err
			}
		}
	})
	return result
}

func roleFor(initiator bool) string {
	if initiator {
		return "controlling"
	}
	return "controlled"
}

func connectionTypeFromPair(pair *nat.CandidatePair) string {
	if pair != nil && pair.Local != nil && pair.Remote != nil &&
		(pair.Local.Type == nat.CandidateTypeRelay || pair.Remote.Type == nat.CandidateTypeRelay) {
		return "relay"
	}
	return "direct"
}

func pathPolicyMetadata(connectionType string, pair *nat.CandidatePair, mode executionMode, publicDirectLocalBases map[string]struct{}, publicDirectTrustedCIDRs []string) (solver.PathRole, []solver.PathDependency) {
	if connectionType == "relay" {
		return solver.PathRolePrimaryCandidate, []solver.PathDependency{{
			Kind:   solver.PathDependencyRelay,
			Reason: "turn_or_relay_candidate",
		}}
	}
	if reason := candidatePairDependencyReason(pair, mode, publicDirectLocalBases, publicDirectTrustedCIDRs); reason != "" {
		return solver.PathRolePrimaryCandidate, []solver.PathDependency{{
			Kind:   solver.PathDependencyUnknown,
			Reason: reason,
		}}
	}
	return solver.PathRoleProtectedDirect, nil
}

func candidatePairDependencyReason(pair *nat.CandidatePair, mode executionMode, publicDirectLocalBases map[string]struct{}, publicDirectTrustedCIDRs []string) string {
	if pair == nil {
		return "selected_pair_unavailable"
	}
	if mode == modePublicDirect {
		return publicDirectCandidatePairDependencyReason(pair, publicDirectLocalBases, publicDirectTrustedCIDRs)
	}
	if reason := candidateDependencyReasonWithTrustedCIDRs("local", pair.Local, publicDirectTrustedCIDRs); reason != "" {
		return reason
	}
	if reason := candidateDependencyReasonWithTrustedCIDRs("remote", pair.Remote, publicDirectTrustedCIDRs); reason != "" {
		return reason
	}
	return ""
}

func publicDirectCandidatePairDependencyReason(pair *nat.CandidatePair, localBases map[string]struct{}, trustedCIDRs []string) string {
	if reason := publicDirectLocalCandidateDependencyReason(pair.Local, localBases, trustedCIDRs); reason != "" {
		return reason
	}
	if reason := candidateDependencyReasonWithTrustedCIDRs("remote", pair.Remote, trustedCIDRs); reason != "" {
		return reason
	}
	return ""
}

func publicDirectLocalCandidateDependencyReason(candidate *nat.Candidate, localBases map[string]struct{}, trustedCIDRs []string) string {
	if candidate == nil || candidate.Address == nil || candidate.Address.IP == nil {
		return "local_candidate_unavailable"
	}
	if candidate.Type == nat.CandidateTypeRelay {
		return ""
	}
	ip := candidate.Address.IP
	if ip.IsPrivate() && candidate.Type == nat.CandidateTypeHost && hasIP(localBases, ip) {
		return ""
	}
	if candidateIPInCIDRs(ip, trustedCIDRs) {
		return ""
	}
	if reason := nonPublicCandidateIPReason(ip); reason != "" {
		return "local_" + reason
	}
	return ""
}

func hasIP(values map[string]struct{}, ip net.IP) bool {
	if ip == nil {
		return false
	}
	_, ok := values[ip.String()]
	return ok
}

func candidateDependencyReason(side string, candidate *nat.Candidate) string {
	return candidateDependencyReasonWithTrustedCIDRs(side, candidate, nil)
}

func candidateDependencyReasonWithTrustedCIDRs(side string, candidate *nat.Candidate, trustedCIDRs []string) string {
	if candidate == nil || candidate.Address == nil || candidate.Address.IP == nil {
		return side + "_candidate_unavailable"
	}
	if candidate.Type == nat.CandidateTypeRelay {
		return ""
	}
	if candidateIPInCIDRs(candidate.Address.IP, trustedCIDRs) {
		return ""
	}
	if reason := nonPublicCandidateIPReason(candidate.Address.IP); reason != "" {
		return side + "_" + reason
	}
	return ""
}

func candidateIPInCIDRs(ip net.IP, cidrs []string) bool {
	if ip == nil || len(cidrs) == 0 {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func nonPublicCandidateIPReason(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "unspecified_candidate"
	case ip.IsLoopback():
		return "loopback_candidate"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link_local_candidate"
	case ip.IsMulticast():
		return "multicast_candidate"
	case ip.IsPrivate():
		return "private_candidate"
	case isCandidateIPInCIDR(ip, "100.64.0.0/10"):
		return "cgnat_or_overlay_candidate"
	case isCandidateIPInCIDR(ip, "198.18.0.0/15"):
		return "benchmark_or_overlay_candidate"
	default:
		return ""
	}
}

func isCandidateIPInCIDR(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	return err == nil && network.Contains(ip)
}

func filterRemoteCandidates(candidates []nat.Candidate, execCfg executorConfig) []nat.Candidate {
	filtered, _ := filterRemoteCandidatesWithSummary(candidates, execCfg)
	return filtered
}

func appendPublicEndpointHintCandidates(candidates []nat.Candidate, execCfg executorConfig) ([]nat.Candidate, error) {
	if execCfg.Mode != modePublicDirect || len(execCfg.PublicEndpointHints) == 0 {
		return candidates, nil
	}
	out := append([]nat.Candidate(nil), candidates...)
	portWindow := publicEndpointHintPortWindow(execCfg.PublicEndpointHintPortWindow)
	seen := make(map[string]struct{}, len(out)+len(execCfg.PublicEndpointHints)*(1+2*portWindow))
	for _, candidate := range out {
		seen[candidateAddressKey(candidate)] = struct{}{}
	}
	for i, raw := range execCfg.PublicEndpointHints {
		candidates, err := publicEndpointHintCandidates(raw, i, portWindow, publicDirectCandidateAllowedCIDRs(execCfg))
		if err != nil {
			return nil, err
		}
		for _, candidate := range candidates {
			key := candidateAddressKey(candidate)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, candidate)
		}
	}
	return out, nil
}

func publicEndpointHintCandidate(raw string, index int, trustedCIDRs []string) (nat.Candidate, error) {
	candidates, err := publicEndpointHintCandidates(raw, index, 0, trustedCIDRs)
	if err != nil {
		return nat.Candidate{}, err
	}
	return candidates[0], nil
}

func publicEndpointHintCandidates(raw string, index int, portWindow int, trustedCIDRs []string) ([]nat.Candidate, error) {
	hint, err := parsePublicEndpointHint(raw)
	if err != nil {
		return nil, err
	}
	ip := net.IP(append([]byte(nil), hint.public.Addr().AsSlice()...))
	if reason := nonPublicCandidateIPReason(ip); reason != "" && !candidateIPInCIDRs(ip, trustedCIDRs) {
		return nil, fmt.Errorf("legacyice: invalid public endpoint hint %q: %s", raw, reason)
	}
	var related *net.UDPAddr
	if hint.local.IsValid() {
		localIP := net.IP(append([]byte(nil), hint.local.Addr().AsSlice()...))
		if reason := publicEndpointHintLocalBaseRejectReason(localIP, trustedCIDRs); reason != "" {
			return nil, fmt.Errorf("legacyice: invalid public endpoint hint local base %q: %s", raw, reason)
		}
		related = &net.UDPAddr{IP: localIP, Port: int(hint.local.Port())}
	}

	offsets := publicEndpointHintPortOffsets(hint.public.Port(), portWindow)
	candidates := make([]nat.Candidate, 0, len(offsets))
	for _, offset := range offsets {
		port := int(hint.public.Port()) + offset
		candidate := nat.Candidate{
			Type:       nat.CandidateTypeSrflx,
			Address:    &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port},
			Priority:   publicEndpointHintPriorityForOffset(index, offset),
			Foundation: publicEndpointHintFoundation(index, offset),
		}
		if related != nil {
			candidate.RelatedAddr = &net.UDPAddr{IP: append(net.IP(nil), related.IP...), Port: related.Port}
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func publicEndpointHintPortWindow(window int) int {
	if window < 0 {
		return 0
	}
	if window > 512 {
		return 512
	}
	return window
}

func publicEndpointHintPortOffsets(port uint16, window int) []int {
	if window <= 0 {
		return []int{0}
	}
	offsets := make([]int, 0, 1+2*window)
	offsets = append(offsets, 0)
	base := int(port)
	for distance := 1; distance <= window; distance++ {
		if base-distance >= 1 {
			offsets = append(offsets, -distance)
		}
		if base+distance <= 65535 {
			offsets = append(offsets, distance)
		}
	}
	return offsets
}

func publicEndpointHintFoundation(index int, offset int) string {
	if offset == 0 {
		return fmt.Sprintf("public-hint-%d", index+1)
	}
	return fmt.Sprintf("public-hint-%d-offset-%d", index+1, offset)
}

func publicEndpointHintLocalBaseRejectReason(ip net.IP, trustedCIDRs []string) string {
	switch {
	case ip == nil:
		return "missing_candidate"
	case ip.IsUnspecified():
		return "unspecified_candidate"
	case ip.IsLoopback():
		return "loopback_candidate"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link_local_candidate"
	case ip.IsMulticast():
		return "multicast_candidate"
	case candidateIPInCIDRs(ip, trustedCIDRs):
		return ""
	case isCandidateIPInCIDR(ip, "100.64.0.0/10"):
		return "cgnat_or_overlay_candidate"
	case isCandidateIPInCIDR(ip, "198.18.0.0/15"):
		return "benchmark_or_overlay_candidate"
	default:
		return ""
	}
}

type publicEndpointHint struct {
	public netip.AddrPort
	local  netip.AddrPort
}

func parsePublicEndpointHint(raw string) (publicEndpointHint, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return publicEndpointHint{}, fmt.Errorf("legacyice: public endpoint hint must not be empty")
	}
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return publicEndpointHint{}, fmt.Errorf("legacyice: invalid public endpoint hint %q", raw)
	}
	public, err := parseEndpointHintAddrPort(parts[0])
	if err != nil {
		return publicEndpointHint{}, fmt.Errorf("legacyice: invalid public endpoint hint %q", raw)
	}
	hint := publicEndpointHint{public: public}
	if len(parts) == 2 {
		local, err := parseEndpointHintAddrPort(parts[1])
		if err != nil {
			return publicEndpointHint{}, fmt.Errorf("legacyice: invalid public endpoint hint local base %q", raw)
		}
		hint.local = local
	}
	return hint, nil
}

func parseEndpointHintAddrPort(raw string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(strings.TrimSpace(raw))
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint")
	}
	return endpoint, nil
}

func publicEndpointHintsHaveLocalBases(values []string) bool {
	for _, raw := range values {
		hint, err := parsePublicEndpointHint(raw)
		if err == nil && hint.local.IsValid() {
			return true
		}
	}
	return false
}

func publicEndpointHintLocalPortRange(values []string) (uint16, uint16, bool) {
	var port uint16
	for _, raw := range values {
		hint, err := parsePublicEndpointHint(raw)
		if err != nil || !hint.local.IsValid() {
			continue
		}
		next := uint16(hint.local.Port())
		if port == 0 {
			port = next
			continue
		}
		if port != next {
			return 0, 0, false
		}
	}
	if port == 0 {
		return 0, 0, false
	}
	return port, port, true
}

func publicEndpointHintLocalBaseCIDRs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		hint, err := parsePublicEndpointHint(raw)
		if err != nil || !hint.local.IsValid() {
			continue
		}
		ip := hint.local.Addr()
		if !ip.Is4() {
			continue
		}
		seen[ip.String()+"/32"] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for cidr := range seen {
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out
}

func publicEndpointHintPriority(index int) uint32 {
	return publicEndpointHintPriorityForOffset(index, 0)
}

func publicEndpointHintPriorityForOffset(index int, offset int) uint32 {
	const (
		srflxTypePreference = 100
		componentID         = 1
	)
	if offset < 0 {
		offset = -offset
	}
	localPreference := 65535 - index*1024 - offset
	if localPreference < 1 {
		localPreference = 1
	}
	return uint32(srflxTypePreference)<<24 | uint32(localPreference)<<8 | uint32(256-componentID)
}

func candidateAddressKey(candidate nat.Candidate) string {
	if candidate.Address == nil {
		return candidate.Type.String()
	}
	return candidate.Type.String() + "|" + candidate.Address.String()
}

func cloneLegacyCandidate(candidate nat.Candidate) nat.Candidate {
	return nat.Candidate{
		Type:        candidate.Type,
		Address:     cloneLegacyUDPAddr(candidate.Address),
		Priority:    candidate.Priority,
		Foundation:  candidate.Foundation,
		RelatedAddr: cloneLegacyUDPAddr(candidate.RelatedAddr),
	}
}

func cloneLegacyCandidates(candidates []nat.Candidate) []nat.Candidate {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]nat.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, cloneLegacyCandidate(candidate))
	}
	return out
}

func cloneLegacyUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	var ip net.IP
	if addr.IP != nil {
		ip = append(net.IP(nil), addr.IP...)
	}
	return &net.UDPAddr{
		IP:   ip,
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func filterRemoteCandidatesWithSummary(candidates []nat.Candidate, execCfg executorConfig) ([]nat.Candidate, candidateFilterSummary) {
	summary := newCandidateFilterSummary()
	filtered := make([]nat.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		reason := remoteCandidateRejectReason(candidate, execCfg)
		kept := reason == ""
		summary.record(candidate, kept, reason)
		if kept {
			filtered = append(filtered, candidate)
		}
	}
	return filtered, summary
}

func filterLocalCandidates(candidates []nat.Candidate, execCfg executorConfig) []nat.Candidate {
	filtered, _ := filterLocalCandidatesWithSummary(candidates, execCfg)
	return filtered
}

func filterLocalCandidatesWithSummary(candidates []nat.Candidate, execCfg executorConfig) ([]nat.Candidate, candidateFilterSummary) {
	summary := newCandidateFilterSummary()
	filtered := make([]nat.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		reason := localCandidateRejectReason(candidate, execCfg)
		kept := reason == ""
		summary.record(candidate, kept, reason)
		if kept {
			filtered = append(filtered, candidate)
		}
	}
	return filtered, summary
}

func remoteCandidateRejectReason(candidate nat.Candidate, execCfg executorConfig) string {
	switch execCfg.Mode {
	case modePublicDirect:
		if candidate.Type == nat.CandidateTypeRelay {
			return "remote_relay_candidate"
		}
		return publicDirectCandidateRejectReason("remote", &candidate, execCfg)
	case modeRelayOnly:
		if candidate.Type != nat.CandidateTypeRelay {
			return "remote_non_relay_candidate"
		}
	}
	return ""
}

func localCandidateRejectReason(candidate nat.Candidate, execCfg executorConfig) string {
	if execCfg.Mode != modePublicDirect {
		return ""
	}
	if candidate.Type == nat.CandidateTypeRelay {
		return "local_relay_candidate"
	}
	return publicDirectCandidateRejectReason("local", &candidate, execCfg)
}

func publicDirectCandidateRejectReason(side string, candidate *nat.Candidate, execCfg executorConfig) string {
	if candidate == nil || candidate.Address == nil || candidate.Address.IP == nil {
		return side + "_candidate_unavailable"
	}
	if candidate.Type == nat.CandidateTypeRelay {
		return ""
	}
	if candidateIPInCIDRs(candidate.Address.IP, publicDirectCandidateAllowedCIDRs(execCfg)) {
		return ""
	}
	if reason := nonPublicCandidateIPReason(candidate.Address.IP); reason != "" {
		return side + "_" + reason
	}
	return ""
}

func publicDirectCandidateAllowedCIDRs(execCfg executorConfig) []string {
	return mergeTrustedCIDRs(
		execCfg.CandidateCIDRInclude,
		execCfg.DirectTrustedCIDRs,
		execCfg.PublicDirectTrustedCIDRs,
	)
}

func mergeTrustedCIDRs(lists ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, list := range lists {
		for _, value := range list {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

type candidateFilterSummary struct {
	Total           int
	Kept            int
	Types           map[string]int
	KeptTypes       map[string]int
	RejectedReasons map[string]int
	KeptSamples     []string
	RejectedSamples []string
}

func newCandidateFilterSummary() candidateFilterSummary {
	return candidateFilterSummary{
		Types:           map[string]int{},
		KeptTypes:       map[string]int{},
		RejectedReasons: map[string]int{},
	}
}

const maxCandidateFilterSamples = 4

func (s *candidateFilterSummary) record(candidate nat.Candidate, kept bool, reason string) {
	s.Total++
	candidateType := candidate.Type.String()
	s.Types[candidateType]++
	if kept {
		s.Kept++
		s.KeptTypes[candidateType]++
		if len(s.KeptSamples) < maxCandidateFilterSamples {
			s.KeptSamples = append(s.KeptSamples, formatCandidate(&candidate))
		}
		return
	}
	if reason == "" {
		reason = "filtered"
	}
	s.RejectedReasons[reason]++
	if len(s.RejectedSamples) < maxCandidateFilterSamples {
		s.RejectedSamples = append(s.RejectedSamples, formatCandidate(&candidate)+"("+reason+")")
	}
}

func (s candidateFilterSummary) details() map[string]string {
	details := map[string]string{
		"candidate_total":    strconv.Itoa(s.Total),
		"candidate_kept":     strconv.Itoa(s.Kept),
		"candidate_rejected": strconv.Itoa(s.Total - s.Kept),
	}
	if types := formatCountMap(s.Types); types != "" {
		details["candidate_types"] = types
	}
	if keptTypes := formatCountMap(s.KeptTypes); keptTypes != "" {
		details["candidate_kept_types"] = keptTypes
	}
	if reasons := formatCountMap(s.RejectedReasons); reasons != "" {
		details["candidate_reject_reasons"] = reasons
	}
	if len(s.KeptSamples) > 0 {
		details["candidate_kept_samples"] = strings.Join(s.KeptSamples, ";")
	}
	if len(s.RejectedSamples) > 0 {
		details["candidate_rejected_samples"] = strings.Join(s.RejectedSamples, ";")
	}
	return details
}

func formatCountMap(values map[string]int) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Itoa(values[key]))
	}
	return strings.Join(parts, ",")
}

func observationFromPair(planID, event, pathID, connectionType string, pair *nat.CandidatePair, details map[string]string) solver.Observation {
	if details == nil {
		details = map[string]string{}
	}
	return solver.Observation{
		PlanID:         planID,
		Event:          event,
		PathID:         pathID,
		ConnectionType: connectionType,
		LocalAddr:      candidateAddrString(nilIfNoPair(pair, true)),
		RemoteAddr:     candidateAddrString(nilIfNoPair(pair, false)),
		LocalKind:      candidateTypeString(nilIfNoPair(pair, true)),
		RemoteKind:     candidateTypeString(nilIfNoPair(pair, false)),
		Details:        details,
		Timestamp:      time.Now(),
	}
}

func nilIfNoPair(pair *nat.CandidatePair, local bool) *nat.Candidate {
	if pair == nil {
		return nil
	}
	if local {
		return pair.Local
	}
	return pair.Remote
}

func candidateAddrString(candidate *nat.Candidate) string {
	if candidate == nil || candidate.Address == nil {
		return ""
	}
	return candidate.Address.String()
}

func candidateTypeString(candidate *nat.Candidate) string {
	if candidate == nil {
		return ""
	}
	return candidate.Type.String()
}

func formatCandidate(candidate *nat.Candidate) string {
	if candidate == nil {
		return ""
	}
	if candidate.Address == nil {
		return candidate.Type.String()
	}
	out := fmt.Sprintf("%s:%s", candidate.Type.String(), candidate.Address.String())
	if candidate.RelatedAddr != nil {
		out += "<-" + candidate.RelatedAddr.String()
	}
	return out
}

func selectedPairDetails(pair *nat.CandidatePair, mode executionMode) map[string]string {
	details := map[string]string{
		"local_candidate":       formatCandidate(nilIfNoPair(pair, true)),
		"remote_candidate":      formatCandidate(nilIfNoPair(pair, false)),
		"local_candidate_kind":  candidateTypeString(nilIfNoPair(pair, true)),
		"remote_candidate_kind": candidateTypeString(nilIfNoPair(pair, false)),
		"peer_reflexive_pair":   fmt.Sprintf("%t", pairHasPeerReflexiveCandidate(pair)),
		"remote_peer_reflexive": fmt.Sprintf("%t", candidateIsPeerReflexive(nilIfNoPair(pair, false))),
		"selected_pair_summary": selectedPairSummary(pair),
	}
	if mode == modePublicDirect {
		details["public_direct_learned_pair"] = details["peer_reflexive_pair"]
		details["public_direct_remote_learned"] = details["remote_peer_reflexive"]
	}
	return details
}

func pairHasPeerReflexiveCandidate(pair *nat.CandidatePair) bool {
	return candidateIsPeerReflexive(nilIfNoPair(pair, true)) || candidateIsPeerReflexive(nilIfNoPair(pair, false))
}

func candidateIsPeerReflexive(candidate *nat.Candidate) bool {
	return candidate != nil && candidate.Type == nat.CandidateTypePrflx
}

func selectedPairSummary(pair *nat.CandidatePair) string {
	if pair == nil {
		return ""
	}
	return formatCandidate(pair.Local) + "<->" + formatCandidate(pair.Remote)
}

func remoteAddrFromPair(pair *nat.CandidatePair) net.Addr {
	if pair == nil || pair.Remote == nil || pair.Remote.Address == nil {
		return nil
	}
	return pair.Remote.Address
}

func connectionStateString(agent nat.ICEAgent) string {
	if stateful, ok := agent.(interface{ GetConnectionState() nat.ConnectionState }); ok {
		switch stateful.GetConnectionState() {
		case nat.ConnectionStateChecking:
			return "checking"
		case nat.ConnectionStateConnected:
			return "connected"
		case nat.ConnectionStateCompleted:
			return "completed"
		case nat.ConnectionStateFailed:
			return "failed"
		case nat.ConnectionStateClosed:
			return "closed"
		default:
			return "new"
		}
	}
	return "connected"
}

func selectedPairMetrics(agent nat.ICEAgent) map[string]string {
	statsProvider, ok := agent.(interface {
		GetSelectedPairStats() (nat.CandidatePairStats, bool)
	})
	if !ok {
		return nil
	}
	stats, ok := statsProvider.GetSelectedPairStats()
	if !ok || stats.CurrentRoundTripTime <= 0 {
		return nil
	}
	rttMS := stats.CurrentRoundTripTime.Milliseconds()
	if rttMS <= 0 {
		rttMS = 1
	}
	return map[string]string{
		"rtt_ms": strconv.FormatInt(rttMS, 10),
	}
}

func classifyObservationError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "unknown"
	}
}
