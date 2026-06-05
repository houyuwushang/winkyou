package legacyice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
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

	mu                     sync.Mutex
	agent                  nat.ICEAgent
	connecting             bool
	closed                 bool
	publicDirectLocalBases map[string]struct{}

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	resultCh        chan solver.Result
	errCh           chan error
	failOnce        sync.Once
}

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
		if offer.PlanID != "" && offer.PlanID != e.plan.ID {
			return nil
		}
		if err := agent.SetRemoteCredentials(offer.ICE.Ufrag, offer.ICE.Pwd); err != nil {
			return err
		}
		if err := agent.SetRemoteCandidates(filterRemoteCandidates(offer.ICE.Candidates, e.execCfg)); err != nil {
			return err
		}
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
		if answer.PlanID != "" && answer.PlanID != e.plan.ID {
			return nil
		}
		if err := agent.SetRemoteCredentials(answer.ICE.Ufrag, answer.ICE.Pwd); err != nil {
			return err
		}
		if err := agent.SetRemoteCandidates(filterRemoteCandidates(answer.ICE.Candidates, e.execCfg)); err != nil {
			return err
		}
		e.startConnect(sess)
		return nil
	case MessageTypeCandidate:
		candidate, err := unmarshalCandidatePayload(msg.Payload)
		if err != nil {
			return err
		}
		if candidate.PlanID != "" && candidate.PlanID != e.plan.ID {
			return nil
		}
		filtered := filterRemoteCandidates([]nat.Candidate{candidate.ICE.Candidate}, e.execCfg)
		if len(filtered) == 0 {
			return nil
		}
		if err := agent.SetRemoteCandidates(filtered); err != nil {
			return err
		}
		e.startConnect(sess)
		return nil
	default:
		return nil
	}
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
	agent, err := e.cfg.NewICEAgent(ctx, AgentRequest{
		Controlling:           e.input.Initiator,
		ForceRelay:            e.execCfg.ForceRelay,
		CandidateCIDRExclude:  append([]string(nil), e.execCfg.CandidateCIDRExclude...),
		PublicDirectCandidate: e.execCfg.PublicDirectCandidate,
	})
	if err != nil {
		return nil, err
	}
	e.agent = agent
	return agent, nil
}

func (e *executor) sendOffer(ctx context.Context, sess solver.SessionIO) error {
	agent, err := e.ensureAgent(ctx)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, e.cfg.GatherTimeout)
	defer cancel()

	candidates, err := agent.GatherCandidates(gatherCtx)
	if err != nil {
		return err
	}
	e.rememberPublicDirectLocalBases(candidates)
	candidates = filterLocalCandidates(candidates, e.execCfg)
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
	return sess.Send(ctx, NewMessage(MessageTypeOffer, payload, time.Now()))
}

func (e *executor) sendAnswer(ctx context.Context, sess solver.SessionIO) error {
	agent, err := e.ensureAgent(ctx)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, e.cfg.GatherTimeout)
	defer cancel()

	candidates, err := agent.GatherCandidates(gatherCtx)
	if err != nil {
		return err
	}
	e.rememberPublicDirectLocalBases(candidates)
	candidates = filterLocalCandidates(candidates, e.execCfg)
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
	return sess.Send(ctx, NewMessage(MessageTypeAnswer, payload, time.Now()))
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
		role, dependencies := pathPolicyMetadata(connectionType, pair, e.execCfg.Mode, e.publicDirectLocalBaseSnapshot())
		metrics := selectedPairMetrics(agent)
		details := map[string]string{
			"ice_state":        connectionStateString(agent),
			"local_candidate":  formatCandidate(pair.Local),
			"remote_candidate": formatCandidate(pair.Remote),
			"plan_mode":        string(e.execCfg.Mode),
		}
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
		e.report(sess, observationFromPair(e.plan.ID, "candidate_succeeded", pathID, connectionType, pair, map[string]string{
			"mode": string(e.execCfg.Mode),
		}))

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

func (e *executor) rememberPublicDirectLocalBases(candidates []nat.Candidate) {
	if e.execCfg.Mode != modePublicDirect {
		return
	}
	bases := make(map[string]struct{})
	for _, candidate := range candidates {
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
		e.report(sess, solver.Observation{
			Strategy:   e.strategyName(),
			PlanID:     e.plan.ID,
			Event:      "candidate_failed",
			ErrorClass: classifyObservationError(err),
			Reason:     err.Error(),
			Details: map[string]string{
				"mode": string(e.execCfg.Mode),
			},
			Timestamp: time.Now(),
		})
	})
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

func pathPolicyMetadata(connectionType string, pair *nat.CandidatePair, mode executionMode, publicDirectLocalBases map[string]struct{}) (solver.PathRole, []solver.PathDependency) {
	if connectionType == "relay" {
		return solver.PathRolePrimaryCandidate, []solver.PathDependency{{
			Kind:   solver.PathDependencyRelay,
			Reason: "turn_or_relay_candidate",
		}}
	}
	if reason := candidatePairDependencyReason(pair, mode, publicDirectLocalBases); reason != "" {
		return solver.PathRolePrimaryCandidate, []solver.PathDependency{{
			Kind:   solver.PathDependencyUnknown,
			Reason: reason,
		}}
	}
	return solver.PathRoleProtectedDirect, nil
}

func candidatePairDependencyReason(pair *nat.CandidatePair, mode executionMode, publicDirectLocalBases map[string]struct{}) string {
	if pair == nil {
		return "selected_pair_unavailable"
	}
	if mode == modePublicDirect {
		return publicDirectCandidatePairDependencyReason(pair, publicDirectLocalBases)
	}
	if reason := candidateDependencyReason("local", pair.Local); reason != "" {
		return reason
	}
	if reason := candidateDependencyReason("remote", pair.Remote); reason != "" {
		return reason
	}
	return ""
}

func publicDirectCandidatePairDependencyReason(pair *nat.CandidatePair, localBases map[string]struct{}) string {
	if reason := publicDirectLocalCandidateDependencyReason(pair.Local, localBases); reason != "" {
		return reason
	}
	if reason := candidateDependencyReason("remote", pair.Remote); reason != "" {
		return reason
	}
	return ""
}

func publicDirectLocalCandidateDependencyReason(candidate *nat.Candidate, localBases map[string]struct{}) string {
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
	if candidate == nil || candidate.Address == nil || candidate.Address.IP == nil {
		return side + "_candidate_unavailable"
	}
	if candidate.Type == nat.CandidateTypeRelay {
		return ""
	}
	if reason := nonPublicCandidateIPReason(candidate.Address.IP); reason != "" {
		return side + "_" + reason
	}
	return ""
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
	if execCfg.Mode == modePublicDirect {
		filtered := make([]nat.Candidate, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.Type == nat.CandidateTypeRelay {
				continue
			}
			if candidateDependencyReason("remote", &candidate) != "" {
				continue
			}
			filtered = append(filtered, candidate)
		}
		return filtered
	}
	if execCfg.Mode != modeRelayOnly {
		return append([]nat.Candidate(nil), candidates...)
	}
	filtered := make([]nat.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Type == nat.CandidateTypeRelay {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func filterLocalCandidates(candidates []nat.Candidate, execCfg executorConfig) []nat.Candidate {
	if execCfg.Mode != modePublicDirect {
		return append([]nat.Candidate(nil), candidates...)
	}
	filtered := make([]nat.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Type == nat.CandidateTypeRelay {
			continue
		}
		if candidateDependencyReason("local", &candidate) != "" {
			continue
		}
		filtered = append(filtered, candidate)
	}
	return filtered
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
	return fmt.Sprintf("%s:%s", candidate.Type.String(), candidate.Address.String())
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
