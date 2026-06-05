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
		candidates, summary := filterRemoteCandidatesWithSummary(offer.ICE.Candidates, e.execCfg)
		e.reportCandidateFilter(sess, "remote_candidates_filtered", "remote", MessageTypeOffer, summary)
		if len(candidates) == 0 {
			e.failRemoteCandidates(sess, MessageTypeOffer)
			return nil
		}
		if err := agent.SetRemoteCandidates(candidates); err != nil {
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
		candidates, summary := filterRemoteCandidatesWithSummary(answer.ICE.Candidates, e.execCfg)
		e.reportCandidateFilter(sess, "remote_candidates_filtered", "remote", MessageTypeAnswer, summary)
		if len(candidates) == 0 {
			e.failRemoteCandidates(sess, MessageTypeAnswer)
			return nil
		}
		if err := agent.SetRemoteCandidates(candidates); err != nil {
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
		filtered, summary := filterRemoteCandidatesWithSummary([]nat.Candidate{candidate.ICE.Candidate}, e.execCfg)
		e.reportCandidateFilter(sess, "remote_candidates_filtered", "remote", MessageTypeCandidate, summary)
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
	req := AgentRequest{
		Controlling:           e.input.Initiator,
		ForceRelay:            e.execCfg.ForceRelay,
		CandidateCIDRInclude:  publicEndpointHintLocalBaseCIDRs(e.execCfg.PublicEndpointHints),
		CandidateCIDRExclude:  append([]string(nil), e.execCfg.CandidateCIDRExclude...),
		PublicDirectCandidate: e.execCfg.PublicDirectCandidate,
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

func (e *executor) failRemoteCandidates(sess solver.SessionIO, messageType string) {
	err := fmt.Errorf("legacyice: no usable remote candidates for %s in %s", e.execCfg.Mode, messageType)
	e.reportFailure(sess, err)
	select {
	case e.errCh <- err:
	default:
	}
}

func (e *executor) reportCandidateFilter(sess solver.SessionIO, event, side, messageType string, summary candidateFilterSummary) {
	details := summary.details()
	details["mode"] = string(e.execCfg.Mode)
	details["candidate_side"] = side
	if messageType != "" {
		details["message_type"] = messageType
	}
	e.report(sess, solver.Observation{
		Strategy:  e.strategyName(),
		PlanID:    e.plan.ID,
		Event:     event,
		Details:   details,
		Timestamp: time.Now(),
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
	filtered, _ := filterRemoteCandidatesWithSummary(candidates, execCfg)
	return filtered
}

func appendPublicEndpointHintCandidates(candidates []nat.Candidate, execCfg executorConfig) ([]nat.Candidate, error) {
	if execCfg.Mode != modePublicDirect || len(execCfg.PublicEndpointHints) == 0 {
		return candidates, nil
	}
	out := append([]nat.Candidate(nil), candidates...)
	seen := make(map[string]struct{}, len(out)+len(execCfg.PublicEndpointHints))
	for _, candidate := range out {
		seen[candidateAddressKey(candidate)] = struct{}{}
	}
	for i, raw := range execCfg.PublicEndpointHints {
		candidate, err := publicEndpointHintCandidate(raw, i)
		if err != nil {
			return nil, err
		}
		key := candidateAddressKey(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, candidate)
	}
	return out, nil
}

func publicEndpointHintCandidate(raw string, index int) (nat.Candidate, error) {
	hint, err := parsePublicEndpointHint(raw)
	if err != nil {
		return nat.Candidate{}, err
	}
	ip := net.IP(append([]byte(nil), hint.public.Addr().AsSlice()...))
	if reason := nonPublicCandidateIPReason(ip); reason != "" {
		return nat.Candidate{}, fmt.Errorf("legacyice: invalid public endpoint hint %q: %s", raw, reason)
	}
	candidate := nat.Candidate{
		Type:       nat.CandidateTypeSrflx,
		Address:    &net.UDPAddr{IP: ip, Port: int(hint.public.Port())},
		Priority:   publicEndpointHintPriority(index),
		Foundation: fmt.Sprintf("public-hint-%d", index+1),
	}
	if hint.local.IsValid() {
		localIP := net.IP(append([]byte(nil), hint.local.Addr().AsSlice()...))
		candidate.RelatedAddr = &net.UDPAddr{IP: localIP, Port: int(hint.local.Port())}
	}
	return candidate, nil
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
	const (
		srflxTypePreference = 100
		componentID         = 1
	)
	localPreference := 65535 - index
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
		return candidateDependencyReason("remote", &candidate)
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
	return candidateDependencyReason("local", &candidate)
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
