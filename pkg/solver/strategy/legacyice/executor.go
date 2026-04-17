package legacyice

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	mu         sync.Mutex
	agent      nat.ICEAgent
	connecting bool
	closed     bool

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
		Strategy:  StrategyName,
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
		Controlling: e.input.Initiator,
		ForceRelay:  e.execCfg.ForceRelay,
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
		pathID := fmt.Sprintf("legacyice:%s:%s", connectionType, e.input.SessionID)
		transport := e.releaseTransport(agent, conn, pathID)
		result := solver.Result{
			Transport: transport,
			Summary: solver.PathSummary{
				PathID:         pathID,
				ConnectionType: connectionType,
				RemoteAddr:     remoteAddrFromPair(pair),
				Details: map[string]string{
					"ice_state":        connectionStateString(agent),
					"local_candidate":  formatCandidate(pair.Local),
					"remote_candidate": formatCandidate(pair.Remote),
					"plan_mode":        string(e.execCfg.Mode),
				},
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
			Strategy:   StrategyName,
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
		obs.Strategy = StrategyName
	}
	if obs.PlanID == "" {
		obs.PlanID = e.plan.ID
	}
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now()
	}
	_ = sess.ReportObservation(context.Background(), obs)
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

func filterRemoteCandidates(candidates []nat.Candidate, execCfg executorConfig) []nat.Candidate {
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

func observationFromPair(planID, event, pathID, connectionType string, pair *nat.CandidatePair, details map[string]string) solver.Observation {
	if details == nil {
		details = map[string]string{}
	}
	return solver.Observation{
		Strategy:       StrategyName,
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
