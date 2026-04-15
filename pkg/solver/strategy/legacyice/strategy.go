package legacyice

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport/iceadapter"
)

type Strategy struct {
	cfg Config

	mu         sync.Mutex
	input      solver.SolveInput
	agent      nat.ICEAgent
	connecting bool
	closed     bool
	resultCh   chan solver.Result
}

func New(cfg Config) *Strategy {
	return &Strategy{
		cfg:      cfg.withDefaults(),
		resultCh: make(chan solver.Result, 1),
	}
}

func (s *Strategy) Name() string {
	return "legacy_ice_udp"
}

func (s *Strategy) Plan(ctx context.Context, in solver.SolveInput) ([]solver.Plan, error) {
	s.mu.Lock()
	s.input = in
	s.mu.Unlock()
	return []solver.Plan{{
		ID:       "legacyice/default",
		Strategy: s.Name(),
		Metadata: map[string]string{"transport": "ice_udp"},
	}}, nil
}

func (s *Strategy) Execute(ctx context.Context, sess solver.SessionIO, plan solver.Plan) (solver.Result, error) {
	if _, err := s.ensureAgent(ctx); err != nil {
		return solver.Result{}, err
	}

	if s.isInitiator() {
		if err := s.sendOffer(ctx, sess); err != nil {
			return solver.Result{}, err
		}
	}

	select {
	case result := <-s.resultCh:
		return result, nil
	case <-ctx.Done():
		return solver.Result{}, ctx.Err()
	}
}

func (s *Strategy) HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error {
	if !IsMessage(msg) {
		return nil
	}

	agent, err := s.ensureAgent(ctx)
	if err != nil {
		return err
	}

	switch msg.Type {
	case MessageTypeOffer:
		offer, err := unmarshalOfferPayload(msg.Payload)
		if err != nil {
			return err
		}
		if err := agent.SetRemoteCredentials(offer.ICE.Ufrag, offer.ICE.Pwd); err != nil {
			return err
		}
		if err := agent.SetRemoteCandidates(offer.ICE.Candidates); err != nil {
			return err
		}
		if err := s.sendAnswer(ctx, sess); err != nil {
			return err
		}
		return s.tryConnect(agent)
	case MessageTypeAnswer:
		answer, err := unmarshalAnswerPayload(msg.Payload)
		if err != nil {
			return err
		}
		if err := agent.SetRemoteCredentials(answer.ICE.Ufrag, answer.ICE.Pwd); err != nil {
			return err
		}
		if err := agent.SetRemoteCandidates(answer.ICE.Candidates); err != nil {
			return err
		}
		return s.tryConnect(agent)
	case MessageTypeCandidate:
		candidate, err := unmarshalCandidatePayload(msg.Payload)
		if err != nil {
			return err
		}
		if err := agent.SetRemoteCandidates([]nat.Candidate{candidate.ICE.Candidate}); err != nil {
			return err
		}
		return s.tryConnect(agent)
	default:
		return nil
	}
}

func (s *Strategy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.agent != nil {
		return s.agent.Close()
	}
	return nil
}

func (s *Strategy) ensureAgent(ctx context.Context) (nat.ICEAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("legacyice: strategy closed")
	}
	if s.agent != nil {
		return s.agent, nil
	}
	if s.cfg.NewICEAgent == nil {
		return nil, fmt.Errorf("legacyice: ice agent factory is nil")
	}
	agent, err := s.cfg.NewICEAgent(ctx, s.input.Initiator)
	if err != nil {
		return nil, err
	}
	s.agent = agent
	return agent, nil
}

func (s *Strategy) sendOffer(ctx context.Context, sess solver.SessionIO) error {
	agent, err := s.ensureAgent(ctx)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, s.cfg.GatherTimeout)
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
		SessionID: s.input.SessionID,
		ICE:       nat.ICESessionDescriptionPayload{Ufrag: ufrag, Pwd: pwd, Role: roleFor(s.input.Initiator), Candidates: candidates},
		SentAt:    time.Now(),
	})
	if err != nil {
		return err
	}
	return sess.Send(ctx, NewMessage(MessageTypeOffer, payload, time.Now()))
}

func (s *Strategy) sendAnswer(ctx context.Context, sess solver.SessionIO) error {
	agent, err := s.ensureAgent(ctx)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, s.cfg.GatherTimeout)
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
		SessionID: s.input.SessionID,
		ICE:       nat.ICESessionDescriptionPayload{Ufrag: ufrag, Pwd: pwd, Role: roleFor(s.input.Initiator), Candidates: candidates},
		SentAt:    time.Now(),
	})
	if err != nil {
		return err
	}
	return sess.Send(ctx, NewMessage(MessageTypeAnswer, payload, time.Now()))
}

func (s *Strategy) tryConnect(agent nat.ICEAgent) error {
	s.mu.Lock()
	if s.connecting {
		s.mu.Unlock()
		return nil
	}
	s.connecting = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.connecting = false
			s.mu.Unlock()
		}()

		connectCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ConnectTimeout)
		defer cancel()

		conn, pair, err := agent.Connect(connectCtx)
		if err != nil {
			return
		}

		connectionType := connectionTypeFromPair(pair)
		pathID := fmt.Sprintf("legacyice:%s:%s", connectionType, s.input.SessionID)
		packetTransport := iceadapter.New(conn, pathID)
		result := solver.Result{
			Transport: packetTransport,
			Summary: solver.PathSummary{
				PathID:         pathID,
				ConnectionType: connectionType,
				RemoteAddr:     remoteAddrFromPair(pair),
				Details: map[string]string{
					"ice_state":        connectionStateString(agent),
					"local_candidate":  formatCandidate(pair.Local),
					"remote_candidate": formatCandidate(pair.Remote),
				},
			},
		}

		select {
		case s.resultCh <- result:
		default:
		}
	}()
	return nil
}

func (s *Strategy) isInitiator() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.input.Initiator
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
