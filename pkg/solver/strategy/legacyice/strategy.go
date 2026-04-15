package legacyice

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport/iceadapter"
)

type dependencyIO interface {
	solver.SessionIO
	NewLegacyICEAgent(ctx context.Context, controlling bool) (nat.ICEAgent, error)
	GatherTimeout() time.Duration
	ConnectTimeout() time.Duration
	CheckTimeout() time.Duration
}

type Strategy struct {
	mu         sync.Mutex
	input      solver.SolveInput
	agent      nat.ICEAgent
	connecting bool
	closed     bool
	resultCh   chan solver.Result
}

type offerPayload struct {
	SessionID string                           `json:"session_id"`
	ICE       nat.ICESessionDescriptionPayload `json:"ice"`
	SentAt    time.Time                        `json:"sent_at"`
}

type answerPayload struct {
	SessionID string                           `json:"session_id"`
	ICE       nat.ICESessionDescriptionPayload `json:"ice"`
	SentAt    time.Time                        `json:"sent_at"`
}

type candidatePayload struct {
	SessionID string                  `json:"session_id"`
	ICE       nat.ICECandidatePayload `json:"ice"`
	SentAt    time.Time               `json:"sent_at"`
}

func New() *Strategy {
	return &Strategy{resultCh: make(chan solver.Result, 1)}
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
	deps, ok := sess.(dependencyIO)
	if !ok {
		return solver.Result{}, fmt.Errorf("legacyice: session io does not provide legacy ICE dependencies")
	}

	if _, err := s.ensureAgent(ctx, deps); err != nil {
		return solver.Result{}, err
	}

	if s.isInitiator() {
		if err := s.sendOffer(ctx, deps); err != nil {
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
	deps, ok := sess.(dependencyIO)
	if !ok {
		return fmt.Errorf("legacyice: session io does not provide legacy ICE dependencies")
	}
	agent, err := s.ensureAgent(ctx, deps)
	if err != nil {
		return err
	}

	switch msg.Kind {
	case solver.MessageKindLegacyICEOffer:
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
		if err := s.sendAnswer(ctx, deps); err != nil {
			return err
		}
		return s.tryConnect(ctx, deps, agent)
	case solver.MessageKindLegacyICEAnswer:
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
		return s.tryConnect(ctx, deps, agent)
	case solver.MessageKindLegacyICECandidate:
		candidate, err := unmarshalCandidatePayload(msg.Payload)
		if err != nil {
			return err
		}
		if err := agent.SetRemoteCandidates([]nat.Candidate{candidate.ICE.Candidate}); err != nil {
			return err
		}
		return s.tryConnect(ctx, deps, agent)
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

func (s *Strategy) ensureAgent(ctx context.Context, deps dependencyIO) (nat.ICEAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("legacyice: strategy closed")
	}
	if s.agent != nil {
		return s.agent, nil
	}
	agent, err := deps.NewLegacyICEAgent(ctx, s.input.Initiator)
	if err != nil {
		return nil, err
	}
	s.agent = agent
	return agent, nil
}

func (s *Strategy) sendOffer(ctx context.Context, deps dependencyIO) error {
	agent, err := s.ensureAgent(ctx, deps)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, deps.GatherTimeout())
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
	return deps.Send(ctx, solver.Message{Kind: solver.MessageKindLegacyICEOffer, Payload: payload, ReceivedAt: time.Now()})
}

func (s *Strategy) sendAnswer(ctx context.Context, deps dependencyIO) error {
	agent, err := s.ensureAgent(ctx, deps)
	if err != nil {
		return err
	}

	gatherCtx, cancel := context.WithTimeout(ctx, deps.GatherTimeout())
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
	return deps.Send(ctx, solver.Message{Kind: solver.MessageKindLegacyICEAnswer, Payload: payload, ReceivedAt: time.Now()})
}

func (s *Strategy) tryConnect(ctx context.Context, deps dependencyIO, agent nat.ICEAgent) error {
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

		connectCtx, cancel := context.WithTimeout(context.Background(), deps.ConnectTimeout())
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

func marshalOfferPayload(payload offerPayload) ([]byte, error) {
	icePayload, err := nat.MarshalICESessionDescriptionPayload(payload.ICE)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: payload.SessionID, ICE: icePayload, SentAt: payload.SentAt})
}

func unmarshalOfferPayload(data []byte) (offerPayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := json.Unmarshal(data, &wrap); err != nil {
		return offerPayload{}, fmt.Errorf("legacyice: unmarshal offer payload: %w", err)
	}
	icePayload, err := nat.UnmarshalICESessionDescriptionPayload(wrap.ICE)
	if err != nil {
		return offerPayload{}, err
	}
	return offerPayload{SessionID: wrap.SessionID, ICE: icePayload, SentAt: wrap.SentAt}, nil
}

func marshalAnswerPayload(payload answerPayload) ([]byte, error) {
	icePayload, err := nat.MarshalICESessionDescriptionPayload(payload.ICE)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: payload.SessionID, ICE: icePayload, SentAt: payload.SentAt})
}

func unmarshalAnswerPayload(data []byte) (answerPayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := json.Unmarshal(data, &wrap); err != nil {
		return answerPayload{}, fmt.Errorf("legacyice: unmarshal answer payload: %w", err)
	}
	icePayload, err := nat.UnmarshalICESessionDescriptionPayload(wrap.ICE)
	if err != nil {
		return answerPayload{}, err
	}
	return answerPayload{SessionID: wrap.SessionID, ICE: icePayload, SentAt: wrap.SentAt}, nil
}

func marshalCandidatePayload(payload candidatePayload) ([]byte, error) {
	icePayload, err := nat.MarshalICECandidatePayload(payload.ICE)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}{SessionID: payload.SessionID, ICE: icePayload, SentAt: payload.SentAt})
}

func unmarshalCandidatePayload(data []byte) (candidatePayload, error) {
	var wrap struct {
		SessionID string    `json:"session_id"`
		ICE       []byte    `json:"ice"`
		SentAt    time.Time `json:"sent_at"`
	}
	if err := json.Unmarshal(data, &wrap); err != nil {
		return candidatePayload{}, fmt.Errorf("legacyice: unmarshal candidate payload: %w", err)
	}
	icePayload, err := nat.UnmarshalICECandidatePayload(wrap.ICE)
	if err != nil {
		return candidatePayload{}, err
	}
	return candidatePayload{SessionID: wrap.SessionID, ICE: icePayload, SentAt: wrap.SentAt}, nil
}
