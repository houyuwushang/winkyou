package signalrelay

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/solver"
)

const (
	StrategyName = "signal_relay"
	PlanID       = "signalrelay/coordinator_signal"

	defaultReadyRetryInterval = 500 * time.Millisecond
)

type Config struct {
	ReadyTimeout       time.Duration
	ReadyRetryInterval time.Duration
	QueueSize          int
}

func (c Config) withDefaults() Config {
	if c.ReadyTimeout <= 0 {
		c.ReadyTimeout = 30 * time.Second
	}
	if c.ReadyRetryInterval <= 0 {
		c.ReadyRetryInterval = defaultReadyRetryInterval
	}
	if c.QueueSize <= 0 {
		c.QueueSize = defaultQueueSize
	}
	return c
}

type Strategy struct {
	cfg Config

	mu          sync.Mutex
	input       solver.SolveInput
	transport   *signalTransport
	remoteReady bool
	readyCh     chan struct{}
	closed      bool
}

func New(cfg Config) *Strategy {
	return &Strategy{cfg: cfg.withDefaults(), readyCh: make(chan struct{}, 1)}
}

func (s *Strategy) Name() string {
	return StrategyName
}

func (s *Strategy) Plan(ctx context.Context, in solver.SolveInput) ([]solver.Plan, error) {
	_ = ctx
	if strings.TrimSpace(in.SessionID) == "" {
		return nil, fmt.Errorf("signalrelay: session id is required")
	}
	s.mu.Lock()
	s.input = in
	s.mu.Unlock()
	return []solver.Plan{{
		ID:       PlanID,
		Strategy: StrategyName,
		Metadata: map[string]string{
			"transport":   StrategyName,
			"mode":        "coordinator_signal",
			"description": "Relay encrypted packets over the coordinator signal stream",
		},
	}}, nil
}

func (s *Strategy) Execute(ctx context.Context, sess solver.SessionIO, plan solver.Plan) (solver.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if plan.ID != PlanID {
		return solver.Result{}, fmt.Errorf("signalrelay: unsupported plan %q", plan.ID)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return solver.Result{}, fmt.Errorf("signalrelay: strategy closed")
	}
	input := s.input
	if s.readyCh == nil {
		s.readyCh = make(chan struct{}, 1)
	}
	transport := newSignalTransport(input, plan, sess, s.cfg.QueueSize)
	s.transport = transport
	s.mu.Unlock()

	if err := s.waitReady(ctx, sess, input.SessionID, plan.ID); err != nil {
		_ = transport.Close()
		return solver.Result{}, err
	}
	return solver.Result{
		Transport: transport,
		Summary: solver.PathSummary{
			PathID:         transport.pathID,
			ConnectionType: "relay",
			RemoteAddr:     transport.RemoteAddr(),
			Role:           solver.PathRolePrimaryCandidate,
			Dependencies: []solver.PathDependency{{
				Kind:   solver.PathDependencyCoordinator,
				NodeID: input.RemoteNodeID,
				Reason: "coordinator_signal_stream",
			}},
			Metrics: map[string]string{
				"transport": StrategyName,
			},
			Details: map[string]string{
				"transport": StrategyName,
				"strategy":  StrategyName,
				"mode":      "coordinator_signal",
			},
		},
	}, nil
}

func (s *Strategy) HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error {
	_ = ctx
	_ = sess
	if !IsMessage(msg) {
		return nil
	}
	receivedAt := msg.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	switch msg.Type {
	case MessageTypeReady:
		payload, err := unmarshalReadyPayload(msg.Payload)
		if err != nil {
			return err
		}
		if !s.acceptMessage(payload.SessionID, payload.PlanID) {
			return nil
		}
		s.markReady()
	case MessageTypePacket:
		payload, err := unmarshalPacketPayload(msg.Payload)
		if err != nil {
			return err
		}
		if !s.acceptMessage(payload.SessionID, payload.PlanID) {
			return nil
		}
		s.mu.Lock()
		transport := s.transport
		s.mu.Unlock()
		if transport != nil {
			return transport.handlePacket(payload, receivedAt)
		}
	case MessageTypeClose:
		payload, err := unmarshalClosePayload(msg.Payload)
		if err != nil {
			return err
		}
		if !s.acceptMessage(payload.SessionID, payload.PlanID) {
			return nil
		}
		s.mu.Lock()
		transport := s.transport
		s.mu.Unlock()
		if transport != nil {
			return transport.handleClose(payload)
		}
	default:
		return fmt.Errorf("signalrelay: unsupported message type %q", msg.Type)
	}
	return nil
}

func (s *Strategy) Close() error {
	s.mu.Lock()
	s.closed = true
	transport := s.transport
	s.transport = nil
	s.mu.Unlock()
	if transport != nil {
		return transport.Close()
	}
	return nil
}

func (s *Strategy) sendReady(ctx context.Context, sess solver.SessionIO, sessionID, planID string) error {
	payload, err := marshalReadyPayload(readyPayload{
		SessionID: sessionID,
		PlanID:    planID,
		SentAt:    time.Now(),
	})
	if err != nil {
		return err
	}
	return sess.Send(ctx, NewMessage(MessageTypeReady, payload, time.Now()))
}

func (s *Strategy) waitReady(ctx context.Context, sess solver.SessionIO, sessionID, planID string) error {
	timeout := s.cfg.ReadyTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := s.sendReady(ctx, sess, sessionID, planID); err != nil {
		return err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	retryInterval := s.cfg.ReadyRetryInterval
	if retryInterval <= 0 {
		retryInterval = defaultReadyRetryInterval
	}
	retry := time.NewTicker(retryInterval)
	defer retry.Stop()
	for {
		s.mu.Lock()
		ready := s.remoteReady
		s.mu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("signalrelay: remote ready timeout")
		case <-retry.C:
			if err := s.sendReady(ctx, sess, sessionID, planID); err != nil {
				return err
			}
		case <-s.readyCh:
		}
	}
}

func (s *Strategy) markReady() {
	s.mu.Lock()
	s.remoteReady = true
	ch := s.readyCh
	s.mu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *Strategy) acceptMessage(sessionID, planID string) bool {
	s.mu.Lock()
	input := s.input
	s.mu.Unlock()
	return acceptSignalMessage(sessionID, planID, input.SessionID)
}

func acceptSignalMessage(sessionID, planID, expectedSessionID string) bool {
	if strings.TrimSpace(sessionID) != "" && strings.TrimSpace(expectedSessionID) != "" && sessionID != expectedSessionID {
		return false
	}
	return strings.TrimSpace(planID) == "" || planID == PlanID
}
