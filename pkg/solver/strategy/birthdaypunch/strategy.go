package birthdaypunch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport/iceadapter"
)

const (
	StrategyName = "birthday_punch"
	PlanID       = "birthdaypunch/direct"

	defaultProbeSamples    = 8
	defaultEndpointTimeout = 15 * time.Second
	defaultPunchTimeout    = 20 * time.Second
)

// localEndpoint is this node's own probed public endpoint and NAT port model.
type localEndpoint struct {
	IP           net.IP
	ObservedPort int
	Pattern      nat.PortAllocationPattern
	Delta        int
}

type Config struct {
	STUNServers     []string
	ProbeSamples    int
	EndpointTimeout time.Duration
	PunchTimeout    time.Duration
	StartLead       time.Duration

	// Injectable seams for tests; nil uses real STUN probing / puncher.Punch /
	// wall-clock time.
	localEndpointFunc func(ctx context.Context) (localEndpoint, error)
	punchFunc         func(ctx context.Context, cfg puncher.Config) (*puncher.Result, error)
	now               func() time.Time
}

func (c Config) withDefaults() Config {
	if c.ProbeSamples <= 0 {
		c.ProbeSamples = defaultProbeSamples
	}
	if c.EndpointTimeout <= 0 {
		c.EndpointTimeout = defaultEndpointTimeout
	}
	if c.PunchTimeout <= 0 {
		c.PunchTimeout = defaultPunchTimeout
	}
	if c.StartLead <= 0 {
		c.StartLead = defaultStartLead
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.punchFunc == nil {
		c.punchFunc = puncher.Punch
	}
	return c
}

type Strategy struct {
	cfg Config

	mu       sync.Mutex
	input    solver.SolveInput
	remote   *peerEndpoint
	startAt  time.Time
	closed   bool
	remoteCh chan struct{}
	startCh  chan struct{}
}

func New(cfg Config) *Strategy {
	return &Strategy{
		cfg:      cfg.withDefaults(),
		remoteCh: make(chan struct{}, 1),
		startCh:  make(chan struct{}, 1),
	}
}

func (s *Strategy) Name() string { return StrategyName }

func (s *Strategy) Plan(ctx context.Context, in solver.SolveInput) ([]solver.Plan, error) {
	_ = ctx
	if strings.TrimSpace(in.SessionID) == "" {
		return nil, fmt.Errorf("birthdaypunch: session id is required")
	}
	s.mu.Lock()
	s.input = in
	s.mu.Unlock()
	return []solver.Plan{{
		ID:       PlanID,
		Strategy: StrategyName,
		Metadata: map[string]string{
			"transport":   StrategyName,
			"mode":        "birthday_punch",
			"description": "Multi-socket birthday-paradox + port-prediction direct punch",
		},
	}}, nil
}

func (s *Strategy) Execute(ctx context.Context, sess solver.SessionIO, plan solver.Plan) (solver.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if plan.ID != PlanID {
		return solver.Result{}, fmt.Errorf("birthdaypunch: unsupported plan %q", plan.ID)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return solver.Result{}, fmt.Errorf("birthdaypunch: strategy closed")
	}
	input := s.input
	s.mu.Unlock()

	local, err := s.probeLocal(ctx)
	if err != nil {
		return solver.Result{}, fmt.Errorf("birthdaypunch: probe local endpoint: %w", err)
	}

	remote, err := s.exchangeEndpoints(ctx, sess, input, local)
	if err != nil {
		return solver.Result{}, err
	}

	startAt, err := s.synchronize(ctx, sess, input, input.Initiator)
	if err != nil {
		return solver.Result{}, err
	}
	if d := delayUntil(s.cfg.now(), startAt); d > 0 {
		select {
		case <-ctx.Done():
			return solver.Result{}, ctx.Err()
		case <-time.After(d):
		}
	}

	pp := planPunch(*remote)
	if !pp.usable() {
		return solver.Result{}, fmt.Errorf("birthdaypunch: no punch targets for peer")
	}

	punchCtx, cancel := context.WithTimeout(ctx, s.cfg.PunchTimeout)
	defer cancel()
	localPort := 0
	if local.Pattern == nat.PortAllocationPreserving && local.ObservedPort > 0 {
		// The STUN probe socket is closed before punching. Re-bind its advertised
		// port so a port-preserving NAT (or a directly addressed host) keeps the
		// endpoint that the peer is actively targeting.
		localPort = local.ObservedPort
	}
	res, err := s.cfg.punchFunc(punchCtx, puncher.Config{
		RemoteIP:    remote.IP,
		TargetPorts: pp.Targets,
		Session:     sessionKey(input.SessionID),
		SocketCount: pp.SocketCount,
		LocalPort:   localPort,
		BirthdayN:   pp.BirthdayN,
		BirthdayLo:  birthdayPortLo,
		BirthdayHi:  birthdayPortHi,
		Burst:       1,
		RoundDelay:  pp.RoundDelay,
		Method:      pp.Method,
	})
	if err != nil {
		return solver.Result{}, fmt.Errorf("birthdaypunch: punch failed: %w", err)
	}
	if res == nil || res.Conn == nil || res.RemoteAddr == nil {
		if res != nil && res.Conn != nil {
			_ = res.Conn.Close()
		}
		return solver.Result{}, fmt.Errorf("birthdaypunch: punch returned an incomplete result")
	}

	conn := res.Connected()
	return solver.Result{
		Transport: iceadapter.New(conn, PlanID),
		Summary: solver.PathSummary{
			PathID:         PlanID,
			ConnectionType: "direct",
			RemoteAddr:     conn.RemoteAddr(),
			Role:           solver.PathRoleProtectedDirect,
			Dependencies:   nil, // independent public direct: no coordinator/relay dependency
			Metrics:        map[string]string{"transport": StrategyName},
			Details: map[string]string{
				"strategy":             StrategyName,
				"mode":                 "birthday_punch",
				"punch_method":         pp.Method,
				"local_addr":           conn.LocalAddr().String(),
				"local_public_ip":      ipString(local.IP),
				"local_observed_port":  strconv.Itoa(local.ObservedPort),
				"local_nat_pattern":    local.Pattern.String(),
				"local_nat_delta":      strconv.Itoa(local.Delta),
				"remote_addr":          conn.RemoteAddr().String(),
				"remote_public_ip":     ipString(remote.IP),
				"remote_observed_port": strconv.Itoa(remote.ObservedPort),
				"remote_nat_pattern":   remote.Pattern.String(),
				"remote_nat_delta":     strconv.Itoa(remote.Delta),
			},
		},
	}, nil
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (s *Strategy) HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error {
	_ = ctx
	_ = sess
	if !IsMessage(msg) {
		return nil
	}
	switch msg.Type {
	case MessageTypeEndpoint:
		payload, err := unmarshalEndpoint(msg.Payload)
		if err != nil {
			return err
		}
		if !s.accept(payload.SessionID, payload.PlanID) {
			return nil
		}
		ip := net.ParseIP(strings.TrimSpace(payload.PublicIP))
		if ip == nil || ip.To4() == nil {
			return nil // ignore endpoints without a usable public IPv4
		}
		s.mu.Lock()
		if s.remote == nil {
			s.remote = &peerEndpoint{
				IP:           ip.To4(),
				ObservedPort: payload.ObservedPort,
				Pattern:      patternFromString(payload.Pattern),
				Delta:        payload.Delta,
			}
		}
		ch := s.remoteCh
		s.mu.Unlock()
		signalOnce(ch)
	case MessageTypeStart:
		payload, err := unmarshalStart(msg.Payload)
		if err != nil {
			return err
		}
		if !s.accept(payload.SessionID, payload.PlanID) {
			return nil
		}
		s.mu.Lock()
		if s.startAt.IsZero() && payload.StartAtUnixMs > 0 {
			s.startAt = time.UnixMilli(payload.StartAtUnixMs)
		}
		ch := s.startCh
		s.mu.Unlock()
		signalOnce(ch)
	default:
		return fmt.Errorf("birthdaypunch: unsupported message type %q", msg.Type)
	}
	return nil
}

func (s *Strategy) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *Strategy) probeLocal(ctx context.Context) (localEndpoint, error) {
	if s.cfg.localEndpointFunc != nil {
		return s.cfg.localEndpointFunc(ctx)
	}
	if len(s.cfg.STUNServers) == 0 {
		return localEndpoint{}, fmt.Errorf("no STUN servers configured")
	}
	report, err := nat.ProbePortAllocationWithMapping(ctx, s.cfg.STUNServers, s.cfg.ProbeSamples)
	if err != nil {
		return localEndpoint{}, err
	}
	return localEndpointFromReport(report), nil
}

func localEndpointFromReport(report nat.PortAllocationReport) localEndpoint {
	port := 0
	if n := len(report.Samples); n > 0 {
		port = report.Samples[n-1].MappedPort
	}
	pattern := report.Pattern
	if report.MappingNATType == nat.NATTypeNone && port > 0 {
		// A directly addressed host has no translation to predict. Even a single
		// successful allocation sample is enough to advertise a reusable local
		// port, whereas the generic classifier intentionally calls it unknown.
		pattern = nat.PortAllocationPreserving
	}
	return localEndpoint{
		IP:           report.MappedIP,
		ObservedPort: port,
		Pattern:      pattern,
		Delta:        report.Delta,
	}
}

func (s *Strategy) exchangeEndpoints(ctx context.Context, sess solver.SessionIO, input solver.SolveInput, local localEndpoint) (*peerEndpoint, error) {
	if err := s.sendEndpoint(ctx, sess, input, local); err != nil {
		return nil, err
	}
	timeout := time.NewTimer(s.cfg.EndpointTimeout)
	defer timeout.Stop()
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()
	for {
		s.mu.Lock()
		remote := s.remote
		s.mu.Unlock()
		if remote != nil {
			return remote, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return nil, fmt.Errorf("birthdaypunch: remote endpoint timeout")
		case <-retry.C:
			if err := s.sendEndpoint(ctx, sess, input, local); err != nil {
				return nil, err
			}
		case <-s.remoteCh:
		}
	}
}

func (s *Strategy) synchronize(ctx context.Context, sess solver.SessionIO, input solver.SolveInput, initiator bool) (time.Time, error) {
	if initiator {
		startAt := syncStartAt(s.cfg.now(), s.cfg.StartLead)
		if err := s.sendStart(ctx, sess, input, startAt); err != nil {
			return time.Time{}, err
		}
		return startAt, nil
	}
	timeout := time.NewTimer(s.cfg.EndpointTimeout)
	defer timeout.Stop()
	for {
		s.mu.Lock()
		startAt := s.startAt
		s.mu.Unlock()
		if !startAt.IsZero() {
			return startAt, nil
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-timeout.C:
			return time.Time{}, fmt.Errorf("birthdaypunch: start signal timeout")
		case <-s.startCh:
		}
	}
}

func (s *Strategy) sendEndpoint(ctx context.Context, sess solver.SessionIO, input solver.SolveInput, local localEndpoint) error {
	ip := ""
	if local.IP != nil {
		ip = local.IP.String()
	}
	payload, err := marshalEndpoint(endpointPayload{
		SessionID:    input.SessionID,
		PlanID:       PlanID,
		PublicIP:     ip,
		ObservedPort: local.ObservedPort,
		Pattern:      local.Pattern.String(),
		Delta:        local.Delta,
		SentAt:       s.cfg.now(),
	})
	if err != nil {
		return err
	}
	return sess.Send(ctx, NewMessage(MessageTypeEndpoint, payload, s.cfg.now()))
}

func (s *Strategy) sendStart(ctx context.Context, sess solver.SessionIO, input solver.SolveInput, startAt time.Time) error {
	payload, err := marshalStart(startPayload{
		SessionID:     input.SessionID,
		PlanID:        PlanID,
		StartAtUnixMs: startAt.UnixMilli(),
		SentAt:        s.cfg.now(),
	})
	if err != nil {
		return err
	}
	return sess.Send(ctx, NewMessage(MessageTypeStart, payload, s.cfg.now()))
}

func (s *Strategy) accept(sessionID, planID string) bool {
	s.mu.Lock()
	expected := s.input.SessionID
	s.mu.Unlock()
	if strings.TrimSpace(sessionID) != "" && strings.TrimSpace(expected) != "" && sessionID != expected {
		return false
	}
	return strings.TrimSpace(planID) == "" || planID == PlanID
}

func signalOnce(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// sessionKey derives the puncher session id from the solver session id so both
// peers compute the same 8-byte key without extra signaling.
func sessionKey(sessionID string) [8]byte {
	sum := sha256.Sum256([]byte(sessionID))
	var key [8]byte
	copy(key[:], sum[:8])
	return key
}
