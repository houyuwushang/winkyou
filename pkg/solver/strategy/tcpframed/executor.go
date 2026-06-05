package tcpframed

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/solver"
	"winkyou/pkg/transport/framedstream"
)

type executor struct {
	cfg   Config
	input solver.SolveInput
	plan  solver.Plan

	offerCh  chan offerPayload
	answerCh chan answerPayload

	mu       sync.Mutex
	listener net.Listener
	conn     net.Conn
}

func newExecutor(cfg Config, input solver.SolveInput, plan solver.Plan) *executor {
	return &executor{
		cfg:      cfg.withDefaults(),
		input:    input,
		plan:     plan,
		offerCh:  make(chan offerPayload, 1),
		answerCh: make(chan answerPayload, 1),
	}
}

func (e *executor) Execute(ctx context.Context, sess solver.SessionIO) (solver.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.input.Initiator {
		return e.executeListen(ctx, sess)
	}
	return e.executeDial(ctx, sess)
}

func (e *executor) HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error {
	_ = ctx
	_ = sess
	if !IsMessage(msg) {
		return nil
	}
	switch msg.Type {
	case MessageTypeOffer:
		payload, err := unmarshalOfferPayload(msg.Payload)
		if err != nil {
			return err
		}
		if !e.acceptMessage(payload.SessionID, payload.PlanID) {
			return nil
		}
		sendLatest(e.offerCh, payload)
	case MessageTypeCandidate:
		payload, err := unmarshalCandidatePayload(msg.Payload)
		if err != nil {
			return err
		}
		if !e.acceptMessage(payload.SessionID, payload.PlanID) {
			return nil
		}
		sendLatest(e.offerCh, offerPayload{
			SessionID: payload.SessionID,
			PlanID:    payload.PlanID,
			Endpoint:  payload.Endpoint,
			SentAt:    payload.SentAt,
		})
	case MessageTypeAnswer:
		payload, err := unmarshalAnswerPayload(msg.Payload)
		if err != nil {
			return err
		}
		if !e.acceptMessage(payload.SessionID, payload.PlanID) {
			return nil
		}
		sendLatest(e.answerCh, payload)
	default:
		return fmt.Errorf("tcpframed: unsupported message type %q", msg.Type)
	}
	return nil
}

func (e *executor) Close() error {
	e.mu.Lock()
	listener := e.listener
	conn := e.conn
	e.listener = nil
	e.conn = nil
	e.mu.Unlock()

	var err error
	if listener != nil {
		err = listener.Close()
	}
	if conn != nil {
		if closeErr := conn.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

func (e *executor) executeListen(ctx context.Context, sess solver.SessionIO) (solver.Result, error) {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", e.cfg.ListenAddr)
	if err != nil {
		return solver.Result{}, err
	}
	e.setListener(listener)

	endpoint, err := e.advertiseEndpoint(listener.Addr())
	if err != nil {
		_ = listener.Close()
		return solver.Result{}, err
	}
	if err := e.sendOffer(ctx, sess, endpoint); err != nil {
		_ = listener.Close()
		return solver.Result{}, err
	}

	conn, err := acceptWithContext(ctx, listener)
	if err != nil {
		_ = listener.Close()
		return solver.Result{}, err
	}
	_ = listener.Close()
	e.setListener(nil)
	e.setConn(conn)
	return e.resultForConn(e.releaseConn(conn), "listener"), nil
}

func (e *executor) executeDial(ctx context.Context, sess solver.SessionIO) (solver.Result, error) {
	offer, err := e.waitOffer(ctx)
	if err != nil {
		return solver.Result{}, err
	}
	if strings.TrimSpace(offer.Endpoint.Address) == "" {
		return solver.Result{}, fmt.Errorf("tcpframed: offer missing endpoint address")
	}
	network := strings.TrimSpace(offer.Endpoint.Network)
	if network == "" {
		network = "tcp"
	}

	dialCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok && e.cfg.DialTimeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, e.cfg.DialTimeout)
	}
	defer cancel()

	var dialer net.Dialer
	if e.cfg.DialTimeout > 0 {
		dialer.Timeout = e.cfg.DialTimeout
	}
	conn, err := dialer.DialContext(dialCtx, network, offer.Endpoint.Address)
	if err != nil {
		_ = e.sendAnswer(ctx, sess, false, err.Error())
		return solver.Result{}, err
	}
	e.setConn(conn)
	if err := e.sendAnswer(ctx, sess, true, ""); err != nil {
		_ = conn.Close()
		return solver.Result{}, err
	}
	return e.resultForConn(e.releaseConn(conn), "dialer"), nil
}

func (e *executor) sendOffer(ctx context.Context, sess solver.SessionIO, endpoint string) error {
	payload, err := marshalOfferPayload(offerPayload{
		SessionID: e.input.SessionID,
		PlanID:    e.plan.ID,
		Endpoint: endpointPayload{
			Network: "tcp",
			Address: endpoint,
		},
		SentAt: time.Now(),
	})
	if err != nil {
		return err
	}
	return sess.Send(ctx, NewMessage(MessageTypeOffer, payload, time.Now()))
}

func (e *executor) sendAnswer(ctx context.Context, sess solver.SessionIO, accepted bool, message string) error {
	payload, err := marshalAnswerPayload(answerPayload{
		SessionID: e.input.SessionID,
		PlanID:    e.plan.ID,
		Accepted:  accepted,
		Error:     message,
		SentAt:    time.Now(),
	})
	if err != nil {
		return err
	}
	return sess.Send(ctx, NewMessage(MessageTypeAnswer, payload, time.Now()))
}

func (e *executor) waitOffer(ctx context.Context) (offerPayload, error) {
	select {
	case offer := <-e.offerCh:
		return offer, nil
	case <-ctx.Done():
		return offerPayload{}, ctx.Err()
	}
}

func (e *executor) acceptMessage(sessionID, planID string) bool {
	if sessionID != "" && sessionID != e.input.SessionID {
		return false
	}
	return planID == "" || planID == e.plan.ID
}

func (e *executor) advertiseEndpoint(addr net.Addr) (string, error) {
	if strings.TrimSpace(e.cfg.AdvertiseAddr) != "" {
		return e.cfg.AdvertiseAddr, nil
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return addr.String(), nil
	}
	if tcpAddr.IP == nil || tcpAddr.IP.IsUnspecified() {
		return "", fmt.Errorf("tcpframed: advertise_addr is required when listen_addr resolves to %s", tcpAddr.IP.String())
	}
	return net.JoinHostPort(tcpAddr.IP.String(), fmt.Sprintf("%d", tcpAddr.Port)), nil
}

func (e *executor) resultForConn(conn net.Conn, role string) solver.Result {
	pathID := "tcpframed:direct:" + e.input.SessionID
	return solver.Result{
		Transport: framedstream.New(conn, pathID),
		Summary: solver.PathSummary{
			PathID:         pathID,
			ConnectionType: "direct",
			RemoteAddr:     conn.RemoteAddr(),
			Role:           solver.PathRolePrimaryCandidate,
			Dependencies: []solver.PathDependency{{
				Kind:   solver.PathDependencyUnknown,
				Reason: "explicit_tcp_address",
			}},
			Metrics: map[string]string{
				"transport": StrategyName,
			},
			Details: map[string]string{
				"transport": StrategyName,
				"role":      role,
			},
		},
	}
}

func (e *executor) setListener(listener net.Listener) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.listener = listener
}

func (e *executor) setConn(conn net.Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn = conn
}

func (e *executor) releaseConn(conn net.Conn) net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == conn {
		e.conn = nil
	}
	return conn
}

func acceptWithContext(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		resultCh <- acceptResult{conn: conn, err: err}
	}()
	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		_ = listener.Close()
		return nil, ctx.Err()
	}
}

func sendLatest[T any](ch chan T, value T) {
	select {
	case ch <- value:
	default:
		select {
		case <-ch:
		default:
		}
		ch <- value
	}
}
