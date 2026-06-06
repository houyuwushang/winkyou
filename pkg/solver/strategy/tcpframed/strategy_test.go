package tcpframed

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"winkyou/pkg/solver"
)

func TestPlanReturnsTCPFramedPlan(t *testing.T) {
	strategy := New(Config{})
	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %d, want 1", len(plans))
	}
	plan := plans[0]
	if plan.ID != PlanID || plan.Strategy != StrategyName {
		t.Fatalf("plan = %#v, want tcp_framed plan identity", plan)
	}
	if plan.Metadata["transport"] != StrategyName || plan.Metadata["mode"] != "direct_explicit" {
		t.Fatalf("metadata = %#v, want tcp_framed direct_explicit", plan.Metadata)
	}
}

func TestNewExecutorRejectsUnsupportedPlan(t *testing.T) {
	strategy := New(Config{})
	if _, err := strategy.NewExecutor(solver.Plan{ID: "tcpframed/other", Strategy: StrategyName}); err == nil {
		t.Fatal("NewExecutor() error = nil, want unsupported plan error")
	}
}

func TestResultForConnAnnotatesPathPolicyMetadata(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	exec := &executor{input: solver.SolveInput{SessionID: "session/node-a/node-b"}}
	result := exec.resultForConn(left, "dialer")
	summary := result.Summary

	if summary.Role != solver.PathRolePrimaryCandidate {
		t.Fatalf("role = %q, want %q", summary.Role, solver.PathRolePrimaryCandidate)
	}
	if len(summary.Dependencies) != 1 || summary.Dependencies[0].Kind != solver.PathDependencyUnknown {
		t.Fatalf("dependencies = %#v, want unknown dependency", summary.Dependencies)
	}
	if got := summary.Metrics["transport"]; got != StrategyName {
		t.Fatalf("transport metric = %q, want %q", got, StrategyName)
	}
	if !solver.IsDirectPath(summary) {
		t.Fatal("IsDirectPath(summary) = false, want true for tcp_framed direct-like result")
	}
}

func TestMessageCodecsRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	offer := offerPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    PlanID,
		Endpoint:  endpointPayload{Network: "tcp", Address: "127.0.0.1:12345"},
		SentAt:    now,
	}
	offerBytes, err := marshalOfferPayload(offer)
	if err != nil {
		t.Fatalf("marshalOfferPayload() error = %v", err)
	}
	decodedOffer, err := unmarshalOfferPayload(offerBytes)
	if err != nil {
		t.Fatalf("unmarshalOfferPayload() error = %v", err)
	}
	if decodedOffer.Endpoint.Address != offer.Endpoint.Address || decodedOffer.SessionID != offer.SessionID {
		t.Fatalf("decoded offer = %#v, want %#v", decodedOffer, offer)
	}

	answer := answerPayload{SessionID: offer.SessionID, PlanID: PlanID, Accepted: true, SentAt: now}
	answerBytes, err := marshalAnswerPayload(answer)
	if err != nil {
		t.Fatalf("marshalAnswerPayload() error = %v", err)
	}
	decodedAnswer, err := unmarshalAnswerPayload(answerBytes)
	if err != nil {
		t.Fatalf("unmarshalAnswerPayload() error = %v", err)
	}
	if !decodedAnswer.Accepted || decodedAnswer.SessionID != answer.SessionID {
		t.Fatalf("decoded answer = %#v, want accepted answer", decodedAnswer)
	}

	candidate := candidatePayload{SessionID: offer.SessionID, PlanID: PlanID, Endpoint: offer.Endpoint, SentAt: now}
	candidateBytes, err := marshalCandidatePayload(candidate)
	if err != nil {
		t.Fatalf("marshalCandidatePayload() error = %v", err)
	}
	decodedCandidate, err := unmarshalCandidatePayload(candidateBytes)
	if err != nil {
		t.Fatalf("unmarshalCandidatePayload() error = %v", err)
	}
	if decodedCandidate.Endpoint.Address != candidate.Endpoint.Address {
		t.Fatalf("decoded candidate = %#v, want endpoint %q", decodedCandidate, candidate.Endpoint.Address)
	}

	msg := NewMessage(MessageTypeOffer, offerBytes, now)
	if !IsMessage(msg) || msg.Namespace != Namespace || msg.Type != MessageTypeOffer {
		t.Fatalf("NewMessage() = %#v, want tcpframed offer message", msg)
	}
}

func TestForcedRolesConnectIndependentOfInitiator(t *testing.T) {
	plan := solver.Plan{ID: PlanID, Strategy: StrategyName}
	listener := newExecutor(Config{ListenAddr: "127.0.0.1:0", Role: RoleListen, DialTimeout: time.Second}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: false,
	}, plan)
	dialer := newExecutor(Config{Role: RoleDial, DialTimeout: time.Second}, solver.SolveInput{
		SessionID: "session/node-a/node-b",
		Initiator: true,
	}, plan)
	defer listener.Close()
	defer dialer.Close()

	listenerIO := &tcpFramedTestIO{target: dialer}
	dialerIO := &tcpFramedTestIO{target: listener}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	type executeResult struct {
		result solver.Result
		err    error
	}
	listenerCh := make(chan executeResult, 1)
	dialerCh := make(chan executeResult, 1)
	go func() {
		result, err := listener.Execute(ctx, listenerIO)
		listenerCh <- executeResult{result: result, err: err}
	}()
	go func() {
		result, err := dialer.Execute(ctx, dialerIO)
		dialerCh <- executeResult{result: result, err: err}
	}()

	listenerResult := <-listenerCh
	if listenerResult.err != nil {
		t.Fatalf("listener Execute() error = %v", listenerResult.err)
	}
	dialerResult := <-dialerCh
	if dialerResult.err != nil {
		t.Fatalf("dialer Execute() error = %v", dialerResult.err)
	}
	defer listenerResult.result.Transport.Close()
	defer dialerResult.result.Transport.Close()

	if got := listenerResult.result.Summary.Details["role"]; got != "listener" {
		t.Fatalf("listener role detail = %q, want listener", got)
	}
	if got := dialerResult.result.Summary.Details["role"]; got != "dialer" {
		t.Fatalf("dialer role detail = %q, want dialer", got)
	}

	packetCtx, packetCancel := context.WithTimeout(context.Background(), time.Second)
	defer packetCancel()
	payload := []byte("forced tcp role packet")
	writeCh := make(chan error, 1)
	go func() {
		writeCh <- listenerResult.result.Transport.WritePacket(packetCtx, payload)
	}()
	buf := make([]byte, 1024)
	n, _, err := dialerResult.result.Transport.ReadPacket(packetCtx, buf)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if got := string(buf[:n]); got != string(payload) {
		t.Fatalf("packet = %q, want %q", got, string(payload))
	}
	if err := <-writeCh; err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
}

func TestDialAddrSkipsOffer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	exec := newExecutor(Config{
		Role:        RoleDial,
		DialAddr:    ln.Addr().String(),
		DialTimeout: time.Second,
	}, solver.SolveInput{SessionID: "session/node-a/node-b"}, solver.Plan{ID: PlanID, Strategy: StrategyName})
	defer exec.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := exec.Execute(ctx, &tcpFramedTestIO{})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	defer result.Transport.Close()

	if got := result.Summary.Details["role"]; got != "dialer_static" {
		t.Fatalf("role detail = %q, want dialer_static", got)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-ctx.Done():
		t.Fatalf("listener did not accept static dial: %v", ctx.Err())
	}
}

func TestInvalidRoleFailsBeforeNetwork(t *testing.T) {
	exec := newExecutor(Config{Role: "sideways"}, solver.SolveInput{SessionID: "session/node-a/node-b"}, solver.Plan{ID: PlanID, Strategy: StrategyName})
	_, err := exec.Execute(context.Background(), &tcpFramedTestIO{})
	if err == nil {
		t.Fatal("Execute() error = nil, want invalid role")
	}
	if !strings.Contains(err.Error(), `invalid role "sideways"`) {
		t.Fatalf("Execute() error = %v, want invalid role", err)
	}
}

type tcpFramedTestIO struct {
	target solver.PlanExecutor
}

func (io *tcpFramedTestIO) Send(ctx context.Context, msg solver.Message) error {
	if io.target == nil {
		return nil
	}
	return io.target.HandleMessage(ctx, io, msg)
}

func (io *tcpFramedTestIO) ReportObservation(context.Context, solver.Observation) error {
	return nil
}
