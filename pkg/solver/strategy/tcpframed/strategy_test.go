package tcpframed

import (
	"context"
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
