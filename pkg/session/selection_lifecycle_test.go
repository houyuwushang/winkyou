package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/pkg/solver"
)

func TestSelectionExecutionGateRejectsMissingExpiredOrReusedCommit(t *testing.T) {
	for _, name := range []string{"missing", "unconfirmed", "expired", "reused", "wrong_strategy", "terminal"} {
		t.Run(name, func(t *testing.T) {
			p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
			defer p.close()
			s := p.sessions[0]
			a := s.agreement
			a.current = &selectionRound{confirmed: true, strategy: "relay_only", deadline: time.Now().Add(time.Second)}
			switch name {
			case "missing":
				a.current = nil
			case "unconfirmed":
				a.current.confirmed = false
			case "expired":
				a.current.deadline = time.Now().Add(-time.Second)
			case "reused":
				a.current.entered = true
			case "wrong_strategy":
				a.current.strategy = "different"
			case "terminal":
				s.stopSelection(selectionFailure("selection_closed"))
			}
			if _, err := s.executeStrategyOutcomes(context.Background(), p.strategies[0]["relay_only"]); err == nil || !IsSelectionError(err) {
				t.Fatal("execution gate accepted invalid commitment")
			}
			if plan, executed := p.strategies[0]["relay_only"].Counts(); plan != 0 || executed != 0 {
				t.Fatal("invalid commitment reached Plan/Execute")
			}
		})
	}
}

func TestSelectionConfirmationConsumesExistingFirstPlanBudget(t *testing.T) {
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	defer p.close()
	s := p.sessions[0]
	start := time.Now().Add(-10 * time.Second)
	s.agreement.current = &selectionRound{budgetStart: start}
	ctx, cancel := s.selectionExecutionContext(context.Background(), 25*time.Second)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(start.Add(25*time.Second)) {
		t.Fatal("confirmation allocated a fresh 25s window")
	}
	budget := s.subtractSelectionTime(solver.ExecutionBudget{TimeBudget: 50 * time.Second})
	if budget.TimeBudget > 40*time.Second || budget.TimeBudget <= 0 {
		t.Fatal("candidate loop did not deduct confirmation time")
	}
	secondAt := time.Now()
	second, cancelSecond := s.selectionExecutionContext(context.Background(), 25*time.Second)
	defer cancelSecond()
	secondDeadline, _ := second.Deadline()
	if secondDeadline.Before(secondAt.Add(25*time.Second)) || secondDeadline.After(time.Now().Add(25*time.Second)) {
		t.Fatal("subsequent plan budget changed")
	}
	parent, cancelParent := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancelParent()
	limited, cancelLimited := s.selectionExecutionContext(parent, 25*time.Second)
	defer cancelLimited()
	parentDeadline, _ := parent.Deadline()
	limitedDeadline, _ := limited.Deadline()
	if !limitedDeadline.Equal(parentDeadline) {
		t.Fatal("parent deadline enlarged")
	}
}

func TestSelectionClearedExecutorPointerIsNotCloseWitness(t *testing.T) {
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	defer p.close()
	s := p.sessions[0]
	executor := &recordingPlanExecutor{}
	s.openSelectionExecutor(executor)
	s.setActiveExecutor("synthetic-plan", executor)
	s.clearActiveExecutor(executor)
	if err := s.requirePreviousSelectionClosed(); !IsSelectionError(err) {
		t.Fatal("pointer clearing passed for actual executor close")
	}
	if err := s.closeSelectionExecutor(executor); err != nil {
		t.Fatal(err)
	}
	if err := s.requirePreviousSelectionClosed(); err != nil {
		t.Fatal("completed close did not release witness")
	}
}

func TestSelectionCapabilitySendSharesDeadlineAndCancellationClass(t *testing.T) {
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	defer p.close()
	s := p.sessions[0]
	if err := s.beginSelectionPass(); err != nil {
		t.Fatal(err)
	}
	deadline := s.agreement.passDeadline
	ctx, cancel := s.selectionCapabilityContext(context.Background())
	defer cancel()
	got, _ := ctx.Deadline()
	if !got.Equal(deadline) || got.Sub(s.agreement.passStart) != 2*time.Second {
		t.Fatal("send and capability wait do not share original 2s")
	}
	err := s.stopSelection(context.Canceled)
	if !errors.Is(err, context.Canceled) || !IsSelectionError(err) {
		t.Fatal("cancellation class lost")
	}
	if err.Error() != "session: selection_closed" {
		t.Fatal("unstable selection cancellation class")
	}
}

func TestSelectionOldEpochCannotReviveFreshRunner(t *testing.T) {
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	p.start(t)
	p.wait(t)
	p.mu.Lock()
	messages := append([]solver.Message(nil), p.messages[0]...)
	p.mu.Unlock()
	p.close()
	fresh := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	defer fresh.close()
	for _, message := range messages {
		if message.Type == selectionProposalType {
			if err := fresh.sessions[1].HandleMessageFrom(context.Background(), "side-a", message); !IsSelectionError(err) {
				t.Fatal("old epoch accepted by fresh runner")
			}
			if _, err := fresh.sessions[1].executeStrategyOutcomes(context.Background(), fresh.strategies[1]["relay_only"]); !IsSelectionError(err) {
				t.Fatal("old epoch authorized executor")
			}
			if plan, executed := fresh.strategies[1]["relay_only"].Counts(); plan != 0 || executed != 0 {
				t.Fatal("replay produced work")
			}
			return
		}
	}
	t.Fatal("missing recorded proposal fixture")
}
