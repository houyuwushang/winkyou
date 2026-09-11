package session

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"winkyou/pkg/solver"
)

func TestSelectionFirstConfirmDeadlineBounds(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name                          string
		received, window, budget, end time.Duration
	}{
		{"immediate", 0, 2 * time.Second, 25 * time.Second, 2 * time.Second},
		{"late_valid", 1900 * time.Millisecond, 2 * time.Second, 25 * time.Second, 3900 * time.Millisecond},
		{"smaller_test_window", 20 * time.Millisecond, 50 * time.Millisecond, 25 * time.Second, 70 * time.Millisecond},
		{"hard_two_second_cap", 1900 * time.Millisecond, 10 * time.Second, 25 * time.Second, 3900 * time.Millisecond},
		{"remaining_budget", 1900 * time.Millisecond, 2 * time.Second, 2100 * time.Millisecond, 2100 * time.Millisecond},
		{"exhausted", 1900 * time.Millisecond, 2 * time.Second, 1900 * time.Millisecond, 1900 * time.Millisecond},
		{"already_expired", 1900 * time.Millisecond, 2 * time.Second, time.Second, time.Second},
		{"received_before_start", -100 * time.Millisecond, 2 * time.Second, 25 * time.Second, 1900 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			received := start.Add(tc.received)
			got := firstSelectionConfirmDeadline(start, received, tc.window, tc.budget)
			if !got.Equal(start.Add(tc.end)) || got.After(start.Add(tc.budget)) || got.After(received.Add(2*time.Second)) {
				t.Fatal("confirmation window extended the local subwindow or original budget")
			}
		})
	}
}

func TestSelectionFirstReceiptUsesLocalClockAndCannotRenew(t *testing.T) {
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	defer p.close()
	s := p.sessions[0]
	if err := s.beginSelectionPass(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(p.sessions[1].agreement.local)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	if err := s.receiveSelectionCapability(encoded, before.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	first := s.agreement.capabilityReceivedAt
	deadline := s.agreement.confirmDeadline
	if first.Before(before) || first.After(after) || !deadline.Equal(first.Add(2*time.Second)) {
		t.Fatal("reported timestamp became the local confirmation deadline")
	}
	if err := s.receiveSelectionCapability(encoded, after.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !s.agreement.capabilityReceivedAt.Equal(first) || !s.agreement.confirmDeadline.Equal(deadline) {
		t.Fatal("duplicate capability renewed the first subwindow")
	}
}

func TestSelectionLateReceiptCannotBackdateReportedTimestamp(t *testing.T) {
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	defer p.close()
	s := p.sessions[0]
	s.agreement.passStart = time.Now().Add(-3 * time.Second)
	s.agreement.capabilityDeadline = s.agreement.passStart.Add(2 * time.Second)
	encoded, err := json.Marshal(p.sessions[1].agreement.local)
	if err != nil {
		t.Fatal(err)
	}
	err = s.receiveSelectionCapability(encoded, s.agreement.passStart.Add(time.Second))
	if err == nil || err.Error() != "session: capability_missing" || !errors.Is(err, context.DeadlineExceeded) || s.agreement.remote != nil || !s.agreement.confirmDeadline.IsZero() {
		t.Fatal("late local capability was accepted by backdating a diagnostic timestamp")
	}
}

func TestSelectionTimelyReceiptSurvivesDelayedWaiter(t *testing.T) {
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
	defer p.close()
	s := p.sessions[0]
	// Reconstruct an already accepted receipt, without a production clock seam:
	// the waiter resumes at t=3s, after capability expiry but before confirm expiry.
	a := s.agreement
	a.passStart = time.Now().Add(-3 * time.Second)
	a.capabilityDeadline = a.passStart.Add(2 * time.Second)
	a.capabilityReceivedAt = a.passStart.Add(1900 * time.Millisecond)
	a.confirmDeadline = firstSelectionConfirmDeadline(a.passStart, a.capabilityReceivedAt, 2*time.Second, 25*time.Second)
	remote := p.sessions[1].agreement.local
	a.remote = &remote
	deadline := a.confirmDeadline
	capability, err := s.waitForSelectionCapability(context.Background())
	if err != nil || len(capability.Strategies) != 1 || capability.Strategies[0] != "relay_only" || !a.confirmDeadline.Equal(deadline) {
		t.Fatal("timely receipt was lost or renewed when the waiter resumed late")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.waitForSelectionCapability(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal("timely receipt bypassed parent cancellation")
	}
}

func TestSelectionFirstPlanAndGroupConsumeBothSubwindows(t *testing.T) {
	for _, timeout := range []time.Duration{25 * time.Second, 50 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
			defer p.close()
			s := p.sessions[0]
			start := time.Now().Add(-2500 * time.Millisecond)
			s.agreement.current = &selectionRound{ordinal: 0, budgetStart: start}
			execution, cancel := s.selectionExecutionContext(context.Background(), timeout)
			defer cancel()
			deadline, ok := execution.Deadline()
			if !ok || !deadline.Equal(start.Add(timeout)) {
				t.Fatal("first plan/group reset its existing execution allowance after selection")
			}
			before := time.Now()
			remaining := s.subtractSelectionTime(solver.ExecutionBudget{TimeBudget: timeout}).TimeBudget
			after := time.Now()
			if remaining > timeout-before.Sub(start) || remaining < timeout-after.Sub(start) {
				t.Fatal("candidate-loop TimeBudget did not deduct the same actual selection interval")
			}
		})
	}
}

func TestSelectionLaterOrdinalRetainsOriginalWindow(t *testing.T) {
	for _, allowance := range []time.Duration{25 * time.Second, time.Second} {
		t.Run(allowance.String(), func(t *testing.T) {
			p := newAgreementPair(t, [2][]string{{"legacy_ice_udp", "relay_only"}, {"legacy_ice_udp", "relay_only"}}, nil)
			defer p.close()
			for side, s := range p.sessions {
				s.cfg.RunTimeout = allowance
				p.strategies[side]["legacy_ice_udp"].onExecute = func(context.Context) error {
					return errors.New("synthetic_first_candidate_failed")
				}
				p.strategies[side]["relay_only"].onExecute = func(ctx context.Context) error {
					a := s.agreement
					a.mu.Lock()
					defer a.mu.Unlock()
					deadline, ok := ctx.Deadline()
					if a.current.ordinal != 1 || !a.current.deadline.Equal(a.current.budgetStart.Add(min(2*time.Second, allowance))) || !ok || !deadline.Equal(a.current.budgetStart.Add(allowance)) {
						return errors.New("synthetic_later_ordinal_window_changed")
					}
					return nil
				}
			}
			p.start(t)
			p.wait(t)
			for side, s := range p.sessions {
				if s.State() != StateBound || p.count(side, "legacy_ice_udp") != 1 || p.count(side, "relay_only") != 1 {
					t.Fatalf("side=%d later ordinal no longer has its original confirmation/execution budget", side)
				}
			}
		})
	}
}
