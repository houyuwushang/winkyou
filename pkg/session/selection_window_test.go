package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

// A bounded in-memory delivery queue, not a production clock hook. Each side
// sends capability once, then proposal/confirm once each. Real timers represent
// explicitly delayed delivery; cleanup cancels and joins every queue worker.
type selectionWindowLink struct {
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	closed    bool
	workers   int
	queued    int
	events    []selectionWindowEvent
	capDone   [2]chan struct{}
	executing [2]bool
	execUntil [2]time.Time
	pair      *agreementPair
}

type selectionWindowEvent struct {
	side int
	kind string
	at   time.Time
}

func newSelectionWindowPair(t *testing.T, capabilityDelay, controlDelay time.Duration, dropConfirm bool) (*agreementPair, *selectionWindowLink) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	link := &selectionWindowLink{ctx: ctx, cancel: cancel}
	for side := range link.capDone {
		link.capDone[side] = make(chan struct{})
	}
	p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, func(side int, msg solver.Message) []solver.Message {
		delay := controlDelay
		switch msg.Type {
		case rproto.MsgTypeCapability:
			delay = capabilityDelay
		case selectionProposalType, selectionConfirmType:
			if dropConfirm && msg.Type == selectionConfirmType {
				return nil
			}
		default:
			return []solver.Message{msg}
		}
		link.mu.Lock()
		if link.closed {
			link.mu.Unlock()
			return nil
		}
		link.queued++
		link.workers++
		link.wg.Add(1)
		link.mu.Unlock()
		go func() {
			defer link.wg.Done()
			defer func() { link.mu.Lock(); link.workers--; link.mu.Unlock() }()
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-link.ctx.Done():
				return
			case <-timer.C:
			}
			// Sender timestamps are not arrival times. The receiving session must
			// use its own local receipt for protocol deadlines, not this envelope.
			msg.ReceivedAt = time.Time{}
			link.mu.Lock()
			link.events = append(link.events, selectionWindowEvent{side: 1 - side, kind: msg.Type, at: time.Now()})
			link.mu.Unlock()
			nodes := [2]string{"side-a", "side-b"}
			_ = link.pair.sessions[1-side].HandleMessageFrom(link.ctx, nodes[side], msg)
			if msg.Type == rproto.MsgTypeCapability {
				close(link.capDone[1-side])
			}
		}()
		return nil
	})
	link.pair = p
	for side := range p.sessions {
		p.strategies[side]["relay_only"].onExecute = func(ctx context.Context) error {
			deadline, _ := ctx.Deadline()
			link.mu.Lock()
			link.executing[side] = p.sessions[side].State() == StateExecuting
			link.execUntil[side] = deadline
			link.mu.Unlock()
			return nil
		}
	}
	t.Cleanup(func() {
		p.close()
		for _, s := range p.sessions {
			s.executeMu.Lock()
			s.executeMu.Unlock()
		}
		link.mu.Lock()
		link.closed = true
		link.cancel()
		link.mu.Unlock()
		link.wg.Wait()
		link.mu.Lock()
		defer link.mu.Unlock()
		t.Logf("SELECTION_WINDOW_DRAIN workers=%d queued=%d", link.workers, link.queued)
		if link.workers != 0 || link.queued > 6 {
			t.Error("in-memory selection delivery leaked or retransmitted")
		}
	})
	return p, link
}

func (link *selectionWindowLink) witness(t *testing.T) {
	t.Helper()
	link.mu.Lock()
	events := append([]selectionWindowEvent(nil), link.events...)
	link.mu.Unlock()
	for _, event := range events {
		s := link.pair.sessions[event.side]
		s.agreement.mu.Lock()
		start := s.agreement.passStart
		s.agreement.mu.Unlock()
		t.Logf("SELECTION_WINDOW side=%d kind=%s received_ns=%d", event.side, event.kind, event.at.Sub(start).Nanoseconds())
	}
	for side, s := range link.pair.sessions {
		class := "none"
		var selectionErr *selectionError
		if errors.As(s.selectionTerminalError(), &selectionErr) {
			class = selectionErr.class
		}
		t.Logf("SELECTION_WINDOW_TERMINAL side=%d state=%s class=%s executions=%d", side, s.State(), class, link.pair.count(side, "relay_only"))
	}
}

func TestSelectionConfirmWindowStartsAtCapabilityReceipt(t *testing.T) {
	p, link := newSelectionWindowPair(t, 1900*time.Millisecond, 300*time.Millisecond, false)
	p.start(t)
	p.wait(t)
	link.witness(t) // Preserve both sides before any assertion fails.
	for side, s := range p.sessions {
		if s.State() != StateBound || p.count(side, "relay_only") != 1 {
			t.Fatalf("side=%d state=%s terminal=%v: 1.9s capability plus 0.6s confirmation must execute", side, s.State(), s.selectionTerminalError())
		}
		link.mu.Lock()
		executing, executionDeadline := link.executing[side], link.execUntil[side]
		link.mu.Unlock()
		s.agreement.mu.Lock()
		start := s.agreement.passStart
		s.agreement.mu.Unlock()
		if !executing || !executionDeadline.Equal(start.Add(25*time.Second)) {
			t.Fatal("first execution did not consume the selection time from its original 25s")
		}
		if p.countMessages(side, selectionProposalType) != 1 || p.countMessages(side, selectionConfirmType) != 1 {
			t.Fatal("first round retransmitted or omitted a control message")
		}
	}
	a, b := p.sessions[0].Snapshot(), p.sessions[1].Snapshot()
	if a.SelectionDigest == "" || a.SelectionDigest != b.SelectionDigest || a.SelectionOrdinal != 0 || b.SelectionOrdinal != 0 {
		t.Fatal("first-round commitments differ")
	}
}

func TestSelectionCapabilityAfterOriginalWindowFails(t *testing.T) {
	p, link := newSelectionWindowPair(t, 2100*time.Millisecond, 0, false)
	p.start(t)
	p.wait(t)
	// Deliver the late capabilities too: the existing terminal must not revive.
	for _, done := range link.capDone {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("late capability delivery did not terminate")
		}
	}
	link.witness(t)
	for side, s := range p.sessions {
		err := s.selectionTerminalError()
		if s.State() != StateFailed || p.count(side, "relay_only") != 0 || err == nil || err.Error() != "session: capability_missing" || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("side=%d late capability escaped: state=%s terminal=%v", side, s.State(), err)
		}
	}
}

func TestSelectionMissingConfirmFailsWithinOwnWindow(t *testing.T) {
	p, link := newSelectionWindowPair(t, 1900*time.Millisecond, 300*time.Millisecond, true)
	p.start(t)
	p.wait(t)
	link.witness(t)
	for side, s := range p.sessions {
		err := s.selectionTerminalError()
		if s.State() != StateFailed || p.count(side, "relay_only") != 0 || err == nil || err.Error() != "session: selection_timeout" || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("side=%d missing confirm escaped: state=%s terminal=%v", side, s.State(), err)
		}
	}
}
