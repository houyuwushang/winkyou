package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type agreementSender func(context.Context, string, solver.Message) error

func (send agreementSender) Send(ctx context.Context, peer string, msg solver.Message) error {
	return send(ctx, peer, msg)
}

type agreementStrategy struct {
	*fakeStrategy
	onExecute func(context.Context) error
	onClose   func() error
}

func (s *agreementStrategy) Execute(ctx context.Context, io solver.SessionIO, plan solver.Plan) (solver.Result, error) {
	if s.onExecute != nil {
		if err := s.onExecute(ctx); err != nil {
			s.mu.Lock()
			s.execCalls++
			s.mu.Unlock()
			return solver.Result{}, err
		}
	}
	return s.fakeStrategy.Execute(ctx, io, plan)
}
func (s *agreementStrategy) Close() error {
	if s.onClose != nil {
		return s.onClose()
	}
	return nil
}

type agreementPair struct {
	done       [2]chan struct{}
	doneOnce   [2]sync.Once
	sessions   [2]*Session
	strategies [2]map[string]*agreementStrategy
	mu         sync.Mutex
	messages   [2][]solver.Message
	failures   [2][]error
	filter     func(int, solver.Message) []solver.Message
}

func newAgreementPair(t *testing.T, orders [2][]string, filter func(int, solver.Message) []solver.Message) *agreementPair {
	t.Helper()
	p := &agreementPair{filter: filter}
	for side := range p.sessions {
		p.done[side] = make(chan struct{})
		p.strategies[side] = make(map[string]*agreementStrategy)
		var entries []StrategyFactoryEntry
		for _, name := range orders[side] {
			strategy := &agreementStrategy{fakeStrategy: &fakeStrategy{name: name, transport: &fakeTransport{}}}
			p.strategies[side][name] = strategy
			entries = append(entries, StrategyFactoryEntry{Name: name, Build: func() solver.Strategy { return strategy }})
		}
		resolver, err := NewFactoryPortfolioResolver(entries, PortfolioResolverPolicy{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		nodes := [2]string{"side-a", "side-b"}
		p.sessions[side], err = NewConverging(Config{
			SessionID: "selection/synthetic-pair", LocalNodeID: nodes[side], PeerID: nodes[1-side], Initiator: side == 0,
			Resolver: resolver, Binder: &fakeBinder{}, RunTimeout: 25 * time.Second,
			Sender: agreementSender(func(ctx context.Context, _ string, msg solver.Message) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				p.mu.Lock()
				p.messages[side] = append(p.messages[side], msg)
				p.mu.Unlock()
				messages := []solver.Message{msg}
				if p.filter != nil {
					messages = p.filter(side, msg)
				}
				for _, delivery := range messages {
					if err := p.sessions[1-side].HandleMessageFrom(ctx, nodes[side], delivery); err != nil {
						// A transport send is not an application-level remote acceptance ACK.
						p.mu.Lock()
						p.failures[1-side] = append(p.failures[1-side], err)
						p.mu.Unlock()
					}
				}
				return nil
			}),
			Hooks: Hooks{
				OnStateChange: func(state State) {
					if state == StateBound || state == StateFailed || state == StateClosed {
						p.doneOnce[side].Do(func() { close(p.done[side]) })
					}
				},
				OnError: func(err error) { p.mu.Lock(); p.failures[side] = append(p.failures[side], err); p.mu.Unlock() },
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// Explicit protocol terminal witnesses work on the Go 1.23.1 minimum without
// scheduler sleeps or testing/synctest.
func runSelectionCase(t *testing.T, run func(*testing.T)) { t.Helper(); run(t) }
func (p *agreementPair) wait(t *testing.T) {
	t.Helper()
	for _, done := range p.done {
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Fatal("selection did not reach a bounded terminal")
		}
	}
	for _, s := range p.sessions {
		s.executeMu.Lock()
		s.executeMu.Unlock()
	}
}
func (p *agreementPair) start(t *testing.T) {
	t.Helper()
	for _, s := range p.sessions {
		if err := s.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}
func (p *agreementPair) close() {
	for _, s := range p.sessions {
		_ = s.Close()
	}
}
func (p *agreementPair) count(side int, name string) int {
	_, count := p.strategies[side][name].Counts()
	return count
}
func (p *agreementPair) countMessages(side int, kind string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, msg := range p.messages[side] {
		if msg.Type == kind {
			count++
		}
	}
	return count
}
func agreementPayload(msg solver.Message, mutate func(map[string]any)) solver.Message {
	envelope, _ := rproto.UnmarshalEnvelope(msg.Payload)
	var payload map[string]any
	_ = json.Unmarshal(envelope.Payload, &payload)
	mutate(payload)
	envelope.Payload, _ = json.Marshal(payload)
	msg.Payload, _ = rproto.MarshalEnvelope(envelope)
	return msg
}

func TestSelectionBilateralOrdersAndPathCommitLoss(t *testing.T) {
	for _, dropCommit := range []bool{false, true} {
		t.Run(fmt.Sprint(dropCommit), func(t *testing.T) {
			runSelectionCase(t, func(t *testing.T) {
				p := newAgreementPair(t, [2][]string{{"relay_only", "legacy_ice_udp"}, {"legacy_ice_udp", "relay_only"}}, func(_ int, msg solver.Message) []solver.Message {
					if dropCommit && msg.Type == rproto.MsgTypePathCommit {
						return nil
					}
					return []solver.Message{msg}
				})
				defer p.close()
				p.start(t)
				p.wait(t)
				for side, s := range p.sessions {
					if s.State() != StateBound || p.count(side, "relay_only") != 1 || p.count(side, "legacy_ice_udp") != 0 {
						t.Fatalf("side=%d state=%s wrong execution", side, s.State())
					}
					if p.countMessages(side, selectionProposalType) != 1 || p.countMessages(side, selectionConfirmType) != 1 {
						t.Fatal("exchange retransmitted or omitted")
					}
				}
				a, b := p.sessions[0].Snapshot(), p.sessions[1].Snapshot()
				if a.SelectionDigest == "" || a.SelectionDigest != b.SelectionDigest || a.SelectionOrdinal != 0 || b.SelectionOrdinal != 0 {
					t.Fatal("bilateral joint commitment differs")
				}
			})
		})
	}
}

func TestSelectionBilateralCapabilityDelayFailsWithoutExecution(t *testing.T) {
	for _, delay := range []time.Duration{4 * time.Second, 8 * time.Second, 16 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			t.Parallel()
			runSelectionCase(t, func(t *testing.T) {
				var p *agreementPair
				delivered := make(chan struct{})
				p = newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, func(side int, msg solver.Message) []solver.Message {
					if side == 0 && msg.Type == rproto.MsgTypeCapability {
						time.AfterFunc(delay, func() { _ = p.sessions[1].HandleMessageFrom(context.Background(), "side-a", msg); close(delivered) })
						return nil
					}
					return []solver.Message{msg}
				})
				defer p.close()
				p.start(t)
				p.wait(t)
				for side, s := range p.sessions {
					if s.State() != StateFailed || p.count(side, "relay_only") != 0 {
						t.Fatalf("side=%d failed/execution=%s/%d", side, s.State(), p.count(side, "relay_only"))
					}
				}
				<-delivered
				p.wait(t)
				for side, s := range p.sessions {
					if s.State() != StateFailed || p.count(side, "relay_only") != 0 {
						t.Fatal("late capability revived terminal")
					}
				}
			})
		})
	}
}

func TestSelectionNegativeControlMatrix(t *testing.T) {
	cases := []struct {
		name, kind string
		change     func(solver.Message) []solver.Message
	}{
		{"missing_capability", rproto.MsgTypeCapability, func(solver.Message) []solver.Message { return nil }},
		{"old_peer", rproto.MsgTypeCapability, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { delete(p, "selection_version"); delete(p, "selection_epoch") })}
		}},
		{"empty_capability", rproto.MsgTypeCapability, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["strategies"] = []string{} })}
		}},
		{"wrong_role", selectionProposalType, func(m solver.Message) []solver.Message {
			e, _ := rproto.UnmarshalEnvelope(m.Payload)
			e.FromNode = "side-b"
			m.Payload, _ = rproto.MarshalEnvelope(e)
			return []solver.Message{m}
		}},
		{"wrong_epoch", selectionProposalType, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["to_epoch"] = strings.Repeat("ab", 16) })}
		}},
		{"future_ordinal", selectionProposalType, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["ordinal"] = "2"; p["previous"] = strings.Repeat("ab", 32) })}
		}},
		{"noncanonical_ordinal", selectionProposalType, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["ordinal"] = "00" })}
		}},
		{"open_previous", selectionProposalType, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["previous_closed"] = false })}
		}},
		{"unknown_field", selectionProposalType, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["fallback"] = true })}
		}},
		{"unlicensed_offer", selectionProposalType, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["strategies"] = []string{"not_supported"} })}
		}},
		{"oversize", selectionProposalType, func(m solver.Message) []solver.Message {
			m.Payload = []byte(strings.Repeat("x", selectionEnvelopeLimit+1))
			return []solver.Message{m}
		}},
		{"duplicate_flood", selectionProposalType, func(m solver.Message) []solver.Message {
			out := make([]solver.Message, selectionReceiveLimit+1)
			for i := range out {
				out[i] = m
			}
			return out
		}},
		{"conflicting_duplicate", selectionProposalType, func(m solver.Message) []solver.Message {
			return []solver.Message{m, agreementPayload(m, func(p map[string]any) { p["strategies"] = []string{"not_supported"} })}
		}},
		{"wrong_confirmation", selectionConfirmType, func(m solver.Message) []solver.Message {
			return []solver.Message{agreementPayload(m, func(p map[string]any) { p["digest"] = strings.Repeat("ab", 32) })}
		}},
		{"last_confirm_lost", selectionConfirmType, func(solver.Message) []solver.Message { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runSelectionCase(t, func(t *testing.T) {
				p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, func(side int, m solver.Message) []solver.Message {
					if side == 0 && m.Type == tc.kind {
						return tc.change(m)
					}
					return []solver.Message{m}
				})
				defer p.close()
				for _, s := range p.sessions {
					s.cfg.CapabilityWaitTimeout = 50 * time.Millisecond
				}
				for side, s := range p.sessions {
					err := s.Start(context.Background())
					if err != nil && !(side == 1 && (tc.name == "old_peer" || tc.name == "empty_capability") && IsSelectionError(err)) {
						t.Fatal(err)
					}
				}
				p.wait(t)
				if p.sessions[1].State() != StateFailed || p.count(1, "relay_only") != 0 {
					t.Fatalf("rejecting receiver state=%s executions=%d", p.sessions[1].State(), p.count(1, "relay_only"))
				}
				// A lost/corrupted final confirmation cannot prove atomic simultaneous start.
				if p.count(0, "relay_only") > 1 {
					t.Fatal("sender retried within ordinal")
				}
				if p.count(0, "relay_only") != 0 {
					if tc.kind != selectionConfirmType && tc.name != "conflicting_duplicate" && tc.name != "duplicate_flood" {
						t.Fatal("execution without a complete capability/proposal exchange")
					}
					// The valid prefix may already have elicited the peer's confirm
					// before a later conflicting copy arrives. Any local execution must
					// still match that exact sent commitment; no atomic-start claim.
					matched := false
					p.mu.Lock()
					for _, message := range p.messages[1] {
						if message.Type == selectionConfirmType {
							envelope, _ := rproto.UnmarshalEnvelope(message.Payload)
							var confirmation selectionConfirmation
							_ = json.Unmarshal(envelope.Payload, &confirmation)
							matched = confirmation.Digest == p.sessions[0].Snapshot().SelectionDigest && confirmation.Strategy == "relay_only"
						}
					}
					p.mu.Unlock()
					if !matched {
						t.Fatal("execution conflicts with peer's valid prefix commitment")
					}
				}
				for _, s := range p.sessions {
					a := s.agreement
					a.mu.Lock()
					if a.err != nil && (a.future.proposal != nil || a.future.confirm != nil) {
						t.Error("terminal queue not cleared")
					}
					a.mu.Unlock()
				}
			})
		})
	}
}

func TestSelectionDuplicateAndNextStrategyAgreement(t *testing.T) {
	runSelectionCase(t, func(t *testing.T) {
		p := newAgreementPair(t, [2][]string{{"legacy_ice_udp", "relay_only"}, {"relay_only", "legacy_ice_udp"}}, func(_ int, m solver.Message) []solver.Message {
			if m.Type == selectionProposalType {
				return []solver.Message{m, m}
			}
			return []solver.Message{m}
		})
		defer p.close()
		for side := range p.sessions {
			p.strategies[side]["legacy_ice_udp"].onExecute = func(context.Context) error { return errors.New("synthetic_candidate_failed") }
		}
		p.start(t)
		p.wait(t)
		for side, s := range p.sessions {
			if s.State() != StateBound || s.Snapshot().SelectionOrdinal != 1 || p.count(side, "legacy_ice_udp") != 1 || p.count(side, "relay_only") != 1 {
				t.Fatalf("side=%d state=%s ordinal=%d", side, s.State(), s.Snapshot().SelectionOrdinal)
			}
			if p.countMessages(side, selectionProposalType) != 2 || p.countMessages(side, selectionConfirmType) != 2 {
				t.Fatal("next strategy missing bounded confirmation")
			}
		}
		if p.sessions[0].Snapshot().SelectionDigest != p.sessions[1].Snapshot().SelectionDigest {
			t.Fatal("next strategy digest differs")
		}
	})
}

func TestSelectionPreviousCloseTimeoutForbidsNextExecutor(t *testing.T) {
	t.Parallel()
	runSelectionCase(t, func(t *testing.T) {
		p := newAgreementPair(t, [2][]string{{"legacy_ice_udp", "relay_only"}, {"legacy_ice_udp", "relay_only"}}, nil)
		defer p.close()
		release := make(chan struct{})
		for side := range p.sessions {
			p.strategies[side]["legacy_ice_udp"].onExecute = func(context.Context) error { return errors.New("synthetic_candidate_failed") }
		}
		p.strategies[0]["legacy_ice_udp"].onClose = func() error { <-release; return nil }
		p.start(t)
		p.wait(t)
		close(release)
		p.wait(t)
		for side, s := range p.sessions {
			if p.count(side, "relay_only") != 0 || s.State() != StateFailed {
				t.Fatalf("side=%d next executor without previous drain", side)
			}
		}
	})
}

func TestSelectionMissingFinalConfirmPreservesBoundPath(t *testing.T) {
	runSelectionCase(t, func(t *testing.T) {
		p := newAgreementPair(t, [2][]string{{"relay_only"}, {"relay_only"}}, nil)
		defer p.close()
		p.start(t)
		p.wait(t)
		for _, s := range p.sessions {
			if s.State() != StateBound {
				t.Fatal("precondition not bound")
			}
		}
		// Subsequent stale control is rejected, but selection failure alone neither
		// unbinds nor closes the transport. Product dispatch uses the bound-safe hook.
		p.mu.Lock()
		messages := slices.Clone(p.messages[0])
		p.mu.Unlock()
		for _, m := range messages {
			if m.Type == selectionProposalType {
				m = agreementPayload(m, func(v map[string]any) { v["to_epoch"] = strings.Repeat("ff", 16) })
				if err := p.sessions[1].HandleMessageFrom(context.Background(), "side-a", m); !IsSelectionError(err) {
					t.Fatal("stale control not rejected")
				}
				break
			}
		}
		if p.sessions[1].State() != StateBound || p.strategies[1]["relay_only"].transport.(*fakeTransport).closed {
			t.Fatal("control failure tore down healthy binding")
		}
	})
}
