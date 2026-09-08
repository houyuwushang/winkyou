package gatecorchestrator

import (
	"errors"
	"testing"
	"time"
)

// Permanent counterexamples from the accepted clock revision A. No host clock
// changes or networking: each time source is an explicitly injected local value.
func TestLivenessClockRevisionProofCannotOutliveEitherSendClock(t *testing.T) {
	for _, rounds := range []int{2, 3} {
		for _, convergence := range []string{"rollback", "gradual", "source-switch", "repeated"} {
			t.Run(time.Duration(rounds).String()+"/"+convergence, func(t *testing.T) {
				m, clock := testLivenessModel(t, rounds)
				clock.shift(20*time.Second, 22*time.Second)
				issueLivenessPing(t, m)
				if _, err := m.receive(replyLiveness(t, m)); err != nil {
					t.Fatal(err)
				}
				switch convergence {
				case "rollback":
					clock.shift(0, -2*time.Second)
				case "gradual":
					for range 4 {
						clock.shift(time.Second, 500*time.Millisecond)
						if err := m.permit(); err != nil {
							t.Fatal(err)
						}
					}
				case "source-switch":
					clock.shift(0, -4*time.Second) // UTC-led +2s becomes mono-led -2s.
				case "repeated":
					for range 4 {
						clock.shift(0, -500*time.Millisecond)
						if err := m.permit(); err != nil {
							t.Fatal(err)
						}
					}
				}
				age := clock.Mono() - 20*time.Second
				clock.advance(m.budget.lease - age - time.Nanosecond)
				if err := m.permit(); err != nil {
					t.Fatalf("before send-age boundary: %v", err)
				}
				clock.advance(time.Nanosecond)
				if err := m.permit(); !errors.Is(err, errLivenessTimeout) {
					t.Fatalf("send age=%s still writable: %v", m.budget.lease, err)
				}
				clock.shift(0, -time.Nanosecond)
				if !errors.Is(m.permit(), errLivenessTimeout) {
					t.Fatal("expired proof resurrected")
				}
			})
		}
	}
}

func TestLivenessClockRevisionResponseWindowAndIntentExpireAtEquality(t *testing.T) {
	for _, window := range []time.Duration{livenessWriteWindow, livenessResponseWindow} {
		for _, age := range []time.Duration{window, window + time.Second} {
			t.Run(window.String()+"/"+age.String(), func(t *testing.T) {
				m, clock := testLivenessModel(t, 3)
				clock.shift(20*time.Second, 22*time.Second)
				seq, err := m.preparePing()
				if err != nil {
					t.Fatal(err)
				}
				e, err := m.ping(seq, [16]byte{1})
				if err != nil || e == nil {
					t.Fatal("no admitted intent")
				}
				pong := replyLiveness(t, m)
				clock.shift(0, -2*time.Second)
				clock.advance(age)
				if window == livenessWriteWindow {
					if allowed, err := m.beginWrite(e); allowed || err != nil || m.snapshot().OutboundExpired != 1 {
						t.Fatalf("expired one-second intent accepted=%t err=%v", allowed, err)
					}
				} else {
					if _, err := m.receive(pong); err != nil {
						t.Fatal(err)
					}
					w := m.snapshot()
					if w.PongValidated != 0 || w.PendingExpired != 1 || w.PongDropped != 1 {
						t.Fatal("late PONG renewed from an elongated response window")
					}
				}
			})
		}
	}
}

func TestLivenessClockRevisionAccountingClockDoesNotFollowRTC(t *testing.T) {
	m, clock := testLivenessModel(t, 3)
	clock.shift(20*time.Second, 22*time.Second)
	if err := m.permit(); err != nil {
		t.Fatal(err)
	}
	if got := m.currentElapsed(); got != 20*time.Second {
		t.Fatalf("WG accounting source=%s, want monotonic 20s", got)
	}
	clock.shift(0, -2*time.Second)
	if err := m.permit(); err != nil {
		t.Fatal(err)
	}
	if got := m.currentElapsed(); got != 20*time.Second || m.snapshot().UTCRollbacks != 1 {
		t.Fatal("legal RTC rollback changed WG accounting or lost its witness")
	}
}

func TestLivenessClockRevisionRTCForwardDoesNotRefillRollingAdmission(t *testing.T) {
	m, clock := testLivenessModel(t, 3)
	for seq := uint64(1); seq <= 4; seq++ {
		packet, _ := buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: seq})
		e, err := m.receive(packet)
		if err != nil || e == nil {
			t.Fatal("initial four admissions failed")
		}
		m.discard(e)
	}
	clock.shift(19*time.Second, 21*time.Second)
	packet, _ := buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: 5})
	if e, err := m.receive(packet); err != nil || e != nil || m.snapshot().PongAdmissionRejected != 1 {
		t.Fatal("UTC forward shift refreshed the monotonic rolling 20s budget")
	}
	clock.shift(time.Second, -time.Second)
	packet, _ = buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: 6})
	e, err := m.receive(packet)
	if err != nil || e == nil || m.snapshot().PongAdmitted != 5 || m.snapshot().UTCRollbacks != 1 {
		t.Fatal("exact monotonic rolling boundary failed after legal rollback")
	}
	m.discard(e)
}
