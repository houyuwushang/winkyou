package session

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

// The standard-library bubble advances the real session's timers, not a copied
// state machine. No sleep, real I/O, production clock hook or longer limit.
func TestSelectionLateCapabilityNeverExecutesImplicitStrategy(t *testing.T) {
	for _, delay := range []time.Duration{4 * time.Second, 8 * time.Second, 16 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var sessions [2]*Session
				var legacy, relay [2]*fakeStrategy
				var failures [2]error
				for side := range sessions {
					legacy[side] = &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}
					relay[side] = &fakeStrategy{name: "relay_only", transport: &fakeTransport{}}
					r, err := NewFactoryPortfolioResolver([]StrategyFactoryEntry{
						{Name: "legacy_ice_udp", Build: func() solver.Strategy { return legacy[side] }},
						{Name: "relay_only", Build: func() solver.Strategy { return relay[side] }},
					}, PortfolioResolverPolicy{AllowImplicitLegacy: true, CompatibilityDefault: "legacy_ice_udp", PinnedFirstStrategy: "relay_only"}, nil)
					if err != nil {
						t.Fatal(err)
					}
					sessions[side], err = New(Config{
						SessionID: "selection/synthetic-pair", LocalNodeID: fmt.Sprintf("side-%d", side), PeerID: fmt.Sprintf("side-%d", 1-side),
						Initiator: side == 0, Resolver: r, Sender: &fakeSender{}, Binder: &fakeBinder{}, RunTimeout: 25 * time.Second,
						Hooks: Hooks{OnError: func(err error) { failures[side] = err }},
					})
					if err != nil {
						t.Fatal(err)
					}
					defer sessions[side].Close()
				}
				capability := rproto.Capability{Strategies: []string{"relay_only"}}
				sessions[0].setRemoteCapability(capability, time.Now())
				lateDone := make(chan struct{})
				go func() {
					<-time.After(delay)
					sessions[1].setRemoteCapability(capability, time.Now())
					close(lateDone)
				}()
				for _, s := range sessions {
					if err := s.Start(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				<-time.After(2 * time.Second)
				synctest.Wait()
				if _, executed := legacy[1].Counts(); executed != 0 {
					t.Errorf("missing capability executed implicit strategy %d times", executed)
				}
				if sessions[1].State() != StateFailed || !errors.Is(failures[1], context.DeadlineExceeded) {
					t.Errorf("missing capability terminal = %s/%v, want failed/deadline", sessions[1].State(), failures[1])
				}
				<-lateDone
				synctest.Wait()
				if plan, executed := legacy[1].Counts(); plan != 0 || executed != 0 {
					t.Errorf("late capability revived implicit plan/execute = %d/%d", plan, executed)
				}
				if sessions[1].State() != StateFailed {
					t.Errorf("late capability changed terminal = %s", sessions[1].State())
				}
				_, peerExecuted := relay[0].Counts()
				if peerExecuted != 1 {
					t.Errorf("control side relay execution = %d, want 1", peerExecuted)
				}
				t.Logf("delay=%s missing_side_state=%s implicit_executions=0_required", delay, sessions[1].State())
			})
		})
	}
}
