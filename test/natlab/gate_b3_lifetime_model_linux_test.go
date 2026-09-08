//go:build linux && natlab

package natlab

import (
	"testing"
	"time"
)

// Pure monotonic-duration model. The OS socket used by the emulator is a
// carrier, not evidence that either NAT state is alive. Mapping and filter
// have separate deadlines; only an outbound packet opens/refreshes state.
// An outbound packet after expiry creates a NEW generation, never revives
// the evicted generation. Keeping the same port is not keeping its old state.
type gateB3LifetimeState struct {
	generation   uint64
	mappingUntil time.Duration
	filterUntil  time.Duration
	lastOutbound time.Duration
	outbounds    uint64
	evicted      bool
}

func (state gateB3LifetimeState) permits(now time.Duration) bool {
	return state.generation != 0 && !state.evicted && now < state.mappingUntil && now < state.filterUntil
}

func (state gateB3LifetimeState) outbound(now, mappingIdle, filterIdle time.Duration) gateB3LifetimeState {
	outbounds := state.outbounds + 1
	if state.generation == 0 || state.evicted || now >= state.mappingUntil {
		state = gateB3LifetimeState{generation: state.generation + 1}
	}
	state.mappingUntil, state.filterUntil = now+mappingIdle, now+filterIdle
	state.lastOutbound = now
	state.outbounds = outbounds
	return state
}

func TestGateB3LifetimePureModel(t *testing.T) {
	const ttl = 30 * time.Second
	initial := (gateB3LifetimeState{}).outbound(0, ttl, ttl)
	for _, test := range []struct {
		now  time.Duration
		want bool
	}{{ttl - 1, true}, {ttl, false}, {ttl + 1, false}} {
		if initial.permits(test.now) != test.want {
			t.Fatal("mapping/filter exact boundary changed")
		}
	}
	filterFirst := (gateB3LifetimeState{}).outbound(0, 60*time.Second, ttl)
	mappingFirst := (gateB3LifetimeState{}).outbound(0, ttl, 60*time.Second)
	if filterFirst.permits(ttl) || mappingFirst.permits(ttl) {
		t.Fatal("independent expiry was ignored")
	}
	// Merely observing inbound data cannot mutate or extend either clock.
	for now := time.Duration(0); now <= ttl; now += time.Second {
		_ = initial.permits(now)
	}
	if initial.mappingUntil != ttl || initial.filterUntil != ttl {
		t.Fatal("inbound observation implicitly refreshed NAT state")
	}
	refreshed := initial.outbound(10*time.Second, ttl, ttl)
	if refreshed.generation != initial.generation || !refreshed.permits(39*time.Second) || refreshed.permits(40*time.Second) {
		t.Fatal("outbound refresh did not preserve the live generation")
	}
	for _, stale := range []gateB3LifetimeState{initial, {generation: 1, mappingUntil: time.Minute, filterUntil: time.Minute, evicted: true}} {
		next := stale.outbound(ttl, ttl, ttl)
		if next.generation != 2 || !next.permits(ttl) || stale.permits(ttl) {
			t.Fatal("expired or evicted generation was reused")
		}
	}
}
