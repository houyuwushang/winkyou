package gatecorchestrator

import (
	"math"
	"time"
)

const (
	livenessInterval       = 20 * time.Second
	livenessResponseWindow = 5 * time.Second
	livenessWriteWindow    = time.Second
	livenessClockTolerance = 2 * time.Second
)

// LivenessClock is injectable only through internal/test composition. Remote
// timestamps and policy never enter this interface.
type LivenessClock interface {
	Mono() time.Duration
	UTC() time.Time
}
type systemLivenessClock struct{ origin time.Time }

func (c systemLivenessClock) Mono() time.Duration { return time.Since(c.origin) }
func (c systemLivenessClock) UTC() time.Time      { return time.Now().UTC() }

type livenessClockGuard struct {
	clock           LivenessClock
	mono0, lastMono time.Duration
	utc0, lastUTC   time.Time
	rollbacks       uint64
}

func newLivenessClock(clock LivenessClock) (livenessClockGuard, error) {
	if clock == nil {
		return livenessClockGuard{}, errLivenessUnavailable
	}
	m, u := clock.Mono(), clock.UTC()
	if m < 0 || u.IsZero() {
		return livenessClockGuard{}, errLivenessClock
	}
	return livenessClockGuard{clock: clock, mono0: m, lastMono: m, utc0: u, lastUTC: u}, nil
}

func (c *livenessClockGuard) read() (time.Duration, error) {
	m, u := c.clock.Mono(), c.clock.UTC()
	if m < c.lastMono || m < c.mono0 || u.IsZero() {
		return 0, errLivenessClock
	}
	mono := m - c.mono0
	utc := u.Sub(c.utc0)
	if mono < 0 || !c.utc0.Add(utc).Equal(u) || mono > time.Duration(math.MaxInt64)-livenessClockTolerance ||
		utc < mono-livenessClockTolerance || utc > mono+livenessClockTolerance {
		return 0, errLivenessClock
	}
	if u.Before(c.lastUTC) {
		c.rollbacks++
	}
	c.lastMono, c.lastUTC = m, u
	if utc > mono {
		return utc, nil
	}
	return mono, nil
}

type livenessBudget struct {
	ceiling, lease      time.Duration
	pings, pongs, total uint64
}

func freezeLivenessBudget(ceiling time.Duration, rounds int) (livenessBudget, error) {
	if ceiling < 5*time.Second || ceiling > 24*time.Hour || (rounds != 2 && rounds != 3) {
		return livenessBudget{}, errLivenessUnavailable
	}
	n := uint64(ceiling / livenessInterval)
	if ceiling%livenessInterval != 0 {
		n++
	}
	return livenessBudget{ceiling: ceiling, lease: time.Duration(rounds)*livenessInterval + livenessResponseWindow, pings: n, pongs: n + 1, total: 2*n + 1}, nil
}
