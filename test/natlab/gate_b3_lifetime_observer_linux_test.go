//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type gateB3LifetimeTuple [2]netip.AddrPort // local public, peer public; never logged

type gateB3LifetimeFlow struct {
	presentAt time.Time
	goneAt    time.Time
	sampledAt time.Time
	present   bool
	samples   int
}

type gateB3NATLifetime struct {
	started  time.Time
	idle     time.Duration
	peerNS   string
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	flows    map[gateB3LifetimeTuple]gateB3LifetimeFlow
	failure  error
	winner   gateB3LifetimeFlow
	age      time.Duration
	refresh  uint64
	sentAt   time.Time
	peer     *gateB3NATLifetime
	point    string
	blocked  atomic.Bool
	injected atomic.Uint64
}

func newGateB3NATLifetime(peerNS string, seconds int) *gateB3NATLifetime {
	ctx, cancel := context.WithCancel(context.Background())
	model := &gateB3NATLifetime{started: time.Now(), idle: time.Duration(seconds) * time.Second,
		peerNS: peerNS, ctx: ctx, cancel: cancel, done: make(chan struct{}), flows: make(map[gateB3LifetimeTuple]gateB3LifetimeFlow)}
	go model.observe()
	return model
}

func (model *gateB3NATLifetime) track(local, peer netip.AddrPort) {
	model.mu.Lock()
	defer model.mu.Unlock()
	key := gateB3LifetimeTuple{local, peer}
	if _, exists := model.flows[key]; !exists {
		if len(model.flows) >= 16384 {
			model.failure = errors.New("mapping lifetime observation key limit")
			return
		}
		model.flows[key] = gateB3LifetimeFlow{}
	}
}

// Only immutable cached evidence is read on the forwarder path. No subprocess,
// kernel query or waiting is permitted here. A missing pre-send sample FAILS
// the fixture; an after-send observation cannot fill in that evidence later.
func (model *gateB3NATLifetime) beforeWinner(local, peer netip.AddrPort, age time.Duration, refresh uint64) {
	model.inject("before_winner")
	model.mu.Lock()
	defer model.mu.Unlock()
	model.winner = model.flows[gateB3LifetimeTuple{local, peer}]
	model.age, model.refresh = age, refresh
	model.sentAt = time.Now()
}

// Test-only one-sided filter policy change. Unlike expiry, the kernel flow
// remains live. No endpoint, tuple, syscall order, packet or protocol is
// substituted; every later inbound datagram on that side is denied until
// the disposable model is destroyed. There is no recovery or unblocking.
func (model *gateB3NATLifetime) inject(point string) {
	if model.point == point && model.peer != nil && model.injected.CompareAndSwap(0, 1) {
		model.peer.blocked.Store(true)
	}
}

func (model *gateB3NATLifetime) observe() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	model.observeTicks(ticker.C, readGateB3LifetimeFlow)
}

// The injectable runner/ticks are test-only seams: the real observer keeps
// its existing 250ms cadence and one-second query deadline.
func (model *gateB3NATLifetime) observeTicks(ticks <-chan time.Time, read func(context.Context, string, gateB3LifetimeTuple) (bool, error)) {
	defer close(model.done)
	for {
		select {
		case <-model.ctx.Done():
			return
		case <-ticks:
		}
		model.mu.Lock()
		keys := make([]gateB3LifetimeTuple, 0, len(model.flows))
		for key := range model.flows {
			keys = append(keys, key)
		}
		model.mu.Unlock()
		for _, key := range keys {
			ctx, cancel := context.WithTimeout(model.ctx, time.Second)
			present, err := read(ctx, model.peerNS, key)
			cancel()
			if model.ctx.Err() != nil {
				return
			}
			model.mu.Lock()
			if err != nil {
				model.failure = err
				model.mu.Unlock()
				return
			}
			flow := model.flows[key]
			flow.present, flow.sampledAt, flow.samples = present, time.Now(), flow.samples+1
			if present && flow.presentAt.IsZero() {
				flow.presentAt = flow.sampledAt
			}
			if !present && !flow.presentAt.IsZero() && flow.goneAt.IsZero() {
				flow.goneAt = flow.sampledAt
			}
			model.flows[key] = flow
			model.mu.Unlock()
		}
	}
}

func readGateB3LifetimeFlow(ctx context.Context, namespace string, tuple gateB3LifetimeTuple) (bool, error) {
	return readGateB3LifetimeFlowWithRunner(ctx, namespace, tuple, (*exec.Cmd).CombinedOutput)
}

func readGateB3LifetimeFlowWithRunner(ctx context.Context, namespace string, tuple gateB3LifetimeTuple, run func(*exec.Cmd) ([]byte, error)) (bool, error) {
	// Exact-key GET does not dump/walk the changing 32K table. A failed or
	// interrupted query is never an absence witness; only the CLI's explicit
	// conntrack ENOENT diagnostic is accepted as a completed negative lookup.
	command := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "conntrack", "-G", "-p", "udp",
		"--orig-src", tuple[1].Addr().String(), "--orig-dst", tuple[0].Addr().String(),
		"--sport", strconv.Itoa(int(tuple[1].Port())), "--dport", strconv.Itoa(int(tuple[0].Port())))
	command.WaitDelay = 100 * time.Millisecond
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := run(command)
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			message := strings.ToLower(strings.TrimSpace(string(output)))
			if exitError.ExitCode() == 1 && strings.HasPrefix(message, "conntrack v") &&
				strings.Contains(message, "such conntrack doesn't exist") &&
				!strings.Contains(message, "\nudp ") {
				return false, nil
			}
			return false, fmt.Errorf("mapping lifetime reverse-flow read failed: exit=%d deadline=%t", exitError.ExitCode(), errors.Is(ctx.Err(), context.DeadlineExceeded))
		}
		return false, errors.New("mapping lifetime reverse-flow command unavailable")
	}
	flows := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "udp ") {
			flows++
		}
	}
	if flows != 1 {
		return false, errors.New("mapping lifetime tuple was not unique")
	}
	return flows == 1, nil
}

func validGateB3StableObservation(flow gateB3LifetimeFlow, age, idle time.Duration, refresh uint64, sentAt time.Time) bool {
	return flow.present && !flow.presentAt.IsZero() && flow.goneAt.IsZero() &&
		refresh == 1 && age < idle && sentAt.Sub(flow.sampledAt) <= 1500*time.Millisecond
}

// This is only the observation part of M-E's existing causal conjunction.
// Packet/frame/age/refresh/injection conditions remain at the netns call site.
func validGateB3ExpiryObservation(flow gateB3LifetimeFlow, sentAt time.Time) bool {
	return !flow.presentAt.IsZero() && !flow.goneAt.IsZero() && flow.presentAt.Before(flow.goneAt) &&
		flow.goneAt.Before(sentAt) && !flow.present && sentAt.Sub(flow.sampledAt) <= 1500*time.Millisecond
}

func (model *gateB3NATLifetime) close() error {
	model.cancel()
	select {
	case <-model.done:
	case <-time.After(2 * time.Second):
		return errors.New("mapping lifetime observer did not drain")
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	return model.failure
}
