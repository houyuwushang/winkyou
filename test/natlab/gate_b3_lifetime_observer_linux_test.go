//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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
	started time.Time
	idle    time.Duration
	peerNS  string
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	flows   map[gateB3LifetimeTuple]gateB3LifetimeFlow
	failure error
	winner  gateB3LifetimeFlow
	age     time.Duration
	refresh uint64
	sentAt  time.Time
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
	model.mu.Lock()
	defer model.mu.Unlock()
	model.winner = model.flows[gateB3LifetimeTuple{local, peer}]
	model.age, model.refresh = age, refresh
	model.sentAt = time.Now()
}

func (model *gateB3NATLifetime) observe() {
	defer close(model.done)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-model.ctx.Done():
			return
		case <-ticker.C:
		}
		model.mu.Lock()
		keys := make([]gateB3LifetimeTuple, 0, len(model.flows))
		for key := range model.flows {
			keys = append(keys, key)
		}
		model.mu.Unlock()
		for _, key := range keys {
			ctx, cancel := context.WithTimeout(model.ctx, time.Second)
			present, err := readGateB3LifetimeFlow(ctx, model.peerNS, key)
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
	command := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, "conntrack", "-L", "-p", "udp",
		"--orig-src", tuple[1].Addr().String(), "--orig-dst", tuple[0].Addr().String(),
		"--sport", strconv.Itoa(int(tuple[1].Port())), "--dport", strconv.Itoa(int(tuple[0].Port())))
	command.WaitDelay = 100 * time.Millisecond
	output, err := command.CombinedOutput()
	if err != nil {
		return false, errors.New("mapping lifetime reverse-flow read failed")
	}
	flows := 0
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "udp ") {
			flows++
		}
	}
	if flows > 1 {
		return false, errors.New("mapping lifetime tuple was not unique")
	}
	return flows == 1, nil
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
