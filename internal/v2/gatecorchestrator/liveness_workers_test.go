package gatecorchestrator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/probeio"
)

type livenessFaultInterface struct {
	*sessionTestInterface
	started chan struct{}
	stall   bool
	once    sync.Once
}

func (f *livenessFaultInterface) InjectPacket([]byte) (int, error) {
	f.once.Do(func() { close(f.started) })
	if f.stall {
		<-f.closed
	}
	return 0, errors.New("synthetic inner writer failure")
}

func TestLivenessWorkersFailClosedAndJoinWithoutForegroundProgress(t *testing.T) {
	for _, fault := range []string{"writer-error", "writer-stall", "writer-stall-rollback", "foreground-stall", "ingress-flood"} {
		t.Run(fault, func(t *testing.T) {
			m, clock := testLivenessModel(t, 3)
			stall := fault == "writer-stall" || fault == "writer-stall-rollback"
			ni := &livenessFaultInterface{sessionTestInterface: newSessionTestInterface(), started: make(chan struct{}), stall: stall}
			var reports atomic.Int64
			c := &livenessController{model: m, ni: ni, gate: &probeio.WireGuardSessionGate{},
				stop: make(chan struct{}), writerDone: make(chan struct{}), watchdogDone: make(chan struct{}),
				inbound: make(chan livenessControlEvent, 2), outbound: make(chan *livenessEmission, 2),
				ownerAvailable: func() error { return nil }, reportViolation: func(probeio.SessionViolation) error { reports.Add(1); return nil }}
			go c.writer()
			go c.watchdog()
			t.Cleanup(func() {
				if err := c.drain(); err != nil {
					t.Error(err)
				}
			})
			if fault == "writer-error" || stall {
				clock.advance(20 * time.Second)
				if fault == "writer-stall-rollback" {
					clock.shift(0, 2*time.Second)
				}
				seq, err := m.preparePing()
				if err != nil {
					t.Fatal(err)
				}
				e, err := m.ping(seq, [16]byte{1})
				if err != nil || e == nil {
					t.Fatal("missing admitted test intent")
				}
				c.enqueue(e)
				select {
				case <-ni.started:
				case <-time.After(time.Second):
					t.Fatal("writer not started")
				}
				if fault == "writer-stall-rollback" {
					clock.shift(0, -2*time.Second)
				}
				if stall {
					clock.advance(1100 * time.Millisecond)
				}
			} else {
				if fault == "ingress-flood" {
					for range 10000 {
						c.Deliver(make([]byte, 92))
					}
				}
				// No foreground run(), no events, no writes: watchdog alone closes.
				clock.advance(65 * time.Second)
			}
			select {
			case <-c.stop:
			case <-time.After(time.Second):
				t.Fatal("watchdog did not revoke")
			}
			if err := c.drain(); err != nil {
				t.Fatal(err)
			}
			wantReports := int64(0)
			if fault == "writer-error" || stall {
				wantReports = 1
			}
			if reports.Load() != wantReports || !c.gate.Witness().Closed || !m.snapshot().Drained || len(c.inbound) != 0 || len(c.outbound) != 0 {
				t.Fatal("fault disposition or drain wrong")
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.pending.valid || m.writing {
				t.Fatal("pending worker state survived drain")
			}
			for _, e := range m.intents {
				if e != nil {
					t.Fatal("emission intent survived")
				}
			}
		})
	}
}

func TestLivenessConcurrentRevokeAndTapHaveNoQueuedResidue(t *testing.T) {
	m, clock := testLivenessModel(t, 3)
	c := &livenessController{model: m, ni: newSessionTestInterface(), gate: &probeio.WireGuardSessionGate{},
		stop: make(chan struct{}), writerDone: make(chan struct{}), watchdogDone: make(chan struct{}),
		inbound: make(chan livenessControlEvent, 2), outbound: make(chan *livenessEmission, 2),
		ownerAvailable: func() error { return nil }, reportViolation: func(probeio.SessionViolation) error { t.Error("clean cancel tripped"); return nil }}
	close(c.writerDone)
	close(c.watchdogDone)
	clock.advance(20 * time.Second)
	issueLivenessPing(t, m)
	pong := replyLiveness(t, m)
	clock.advance(45 * time.Second) // equality expires BEFORE dispatching the late PONG
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				c.Deliver(pong)
			}
		}()
	}
	c.end(context.Canceled)
	if err := c.drain(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if c.Deliver(pong) || len(c.inbound) != 0 || m.snapshot().PongValidated != 0 {
		t.Fatal("late callback queued or resurrected permit")
	}
}
