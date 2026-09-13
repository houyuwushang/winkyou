package gatecorchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/probeio"
)

type closeTestInterface struct {
	*sessionTestInterface
	entered chan struct{}
	err     error
	short   bool
	stall   bool
}

func (f *closeTestInterface) InjectPacket(packet []byte) (int, error) {
	close(f.entered)
	if f.stall {
		<-f.closed
		return 0, io.ErrClosedPipe
	}
	if f.err != nil {
		return 0, f.err
	}
	if f.short {
		return len(packet) - 1, nil
	}
	return len(packet), nil // deliberately NO WireGuard or outer transmission
}

func TestLivenessCloseInnerReceiptIsNotOuterSend(t *testing.T) {
	for _, mode := range []string{"injected", "writer-error", "short-write", "writer-stall"} {
		t.Run(mode, func(t *testing.T) {
			m, clock := testLivenessModel(t, 3)
			ni := &closeTestInterface{sessionTestInterface: newSessionTestInterface(), entered: make(chan struct{}), short: mode == "short-write", stall: mode == "writer-stall"}
			if mode == "writer-error" {
				ni.err = io.ErrClosedPipe
			}
			var reports atomic.Int64
			var reportOnce sync.Once // mirrors the durable owner's idempotent trip
			c := &livenessController{model: m, ni: ni, gate: &probeio.WireGuardSessionGate{},
				random: bytes.NewReader(make([]byte, 8)), ownerAvailable: func() error { return nil },
				reportViolation: func(v probeio.SessionViolation) error {
					if v != probeio.SessionWriterFailure {
						t.Errorf("unexpected violation: %v", v)
					}
					reportOnce.Do(func() { reports.Add(1) })
					return nil
				},
				stop: make(chan struct{}), writerDone: make(chan struct{}), watchdogDone: make(chan struct{}),
				inbound: make(chan livenessControlEvent, 2), outbound: make(chan *livenessEmission, 2)}
			go c.writer()
			go c.watchdog()
			t.Cleanup(func() {
				if err := c.drain(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			type outcome struct {
				end string
				err error
			}
			done := make(chan outcome, 1)
			go func() { end, err := c.run(ctx, context.Background()); done <- outcome{end, err} }()
			select {
			case <-ni.entered:
			case <-time.After(time.Second):
				t.Fatal("CLOSE writer did not enter")
			}
			if mode == "injected" {
				// Let the writer finish its one inner injection. Fake time advances
				// from the original admission, never from injection completion.
				deadline := time.Now().Add(time.Second)
				for {
					m.mu.Lock()
					writing := m.writing
					m.mu.Unlock()
					if !writing {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("inner writer did not finish")
					}
					time.Sleep(time.Millisecond)
				}
				select {
				case got := <-done:
					t.Fatalf("inner admission prematurely terminated WG opportunity: %+v", got)
				default:
				}
				clock.advance(time.Second)
			}
			if mode == "writer-stall" {
				clock.advance(time.Second)
			}
			var got outcome
			select {
			case got = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("CLOSE did not terminate in original window")
			}
			if err := c.drain(); err != nil {
				t.Fatal(err)
			}
			if c.closeWrites != 0 || got.end == "authenticated_close_sent" {
				t.Fatal("inner queue acceptance fabricated an outer completion")
			}
			if mode == "injected" {
				if got.err != nil || got.end != "canceled" || reports.Load() != 0 {
					t.Fatalf("clean cancel: %+v", got)
				}
			} else if !errors.Is(got.err, ErrSessionDrain) || reports.Load() != 1 {
				t.Errorf("cancel masked writer fault: end=%s err=%v reports=%d", got.end, got.err, reports.Load())
			}
			// Decode the public receipt so this regression also compiles and
			// fails on the old implementation (which has no honest receipt).
			encoded, err := json.Marshal(m.snapshot())
			if err != nil {
				t.Fatal(err)
			}
			var receipt struct {
				Admitted uint64 `json:"close_admitted"`
				Injected uint64 `json:"close_inner_injected"`
			}
			if err := json.Unmarshal(encoded, &receipt); err != nil {
				t.Fatal(err)
			}
			want := uint64(0)
			if mode == "injected" {
				want = 1
			}
			if receipt.Admitted != 1 || receipt.Injected != want || m.snapshot().InnerInjected != 0 || !m.snapshot().Drained {
				t.Errorf("CLOSE receipt or separate liveness accounting: %+v witness=%+v", receipt, m.snapshot())
			}
		})
	}
}

func TestLivenessCloseExpiredPermitNeverAdmits(t *testing.T) {
	for _, elapsed := range []time.Duration{65 * time.Second, 10 * time.Minute} {
		t.Run(elapsed.String(), func(t *testing.T) {
			m, clock := testLivenessModel(t, 3)
			clock.advance(elapsed)
			c := &livenessController{model: m, random: bytes.NewReader(make([]byte, 8)), ownerAvailable: func() error { return nil }}
			// No gate, writer or interface exists. Accessing any I/O panics;
			// an expired permit must return before constructing the intent.
			c.bestEffortClose(nil)
			if m.snapshot().CloseAdmitted != 0 || m.snapshot().CloseInnerInjected != 0 || c.closeWrites != 0 {
				t.Fatal("expired CLOSE acquired an emission receipt")
			}
		})
	}
}
