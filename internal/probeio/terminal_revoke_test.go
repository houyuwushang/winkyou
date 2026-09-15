package probeio

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestTerminalRevokeClosesEveryHandleButRetainsAttempt(t *testing.T) {
	h := newHarness(t, normalResources())
	pairing, err := h.lease.RegisterDrain("pairing-owned")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pairing.Complete() })
	request := h.lease.Request()
	var sockets []*ProbeSocket
	for i := 0; i < 2; i++ {
		socket, _ := openSocket(t, h)
		if err := socket.RegisterTarget(targetA); err != nil {
			t.Fatal(err)
		}
		if err := socket.SendProbe(context.Background(), targetA, []byte("synthetic")); err != nil {
			t.Fatal(err)
		}
		sockets = append(sockets, socket)
	}
	if err := h.controller.RevokeForTerminal(); err != nil {
		t.Fatal(err)
	}
	for i, socket := range sockets {
		if !h.factory.at(i).isClosed() || h.factory.at(i).writeCount() != 1 {
			t.Fatal("terminal revoke must close every datagram without another write")
		}
		if err := socket.SendProbe(context.Background(), targetA, []byte("late")); !errors.Is(err, ErrLeaseClosed) {
			t.Fatalf("revoked write: %v", err)
		}
		if err := socket.RegisterTarget(targetB); !errors.Is(err, ErrLeaseClosed) {
			t.Fatalf("revoked registration: %v", err)
		}
		if _, _, err := socket.ReceiveReply(context.Background(), make([]byte, 16), func([]byte, netip.AddrPort) error { return nil }); !errors.Is(err, ErrLeaseClosed) {
			t.Fatalf("revoked read: %v", err)
		}
	}
	if _, err := h.controller.OpenProbeSocket(context.Background()); !errors.Is(err, ErrLeaseClosed) || h.factory.count() != 2 {
		t.Fatal("revoked controller opened a socket")
	}
	// All simultaneous/repeated terminal calls join the same finished drain.
	var calls sync.WaitGroup
	for i := 0; i < 16; i++ {
		calls.Add(1)
		go func() {
			defer calls.Done()
			if err := h.controller.RevokeForTerminal(); err != nil {
				t.Error(err)
			}
		}()
	}
	calls.Wait()
	select {
	case <-h.controller.watchDone:
	default:
		t.Fatal("terminal revoke returned before lifecycle exit")
	}
	// Deliver an expired duration after terminal return: no watcher remains to
	// trip during arbitrarily slow FINISH. The lease itself is still live.
	h.timer.ch <- h.clock.Now().Add(time.Minute)
	h.lease.mu.Lock()
	drains, stopping, done := h.lease.drains, h.lease.stoppingClosed, h.lease.doneClosed
	h.lease.mu.Unlock()
	if drains != 1 || stopping || done || len(h.lease.tripEvents()) != 0 || h.lease.Request() != request {
		t.Fatalf("retained attempt: drains=%d stopping=%t done=%t", drains, stopping, done)
	}
	h.controller.mu.Lock()
	socketsLeft, targetsLeft, tuplesLeft, packets := len(h.controller.sockets), len(h.controller.targetRefs), h.controller.fiveTuples, h.controller.packetsSent
	h.controller.mu.Unlock()
	if socketsLeft != 0 || targetsLeft != 0 || tuplesLeft != 0 || packets != 2 {
		t.Fatal("revoke leaked resources or refunded emitted packet accounting")
	}
	_ = pairing.Complete() // durable owner completion is separate from revoke
	if err := h.controller.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.lease.Done():
	default:
		t.Fatal("final Close did not release the fully drained attempt")
	}
	if err := h.controller.RevokeForTerminal(); err != nil {
		t.Fatal(err)
	}
}

type terminalBlockedDatagram struct {
	*fakeDatagram
	readEntered, writeEntered chan struct{}
}

func (d *terminalBlockedDatagram) ReadFrom(ctx context.Context, dst []byte) (int, netip.AddrPort, error) {
	close(d.readEntered)
	return d.fakeDatagram.ReadFrom(ctx, dst)
}

func (d *terminalBlockedDatagram) WriteTo(ctx context.Context, _ []byte, _ netip.AddrPort) (int, error) {
	close(d.writeEntered)
	<-ctx.Done()
	return 0, ctx.Err()
}

type terminalFactory struct {
	datagram Datagram
	entered  chan struct{}
}

func (f terminalFactory) Open(ctx context.Context) (Datagram, error) {
	if f.entered != nil {
		close(f.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.datagram, nil
}

func TestTerminalRevokeDrainsPendingOpenAndInFlightIO(t *testing.T) {
	for _, kind := range []string{"open", "read", "write"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			d := &terminalBlockedDatagram{newFakeDatagram(), make(chan struct{}), make(chan struct{})}
			factory := terminalFactory{datagram: d}
			entered := d.readEntered
			if kind == "open" {
				factory.entered = make(chan struct{})
				entered = factory.entered
			} else if kind == "write" {
				entered = d.writeEntered
			}
			lease := newFakeLease(normalResources())
			controller, err := New(Config{Lease: lease, Generation: NewGeneration(1), ExpectedGeneration: 1, Factory: factory, BuildVersion: "terminal-drain-test"})
			if err != nil {
				t.Fatal(err)
			}
			defer controller.Close()
			var socket *ProbeSocket
			if kind != "open" {
				socket, err = controller.OpenProbeSocket(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := socket.RegisterTarget(targetA); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() {
				var err error
				switch kind {
				case "open":
					_, err = controller.OpenProbeSocket(ctx)
				case "read":
					_, _, err = socket.ReceiveReply(ctx, make([]byte, 16), func([]byte, netip.AddrPort) error { return nil })
				case "write":
					err = socket.SendProbe(ctx, targetA, []byte("synthetic"))
				}
				result <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("operation did not enter the bounded adapter")
			}
			if err := controller.RevokeForTerminal(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrLeaseClosed) {
				t.Fatalf("drained operation: %v", err)
			}
			if ctx.Err() != nil || len(lease.tripEvents()) != 0 || kind != "open" && !d.isClosed() {
				t.Fatal("terminal drain required the caller timeout, tripped, or leaked a socket")
			}
		})
	}
}

// The terminal caller must not silently discard the drain completion error.
type terminalErrorDrain struct{ err error }

func (d terminalErrorDrain) Complete() error { return d.err }

func TestTerminalRevokeJoinsOwnDrainCompletion(t *testing.T) {
	want := errors.New("synthetic probe drain error")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan struct{})
	close(closed)
	c := &Controller{lifecycleCtx: ctx, lifecycleCancel: cancel, pendingDone: closed, watchDone: closed, handoffDone: make(chan struct{}), drain: terminalErrorDrain{want}}
	if err := c.RevokeForTerminal(); !errors.Is(err, want) {
		t.Fatalf("completion error: %v", err)
	}
	var absent *Controller
	if err := absent.RevokeForTerminal(); err != nil {
		t.Fatal(err)
	}
}
