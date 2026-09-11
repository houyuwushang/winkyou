package oobcarrier

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
)

// These deliberately violate BoundedStream's close contract. The harness
// releases and joins the stubborn read AFTER checking fail-closed behavior;
// production must neither invent a physical drain nor add an abandoned waiter.
type nonDrainingStream struct {
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	closeErr  error
}

func (s *nonDrainingStream) Read([]byte) (int, error) {
	s.startOnce.Do(func() { close(s.started) })
	<-s.release
	return 0, io.EOF
}
func (*nonDrainingStream) Write(p []byte) (int, error) { return len(p), nil }
func (*nonDrainingStream) SetDeadline(time.Time) error { return nil }
func (s *nonDrainingStream) Close() error              { return s.closeErr }

func TestCarrierDrainFailureIsBoundedAndNeverCompletesGovernorWitness(t *testing.T) {
	for _, reported := range []bool{true, false} {
		name := "unreported"
		if reported {
			name = "reported"
		}
		t.Run(name, func(t *testing.T) {
			sentinel := errors.New("synthetic drain failure")
			stream := &nonDrainingStream{started: make(chan struct{}), release: make(chan struct{})}
			if reported {
				stream.closeErr = sentinel
			}
			attempt := newFakeAttempt(t, directattempt.RoleResponder)
			carrier, err := Adopt(Config{Stream: stream, OOBChannelID: testChannelID,
				Role: directattempt.RoleResponder, testLease: attempt})
			if err != nil {
				t.Fatal(err)
			}
			readDone := make(chan error, 1)
			go func() { readDone <- carrier.AwaitPresence(context.Background()) }()
			defer func() {
				close(stream.release)
				select {
				case <-readDone:
				case <-time.After(time.Second):
					t.Error("owned fault read did not join after release")
				}
			}()
			select {
			case <-stream.started:
			case <-time.After(time.Second):
				t.Fatal("fault read never started")
			}
			closed := make(chan error, 1)
			started := time.Now()
			go func() { closed <- carrier.Close() }()
			select {
			case err := <-closed:
				if !errors.Is(err, ErrCarrierDrain) || !errors.Is(err, ErrCarrierTransport) || reported && !errors.Is(err, sentinel) {
					t.Fatalf("close did not propagate drain failure: %v", err)
				}
			case <-time.After(DrainTimeout + time.Second):
				t.Fatal("carrier added an unbounded join after failed stream drain")
			}
			if witness := carrier.Witness(); !witness.Closed || witness.Drained {
				t.Fatalf("logical close claimed physical drain: %+v", witness)
			}
			attempt.mu.Lock()
			drains := attempt.drains
			attempt.mu.Unlock()
			if drains != 1 {
				t.Fatal("failed drain released governor witness")
			}
			if err := carrier.Close(); !errors.Is(err, ErrCarrierDrain) {
				t.Fatal("repeat close lost drain failure")
			}
			t.Logf("reported=%t bounded_close_ms=%d physical_drained=false pending_governor_witness=1", reported, time.Since(started).Milliseconds())
		})
	}
}

func TestAsyncReceiverDoesNotWaitForeverOnFailedPhysicalDrain(t *testing.T) {
	stream := &nonDrainingStream{started: make(chan struct{}), release: make(chan struct{}), closeErr: errors.New("synthetic drain failure")}
	attempt := newFakeAttempt(t, directattempt.RoleResponder)
	carrier, err := Adopt(Config{Stream: stream, OOBChannelID: testChannelID,
		Role: directattempt.RoleResponder, testLease: attempt})
	if err != nil {
		t.Fatal(err)
	}
	carrier.mu.Lock()
	carrier.state, carrier.handshakeSent, carrier.handshakeRead = stateActive, true, true
	carrier.mu.Unlock()
	if err := carrier.MarkHandshakeComplete(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(stream.release)
		select {
		case <-carrier.readerDone:
		case <-time.After(time.Second):
			t.Error("owned async fault read did not join")
		}
	}()
	select {
	case <-stream.started:
	case <-time.After(time.Second):
		t.Fatal("async reader did not start")
	}
	received := make(chan error, 1)
	go func() { _, err := carrier.read(context.Background()); received <- err }()
	closed := make(chan error, 1)
	go func() { closed <- carrier.Close() }()
	// Both joins share the same original deadline; neither receives a fresh
	// two-second extension when the lower-level Close reports ErrDrain.
	timer := time.NewTimer(DrainTimeout + time.Second)
	defer timer.Stop()
	for _, result := range []<-chan error{received, closed} {
		select {
		case err := <-result:
			if !errors.Is(err, ErrCarrierDrain) {
				t.Fatalf("unproven drain result=%v", err)
			}
		case <-timer.C:
			t.Fatal("async receive/close exceeded the shared drain envelope")
		}
	}
	if carrier.Witness().Drained {
		t.Fatal("async physical drain was fabricated")
	}
}
