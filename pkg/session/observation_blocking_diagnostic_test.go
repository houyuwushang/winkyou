package session

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/solver"
)

type diagnosticBlockingSink struct {
	entered chan struct{}
	release chan struct{}
	err     error
}

func (sink *diagnosticBlockingSink) Record(solver.Observation) error {
	close(sink.entered)
	<-sink.release
	return sink.err
}

type diagnosticObservationSender struct{ calls atomic.Int64 }

func (send *diagnosticObservationSender) Send(context.Context, string, solver.Message) error {
	send.calls.Add(1)
	return nil
}

// A synthetic blocked sink proves ordering and cancellation behavior only.
// It does not claim that disk latency caused any particular historical RED.
func TestSessionDiagnosticObservationSinkBlocksBeforeEnvelopeSend(t *testing.T) {
	if os.Getenv("WINKYOU_124_CAUSAL_DIAGNOSTIC") != "1" {
		t.Skip("historical synchronous-sink characterization, not a fix acceptance oracle")
	}
	want := errors.New("synthetic_observation_sink_failure")
	sink := &diagnosticBlockingSink{entered: make(chan struct{}), release: make(chan struct{}), err: want}
	sender := &diagnosticObservationSender{}
	cfg := Config{SessionID: "synthetic-session", LocalNodeID: "synthetic-local", PeerID: "synthetic-peer", ObservationSink: sink, Sender: sender}
	s := &Session{cfg: cfg, io: &solverIO{cfg: cfg}}
	s.io.session = s
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(sink.release) }) })
	done := make(chan error, 1)
	go func() { done <- s.reportObservation(ctx, solver.Observation{Event: "synthetic-observation"}) }()
	select {
	case <-sink.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("observation sink not entered")
	}
	cancel()
	if len(s.Observations()) != 1 || sender.calls.Load() != 0 {
		t.Fatal("memory/sink/send ordering changed")
	}
	select {
	case <-done:
		t.Fatal("cancellation unexpectedly interrupted a synchronous sink")
	default:
	}
	once.Do(func() { close(sink.release) })
	select {
	case err := <-done:
		if !errors.Is(err, want) || sender.calls.Load() != 0 {
			t.Fatal("sink error was not returned before envelope send")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("released observation call did not join")
	}
	t.Log("DIAGNOSTIC_CAUSAL memory_recorded=true sink_blocks_envelope=true cancel_did_not_interrupt_sink=true packets=0 joined=true")
}
