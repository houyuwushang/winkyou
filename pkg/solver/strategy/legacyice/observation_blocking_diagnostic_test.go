package legacyice

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type blockingDiagnosticObservationIO struct {
	entered chan context.Context
	release chan struct{}
}

func (*blockingDiagnosticObservationIO) Send(context.Context, solver.Message) error {
	return errors.New("diagnostic must not send")
}

func (io *blockingDiagnosticObservationIO) ReportObservation(ctx context.Context, obs solver.Observation) error {
	if obs.Event == "candidate_started" {
		io.entered <- ctx
		<-io.release
	}
	return nil
}

// A causal characterization, NOT a reproduction of the historical stress
// failure. All network factories are replaced by an in-memory error witness.
// This tests the existing background-context observation-before-agent order.
func TestExecutorDiagnosticObservationIgnoresRunCancellation(t *testing.T) {
	var agentCalls atomic.Int64
	e := newExecutor(Config{NewICEAgent: func(ctx context.Context, _ AgentRequest) (nat.ICEAgent, error) {
		agentCalls.Add(1)
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Error("factory should observe the original canceled run context")
		}
		return nil, ctx.Err()
	}}, solver.SolveInput{}, solver.Plan{ID: "synthetic-plan"}, executorConfig{})
	runCtx, cancel := context.WithCancel(context.Background())
	io := &blockingDiagnosticObservationIO{entered: make(chan context.Context, 1), release: make(chan struct{})}
	done := make(chan error, 1)
	var once sync.Once
	t.Cleanup(func() {
		cancel()
		once.Do(func() { close(io.release) })
		_ = e.Close()
	})
	go func() { _, err := e.Execute(runCtx, io); done <- err }()
	var reportCtx context.Context
	select {
	case reportCtx = <-io.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("candidate_started observation not reached")
	}
	cancel()
	if reportCtx.Done() != nil || reportCtx.Err() != nil {
		t.Fatal("existing report context unexpectedly follows run cancellation")
	}
	if agentCalls.Load() != 0 {
		t.Fatal("agent factory ran before observation returned")
	}
	select {
	case <-done:
		t.Fatal("executor unexpectedly returned through the blocked observation")
	default:
	}
	once.Do(func() { close(io.release) })
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || agentCalls.Load() != 1 {
			t.Fatalf("after release: canceled=%t factory_calls=%d", errors.Is(err, context.Canceled), agentCalls.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("released diagnostic executor did not join")
	}
	t.Log("DIAGNOSTIC_CAUSAL report_cancelable=false blocked_before_agent=true packets=0 returned_after_release=true")
}
