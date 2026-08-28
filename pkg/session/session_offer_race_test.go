package session

import (
	"context"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

const raceExecutorPlanID = "raceplan/turn"

// offerWaitExecutor completes only after HandleMessage delivered the one-shot
// "offer" strategy message, mirroring a responder-side legacy ICE executor.
type offerWaitExecutor struct {
	installed chan<- struct{}
	once      sync.Once
	got       chan struct{}
}

func (e *offerWaitExecutor) HandleMessage(_ context.Context, _ solver.SessionIO, msg solver.Message) error {
	if msg.Kind == solver.MessageKindStrategy && msg.Type == "offer" {
		e.once.Do(func() { close(e.got) })
	}
	return nil
}

func (e *offerWaitExecutor) Execute(ctx context.Context, _ solver.SessionIO) (solver.Result, error) {
	select {
	case <-e.got:
		return solver.Result{
			Transport: &fakeTransport{},
			Summary: solver.PathSummary{
				PathID:         raceExecutorPlanID,
				ConnectionType: "relay",
			},
		}, nil
	case <-ctx.Done():
		return solver.Result{}, ctx.Err()
	}
}

func (e *offerWaitExecutor) Close() error { return nil }

type offerExecutorStrategy struct {
	installed chan struct{}
}

func (s *offerExecutorStrategy) Name() string { return "race_exec" }

func (s *offerExecutorStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: raceExecutorPlanID, Strategy: s.Name()}}, nil
}

func (s *offerExecutorStrategy) NewExecutor(plan solver.Plan) (solver.PlanExecutor, error) {
	executor := &offerWaitExecutor{installed: s.installed, got: make(chan struct{})}
	// Signal the racing sender at the narrowest point: after the executor
	// exists but before setActiveExecutor installs it and flushes pending
	// messages. A snapshot-then-enqueue HandleMessage implementation loses the
	// offer exactly in this window.
	select {
	case s.installed <- struct{}{}:
	default:
	}
	return executor, nil
}

func (s *offerExecutorStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	return solver.Result{}, context.Canceled
}

func (s *offerExecutorStrategy) Close() error { return nil }

// TestStrategyMessageRacingExecutorInstallIsDelivered guards issue #33: a
// one-shot strategy message (legacy ICE offer) that arrives while the plan
// executor is being installed must either be enqueued before the install-time
// flush or handed to the installed executor directly. Losing it silently
// stalls the responder until every run timeout expires.
func TestStrategyMessageRacingExecutorInstallIsDelivered(t *testing.T) {
	offerPayload := []byte(`{"plan_id":"` + raceExecutorPlanID + `"}`)

	for iteration := 0; iteration < 200; iteration++ {
		strategy := &offerExecutorStrategy{installed: make(chan struct{}, 1)}
		resolver := &fakeResolver{
			local:     rproto.Capability{Strategies: []string{"race_exec"}},
			strategy:  strategy,
			selection: Selection{StrategyName: "race_exec", Negotiated: true},
		}
		bound := make(chan solver.Result, 1)
		failed := make(chan error, 1)
		sess, err := New(Config{
			SessionID:             "session/node-a/node-b",
			LocalNodeID:           "node-b",
			PeerID:                "node-a",
			Initiator:             false,
			Resolver:              resolver,
			Binder:                &fakeBinder{},
			Sender:                &fakeSender{},
			RunTimeout:            2 * time.Second,
			CapabilityWaitTimeout: time.Second,
			Hooks: Hooks{
				OnBound: func(result solver.Result) { bound <- result },
				OnError: func(err error) {
					select {
					case failed <- err:
					default:
					}
				},
			},
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		sess.setRemoteCapability(rproto.Capability{Strategies: []string{"race_exec"}}, time.Now())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-strategy.installed:
			case <-time.After(2 * time.Second):
			}
			_ = sess.HandleMessage(context.Background(), solver.Message{
				Kind:       solver.MessageKindStrategy,
				Type:       "offer",
				Payload:    offerPayload,
				ReceivedAt: time.Now(),
			})
		}()

		if err := sess.Start(context.Background()); err != nil {
			t.Fatalf("iteration %d: Start() error = %v", iteration, err)
		}

		select {
		case <-bound:
		case err := <-failed:
			t.Fatalf("iteration %d: racing offer was lost, session failed: %v", iteration, err)
		case <-time.After(4 * time.Second):
			t.Fatalf("iteration %d: session neither bound nor failed; state=%s", iteration, sess.State())
		}
		wg.Wait()
		if err := sess.Close(); err != nil {
			t.Fatalf("iteration %d: Close() error = %v", iteration, err)
		}
	}
}
