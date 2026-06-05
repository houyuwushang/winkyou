package session

import (
	"context"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type pathMetadataStrategy struct {
	name      string
	transport *fakeTransport
}

func (s *pathMetadataStrategy) Name() string { return s.name }

func (s *pathMetadataStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "path-metadata-plan", Strategy: s.name}}, nil
}

func (s *pathMetadataStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	return solver.Result{
		Transport: s.transport,
		Summary: solver.PathSummary{
			PathID:         "relay/path",
			ConnectionType: "relay",
			RemoteAddr:     s.transport.RemoteAddr(),
			Role:           solver.PathRolePrimaryCandidate,
			Dependencies: []solver.PathDependency{{
				Kind:   solver.PathDependencyRelay,
				NodeID: "relay-1",
				Reason: "turn_or_relay_candidate",
			}},
			Metrics: map[string]string{
				"rtt_ms": "15",
			},
		},
	}, nil
}

func (s *pathMetadataStrategy) Close() error { return nil }

func TestPathMetadataIncludedInSelectedAndCommittedObservations(t *testing.T) {
	strategy := &pathMetadataStrategy{name: "relay_only", transport: &fakeTransport{}}
	bound := make(chan struct{}, 1)
	session, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"relay_only"}}, strategy: strategy, selection: Selection{StrategyName: "relay_only", Negotiated: true}},
		Sender:                &callbackSender{},
		RunTimeout:            2 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
		Hooks: Hooks{
			OnBound: func(solver.Result) {
				bound <- struct{}{}
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := session.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"relay_only"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := session.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case <-bound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bound session")
	}

	assertPathMetadataObservation(t, session.Observations(), "path_selected")
	assertPathMetadataObservation(t, session.Observations(), "path_committed")
}

func assertPathMetadataObservation(t *testing.T, observations []solver.Observation, event string) {
	t.Helper()
	for _, obs := range observations {
		if obs.Event != event {
			continue
		}
		if obs.Details["path_role"] != string(solver.PathRolePrimaryCandidate) {
			t.Fatalf("%s path_role = %q, want %q", event, obs.Details["path_role"], solver.PathRolePrimaryCandidate)
		}
		if obs.Details["path_dependency_kinds"] != string(solver.PathDependencyRelay) {
			t.Fatalf("%s path_dependency_kinds = %q, want %q", event, obs.Details["path_dependency_kinds"], solver.PathDependencyRelay)
		}
		if obs.Details["path_metric_rtt_ms"] != "15" {
			t.Fatalf("%s path_metric_rtt_ms = %q, want 15", event, obs.Details["path_metric_rtt_ms"])
		}
		return
	}
	t.Fatalf("observations = %#v, want %s", observations, event)
}
