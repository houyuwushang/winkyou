package session

import (
	"context"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
	"winkyou/pkg/transport/multipath"
)

func TestBuildResultTransportFromOutcomesBuildsRelayPrimaryDirectStandby(t *testing.T) {
	relayTransport := &fakeTransport{}
	directTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/path", relayTransport, solver.PathSummary{PathID: "relay/path", ConnectionType: "relay", Role: solver.PathRolePrimaryCandidate}),
		successfulOutcome("direct/path", directTransport, solver.PathSummary{PathID: "direct/path", ConnectionType: "direct", Role: solver.PathRoleProtectedDirect}),
	}
	best := &outcomes[0]

	result, cleanups := buildResultTransportFromOutcomes(best, outcomes, solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2})
	if len(cleanups) != 0 {
		t.Fatalf("cleanups = %d, want 0", len(cleanups))
	}
	provider, ok := result.Transport.(multipath.StatsProvider)
	if !ok {
		t.Fatalf("transport = %T, want multipath stats provider", result.Transport)
	}
	defer result.Transport.Close()
	stats := provider.MultipathStats()
	if stats.ActivePathID != "relay/path" || stats.ChildPathCount != 2 {
		t.Fatalf("stats = %+v, want relay primary with 2 children", stats)
	}
	if result.Summary.PathID != "multipath:relay/path" {
		t.Fatalf("summary path id = %q, want multipath:relay/path", result.Summary.PathID)
	}
	if result.Summary.Details["protected_direct_path_id"] != "direct/path" {
		t.Fatalf("protected direct detail = %q, want direct/path", result.Summary.Details["protected_direct_path_id"])
	}
	if got := result.Summary.Details["child_paths"]; got == "" {
		t.Fatal("child_paths detail is empty")
	}
}

func TestBuildResultTransportFromOutcomesExposesProtectedDirectPrimary(t *testing.T) {
	directTransport := &fakeTransport{}
	relayTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("direct/path", directTransport, solver.PathSummary{PathID: "direct/path", ConnectionType: "direct", Role: solver.PathRoleProtectedDirect}),
		successfulOutcome("relay/path", relayTransport, solver.PathSummary{PathID: "relay/path", ConnectionType: "relay", Role: solver.PathRolePrimaryCandidate}),
	}
	best := &outcomes[0]

	result, cleanups := buildResultTransportFromOutcomes(best, outcomes, solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2})
	if len(cleanups) != 0 {
		t.Fatalf("cleanups = %d, want 0", len(cleanups))
	}
	provider, ok := result.Transport.(multipath.StatsProvider)
	if !ok {
		t.Fatalf("transport = %T, want multipath stats provider", result.Transport)
	}
	defer result.Transport.Close()
	stats := provider.MultipathStats()
	if stats.ActivePathID != "direct/path" || stats.ChildPathCount != 2 {
		t.Fatalf("stats = %+v, want direct primary with 2 children", stats)
	}
	if result.Summary.PathID != "multipath:direct/path" {
		t.Fatalf("summary path id = %q, want multipath:direct/path", result.Summary.PathID)
	}
	if result.Summary.Details["protected_direct_path_id"] != "direct/path" {
		t.Fatalf("protected direct detail = %q, want direct/path", result.Summary.Details["protected_direct_path_id"])
	}
	if result.Summary.Details["standby_path_ids"] != "relay/path" {
		t.Fatalf("standby path ids = %q, want relay/path", result.Summary.Details["standby_path_ids"])
	}
}

func TestBuildResultTransportFromOutcomesKeepsSingleDirectPrimary(t *testing.T) {
	directTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("direct/path", directTransport, solver.PathSummary{PathID: "direct/path", ConnectionType: "direct", Role: solver.PathRoleProtectedDirect}),
	}
	best := &outcomes[0]

	result, _ := buildResultTransportFromOutcomes(best, outcomes, solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2})
	if result.Transport != directTransport {
		t.Fatalf("transport = %T, want original direct transport", result.Transport)
	}
	if result.Summary.PathID != "direct/path" {
		t.Fatalf("path id = %q, want direct/path", result.Summary.PathID)
	}
}

func TestBuildResultTransportFromOutcomesBuildsRegularStandbyWithoutDirect(t *testing.T) {
	primaryTransport := &fakeTransport{}
	standbyTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/a", primaryTransport, solver.PathSummary{PathID: "relay/a", ConnectionType: "relay", Role: solver.PathRolePrimaryCandidate}),
		successfulOutcome("relay/b", standbyTransport, solver.PathSummary{PathID: "relay/b", ConnectionType: "relay", Role: solver.PathRoleStandby}),
	}
	best := &outcomes[0]

	result, _ := buildResultTransportFromOutcomes(best, outcomes, solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2})
	provider, ok := result.Transport.(multipath.StatsProvider)
	if !ok {
		t.Fatalf("transport = %T, want multipath stats provider", result.Transport)
	}
	defer result.Transport.Close()
	stats := provider.MultipathStats()
	if stats.ChildPathCount != 2 {
		t.Fatalf("child path count = %d, want 2", stats.ChildPathCount)
	}
	if result.Summary.Details["protected_direct_path_id"] != "" {
		t.Fatalf("protected direct detail = %q, want empty", result.Summary.Details["protected_direct_path_id"])
	}
}

func TestBuildResultTransportFromOutcomesDoesNotExposeDependentDirectAsProtected(t *testing.T) {
	primaryTransport := &fakeTransport{}
	standbyTransport := &fakeTransport{}
	outcomes := []solver.CandidateOutcome{
		successfulOutcome("relay/a", primaryTransport, solver.PathSummary{PathID: "relay/a", ConnectionType: "relay", Role: solver.PathRolePrimaryCandidate}),
		successfulOutcome("overlay/direct", standbyTransport, solver.PathSummary{
			PathID:         "overlay/direct",
			ConnectionType: "direct",
			Role:           solver.PathRolePrimaryCandidate,
			Dependencies: []solver.PathDependency{{
				Kind:   solver.PathDependencyUnknown,
				Reason: "remote_cgnat_or_overlay_candidate",
			}},
		}),
	}
	best := &outcomes[0]

	result, _ := buildResultTransportFromOutcomes(best, outcomes, solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2})
	provider, ok := result.Transport.(multipath.StatsProvider)
	if !ok {
		t.Fatalf("transport = %T, want multipath stats provider", result.Transport)
	}
	defer result.Transport.Close()
	if got := provider.MultipathStats().ProtectedDirectPathID; got != "" {
		t.Fatalf("protected direct path id = %q, want empty for dependent direct-like path", got)
	}
	if got := result.Summary.Details["protected_direct_path_id"]; got != "" {
		t.Fatalf("protected direct detail = %q, want empty for dependent direct-like path", got)
	}
}

func TestSessionBindUsesMultipathTransportWhenPolicyEnabled(t *testing.T) {
	strategy := &executorFactoryStrategy{
		name: "legacy_ice_udp",
		plans: []solver.Plan{
			{ID: "plan-relay", Strategy: "legacy_ice_udp"},
			{ID: "plan-direct", Strategy: "legacy_ice_udp"},
		},
		executors: map[string]*scriptedExecutor{
			"plan-relay": newScriptedExecutor(solver.Result{
				Transport: &fakeTransport{},
				Summary: solver.PathSummary{
					PathID:         "relay/path",
					ConnectionType: "relay",
					Role:           solver.PathRolePrimaryCandidate,
				},
			}, nil),
			"plan-direct": newScriptedExecutor(solver.Result{
				Transport: &fakeTransport{},
				Summary: solver.PathSummary{
					PathID:         "direct/path",
					ConnectionType: "relay",
					Role:           solver.PathRoleProtectedDirect,
				},
			}, nil),
		},
	}
	binder := &recordingBinder{}
	bound := make(chan solver.Result, 1)
	session, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Binder:                binder,
		Sender:                &callbackSender{},
		PathPolicy:            solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2},
		RunTimeout:            2 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
		Hooks: Hooks{
			OnBound: func(result solver.Result) {
				bound <- result
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := session.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := session.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer session.Close()

	var result solver.Result
	select {
	case result = <-bound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bound result")
	}
	if _, ok := result.Transport.(multipath.StatsProvider); !ok {
		t.Fatalf("bound result transport = %T, want multipath", result.Transport)
	}
	if _, ok := binder.boundTransport.(multipath.StatsProvider); !ok {
		t.Fatalf("binder transport = %T, want multipath", binder.boundTransport)
	}
	if result.Summary.PathID != "multipath:direct/path" {
		t.Fatalf("bound path id = %q, want multipath:direct/path", result.Summary.PathID)
	}
	if result.Summary.Details["primary_path_id"] != "direct/path" {
		t.Fatalf("primary_path_id = %q, want direct/path", result.Summary.Details["primary_path_id"])
	}
	if result.Summary.Details["protected_direct_path_id"] != "direct/path" {
		t.Fatalf("protected_direct_path_id = %q, want direct/path", result.Summary.Details["protected_direct_path_id"])
	}
	if result.Summary.Details["standby_path_ids"] != "relay/path" {
		t.Fatalf("standby_path_ids = %q, want relay/path", result.Summary.Details["standby_path_ids"])
	}
	assertMultipathObservation(t, session.Observations(), "path_selected", "multipath:direct/path", "direct/path", "direct/path")
	assertMultipathObservation(t, session.Observations(), "path_committed", "multipath:direct/path", "direct/path", "direct/path")
}

func TestSessionEvaluatesRelayAfterProtectedDirectForLowerLatencyPrimary(t *testing.T) {
	strategy := &executorFactoryStrategy{
		name: "legacy_ice_udp",
		plans: []solver.Plan{
			{ID: "plan-direct", Strategy: "legacy_ice_udp"},
			{ID: "plan-relay", Strategy: "legacy_ice_udp"},
		},
		executors: map[string]*scriptedExecutor{
			"plan-direct": newScriptedExecutor(solver.Result{
				Transport: &fakeTransport{},
				Summary: solver.PathSummary{
					PathID:         "direct/path",
					ConnectionType: "direct",
					Role:           solver.PathRoleProtectedDirect,
					Metrics:        map[string]string{"rtt_ms": "400"},
				},
			}, nil),
			"plan-relay": newScriptedExecutor(solver.Result{
				Transport: &fakeTransport{},
				Summary: solver.PathSummary{
					PathID:         "relay/path",
					ConnectionType: "relay",
					Role:           solver.PathRolePrimaryCandidate,
					Dependencies:   []solver.PathDependency{{Kind: solver.PathDependencyRelay, Reason: "turn_or_relay_candidate"}},
					Metrics:        map[string]string{"rtt_ms": "1"},
				},
			}, nil),
		},
	}
	binder := &recordingBinder{}
	bound := make(chan solver.Result, 1)
	session, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: strategy, selection: Selection{StrategyName: "legacy_ice_udp", Negotiated: true}},
		Binder:                binder,
		Sender:                &callbackSender{},
		PathPolicy:            solver.PathPolicy{MultipathEnabled: true, ProtectDirect: true, MaxPaths: 2},
		RunTimeout:            2 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
		Hooks: Hooks{
			OnBound: func(result solver.Result) {
				bound <- result
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := session.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	if err := session.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer session.Close()

	var result solver.Result
	select {
	case result = <-bound:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bound result")
	}
	if _, ok := result.Transport.(multipath.StatsProvider); !ok {
		t.Fatalf("bound result transport = %T, want multipath", result.Transport)
	}
	if result.Summary.Details["primary_path_id"] != "relay/path" {
		t.Fatalf("primary_path_id = %q, want relay/path", result.Summary.Details["primary_path_id"])
	}
	if result.Summary.Details["protected_direct_path_id"] != "direct/path" {
		t.Fatalf("protected_direct_path_id = %q, want direct/path", result.Summary.Details["protected_direct_path_id"])
	}
	if _, ok := binder.boundTransport.(multipath.StatsProvider); !ok {
		t.Fatalf("binder transport = %T, want multipath", binder.boundTransport)
	}
}

type recordingBinder struct {
	boundTransport transport.PacketTransport
}

func (b *recordingBinder) Bind(_ context.Context, _ string, transport transport.PacketTransport) error {
	b.boundTransport = transport
	return nil
}

func (b *recordingBinder) Unbind(context.Context, string) error { return nil }

func assertMultipathObservation(t *testing.T, observations []solver.Observation, event, pathID, primaryPathID, protectedDirectPathID string) {
	t.Helper()
	for _, obs := range observations {
		if obs.Event != event || obs.PathID != pathID {
			continue
		}
		if obs.Details["multipath"] != "true" {
			t.Fatalf("%s multipath detail = %q, want true", event, obs.Details["multipath"])
		}
		if obs.Details["primary_path_id"] != primaryPathID {
			t.Fatalf("%s primary_path_id = %q, want %s", event, obs.Details["primary_path_id"], primaryPathID)
		}
		if obs.Details["protected_direct_path_id"] != protectedDirectPathID {
			t.Fatalf("%s protected_direct_path_id = %q, want %s", event, obs.Details["protected_direct_path_id"], protectedDirectPathID)
		}
		return
	}
	t.Fatalf("observations = %#v, want %s for %s", observations, event, pathID)
}
