package session

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/relayonly"
)

func TestPortfolioResolverLocalCapabilityAdvertisesRegisteredStrategies(t *testing.T) {
	legacy := &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}
	fakeTCP := &fakeStrategy{name: "fake_tcp_443", transport: &fakeTransport{}}
	resolver := newTestPortfolioResolver(t, []StrategyEntry{
		{Name: legacy.Name(), Strategy: legacy},
		{Name: fakeTCP.Name(), Strategy: fakeTCP},
	})

	capability := resolver.LocalCapability()
	if got, want := capability.Strategies, []string{"legacy_ice_udp", "fake_tcp_443"}; !slices.Equal(got, want) {
		t.Fatalf("LocalCapability().Strategies = %#v, want %#v", got, want)
	}
}

func TestPortfolioResolverSelectsFirstMutualStrategyByRegistrationOrder(t *testing.T) {
	legacy := &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}
	fakeTCP := &fakeStrategy{name: "fake_tcp_443", transport: &fakeTransport{}}
	resolver := newTestPortfolioResolver(t, []StrategyEntry{
		{Name: legacy.Name(), Strategy: legacy},
		{Name: fakeTCP.Name(), Strategy: fakeTCP},
	})

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{"fake_tcp_443", "legacy_ice_udp"}}, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if strategy != legacy {
		t.Fatalf("Resolve() strategy = %p, want legacy %p", strategy, legacy)
	}
	if selection.StrategyName != "legacy_ice_udp" || !selection.Negotiated {
		t.Fatalf("Resolve() selection = %#v, want legacy_ice_udp negotiated", selection)
	}
}

func TestPortfolioResolverSkipsUnsupportedLocalStrategy(t *testing.T) {
	legacy := &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}
	fakeTCP := &fakeStrategy{name: "fake_tcp_443", transport: &fakeTransport{}}
	resolver := newTestPortfolioResolver(t, []StrategyEntry{
		{Name: legacy.Name(), Strategy: legacy},
		{Name: fakeTCP.Name(), Strategy: fakeTCP},
	})

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{"fake_tcp_443"}}, false)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if strategy != fakeTCP {
		t.Fatalf("Resolve() strategy = %p, want fakeTCP %p", strategy, fakeTCP)
	}
	if selection.StrategyName != "fake_tcp_443" || !selection.Negotiated {
		t.Fatalf("Resolve() selection = %#v, want fake_tcp_443 negotiated", selection)
	}
}

func TestPortfolioResolverErrorsWhenNoMutualStrategy(t *testing.T) {
	legacy := &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}
	resolver := newTestPortfolioResolver(t, []StrategyEntry{{Name: legacy.Name(), Strategy: legacy}})

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{"fake_tcp_443"}}, true)
	if err == nil {
		t.Fatal("Resolve() error = nil, want no mutual strategy error")
	}
	if strategy != nil {
		t.Fatalf("Resolve() strategy = %#v, want nil", strategy)
	}
	if selection != (Selection{}) {
		t.Fatalf("Resolve() selection = %#v, want zero value", selection)
	}
	if !strings.Contains(err.Error(), "no mutually supported strategy") {
		t.Fatalf("Resolve() error = %q, want no mutually supported strategy", err)
	}
}

func TestPortfolioResolverRejectsDuplicateStrategyNames(t *testing.T) {
	_, err := NewPortfolioResolver([]StrategyEntry{
		{Name: "legacy_ice_udp", Strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}},
		{Name: "legacy_ice_udp", Strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}},
	})
	if err == nil {
		t.Fatal("NewPortfolioResolver() error = nil, want duplicate strategy name error")
	}
	if !strings.Contains(err.Error(), "duplicate strategy name") {
		t.Fatalf("NewPortfolioResolver() error = %q, want duplicate strategy name", err)
	}
}

func TestPortfolioResolverRejectsNilStrategy(t *testing.T) {
	_, err := NewPortfolioResolver([]StrategyEntry{{Name: "legacy_ice_udp"}})
	if err == nil {
		t.Fatal("NewPortfolioResolver() error = nil, want nil strategy error")
	}
	if !strings.Contains(err.Error(), "nil strategy") {
		t.Fatalf("NewPortfolioResolver() error = %q, want nil strategy", err)
	}
}

func TestPortfolioResolverRejectsEmptyStrategyNames(t *testing.T) {
	_, err := NewPortfolioResolver([]StrategyEntry{
		{Name: "", Strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}},
	})
	if err == nil {
		t.Fatal("NewPortfolioResolver() error = nil, want empty entry name error")
	}
	if !strings.Contains(err.Error(), "empty name") {
		t.Fatalf("NewPortfolioResolver() error = %q, want empty name", err)
	}

	_, err = NewPortfolioResolver([]StrategyEntry{
		{Name: "legacy_ice_udp", Strategy: &fakeStrategy{name: "", transport: &fakeTransport{}}},
	})
	if err == nil {
		t.Fatal("NewPortfolioResolver() error = nil, want empty strategy name error")
	}
	if !strings.Contains(err.Error(), "strategy returned empty name") {
		t.Fatalf("NewPortfolioResolver() error = %q, want strategy returned empty name", err)
	}
}

func TestPortfolioResolverRejectsEntryNameMismatch(t *testing.T) {
	_, err := NewPortfolioResolver([]StrategyEntry{
		{Name: "legacy_ice_udp", Strategy: &fakeStrategy{name: "fake_tcp_443", transport: &fakeTransport{}}},
	})
	if err == nil {
		t.Fatal("NewPortfolioResolver() error = nil, want name mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match strategy name") {
		t.Fatalf("NewPortfolioResolver() error = %q, want name mismatch", err)
	}
}

func TestFactoryPortfolioResolverSelectsFirstMutualByLocalOrder(t *testing.T) {
	builds := map[string]int{}
	resolver := newTestFactoryPortfolioResolver(t, []StrategyFactoryEntry{
		{Name: "legacy_ice_udp", Build: countingStrategyFactory("legacy_ice_udp", builds)},
		{Name: "future_quic", Build: countingStrategyFactory("future_quic", builds)},
	}, PortfolioResolverPolicy{}, nil)

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{"future_quic", "legacy_ice_udp"}}, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if strategy.Name() != "legacy_ice_udp" {
		t.Fatalf("Resolve() strategy = %q, want legacy_ice_udp", strategy.Name())
	}
	if selection != (Selection{StrategyName: "legacy_ice_udp", Negotiated: true}) {
		t.Fatalf("Resolve() selection = %#v, want negotiated legacy_ice_udp", selection)
	}
	if builds["legacy_ice_udp"] != 1 || builds["future_quic"] != 0 {
		t.Fatalf("factory builds = %#v, want only legacy_ice_udp built once", builds)
	}
}

func TestFactoryPortfolioResolverErrorsWhenNoMutualStrategy(t *testing.T) {
	resolver := newTestFactoryPortfolioResolver(t, []StrategyFactoryEntry{
		{Name: "legacy_ice_udp", Build: countingStrategyFactory("legacy_ice_udp", nil)},
	}, PortfolioResolverPolicy{}, nil)

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{"future_quic"}}, true)
	if err == nil {
		t.Fatal("Resolve() error = nil, want no mutual strategy error")
	}
	if strategy != nil {
		t.Fatalf("Resolve() strategy = %#v, want nil", strategy)
	}
	if selection != (Selection{}) {
		t.Fatalf("Resolve() selection = %#v, want zero value", selection)
	}
	if !strings.Contains(err.Error(), "no mutually supported strategy") {
		t.Fatalf("Resolve() error = %q, want no mutually supported strategy", err)
	}
}

func TestFactoryPortfolioResolverAllowsImplicitLegacyFallback(t *testing.T) {
	resolver := newTestFactoryPortfolioResolver(t, []StrategyFactoryEntry{
		{Name: "legacy_ice_udp", Build: countingStrategyFactory("legacy_ice_udp", nil)},
	}, PortfolioResolverPolicy{
		CompatibilityDefault: "legacy_ice_udp",
		AllowImplicitLegacy:  true,
	}, nil)

	strategy, selection, err := resolver.Resolve(rproto.Capability{}, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if strategy.Name() != "legacy_ice_udp" {
		t.Fatalf("Resolve() strategy = %q, want legacy_ice_udp", strategy.Name())
	}
	if selection != (Selection{StrategyName: "legacy_ice_udp", Negotiated: false}) {
		t.Fatalf("Resolve() selection = %#v, want implicit legacy fallback", selection)
	}
}

func TestFactoryPortfolioResolverSkipsInvalidAndDuplicateFactories(t *testing.T) {
	builds := map[string]int{}
	resolver := newTestFactoryPortfolioResolver(t, []StrategyFactoryEntry{
		{Name: "", Build: countingStrategyFactory("empty", builds)},
		{Name: "ignored_nil"},
		{Name: "legacy_ice_udp", Build: countingStrategyFactory("legacy_ice_udp", builds)},
		{Name: "legacy_ice_udp", Build: countingStrategyFactory("duplicate_legacy", builds)},
	}, PortfolioResolverPolicy{}, []string{rproto.FeatureProbeLabV1})

	capability := resolver.LocalCapability()
	if got, want := capability.Strategies, []string{"legacy_ice_udp"}; !slices.Equal(got, want) {
		t.Fatalf("LocalCapability().Strategies = %#v, want %#v", got, want)
	}
	if got, want := capability.Features, []string{rproto.FeatureProbeLabV1}; !slices.Equal(got, want) {
		t.Fatalf("LocalCapability().Features = %#v, want %#v", got, want)
	}

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if strategy.Name() != "legacy_ice_udp" {
		t.Fatalf("Resolve() strategy = %q, want legacy_ice_udp", strategy.Name())
	}
	if selection != (Selection{StrategyName: "legacy_ice_udp", Negotiated: true}) {
		t.Fatalf("Resolve() selection = %#v, want negotiated legacy_ice_udp", selection)
	}
	if builds["legacy_ice_udp"] != 1 || builds["duplicate_legacy"] != 0 || builds["empty"] != 0 {
		t.Fatalf("factory builds = %#v, want only first valid legacy factory built", builds)
	}
}

func TestSessionStrategySelectionUsesPortfolioResolver(t *testing.T) {
	legacy := &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}
	fakeTCP := &fakeStrategy{name: "fake_tcp_443", transport: &fakeTransport{}}
	resolver := newTestPortfolioResolver(t, []StrategyEntry{
		{Name: legacy.Name(), Strategy: legacy},
		{Name: fakeTCP.Name(), Strategy: fakeTCP},
	})
	sender := &fakeSender{}
	stateCh := make(chan State, 8)

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              resolver,
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
		Hooks: Hooks{
			OnStateChange: func(state State) {
				stateCh <- state
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{"fake_tcp_443"}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}

	waitForState(t, s, StateBound)

	snapshot := s.Snapshot()
	if snapshot.SelectedStrategy != "fake_tcp_443" {
		t.Fatalf("SelectedStrategy = %q, want fake_tcp_443", snapshot.SelectedStrategy)
	}
	if !snapshot.SelectionNegotiated {
		t.Fatal("SelectionNegotiated = false, want true")
	}
	if states := collectStates(stateCh); !slices.Contains(states, StateSelecting) || !slices.Contains(states, StateBound) {
		t.Fatalf("state transitions = %v, want selecting and bound", states)
	}

	legacyPlans, legacyExecs := legacy.Counts()
	if legacyPlans != 0 || legacyExecs != 0 {
		t.Fatalf("legacy strategy calls = plan:%d exec:%d, want 0/0", legacyPlans, legacyExecs)
	}
	fakePlans, fakeExecs := fakeTCP.Counts()
	if fakePlans != 1 || fakeExecs != 1 {
		t.Fatalf("fake strategy calls = plan:%d exec:%d, want 1/1", fakePlans, fakeExecs)
	}

	pathCommitMsg := waitForEnvelopeMessage(t, sender.Messages, rproto.MsgTypePathCommit)
	envelope, err := rproto.UnmarshalEnvelope(pathCommitMsg.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(path_commit) error = %v", err)
	}
	pathCommit := mustDecodePathCommit(t, envelope.Payload)
	if pathCommit.Strategy != "fake_tcp_443" {
		t.Fatalf("path_commit strategy = %q, want fake_tcp_443", pathCommit.Strategy)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestSessionRelayOnlyPathCommitAndObservationsUseRelayOnlyStrategy(t *testing.T) {
	strategy := &relayOnlySessionStrategy{transport: &fakeTransport{}}
	resolver := &fakeResolver{
		local:     rproto.Capability{Strategies: []string{relayonly.StrategyName}},
		strategy:  strategy,
		selection: Selection{StrategyName: relayonly.StrategyName, Negotiated: true},
	}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              resolver,
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{relayonly.StrategyName}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateBound)

	pathCommitMsg := waitForEnvelopeMessage(t, sender.Messages, rproto.MsgTypePathCommit)
	envelope, err := rproto.UnmarshalEnvelope(pathCommitMsg.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(path_commit) error = %v", err)
	}
	pathCommit := mustDecodePathCommit(t, envelope.Payload)
	if pathCommit.Strategy != relayonly.StrategyName {
		t.Fatalf("path_commit strategy = %q, want %q", pathCommit.Strategy, relayonly.StrategyName)
	}

	wantEvents := map[string]bool{
		"candidate_planned": false,
		"path_selected":     false,
		"path_committed":    false,
	}
	for _, obs := range s.Observations() {
		if _, ok := wantEvents[obs.Event]; !ok {
			continue
		}
		if obs.Strategy != relayonly.StrategyName {
			t.Fatalf("%s observation strategy = %q, want %q; obs=%#v", obs.Event, obs.Strategy, relayonly.StrategyName, obs)
		}
		wantEvents[obs.Event] = true
	}
	for event, seen := range wantEvents {
		if !seen {
			t.Fatalf("observations = %#v, want event %s", s.Observations(), event)
		}
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func newTestPortfolioResolver(t *testing.T, entries []StrategyEntry) *PortfolioResolver {
	t.Helper()
	resolver, err := NewPortfolioResolver(entries)
	if err != nil {
		t.Fatalf("NewPortfolioResolver() error = %v", err)
	}
	return resolver
}

func newTestFactoryPortfolioResolver(t *testing.T, entries []StrategyFactoryEntry, policy PortfolioResolverPolicy, features []string) *FactoryPortfolioResolver {
	t.Helper()
	resolver, err := NewFactoryPortfolioResolver(entries, policy, features)
	if err != nil {
		t.Fatalf("NewFactoryPortfolioResolver() error = %v", err)
	}
	return resolver
}

func countingStrategyFactory(name string, builds map[string]int) func() solver.Strategy {
	return func() solver.Strategy {
		if builds != nil {
			builds[name]++
		}
		return &fakeStrategy{name: name, transport: &fakeTransport{}}
	}
}

type relayOnlySessionStrategy struct {
	transport *fakeTransport
}

func (s *relayOnlySessionStrategy) Name() string { return relayonly.StrategyName }

func (s *relayOnlySessionStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{
		ID:       relayonly.PlanID,
		Strategy: relayonly.StrategyName,
		Metadata: map[string]string{"mode": "relay_only"},
	}}, nil
}

func (s *relayOnlySessionStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	return solver.Result{
		Transport: s.transport,
		Summary: solver.PathSummary{
			PathID:         "relayonly:relay:session/node-a/node-b",
			ConnectionType: "relay",
			RemoteAddr:     s.transport.RemoteAddr(),
		},
	}, nil
}

func (s *relayOnlySessionStrategy) Close() error { return nil }

func mustDecodePathCommit(t *testing.T, payload []byte) rproto.PathCommit {
	t.Helper()
	var pathCommit rproto.PathCommit
	if err := json.Unmarshal(payload, &pathCommit); err != nil {
		t.Fatalf("decode path_commit: %v", err)
	}
	return pathCommit
}
