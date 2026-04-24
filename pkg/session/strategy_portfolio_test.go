package session

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
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

func newTestPortfolioResolver(t *testing.T, entries []StrategyEntry) *PortfolioResolver {
	t.Helper()
	resolver, err := NewPortfolioResolver(entries)
	if err != nil {
		t.Fatalf("NewPortfolioResolver() error = %v", err)
	}
	return resolver
}

func mustDecodePathCommit(t *testing.T, payload []byte) rproto.PathCommit {
	t.Helper()
	var pathCommit rproto.PathCommit
	if err := json.Unmarshal(payload, &pathCommit); err != nil {
		t.Fatalf("decode path_commit: %v", err)
	}
	return pathCommit
}
