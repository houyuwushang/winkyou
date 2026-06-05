package client

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/nat"
	rproto "winkyou/pkg/rendezvous/proto"
	sesspkg "winkyou/pkg/session"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
	"winkyou/pkg/solver/strategy/relayonly"
	"winkyou/pkg/solver/strategy/tcpframed"
)

type resolverStrategy struct {
	name string
}

func (s resolverStrategy) Name() string { return s.name }
func (s resolverStrategy) Plan(context.Context, solver.SolveInput) ([]solver.Plan, error) {
	return []solver.Plan{{ID: "plan", Strategy: s.name}}, nil
}
func (s resolverStrategy) Execute(context.Context, solver.SessionIO, solver.Plan) (solver.Result, error) {
	return solver.Result{Summary: solver.PathSummary{PathID: s.name, ConnectionType: "direct", RemoteAddr: &net.UDPAddr{Port: 1}}}, nil
}
func (s resolverStrategy) Close() error { return nil }

func TestStrategyResolverLocalCapabilityComesFromRegistry(t *testing.T) {
	resolver := newStrategyResolverWithFeatures([]strategyFactory{
		{name: "legacy_ice_udp", build: func() solver.Strategy { return resolverStrategy{name: "legacy_ice_udp"} }},
		{name: "future_quic", build: func() solver.Strategy { return resolverStrategy{name: "future_quic"} }},
	}, ResolverPolicy{}, []string{rproto.FeatureProbeLabV1, rproto.FeatureProbeScriptV1})

	got := resolver.LocalCapability()
	if len(got.Strategies) != 2 || got.Strategies[0] != "legacy_ice_udp" || got.Strategies[1] != "future_quic" {
		t.Fatalf("LocalCapability = %#v, want legacy_ice_udp+future_quic", got)
	}
	if len(got.Features) != 2 || got.Features[0] != rproto.FeatureProbeLabV1 || got.Features[1] != rproto.FeatureProbeScriptV1 {
		t.Fatalf("LocalCapability.Features = %#v, want probe features", got.Features)
	}
}

func TestStrategyResolverResolveNegotiatedIntersection(t *testing.T) {
	resolver := newStrategyResolver([]strategyFactory{
		{name: "legacy_ice_udp", build: func() solver.Strategy { return resolverStrategy{name: "legacy_ice_udp"} }},
		{name: "future_quic", build: func() solver.Strategy { return resolverStrategy{name: "future_quic"} }},
	}, ResolverPolicy{})

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{"future_quic"}}, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if strategy.Name() != "future_quic" {
		t.Fatalf("strategy = %q, want future_quic", strategy.Name())
	}
	if selection != (sesspkg.Selection{StrategyName: "future_quic", Negotiated: true}) {
		t.Fatalf("selection = %#v, want negotiated future_quic", selection)
	}
}

func TestStrategyResolverResolveNoIntersection(t *testing.T) {
	resolver := newStrategyResolver([]strategyFactory{
		{name: "legacy_ice_udp", build: func() solver.Strategy { return resolverStrategy{name: "legacy_ice_udp"} }},
	}, ResolverPolicy{})

	_, _, err := resolver.Resolve(rproto.Capability{Strategies: []string{"future_quic"}}, true)
	if err == nil {
		t.Fatal("Resolve() error = nil, want no intersection failure")
	}
	if !strings.Contains(err.Error(), "no mutually supported strategy") {
		t.Fatalf("Resolve() error = %v, want no mutually supported strategy", err)
	}
}

func TestStrategyResolverResolveCompatibilityFallback(t *testing.T) {
	resolver := newStrategyResolver([]strategyFactory{
		{name: "legacy_ice_udp", build: func() solver.Strategy { return resolverStrategy{name: "legacy_ice_udp"} }},
	}, ResolverPolicy{
		CompatibilityDefault: "legacy_ice_udp",
		AllowImplicitLegacy:  true,
	})

	strategy, selection, err := resolver.Resolve(rproto.Capability{}, true)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if strategy.Name() != "legacy_ice_udp" {
		t.Fatalf("strategy = %q, want legacy_ice_udp", strategy.Name())
	}
	if selection != (sesspkg.Selection{StrategyName: "legacy_ice_udp", Negotiated: false}) {
		t.Fatalf("selection = %#v, want compatibility fallback", selection)
	}
}

func TestStrategyResolverResolveMissingCapabilityWithoutFallback(t *testing.T) {
	resolver := newStrategyResolver([]strategyFactory{
		{name: "legacy_ice_udp", build: func() solver.Strategy { return resolverStrategy{name: "legacy_ice_udp"} }},
	}, ResolverPolicy{})

	_, _, err := resolver.Resolve(rproto.Capability{}, true)
	if err == nil {
		t.Fatal("Resolve() error = nil, want fallback disabled failure")
	}
	if !strings.Contains(err.Error(), "fallback disabled") {
		t.Fatalf("Resolve() error = %v, want fallback disabled", err)
	}
}

func TestEngineStrategyResolverDefaultsToLegacyWithImplicitFallback(t *testing.T) {
	eng := &engine{}
	resolver := eng.newStrategyResolver()

	capability := resolver.LocalCapability()
	if len(capability.Strategies) != 2 || capability.Strategies[0] != legacyice.StrategyName || capability.Strategies[1] != relayonly.StrategyName {
		t.Fatalf("LocalCapability().Strategies = %#v, want legacy then relay_only", capability.Strategies)
	}

	strategy, selection, err := resolver.Resolve(rproto.Capability{}, true)
	if err != nil {
		t.Fatalf("Resolve(empty capability) error = %v", err)
	}
	if strategy.Name() != legacyice.StrategyName {
		t.Fatalf("Resolve(empty capability) strategy = %q, want %q", strategy.Name(), legacyice.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: legacyice.StrategyName, Negotiated: false}) {
		t.Fatalf("Resolve(empty capability) selection = %#v, want implicit legacy fallback", selection)
	}
}

func TestEngineStrategyResolverSelectsRelayOnlyWhenRemoteOnlySupportsRelayOnly(t *testing.T) {
	eng := &engine{}
	resolver := eng.newStrategyResolver()

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{relayonly.StrategyName}}, true)
	if err != nil {
		t.Fatalf("Resolve(relay_only) error = %v", err)
	}
	if strategy.Name() != relayonly.StrategyName {
		t.Fatalf("Resolve(relay_only) strategy = %q, want %q", strategy.Name(), relayonly.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: relayonly.StrategyName, Negotiated: true}) {
		t.Fatalf("Resolve(relay_only) selection = %#v, want negotiated relay_only", selection)
	}
}

func TestEngineStrategyResolverOrdersRelayOnlyFromScopedObservations(t *testing.T) {
	eng := &engine{cfg: config.Default()}
	resolver := eng.newStrategyResolver()
	ordered, ok := resolver.(sesspkg.OrderedStrategyResolver)
	if !ok {
		t.Fatalf("resolver %T does not implement OrderedStrategyResolver", resolver)
	}

	candidates, err := ordered.ResolveAll(sesspkg.ResolveInput{
		SessionID:        "session/node-a/node-b",
		LocalNodeID:      "node-a",
		PeerID:           "node-b",
		Initiator:        true,
		RemoteCapability: rproto.Capability{Strategies: []string{legacyice.StrategyName, relayonly.StrategyName}},
		LocalObservations: []solver.Observation{
			clientStrategyOrderObservation(legacyice.StrategyName, "candidate_failed", "", "timeout", true),
			clientStrategyOrderObservation(legacyice.StrategyName, "candidate_failed", "", "unreachable", true),
			clientStrategyOrderObservation(relayonly.StrategyName, "candidate_succeeded", "relay", "", true),
		},
	})
	if err != nil {
		t.Fatalf("ResolveAll() error = %v", err)
	}
	if got, want := resolverCandidateNames(candidates), []string{relayonly.StrategyName, legacyice.StrategyName}; !slices.Equal(got, want) {
		t.Fatalf("ResolveAll() candidates = %#v, want %#v", got, want)
	}
}

func TestEngineStrategyResolverConnectivityRelayOnlyModePrefersRelayOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.Mode = relayonly.StrategyName
	eng := &engine{cfg: cfg}
	resolver := eng.newStrategyResolver()

	capability := resolver.LocalCapability()
	if len(capability.Strategies) != 2 || capability.Strategies[0] != relayonly.StrategyName || capability.Strategies[1] != legacyice.StrategyName {
		t.Fatalf("LocalCapability().Strategies = %#v, want relay_only then legacy", capability.Strategies)
	}

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{legacyice.StrategyName, relayonly.StrategyName}}, true)
	if err != nil {
		t.Fatalf("Resolve(mutual relay_only) error = %v", err)
	}
	if strategy.Name() != relayonly.StrategyName {
		t.Fatalf("Resolve(mutual relay_only) strategy = %q, want %q", strategy.Name(), relayonly.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: relayonly.StrategyName, Negotiated: true}) {
		t.Fatalf("Resolve(mutual relay_only) selection = %#v, want negotiated relay_only", selection)
	}
}

func TestEngineStrategyResolverStrategyOrderCanPreferRelayOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.StrategyOrder = []string{relayonly.StrategyName, legacyice.StrategyName}
	eng := &engine{cfg: cfg}
	resolver := eng.newStrategyResolver()

	capability := resolver.LocalCapability()
	if len(capability.Strategies) != 2 || capability.Strategies[0] != relayonly.StrategyName || capability.Strategies[1] != legacyice.StrategyName {
		t.Fatalf("LocalCapability().Strategies = %#v, want relay_only then legacy", capability.Strategies)
	}

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{legacyice.StrategyName, relayonly.StrategyName}}, true)
	if err != nil {
		t.Fatalf("Resolve(mutual relay_only) error = %v", err)
	}
	if strategy.Name() != relayonly.StrategyName {
		t.Fatalf("Resolve(mutual relay_only) strategy = %q, want %q", strategy.Name(), relayonly.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: relayonly.StrategyName, Negotiated: true}) {
		t.Fatalf("Resolve(mutual relay_only) selection = %#v, want negotiated relay_only", selection)
	}
}

func TestEngineStrategyResolverRegistersTCPFramedWhenEnabled(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.StrategyOrder = []string{tcpframed.StrategyName, legacyice.StrategyName, relayonly.StrategyName}
	cfg.TCPFramed.Enabled = true
	cfg.TCPFramed.ListenAddr = "127.0.0.1:0"
	eng := &engine{cfg: cfg}
	resolver := eng.newStrategyResolver()

	capability := resolver.LocalCapability()
	if got, want := capability.Strategies, []string{tcpframed.StrategyName, legacyice.StrategyName, relayonly.StrategyName}; !slices.Equal(got, want) {
		t.Fatalf("LocalCapability().Strategies = %#v, want %#v", got, want)
	}

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{tcpframed.StrategyName}}, true)
	if err != nil {
		t.Fatalf("Resolve(tcp_framed) error = %v", err)
	}
	if strategy.Name() != tcpframed.StrategyName {
		t.Fatalf("Resolve(tcp_framed) strategy = %q, want %q", strategy.Name(), tcpframed.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: tcpframed.StrategyName, Negotiated: true}) {
		t.Fatalf("Resolve(tcp_framed) selection = %#v, want negotiated tcp_framed", selection)
	}
}

func TestEngineStrategyResolverConnectivityRelayOnlyKeepsImplicitLegacyFallback(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.Mode = relayonly.StrategyName
	eng := &engine{cfg: cfg}
	resolver := eng.newStrategyResolver()

	strategy, selection, err := resolver.Resolve(rproto.Capability{}, true)
	if err != nil {
		t.Fatalf("Resolve(empty capability) error = %v", err)
	}
	if strategy.Name() != legacyice.StrategyName {
		t.Fatalf("Resolve(empty capability) strategy = %q, want %q", strategy.Name(), legacyice.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: legacyice.StrategyName, Negotiated: false}) {
		t.Fatalf("Resolve(empty capability) selection = %#v, want implicit legacy fallback", selection)
	}
}

func TestNewEngineRejectsUnknownConnectivityStrategy(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.StrategyOrder = []string{legacyice.StrategyName, "future_quic"}

	_, err := NewEngine(&cfg, nil, "")
	if err == nil {
		t.Fatal("NewEngine() error = nil, want unknown strategy error")
	}
	if !strings.Contains(err.Error(), `invalid connectivity.strategy_order[1]: "future_quic"`) {
		t.Fatalf("NewEngine() error = %v, want unknown strategy error", err)
	}
}

func TestEngineStrategyResolverForceRelayPrefersRelayOnlyWhenMutual(t *testing.T) {
	eng := &engine{cfg: config.Config{NAT: config.NATConfig{ForceRelay: true}}}
	resolver := eng.newStrategyResolver()

	capability := resolver.LocalCapability()
	if len(capability.Strategies) != 2 || capability.Strategies[0] != relayonly.StrategyName || capability.Strategies[1] != legacyice.StrategyName {
		t.Fatalf("LocalCapability().Strategies = %#v, want relay_only then legacy", capability.Strategies)
	}

	strategy, selection, err := resolver.Resolve(rproto.Capability{Strategies: []string{legacyice.StrategyName, relayonly.StrategyName}}, true)
	if err != nil {
		t.Fatalf("Resolve(mutual relay_only) error = %v", err)
	}
	if strategy.Name() != relayonly.StrategyName {
		t.Fatalf("Resolve(mutual relay_only) strategy = %q, want %q", strategy.Name(), relayonly.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: relayonly.StrategyName, Negotiated: true}) {
		t.Fatalf("Resolve(mutual relay_only) selection = %#v, want negotiated relay_only", selection)
	}
}

func TestEngineStrategyResolverForceRelayKeepsImplicitLegacyFallback(t *testing.T) {
	eng := &engine{cfg: config.Config{NAT: config.NATConfig{ForceRelay: true}}}
	resolver := eng.newStrategyResolver()

	strategy, selection, err := resolver.Resolve(rproto.Capability{}, true)
	if err != nil {
		t.Fatalf("Resolve(empty capability) error = %v", err)
	}
	if strategy.Name() != legacyice.StrategyName {
		t.Fatalf("Resolve(empty capability) strategy = %q, want %q", strategy.Name(), legacyice.StrategyName)
	}
	if selection != (sesspkg.Selection{StrategyName: legacyice.StrategyName, Negotiated: false}) {
		t.Fatalf("Resolve(empty capability) selection = %#v, want implicit legacy fallback", selection)
	}
}

func TestLegacyICEStrategyConfigPropagatesForceRelay(t *testing.T) {
	eng := &engine{
		cfg: config.Config{
			NAT: config.NATConfig{
				GatherTimeout:  3 * time.Second,
				ConnectTimeout: 4 * time.Second,
				CheckTimeout:   5 * time.Second,
				ForceRelay:     true,
			},
		},
	}

	cfg := eng.legacyICEStrategyConfig()
	if !cfg.ForceRelay {
		t.Fatal("legacyICEStrategyConfig().ForceRelay = false, want true")
	}
}

func TestLegacyICEStrategyConfigConnectivityRelayOnlyForcesRelay(t *testing.T) {
	eng := &engine{
		cfg: config.Config{
			Connectivity: config.ConnectivityConfig{Mode: relayonly.StrategyName},
		},
	}

	cfg := eng.legacyICEStrategyConfig()
	if !cfg.ForceRelay {
		t.Fatal("legacyICEStrategyConfig().ForceRelay = false, want true")
	}
}

func TestLegacyICEStrategyConfigPropagatesCandidateFilters(t *testing.T) {
	recorder := &recordingNATTraversal{}
	eng := &engine{
		nat: recorder,
		cfg: config.Config{
			NAT: config.NATConfig{
				CandidateInterfaceInclude: []string{"Ethernet"},
				CandidateInterfaceExclude: []string{"tailscale0"},
				CandidateCIDRInclude:      []string{"192.168.0.0/16"},
				CandidateCIDRExclude:      []string{"100.64.0.0/10"},
			},
		},
	}

	cfg := eng.legacyICEStrategyConfig()
	if _, err := cfg.NewICEAgent(context.Background(), legacyice.AgentRequest{
		Controlling:          true,
		CandidateCIDRExclude: []string{"198.18.0.0/15"},
	}); err != nil {
		t.Fatalf("NewICEAgent() error = %v", err)
	}
	got := recorder.cfg
	if got.CandidateInterfaceInclude[0] != "Ethernet" || got.CandidateInterfaceExclude[0] != "tailscale0" {
		t.Fatalf("interface filters = include=%#v exclude=%#v", got.CandidateInterfaceInclude, got.CandidateInterfaceExclude)
	}
	if got.CandidateCIDRInclude[0] != "192.168.0.0/16" ||
		len(got.CandidateCIDRExclude) != 2 ||
		got.CandidateCIDRExclude[0] != "100.64.0.0/10" ||
		got.CandidateCIDRExclude[1] != "198.18.0.0/15" {
		t.Fatalf("cidr filters = include=%#v exclude=%#v", got.CandidateCIDRInclude, got.CandidateCIDRExclude)
	}
}

type recordingNATTraversal struct {
	cfg nat.ICEConfig
}

func (r *recordingNATTraversal) DetectNATType(context.Context) (nat.NATType, error) {
	return nat.NATTypeUnknown, nil
}

func (r *recordingNATTraversal) NewICEAgent(cfg nat.ICEConfig) (nat.ICEAgent, error) {
	r.cfg = cfg
	return nil, nil
}

func resolverCandidateNames(candidates []sesspkg.StrategyCandidate) []string {
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.Name)
	}
	return names
}

func clientStrategyOrderObservation(strategy, event, connectionType, errorClass string, scoped bool) solver.Observation {
	obs := solver.Observation{
		Strategy:       strategy,
		Event:          event,
		ConnectionType: connectionType,
		ErrorClass:     errorClass,
	}
	if scoped {
		obs.Details = map[string]string{
			"session_id":     "session/node-a/node-b",
			"local_node_id":  "node-a",
			"peer_id":        "node-b",
			"remote_node_id": "node-b",
			"initiator":      "true",
		}
	}
	return obs
}
