package client

import (
	"context"
	"errors"
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

func TestEngineStrategyResolverPrefersRelayFirstForSymmetricNAT(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.TURNServers = []config.TURNServerConfig{{URL: "turn:relay.example.com:3478", Username: "user", Password: "pass"}}
	eng := &engine{cfg: cfg}
	eng.status.NATType = nat.NATTypeSymmetric.String()
	resolver := eng.newStrategyResolver()
	ordered, ok := resolver.(sesspkg.OrderedStrategyResolver)
	if !ok {
		t.Fatalf("resolver %T does not implement OrderedStrategyResolver", resolver)
	}

	capability := resolver.LocalCapability()
	if got, want := capability.Strategies, []string{relayonly.StrategyName, legacyice.StrategyName}; !slices.Equal(got, want) {
		t.Fatalf("LocalCapability().Strategies = %#v, want %#v", got, want)
	}

	candidates, err := ordered.ResolveAll(sesspkg.ResolveInput{
		SessionID:        "session/node-a/node-b",
		LocalNodeID:      "node-a",
		PeerID:           "node-b",
		Initiator:        true,
		RemoteCapability: rproto.Capability{Strategies: []string{legacyice.StrategyName, relayonly.StrategyName}},
	})
	if err != nil {
		t.Fatalf("ResolveAll() error = %v", err)
	}
	if got, want := resolverCandidateNames(candidates), []string{relayonly.StrategyName, legacyice.StrategyName}; !slices.Equal(got, want) {
		t.Fatalf("ResolveAll() candidates = %#v, want %#v", got, want)
	}
}

func TestEngineStrategyResolverKeepsLegacyFirstForSymmetricNATWithoutTURN(t *testing.T) {
	eng := &engine{cfg: config.Default()}
	eng.status.NATType = nat.NATTypeSymmetric.String()
	resolver := eng.newStrategyResolver()
	ordered, ok := resolver.(sesspkg.OrderedStrategyResolver)
	if !ok {
		t.Fatalf("resolver %T does not implement OrderedStrategyResolver", resolver)
	}

	capability := resolver.LocalCapability()
	if got, want := capability.Strategies, []string{legacyice.StrategyName, relayonly.StrategyName}; !slices.Equal(got, want) {
		t.Fatalf("LocalCapability().Strategies = %#v, want %#v", got, want)
	}

	candidates, err := ordered.ResolveAll(sesspkg.ResolveInput{
		SessionID:        "session/node-a/node-b",
		LocalNodeID:      "node-a",
		PeerID:           "node-b",
		Initiator:        true,
		RemoteCapability: rproto.Capability{Strategies: []string{legacyice.StrategyName, relayonly.StrategyName}},
	})
	if err != nil {
		t.Fatalf("ResolveAll() error = %v", err)
	}
	if got, want := resolverCandidateNames(candidates), []string{legacyice.StrategyName, relayonly.StrategyName}; !slices.Equal(got, want) {
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

func TestLegacyICEStrategyConfigDisablesRelayPlanWithoutTURN(t *testing.T) {
	eng := &engine{cfg: config.Default()}

	cfg := eng.legacyICEStrategyConfig()
	if !cfg.RelayDisabled {
		t.Fatal("legacyICEStrategyConfig().RelayDisabled = false, want true without TURN in auto mode")
	}
}

func TestLegacyICEStrategyConfigKeepsRelayPlanWithTURN(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.TURNServers = []config.TURNServerConfig{{URL: "turn:relay.example.com:3478"}}
	eng := &engine{cfg: cfg}

	legacyCfg := eng.legacyICEStrategyConfig()
	if legacyCfg.RelayDisabled {
		t.Fatal("legacyICEStrategyConfig().RelayDisabled = true, want false when TURN is configured")
	}
}

func TestLegacyICEStrategyConfigKeepsRelayPlanForExplicitRelayOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Connectivity.Mode = relayonly.StrategyName
	eng := &engine{cfg: cfg}

	legacyCfg := eng.legacyICEStrategyConfig()
	if legacyCfg.RelayDisabled {
		t.Fatal("legacyICEStrategyConfig().RelayDisabled = true, want false for explicit relay-only mode")
	}
}

func TestLegacyICEStrategyConfigPropagatesCandidateFilters(t *testing.T) {
	recorder := &recordingNATTraversal{}
	eng := &engine{
		nat: recorder,
		cfg: config.Config{
			NAT: config.NATConfig{
				CandidatePortMin:             40000,
				CandidatePortMax:             40100,
				CandidateInterfaceInclude:    []string{"Ethernet"},
				CandidateInterfaceExclude:    []string{"tailscale0"},
				CandidateCIDRInclude:         []string{"192.168.0.0/16"},
				CandidateCIDRExclude:         []string{"100.64.0.0/10"},
				NAT1To1IPs:                   []string{"203.0.113.10/192.168.0.10"},
				NAT1To1CandidateType:         "srflx",
				PublicEndpointHints:          []string{"117.48.146.2:41000/192.168.1.20:40000"},
				PublicEndpointHintPortWindow: 2,
				DirectTrustedCIDRs:           []string{"100.64.0.0/10"},
				PublicDirectTrustedCIDRs:     []string{"198.18.0.0/15"},
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
	if got.CandidatePortMin != 40000 || got.CandidatePortMax != 40100 {
		t.Fatalf("candidate port range = %d-%d, want 40000-40100", got.CandidatePortMin, got.CandidatePortMax)
	}
	if got.CandidateCIDRInclude[0] != "192.168.0.0/16" ||
		len(got.CandidateCIDRExclude) != 2 ||
		got.CandidateCIDRExclude[0] != "100.64.0.0/10" ||
		got.CandidateCIDRExclude[1] != "198.18.0.0/15" {
		t.Fatalf("cidr filters = include=%#v exclude=%#v", got.CandidateCIDRInclude, got.CandidateCIDRExclude)
	}
	if len(got.NAT1To1IPs) != 1 || got.NAT1To1IPs[0] != "203.0.113.10/192.168.0.10" || got.NAT1To1CandidateType != "srflx" {
		t.Fatalf("nat1to1 hints = ips=%#v type=%q, want configured hints", got.NAT1To1IPs, got.NAT1To1CandidateType)
	}
	if len(cfg.PublicEndpointHints) != 1 || cfg.PublicEndpointHints[0] != "117.48.146.2:41000/192.168.1.20:40000" {
		t.Fatalf("legacy public endpoint hints = %#v, want configured hint", cfg.PublicEndpointHints)
	}
	if cfg.PublicEndpointHintPortWindow != 2 {
		t.Fatalf("legacy public endpoint hint port window = %d, want 2", cfg.PublicEndpointHintPortWindow)
	}
	if len(cfg.DirectTrustedCIDRs) != 1 || cfg.DirectTrustedCIDRs[0] != "100.64.0.0/10" {
		t.Fatalf("legacy direct trusted CIDRs = %#v, want configured direct trusted CIDR", cfg.DirectTrustedCIDRs)
	}
	if len(cfg.PublicDirectTrustedCIDRs) != 1 || cfg.PublicDirectTrustedCIDRs[0] != "198.18.0.0/15" {
		t.Fatalf("legacy public direct trusted CIDRs = %#v, want configured public direct trusted CIDR", cfg.PublicDirectTrustedCIDRs)
	}
	if len(cfg.CandidateCIDRInclude) != 1 || cfg.CandidateCIDRInclude[0] != "192.168.0.0/16" {
		t.Fatalf("legacy candidate CIDR include = %#v, want configured include", cfg.CandidateCIDRInclude)
	}

	if _, err := cfg.NewICEAgent(context.Background(), legacyice.AgentRequest{
		PublicDirectCandidate: true,
		CandidatePortMin:      40000,
		CandidatePortMax:      40000,
		CandidateCIDRInclude:  []string{"192.168.1.20/32"},
	}); err != nil {
		t.Fatalf("NewICEAgent(public direct) error = %v", err)
	}
	if !recorder.cfg.PublicDirectCandidate {
		t.Fatal("PublicDirectCandidate was not propagated to nat ICE config")
	}
	if recorder.cfg.CandidatePortMin != 40000 || recorder.cfg.CandidatePortMax != 40000 {
		t.Fatalf("public direct candidate port range = %d-%d, want hint override 40000-40000", recorder.cfg.CandidatePortMin, recorder.cfg.CandidatePortMax)
	}
	if len(recorder.cfg.CandidateCIDRInclude) != 1 || recorder.cfg.CandidateCIDRInclude[0] != "192.168.1.20/32" {
		t.Fatalf("public direct candidate CIDR include = %#v, want mapped hint local base override", recorder.cfg.CandidateCIDRInclude)
	}
	if len(recorder.cfg.PublicDirectTrustedCIDRs) != 2 ||
		recorder.cfg.PublicDirectTrustedCIDRs[0] != "100.64.0.0/10" ||
		recorder.cfg.PublicDirectTrustedCIDRs[1] != "198.18.0.0/15" {
		t.Fatalf("public direct trusted CIDRs = %#v, want merged configured trusted CIDRs", recorder.cfg.PublicDirectTrustedCIDRs)
	}
}

func TestLegacyICEStrategyConfigMergesRuntimePublicEndpointHints(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.PublicEndpointHints = []string{"117.48.146.2:41000/192.168.1.20:40000"}
	eng := &engine{
		cfg: cfg,
		runtimePublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:41001/192.168.1.20:40001",
		},
	}

	legacyCfg := eng.legacyICEStrategyConfig()
	want := []string{
		"117.48.146.2:41000/192.168.1.20:40000",
		"117.48.146.3:41001/192.168.1.20:40001",
	}
	if !slices.Equal(legacyCfg.PublicEndpointHints, want) {
		t.Fatalf("PublicEndpointHints = %#v, want %#v", legacyCfg.PublicEndpointHints, want)
	}
}

func TestStrategyResolverBuildUsesCurrentRuntimePublicEndpointHints(t *testing.T) {
	cfg := config.Default()
	eng := &engine{
		cfg: cfg,
		runtimePublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
			"117.48.146.3:41001/192.168.1.20:40001",
		},
	}
	resolver := eng.newStrategyResolver()

	eng.runtimePublicEndpointHints = []string{
		"117.48.146.4:41002/192.168.1.21:40000",
		"117.48.146.5:41003/192.168.1.22:40000",
	}
	strategy, _, err := resolver.Resolve(rproto.Capability{Strategies: []string{legacyice.StrategyName}}, true)
	if err != nil {
		t.Fatalf("Resolve(legacy) error = %v", err)
	}
	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		RemoteNodeID: "node-b",
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	hints := publicEndpointHintPlanMetadata(plans)
	want := []string{
		"117.48.146.4:41002/192.168.1.21:40000",
		"117.48.146.5:41003/192.168.1.22:40000",
	}
	if !slices.Equal(hints, want) {
		t.Fatalf("planned public endpoint hints = %#v, want current runtime hints %#v", hints, want)
	}
}

func TestLegacyICEStrategyConfigWidensEndpointHintWindowForSymmetricNAT(t *testing.T) {
	cfg := config.Default()
	eng := &engine{
		cfg: cfg,
		status: EngineStatus{
			NATType: nat.NATTypeSymmetric.String(),
		},
		runtimePublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
		},
	}

	legacyCfg := eng.legacyICEStrategyConfig()
	if legacyCfg.PublicEndpointHintPortWindow != symmetricPublicEndpointHintPortWindow {
		t.Fatalf("PublicEndpointHintPortWindow = %d, want symmetric window %d", legacyCfg.PublicEndpointHintPortWindow, symmetricPublicEndpointHintPortWindow)
	}
}

func TestLegacyICEStrategyConfigWidensEndpointHintWindowForUnknownNAT(t *testing.T) {
	cfg := config.Default()
	eng := &engine{
		cfg: cfg,
		status: EngineStatus{
			NATType: nat.NATTypeUnknown.String(),
		},
		runtimePublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
		},
	}

	legacyCfg := eng.legacyICEStrategyConfig()
	if legacyCfg.PublicEndpointHintPortWindow != symmetricPublicEndpointHintPortWindow {
		t.Fatalf("PublicEndpointHintPortWindow = %d, want unclassified runtime hint window %d", legacyCfg.PublicEndpointHintPortWindow, symmetricPublicEndpointHintPortWindow)
	}
}

func TestLegacyICEStrategyConfigKeepsEndpointHintWindowForNoNAT(t *testing.T) {
	cfg := config.Default()
	eng := &engine{
		cfg: cfg,
		status: EngineStatus{
			NATType: nat.NATTypeNone.String(),
		},
		runtimePublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
		},
	}

	legacyCfg := eng.legacyICEStrategyConfig()
	if legacyCfg.PublicEndpointHintPortWindow != cfg.NAT.PublicEndpointHintPortWindow {
		t.Fatalf("PublicEndpointHintPortWindow = %d, want configured %d", legacyCfg.PublicEndpointHintPortWindow, cfg.NAT.PublicEndpointHintPortWindow)
	}
}

func TestLegacyICEStrategyConfigHonorsEndpointHintWindowOptOut(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.PublicEndpointHintPortWindow = 0
	eng := &engine{
		cfg: cfg,
		status: EngineStatus{
			NATType: nat.NATTypeSymmetric.String(),
		},
		runtimePublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
		},
	}

	legacyCfg := eng.legacyICEStrategyConfig()
	if legacyCfg.PublicEndpointHintPortWindow != 0 {
		t.Fatalf("PublicEndpointHintPortWindow = %d, want explicit opt-out 0", legacyCfg.PublicEndpointHintPortWindow)
	}
}

func TestLegacyICEStrategyConfigKeepsLargerEndpointHintWindow(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.PublicEndpointHintPortWindow = symmetricPublicEndpointHintPortWindow + 1
	eng := &engine{
		cfg: cfg,
		status: EngineStatus{
			NATType: nat.NATTypeSymmetric.String(),
		},
		runtimePublicEndpointHints: []string{
			"117.48.146.2:41000/192.168.1.20:40000",
		},
	}

	legacyCfg := eng.legacyICEStrategyConfig()
	if legacyCfg.PublicEndpointHintPortWindow != cfg.NAT.PublicEndpointHintPortWindow {
		t.Fatalf("PublicEndpointHintPortWindow = %d, want configured %d", legacyCfg.PublicEndpointHintPortWindow, cfg.NAT.PublicEndpointHintPortWindow)
	}
}

func TestRefreshRuntimePublicEndpointHintsUpdatesRuntimeState(t *testing.T) {
	cfg := config.Default()
	recorder := &recordingNATTraversal{
		report: nat.STUNMappingReport{
			NATType: nat.NATTypeUnknown,
			Probes: []nat.STUNMappingProbe{{
				LocalAddr:  &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000},
				MappedAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 44), Port: 45678},
				ServerAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 3478},
			}},
		},
	}
	eng := &engine{
		cfg: cfg,
		nat: recorder,
		status: EngineStatus{
			NATType: nat.NATTypeSymmetric.String(),
		},
		runtimePublicEndpointHints: []string{"117.48.146.2:41000/192.168.1.20:40000"},
	}

	eng.refreshRuntimePublicEndpointHints(context.Background(), "test")

	if recorder.detectCalls != 1 {
		t.Fatalf("DetectSTUNMapping calls = %d, want 1", recorder.detectCalls)
	}
	if eng.status.NATType != nat.NATTypeUnknown.String() {
		t.Fatalf("NATType = %q, want %q", eng.status.NATType, nat.NATTypeUnknown.String())
	}
	want := []string{"198.51.100.44:45678/192.168.1.20:40000"}
	if !slices.Equal(eng.runtimePublicEndpointHints, want) {
		t.Fatalf("runtimePublicEndpointHints = %#v, want %#v", eng.runtimePublicEndpointHints, want)
	}
}

func TestRefreshRuntimePublicEndpointHintsPreservesHintsOnError(t *testing.T) {
	cfg := config.Default()
	recorder := &recordingNATTraversal{
		detectErr: errors.New("stun timeout"),
	}
	eng := &engine{
		cfg: cfg,
		nat: recorder,
		status: EngineStatus{
			NATType: nat.NATTypeSymmetric.String(),
		},
		runtimePublicEndpointHints: []string{"117.48.146.2:41000/192.168.1.20:40000"},
	}

	eng.refreshRuntimePublicEndpointHints(context.Background(), "test")

	if recorder.detectCalls != 1 {
		t.Fatalf("DetectSTUNMapping calls = %d, want 1", recorder.detectCalls)
	}
	want := []string{"117.48.146.2:41000/192.168.1.20:40000"}
	if !slices.Equal(eng.runtimePublicEndpointHints, want) {
		t.Fatalf("runtimePublicEndpointHints = %#v, want preserved hints %#v", eng.runtimePublicEndpointHints, want)
	}
	if eng.status.NATType != nat.NATTypeSymmetric.String() {
		t.Fatalf("NATType = %q, want preserved %q", eng.status.NATType, nat.NATTypeSymmetric.String())
	}
}

func TestRefreshRuntimePublicEndpointHintsPreservesHintsOnEmptyResult(t *testing.T) {
	cfg := config.Default()
	recorder := &recordingNATTraversal{
		report: nat.STUNMappingReport{NATType: nat.NATTypeUnknown},
	}
	eng := &engine{
		cfg: cfg,
		nat: recorder,
		status: EngineStatus{
			NATType: nat.NATTypeSymmetric.String(),
		},
		runtimePublicEndpointHints: []string{"117.48.146.2:41000/192.168.1.20:40000"},
	}

	eng.refreshRuntimePublicEndpointHints(context.Background(), "test")

	if recorder.detectCalls != 1 {
		t.Fatalf("DetectSTUNMapping calls = %d, want 1", recorder.detectCalls)
	}
	want := []string{"117.48.146.2:41000/192.168.1.20:40000"}
	if !slices.Equal(eng.runtimePublicEndpointHints, want) {
		t.Fatalf("runtimePublicEndpointHints = %#v, want preserved hints %#v", eng.runtimePublicEndpointHints, want)
	}
	if eng.status.NATType != nat.NATTypeUnknown.String() {
		t.Fatalf("NATType = %q, want updated %q", eng.status.NATType, nat.NATTypeUnknown.String())
	}
}

func TestRefreshRuntimePublicEndpointHintsHonorsOptOut(t *testing.T) {
	cfg := config.Default()
	cfg.NAT.AutoPublicEndpointHints = false
	recorder := &recordingNATTraversal{
		report: nat.STUNMappingReport{NATType: nat.NATTypeUnknown},
	}
	eng := &engine{
		cfg:                        cfg,
		nat:                        recorder,
		runtimePublicEndpointHints: []string{"117.48.146.2:41000/192.168.1.20:40000"},
	}

	eng.refreshRuntimePublicEndpointHints(context.Background(), "test")

	if recorder.detectCalls != 0 {
		t.Fatalf("DetectSTUNMapping calls = %d, want 0 when auto hints disabled", recorder.detectCalls)
	}
}

func TestRuntimePublicEndpointHintsFromReportUsesDefaultAndAllowsOptOut(t *testing.T) {
	report := nat.STUNMappingReport{
		NATType: nat.NATTypeUnknown,
		Probes: []nat.STUNMappingProbe{{
			LocalAddr:  &net.UDPAddr{IP: net.IPv4(192, 168, 1, 20), Port: 40000},
			MappedAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 44), Port: 45678},
			ServerAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 3478},
		}},
	}
	cfg := config.Default().NAT
	if got := runtimePublicEndpointHintsFromReport(cfg, report); len(got) != 1 || got[0] != "198.51.100.44:45678/192.168.1.20:40000" {
		t.Fatalf("runtimePublicEndpointHintsFromReport(default) = %#v, want stable hint", got)
	}

	cfg.AutoPublicEndpointHints = false
	if got := runtimePublicEndpointHintsFromReport(cfg, report); len(got) != 0 {
		t.Fatalf("runtimePublicEndpointHintsFromReport(auto disabled) = %#v, want none", got)
	}

	cfg.AutoPublicEndpointHints = true
	if got := runtimePublicEndpointHintsFromReport(cfg, report); len(got) != 1 || got[0] != "198.51.100.44:45678/192.168.1.20:40000" {
		t.Fatalf("runtimePublicEndpointHintsFromReport(stable) = %#v, want stable hint", got)
	}

	report.NATType = nat.NATTypeSymmetric
	if got := runtimePublicEndpointHintsFromReport(cfg, report); len(got) != 1 || got[0] != "198.51.100.44:45678/192.168.1.20:40000" {
		t.Fatalf("runtimePublicEndpointHintsFromReport(symmetric) = %#v, want best-effort hint", got)
	}
}

func TestRuntimePublicEndpointHintsFromReportHonorsTrustedCIDRs(t *testing.T) {
	report := nat.STUNMappingReport{
		NATType: nat.NATTypeUnknown,
		Probes: []nat.STUNMappingProbe{{
			LocalAddr:  &net.UDPAddr{IP: net.IPv4(100, 102, 17, 35), Port: 40000},
			MappedAddr: &net.UDPAddr{IP: net.IPv4(100, 102, 17, 36), Port: 45678},
			ServerAddr: &net.UDPAddr{IP: net.IPv4(100, 102, 17, 1), Port: 3478},
		}},
	}
	cfg := config.Default().NAT
	if got := runtimePublicEndpointHintsFromReport(cfg, report); len(got) != 0 {
		t.Fatalf("runtimePublicEndpointHintsFromReport(default) = %#v, want no untrusted non-public hint", got)
	}

	cfg.CandidateCIDRInclude = []string{"100.64.0.0/10"}
	if got := runtimePublicEndpointHintsFromReport(cfg, report); len(got) != 1 || got[0] != "100.102.17.36:45678/100.102.17.35:40000" {
		t.Fatalf("runtimePublicEndpointHintsFromReport(candidate include) = %#v, want included non-public hint", got)
	}

	cfg = config.Default().NAT
	cfg.DirectTrustedCIDRs = []string{"100.64.0.0/10"}
	if got := runtimePublicEndpointHintsFromReport(cfg, report); len(got) != 1 || got[0] != "100.102.17.36:45678/100.102.17.35:40000" {
		t.Fatalf("runtimePublicEndpointHintsFromReport(trusted) = %#v, want trusted non-public hint", got)
	}
}

type recordingNATTraversal struct {
	cfg         nat.ICEConfig
	report      nat.STUNMappingReport
	detectErr   error
	detectCalls int
}

func (r *recordingNATTraversal) DetectNATType(context.Context) (nat.NATType, error) {
	return nat.NATTypeUnknown, nil
}

func (r *recordingNATTraversal) DetectSTUNMapping(context.Context) (nat.STUNMappingReport, error) {
	r.detectCalls++
	if r.detectErr != nil {
		return nat.STUNMappingReport{}, r.detectErr
	}
	return r.report, nil
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

func publicEndpointHintPlanMetadata(plans []solver.Plan) []string {
	out := make([]string, 0)
	for _, plan := range plans {
		if plan.Metadata == nil {
			continue
		}
		if value := plan.Metadata["public_endpoint_hints"]; value != "" {
			out = append(out, value)
		}
	}
	return out
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
