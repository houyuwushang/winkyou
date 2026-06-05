package client

import (
	"context"
	"strings"
	"time"

	"winkyou/pkg/nat"
	rproto "winkyou/pkg/rendezvous/proto"
	sesspkg "winkyou/pkg/session"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
	"winkyou/pkg/solver/strategy/relayonly"
	"winkyou/pkg/solver/strategy/tcpframed"
)

type ResolverPolicy = sesspkg.PortfolioResolverPolicy

type strategyFactory struct {
	name  string
	build func() solver.Strategy
}

func newStrategyResolver(factories []strategyFactory, policy ResolverPolicy) sesspkg.StrategyResolver {
	return newStrategyResolverWithFeatures(factories, policy, nil)
}

func newStrategyResolverWithFeatures(factories []strategyFactory, policy ResolverPolicy, features []string) sesspkg.StrategyResolver {
	entries := make([]sesspkg.StrategyFactoryEntry, 0, len(factories))
	for _, factory := range factories {
		entries = append(entries, sesspkg.StrategyFactoryEntry{
			Name:  factory.name,
			Build: factory.build,
		})
	}
	resolver, err := sesspkg.NewFactoryPortfolioResolver(entries, policy, features)
	if err != nil {
		panic(err)
	}
	return resolver
}

func (e *engine) newStrategyResolver() sesspkg.StrategyResolver {
	legacyCfg := e.legacyICEStrategyConfig()
	factories := e.strategyFactoriesForOrder(legacyCfg)
	policy := ResolverPolicy{
		CompatibilityDefault: legacyice.StrategyName,
		AllowImplicitLegacy:  true,
		DirectStrategy:       legacyice.StrategyName,
		RelayStrategy:        relayonly.StrategyName,
	}
	if e.relayOnlyMode() {
		policy.PinnedFirstStrategy = relayonly.StrategyName
	}
	return newStrategyResolverWithFeatures(factories, policy, probeFeatures(e.probeRunner() != nil))
}

func (e *engine) strategyFactoriesForOrder(legacyCfg legacyice.Config) []strategyFactory {
	order := e.connectivityStrategyOrder()
	factories := make([]strategyFactory, 0, len(order))
	for _, name := range order {
		switch name {
		case legacyice.StrategyName:
			factories = append(factories, strategyFactory{
				name: legacyice.StrategyName,
				build: func() solver.Strategy {
					return legacyice.New(legacyCfg)
				},
			})
		case relayonly.StrategyName:
			factories = append(factories, strategyFactory{
				name: relayonly.StrategyName,
				build: func() solver.Strategy {
					return relayonly.New(legacyCfg)
				},
			})
		case tcpframed.StrategyName:
			if !e.cfg.TCPFramed.Enabled {
				continue
			}
			tcpCfg := e.tcpFramedStrategyConfig()
			factories = append(factories, strategyFactory{
				name: tcpframed.StrategyName,
				build: func() solver.Strategy {
					return tcpframed.New(tcpCfg)
				},
			})
		}
	}
	return factories
}

func (e *engine) connectivityStrategyOrder() []string {
	order := append([]string(nil), e.cfg.Connectivity.StrategyOrder...)
	if len(order) == 0 {
		order = []string{legacyice.StrategyName, relayonly.StrategyName}
	}
	if e.relayOnlyMode() {
		order = preferRelayOnly(order)
	}
	return ensureLegacyFallback(order)
}

func (e *engine) relayOnlyMode() bool {
	mode := strings.ToLower(strings.TrimSpace(e.cfg.Connectivity.Mode))
	return mode == relayonly.StrategyName || e.cfg.NAT.ForceRelay
}

func (e *engine) legacyICEStrategyConfig() legacyice.Config {
	cfg := legacyice.Config{
		GatherTimeout:  e.iceGatherTimeout(),
		ConnectTimeout: e.iceConnectTimeout(),
		CheckTimeout:   e.iceCheckTimeout(),
		ForceRelay:     e.relayOnlyMode(),
	}
	cfg.NewICEAgent = func(ctx context.Context, req legacyice.AgentRequest) (nat.ICEAgent, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		if e.nat == nil {
			return nil, ErrEngineNotStarted
		}
		return e.nat.NewICEAgent(nat.ICEConfig{
			GatherTimeout:             cfg.GatherTimeout,
			CheckTimeout:              cfg.CheckTimeout,
			ConnectTimeout:            cfg.ConnectTimeout,
			STUNServers:               e.cfg.NAT.STUNServers,
			TURNServers:               toNATTURNServers(e.cfg.NAT.TURNServers),
			Controlling:               req.Controlling,
			CandidateInterfaceInclude: append([]string(nil), e.cfg.NAT.CandidateInterfaceInclude...),
			CandidateInterfaceExclude: append([]string(nil), e.cfg.NAT.CandidateInterfaceExclude...),
			CandidateCIDRInclude:      append([]string(nil), e.cfg.NAT.CandidateCIDRInclude...),
			CandidateCIDRExclude:      append(append([]string(nil), e.cfg.NAT.CandidateCIDRExclude...), req.CandidateCIDRExclude...),
			ForceRelay:                req.ForceRelay,
		})
	}
	return cfg
}

func (e *engine) tcpFramedStrategyConfig() tcpframed.Config {
	return tcpframed.Config{
		ListenAddr:    e.cfg.TCPFramed.ListenAddr,
		AdvertiseAddr: e.cfg.TCPFramed.AdvertiseAddr,
		DialTimeout:   e.cfg.TCPFramed.DialTimeout,
	}
}

func preferRelayOnly(order []string) []string {
	next := []string{relayonly.StrategyName}
	for _, name := range order {
		if name == relayonly.StrategyName {
			continue
		}
		next = append(next, name)
	}
	return next
}

func ensureLegacyFallback(order []string) []string {
	seen := make(map[string]struct{}, len(order)+1)
	next := make([]string, 0, len(order)+1)
	for _, name := range order {
		if strings.TrimSpace(name) == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		next = append(next, name)
	}
	if _, ok := seen[legacyice.StrategyName]; !ok {
		next = append(next, legacyice.StrategyName)
	}
	return next
}

func (e *engine) legacyICERunTimeout() time.Duration {
	return e.iceGatherTimeout() + e.iceConnectTimeout() + e.iceCheckTimeout()
}

func (e *engine) capabilityWaitTimeout() time.Duration {
	return 2 * time.Second
}

func probeFeatures(enabled bool) []string {
	if !enabled {
		return nil
	}
	return []string{
		rproto.FeatureProbeLabV1,
		rproto.FeatureProbeScriptV1,
	}
}
