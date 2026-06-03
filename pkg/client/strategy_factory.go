package client

import (
	"context"
	"time"

	"winkyou/pkg/nat"
	rproto "winkyou/pkg/rendezvous/proto"
	sesspkg "winkyou/pkg/session"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
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
	return newStrategyResolverWithFeatures([]strategyFactory{
		{
			name: legacyice.StrategyName,
			build: func() solver.Strategy {
				return legacyice.New(legacyCfg)
			},
		},
	}, ResolverPolicy{
		CompatibilityDefault: legacyice.StrategyName,
		AllowImplicitLegacy:  true,
	}, probeFeatures(e.probeRunner() != nil))
}

func (e *engine) legacyICEStrategyConfig() legacyice.Config {
	cfg := legacyice.Config{
		GatherTimeout:  e.iceGatherTimeout(),
		ConnectTimeout: e.iceConnectTimeout(),
		CheckTimeout:   e.iceCheckTimeout(),
		ForceRelay:     e.cfg.NAT.ForceRelay,
	}
	cfg.NewICEAgent = func(ctx context.Context, req legacyice.AgentRequest) (nat.ICEAgent, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		if e.nat == nil {
			return nil, ErrEngineNotStarted
		}
		return e.nat.NewICEAgent(nat.ICEConfig{
			GatherTimeout:  cfg.GatherTimeout,
			CheckTimeout:   cfg.CheckTimeout,
			ConnectTimeout: cfg.ConnectTimeout,
			STUNServers:    e.cfg.NAT.STUNServers,
			TURNServers:    toNATTURNServers(e.cfg.NAT.TURNServers),
			Controlling:    req.Controlling,
			ForceRelay:     req.ForceRelay,
		})
	}
	return cfg
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
