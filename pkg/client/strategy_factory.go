package client

import (
	"context"
	"fmt"
	"time"

	"winkyou/pkg/nat"
	rproto "winkyou/pkg/rendezvous/proto"
	sesspkg "winkyou/pkg/session"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/legacyice"
)

type ResolverPolicy struct {
	CompatibilityDefault string
	AllowImplicitLegacy  bool
}

type strategyFactory struct {
	name  string
	build func() solver.Strategy
}

type strategyResolver struct {
	capability rproto.Capability
	order      []string
	factories  map[string]func() solver.Strategy
	policy     ResolverPolicy
}

func newStrategyResolver(factories []strategyFactory, policy ResolverPolicy) *strategyResolver {
	return newStrategyResolverWithFeatures(factories, policy, nil)
}

func newStrategyResolverWithFeatures(factories []strategyFactory, policy ResolverPolicy, features []string) *strategyResolver {
	order := make([]string, 0, len(factories))
	builders := make(map[string]func() solver.Strategy, len(factories))
	strategies := make([]string, 0, len(factories))
	for _, factory := range factories {
		if factory.name == "" || factory.build == nil {
			continue
		}
		if _, exists := builders[factory.name]; exists {
			continue
		}
		order = append(order, factory.name)
		builders[factory.name] = factory.build
		strategies = append(strategies, factory.name)
	}
	return &strategyResolver{
		capability: rproto.Capability{Strategies: strategies, Features: append([]string(nil), features...)},
		order:      order,
		factories:  builders,
		policy:     policy,
	}
}

func (r *strategyResolver) LocalCapability() rproto.Capability {
	if r == nil {
		return rproto.Capability{}
	}
	return rproto.Capability{
		Strategies: append([]string(nil), r.capability.Strategies...),
		Features:   append([]string(nil), r.capability.Features...),
	}
}

func (r *strategyResolver) Resolve(remote rproto.Capability, initiator bool) (solver.Strategy, sesspkg.Selection, error) {
	_ = initiator
	if r == nil {
		return nil, sesspkg.Selection{}, fmt.Errorf("client: strategy resolver is nil")
	}

	if name, ok := r.firstIntersection(remote); ok {
		strategy, err := r.build(name)
		if err != nil {
			return nil, sesspkg.Selection{}, err
		}
		return strategy, sesspkg.Selection{StrategyName: name, Negotiated: true}, nil
	}

	if len(remote.Strategies) == 0 && r.policy.AllowImplicitLegacy && r.policy.CompatibilityDefault != "" {
		strategy, err := r.build(r.policy.CompatibilityDefault)
		if err != nil {
			return nil, sesspkg.Selection{}, err
		}
		return strategy, sesspkg.Selection{StrategyName: r.policy.CompatibilityDefault, Negotiated: false}, nil
	}

	if len(remote.Strategies) == 0 {
		return nil, sesspkg.Selection{}, fmt.Errorf("client: remote capability missing and compatibility fallback disabled")
	}
	return nil, sesspkg.Selection{}, fmt.Errorf("client: no compatible strategy between local=%v and remote=%v", r.capability.Strategies, remote.Strategies)
}

func (r *strategyResolver) firstIntersection(remote rproto.Capability) (string, bool) {
	if len(remote.Strategies) == 0 {
		return "", false
	}
	remoteSet := make(map[string]struct{}, len(remote.Strategies))
	for _, strategy := range remote.Strategies {
		if strategy == "" {
			continue
		}
		remoteSet[strategy] = struct{}{}
	}
	for _, strategy := range r.order {
		if _, ok := remoteSet[strategy]; ok {
			return strategy, true
		}
	}
	return "", false
}

func (r *strategyResolver) build(name string) (solver.Strategy, error) {
	build, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("client: strategy %q is not registered", name)
	}
	strategy := build()
	if strategy == nil {
		return nil, fmt.Errorf("client: strategy %q builder returned nil", name)
	}
	return strategy, nil
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
