package session

import (
	"fmt"
	"strings"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type StrategyEntry struct {
	Name     string
	Strategy solver.Strategy
}

type PortfolioResolver struct {
	entries []StrategyEntry
}

type StrategyFactoryEntry struct {
	Name  string
	Build func() solver.Strategy
}

type PortfolioResolverPolicy struct {
	CompatibilityDefault string
	AllowImplicitLegacy  bool
}

type FactoryPortfolioResolver struct {
	capability rproto.Capability
	order      []string
	factories  map[string]func() solver.Strategy
	policy     PortfolioResolverPolicy
}

func NewPortfolioResolver(entries []StrategyEntry) (*PortfolioResolver, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("session: strategy portfolio requires at least one strategy")
	}

	seen := make(map[string]struct{}, len(entries))
	validated := make([]StrategyEntry, 0, len(entries))
	for i, entry := range entries {
		if entry.Strategy == nil {
			return nil, fmt.Errorf("session: strategy portfolio entry %d has nil strategy", i)
		}
		if strings.TrimSpace(entry.Name) == "" {
			return nil, fmt.Errorf("session: strategy portfolio entry %d has empty name", i)
		}
		strategyName := entry.Strategy.Name()
		if strings.TrimSpace(strategyName) == "" {
			return nil, fmt.Errorf("session: strategy portfolio entry %d strategy returned empty name", i)
		}
		if entry.Name != strategyName {
			return nil, fmt.Errorf("session: strategy portfolio entry %d name %q does not match strategy name %q", i, entry.Name, strategyName)
		}
		if _, ok := seen[entry.Name]; ok {
			return nil, fmt.Errorf("session: duplicate strategy name %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		validated = append(validated, entry)
	}

	return &PortfolioResolver{entries: validated}, nil
}

func NewFactoryPortfolioResolver(entries []StrategyFactoryEntry, policy PortfolioResolverPolicy, features []string) (*FactoryPortfolioResolver, error) {
	order := make([]string, 0, len(entries))
	factories := make(map[string]func() solver.Strategy, len(entries))
	strategies := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" || entry.Build == nil {
			continue
		}
		if _, exists := factories[name]; exists {
			continue
		}
		order = append(order, name)
		factories[name] = entry.Build
		strategies = append(strategies, name)
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("session: factory strategy portfolio requires at least one valid strategy factory")
	}
	return &FactoryPortfolioResolver{
		capability: rproto.Capability{
			Strategies: strategies,
			Features:   append([]string(nil), features...),
		},
		order:     order,
		factories: factories,
		policy:    policy,
	}, nil
}

func (r *PortfolioResolver) LocalCapability() rproto.Capability {
	if r == nil {
		return rproto.Capability{}
	}
	strategies := make([]string, 0, len(r.entries))
	for _, entry := range r.entries {
		strategies = append(strategies, entry.Name)
	}
	return rproto.Capability{Strategies: strategies}
}

func (r *PortfolioResolver) Resolve(remote rproto.Capability, initiator bool) (solver.Strategy, Selection, error) {
	_ = initiator
	if r == nil {
		return nil, Selection{}, fmt.Errorf("session: strategy portfolio resolver is nil")
	}

	if name, ok := firstMutualStrategy(strategyEntryNames(r.entries), remote); ok {
		for _, entry := range r.entries {
			if entry.Name != name {
				continue
			}
			return entry.Strategy, Selection{StrategyName: entry.Name, Negotiated: true}, nil
		}
	}

	return nil, Selection{}, fmt.Errorf("session: no mutually supported strategy between local=%v and remote=%v", strategyEntryNames(r.entries), remote.Strategies)
}

func (r *FactoryPortfolioResolver) LocalCapability() rproto.Capability {
	if r == nil {
		return rproto.Capability{}
	}
	return rproto.Capability{
		Strategies: append([]string(nil), r.capability.Strategies...),
		Features:   append([]string(nil), r.capability.Features...),
	}
}

func (r *FactoryPortfolioResolver) Resolve(remote rproto.Capability, initiator bool) (solver.Strategy, Selection, error) {
	_ = initiator
	if r == nil {
		return nil, Selection{}, fmt.Errorf("session: factory strategy portfolio resolver is nil")
	}

	if name, ok := firstMutualStrategy(r.order, remote); ok {
		strategy, err := r.build(name)
		if err != nil {
			return nil, Selection{}, err
		}
		return strategy, Selection{StrategyName: name, Negotiated: true}, nil
	}

	if len(remote.Strategies) == 0 && r.policy.AllowImplicitLegacy && r.policy.CompatibilityDefault != "" {
		strategy, err := r.build(r.policy.CompatibilityDefault)
		if err != nil {
			return nil, Selection{}, err
		}
		return strategy, Selection{StrategyName: r.policy.CompatibilityDefault, Negotiated: false}, nil
	}

	if len(remote.Strategies) == 0 {
		return nil, Selection{}, fmt.Errorf("session: remote capability missing and compatibility fallback disabled")
	}
	return nil, Selection{}, fmt.Errorf("session: no mutually supported strategy between local=%v and remote=%v", r.order, remote.Strategies)
}

func (r *FactoryPortfolioResolver) build(name string) (solver.Strategy, error) {
	build, ok := r.factories[name]
	if !ok {
		return nil, fmt.Errorf("session: strategy %q is not registered", name)
	}
	strategy := build()
	if strategy == nil {
		return nil, fmt.Errorf("session: strategy %q factory returned nil", name)
	}
	strategyName := strings.TrimSpace(strategy.Name())
	if strategyName == "" {
		return nil, fmt.Errorf("session: strategy %q factory returned strategy with empty name", name)
	}
	if strategyName != name {
		return nil, fmt.Errorf("session: strategy %q factory returned strategy named %q", name, strategyName)
	}
	return strategy, nil
}

func strategyEntryNames(entries []StrategyEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

func firstMutualStrategy(localOrder []string, remote rproto.Capability) (string, bool) {
	if len(remote.Strategies) == 0 {
		return "", false
	}
	remoteSet := make(map[string]struct{}, len(remote.Strategies))
	for _, name := range remote.Strategies {
		if name == "" {
			continue
		}
		remoteSet[name] = struct{}{}
	}
	for _, name := range localOrder {
		if _, ok := remoteSet[name]; ok {
			return name, true
		}
	}
	return "", false
}
