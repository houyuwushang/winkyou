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

	remoteSet := make(map[string]struct{}, len(remote.Strategies))
	for _, name := range remote.Strategies {
		if name == "" {
			continue
		}
		remoteSet[name] = struct{}{}
	}

	for _, entry := range r.entries {
		if _, ok := remoteSet[entry.Name]; ok {
			return entry.Strategy, Selection{StrategyName: entry.Name, Negotiated: true}, nil
		}
	}

	return nil, Selection{}, fmt.Errorf("session: no mutually supported strategy between local=%v and remote=%v", strategyEntryNames(r.entries), remote.Strategies)
}

func strategyEntryNames(entries []StrategyEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}
