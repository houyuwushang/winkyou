package session

import (
	"fmt"
	"sort"
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
	DirectStrategy       string
	RelayStrategy        string
	PinnedFirstStrategy  string
}

type FactoryPortfolioResolver struct {
	capability rproto.Capability
	order      []string
	factories  map[string]func() solver.Strategy
	policy     PortfolioResolverPolicy
}

const recentStrategyObservationLimit = 32

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

func (r *PortfolioResolver) ResolveAll(input ResolveInput) ([]StrategyCandidate, error) {
	if r == nil {
		return nil, fmt.Errorf("session: strategy portfolio resolver is nil")
	}

	names := mutualStrategies(strategyEntryNames(r.entries), input.RemoteCapability)
	if len(names) == 0 {
		return nil, fmt.Errorf("session: no mutually supported strategy between local=%v and remote=%v", strategyEntryNames(r.entries), input.RemoteCapability.Strategies)
	}

	candidates := make([]StrategyCandidate, 0, len(names))
	for _, name := range names {
		for _, entry := range r.entries {
			if entry.Name != name {
				continue
			}
			candidates = append(candidates, StrategyCandidate{
				Name:      entry.Name,
				Strategy:  entry.Strategy,
				Selection: Selection{StrategyName: entry.Name, Negotiated: true},
			})
			break
		}
	}
	return candidates, nil
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

func (r *FactoryPortfolioResolver) ResolveAll(input ResolveInput) ([]StrategyCandidate, error) {
	if r == nil {
		return nil, fmt.Errorf("session: factory strategy portfolio resolver is nil")
	}

	names := mutualStrategies(r.order, input.RemoteCapability)
	orderReason := "configured_order"
	if len(names) == 0 {
		if len(input.RemoteCapability.Strategies) == 0 && r.policy.AllowImplicitLegacy && r.policy.CompatibilityDefault != "" {
			strategy, err := r.build(r.policy.CompatibilityDefault)
			if err != nil {
				return nil, err
			}
			return []StrategyCandidate{{
				Name:      r.policy.CompatibilityDefault,
				Strategy:  strategy,
				Selection: Selection{StrategyName: r.policy.CompatibilityDefault, Negotiated: false},
				Reason:    "implicit_legacy_fallback",
			}}, nil
		}
		if len(input.RemoteCapability.Strategies) == 0 {
			return nil, fmt.Errorf("session: remote capability missing and compatibility fallback disabled")
		}
		return nil, fmt.Errorf("session: no mutually supported strategy between local=%v and remote=%v", r.order, input.RemoteCapability.Strategies)
	}
	names, orderReason = orderStrategiesFromObservations(names, input, r.policy)

	candidates := make([]StrategyCandidate, 0, len(names))
	for _, name := range names {
		strategy, err := r.build(name)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, StrategyCandidate{
			Name:      name,
			Strategy:  strategy,
			Selection: Selection{StrategyName: name, Negotiated: true},
			Reason:    orderReason,
		})
	}
	return candidates, nil
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
	mutual := mutualStrategies(localOrder, remote)
	if len(mutual) == 0 {
		return "", false
	}
	return mutual[0], true
}

func mutualStrategies(localOrder []string, remote rproto.Capability) []string {
	if len(remote.Strategies) == 0 {
		return nil
	}
	remoteSet := make(map[string]struct{}, len(remote.Strategies))
	for _, name := range remote.Strategies {
		if name == "" {
			continue
		}
		remoteSet[name] = struct{}{}
	}
	mutual := make([]string, 0, len(localOrder))
	for _, name := range localOrder {
		if _, ok := remoteSet[name]; ok {
			mutual = append(mutual, name)
		}
	}
	return mutual
}

func orderStrategiesFromObservations(names []string, input ResolveInput, policy PortfolioResolverPolicy) ([]string, string) {
	ordered := append([]string(nil), names...)
	if len(ordered) <= 1 {
		return ordered, "single_strategy"
	}
	if policy.PinnedFirstStrategy != "" {
		if pinned := moveStrategyFirst(ordered, policy.PinnedFirstStrategy); pinned != nil {
			return pinned, "pinned:" + policy.PinnedFirstStrategy
		}
	}

	scores, reason := scoreStrategyOrder(ordered, input, policy)
	index := make(map[string]int, len(ordered))
	for i, name := range ordered {
		index[name] = i
	}
	sort.SliceStable(scores, func(i, j int) bool {
		if scores[i].Score == scores[j].Score {
			return index[scores[i].Name] < index[scores[j].Name]
		}
		return scores[i].Score > scores[j].Score
	})
	for i, score := range scores {
		ordered[i] = score.Name
	}
	return ordered, reason
}

func scoreStrategyOrder(names []string, input ResolveInput, policy PortfolioResolverPolicy) ([]StrategyScore, string) {
	scores := make([]StrategyScore, 0, len(names))
	for i, name := range names {
		scores = append(scores, StrategyScore{
			Name:   name,
			Score:  (len(names) - i) * 10,
			Reason: "configured_order",
		})
	}

	directStrategy := strings.TrimSpace(policy.DirectStrategy)
	relayStrategy := strings.TrimSpace(policy.RelayStrategy)
	if directStrategy == "" || relayStrategy == "" {
		return scores, "configured_order"
	}

	evidence := summarizeStrategyOrderEvidence(input, directStrategy, relayStrategy)
	reasons := make([]string, 0, 4)
	for i := range scores {
		switch scores[i].Name {
		case relayStrategy:
			if evidence.RelaySuccesses > 0 {
				scores[i].Score += 30
				reasons = append(reasons, "relay_success")
			}
			if evidence.DirectFailures >= 2 {
				scores[i].Score += 40
				reasons = append(reasons, "direct_failures")
			}
			if evidence.RelayFailures > 0 {
				scores[i].Score -= 20
				reasons = append(reasons, "relay_failure")
			}
		case directStrategy:
			if evidence.DirectSuccesses > 0 {
				scores[i].Score += 30
				reasons = append(reasons, "direct_success")
			}
		}
		if len(reasons) > 0 {
			scores[i].Reason = "observation_scored:" + strings.Join(uniqueStrings(reasons), ",")
		}
	}
	if len(reasons) == 0 {
		return scores, "configured_order"
	}
	return scores, "observation_scored:" + strings.Join(uniqueStrings(reasons), ",")
}

type strategyOrderEvidence struct {
	DirectFailures  int
	DirectSuccesses int
	RelayFailures   int
	RelaySuccesses  int
}

func summarizeStrategyOrderEvidence(input ResolveInput, directStrategy, relayStrategy string) strategyOrderEvidence {
	summary := strategyOrderEvidence{}
	for _, obs := range recentScopedStrategyObservations(input, recentStrategyObservationLimit) {
		switch {
		case observationMatchesStrategyOrPath(obs, relayStrategy, "relay") && observationSuccess(obs):
			summary.RelaySuccesses++
		case observationMatchesStrategyOrPath(obs, relayStrategy, "relay") && observationFailure(obs):
			summary.RelayFailures++
		case observationMatchesStrategyOrPath(obs, directStrategy, "direct") && observationSuccess(obs):
			summary.DirectSuccesses++
		case observationMatchesStrategyOrPath(obs, directStrategy, "") && observationFailure(obs):
			summary.DirectFailures++
		}
	}
	return summary
}

func recentScopedStrategyObservations(input ResolveInput, limit int) []solver.Observation {
	scoped := make([]solver.Observation, 0, len(input.LocalObservations)+len(input.RemoteObservations))
	for _, obs := range input.LocalObservations {
		if observationScopeMatchesResolveInput(obs, input, false) {
			scoped = append(scoped, obs)
		}
	}
	for _, obs := range input.RemoteObservations {
		if observationScopeMatchesResolveInput(obs, input, true) {
			scoped = append(scoped, obs)
		}
	}
	if limit > 0 && len(scoped) > limit {
		return append([]solver.Observation(nil), scoped[len(scoped)-limit:]...)
	}
	return scoped
}

func observationScopeMatchesResolveInput(obs solver.Observation, input ResolveInput, remoteSource bool) bool {
	if input.SessionID == "" || input.LocalNodeID == "" || input.PeerID == "" {
		return false
	}
	if obs.Details == nil {
		return false
	}
	if strings.TrimSpace(obs.Details["session_id"]) != input.SessionID {
		return false
	}
	if remoteSource {
		return strings.TrimSpace(obs.Details["local_node_id"]) == input.PeerID &&
			strings.TrimSpace(obs.Details["remote_node_id"]) == input.LocalNodeID &&
			strings.TrimSpace(obs.Details["peer_id"]) == input.LocalNodeID &&
			strings.TrimSpace(obs.Details["initiator"]) == fmt.Sprintf("%t", !input.Initiator)
	}
	return strings.TrimSpace(obs.Details["local_node_id"]) == input.LocalNodeID &&
		strings.TrimSpace(obs.Details["remote_node_id"]) == input.PeerID &&
		strings.TrimSpace(obs.Details["peer_id"]) == input.PeerID &&
		strings.TrimSpace(obs.Details["initiator"]) == fmt.Sprintf("%t", input.Initiator)
}

func observationMatchesStrategyOrPath(obs solver.Observation, strategy, connectionType string) bool {
	if strategy != "" && obs.Strategy == strategy {
		return true
	}
	return connectionType != "" && obs.ConnectionType == connectionType
}

func observationSuccess(obs solver.Observation) bool {
	switch obs.Event {
	case "candidate_succeeded", "path_selected", "bind_succeeded", "path_committed":
		return true
	default:
		return false
	}
}

func observationFailure(obs solver.Observation) bool {
	if obs.ErrorClass == "timeout" || obs.ErrorClass == "unreachable" {
		return true
	}
	return strings.Contains(obs.Event, "failed")
}

func moveStrategyFirst(names []string, strategy string) []string {
	for i, name := range names {
		if name != strategy {
			continue
		}
		next := make([]string, 0, len(names))
		next = append(next, name)
		next = append(next, names[:i]...)
		next = append(next, names[i+1:]...)
		return next
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
