package client

import (
	"context"
	"strings"
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

type ResolverPolicy = sesspkg.PortfolioResolverPolicy

type strategyFactory struct {
	name  string
	build func() solver.Strategy
}

const symmetricPublicEndpointHintPortWindow = 16

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
	factories := e.strategyFactoriesForOrder()
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

func (e *engine) strategyFactoriesForOrder() []strategyFactory {
	order := e.connectivityStrategyOrder()
	factories := make([]strategyFactory, 0, len(order))
	for _, name := range order {
		switch name {
		case legacyice.StrategyName:
			factories = append(factories, strategyFactory{
				name: legacyice.StrategyName,
				build: func() solver.Strategy {
					return legacyice.New(e.legacyICEStrategyConfig())
				},
			})
		case relayonly.StrategyName:
			factories = append(factories, strategyFactory{
				name: relayonly.StrategyName,
				build: func() solver.Strategy {
					return relayonly.New(e.legacyICEStrategyConfig())
				},
			})
		case tcpframed.StrategyName:
			if !e.cfg.TCPFramed.Enabled {
				continue
			}
			factories = append(factories, strategyFactory{
				name: tcpframed.StrategyName,
				build: func() solver.Strategy {
					return tcpframed.New(e.tcpFramedStrategyConfig())
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
	} else if e.preferRelayForSymmetricNAT() {
		order = preferRelayOnly(order)
	}
	return ensureLegacyFallback(order)
}

func (e *engine) relayOnlyMode() bool {
	mode := strings.ToLower(strings.TrimSpace(e.cfg.Connectivity.Mode))
	return mode == relayonly.StrategyName || e.cfg.NAT.ForceRelay
}

func (e *engine) preferRelayForSymmetricNAT() bool {
	if !strings.EqualFold(strings.TrimSpace(e.cfg.Connectivity.Mode), "auto") {
		return false
	}
	if !hasTURNServers(e.cfg.NAT.TURNServers) {
		return false
	}
	e.mu.RLock()
	natType := strings.TrimSpace(e.status.NATType)
	e.mu.RUnlock()
	return natType == nat.NATTypeSymmetric.String()
}

func hasTURNServers(servers []config.TURNServerConfig) bool {
	for _, server := range servers {
		if strings.TrimSpace(server.URL) != "" {
			return true
		}
	}
	return false
}

func (e *engine) legacyICEStrategyConfig() legacyice.Config {
	publicEndpointHints := e.publicEndpointHints()
	cfg := legacyice.Config{
		GatherTimeout:                e.iceGatherTimeout(),
		ConnectTimeout:               e.iceConnectTimeout(),
		CheckTimeout:                 e.iceCheckTimeout(),
		ForceRelay:                   e.relayOnlyMode(),
		RelayDisabled:                e.disableLegacyRelayPlan(),
		CandidateCIDRInclude:         append([]string(nil), e.cfg.NAT.CandidateCIDRInclude...),
		PublicEndpointHints:          publicEndpointHints,
		PublicEndpointHintPortWindow: e.publicEndpointHintPortWindow(publicEndpointHints),
		DirectTrustedCIDRs:           append([]string(nil), e.cfg.NAT.DirectTrustedCIDRs...),
		PublicDirectTrustedCIDRs:     append([]string(nil), e.cfg.NAT.PublicDirectTrustedCIDRs...),
	}
	cfg.NewICEAgent = func(ctx context.Context, req legacyice.AgentRequest) (nat.ICEAgent, error) {
		if ctx == nil {
			ctx = context.Background()
		}
		if e.nat == nil {
			return nil, ErrEngineNotStarted
		}
		candidatePortMin := candidatePortValue(e.cfg.NAT.CandidatePortMin)
		candidatePortMax := candidatePortValue(e.cfg.NAT.CandidatePortMax)
		if req.CandidatePortMin > 0 && req.CandidatePortMax > 0 {
			candidatePortMin = req.CandidatePortMin
			candidatePortMax = req.CandidatePortMax
		}
		candidateCIDRInclude := append([]string(nil), e.cfg.NAT.CandidateCIDRInclude...)
		if len(req.CandidateCIDRInclude) > 0 {
			candidateCIDRInclude = append([]string(nil), req.CandidateCIDRInclude...)
		}
		publicDirectTrustedCIDRs := mergeStrategyTrustedCIDRs(e.cfg.NAT.DirectTrustedCIDRs, e.cfg.NAT.PublicDirectTrustedCIDRs)
		if len(req.PublicDirectTrustedCIDRs) > 0 {
			publicDirectTrustedCIDRs = mergeStrategyTrustedCIDRs(req.PublicDirectTrustedCIDRs)
		}
		return e.nat.NewICEAgent(nat.ICEConfig{
			GatherTimeout:             cfg.GatherTimeout,
			CheckTimeout:              cfg.CheckTimeout,
			ConnectTimeout:            cfg.ConnectTimeout,
			CandidatePortMin:          candidatePortMin,
			CandidatePortMax:          candidatePortMax,
			STUNServers:               e.cfg.NAT.STUNServers,
			TURNServers:               toNATTURNServers(e.cfg.NAT.TURNServers),
			Controlling:               req.Controlling,
			CandidateInterfaceInclude: append([]string(nil), e.cfg.NAT.CandidateInterfaceInclude...),
			CandidateInterfaceExclude: append([]string(nil), e.cfg.NAT.CandidateInterfaceExclude...),
			CandidateCIDRInclude:      candidateCIDRInclude,
			CandidateCIDRExclude:      append(append([]string(nil), e.cfg.NAT.CandidateCIDRExclude...), req.CandidateCIDRExclude...),
			NAT1To1IPs:                append([]string(nil), e.cfg.NAT.NAT1To1IPs...),
			NAT1To1CandidateType:      e.cfg.NAT.NAT1To1CandidateType,
			PublicDirectTrustedCIDRs:  publicDirectTrustedCIDRs,
			PublicDirectCandidate:     req.PublicDirectCandidate,
			ForceRelay:                req.ForceRelay,
		})
	}
	return cfg
}

func (e *engine) publicEndpointHints() []string {
	e.mu.RLock()
	runtimeHints := append([]string(nil), e.runtimePublicEndpointHints...)
	e.mu.RUnlock()
	return mergeStrategyTrustedCIDRs(e.cfg.NAT.PublicEndpointHints, runtimeHints)
}

func (e *engine) publicEndpointHintPortWindow(hints []string) int {
	configured := e.cfg.NAT.PublicEndpointHintPortWindow
	if configured <= 0 || len(hints) == 0 || configured >= symmetricPublicEndpointHintPortWindow {
		return configured
	}
	e.mu.RLock()
	natType := strings.TrimSpace(e.status.NATType)
	e.mu.RUnlock()
	switch natType {
	case nat.NATTypeSymmetric.String(), nat.NATTypeUnknown.String():
		return symmetricPublicEndpointHintPortWindow
	}
	return configured
}

func runtimePublicEndpointHintsFromReport(cfg config.NATConfig, report nat.STUNMappingReport) []string {
	if !cfg.AutoPublicEndpointHints {
		return nil
	}
	return nat.PublicEndpointHintsFromSTUNMappingWithAllowedCIDRs(
		report,
		mergeStrategyTrustedCIDRs(cfg.CandidateCIDRInclude, cfg.DirectTrustedCIDRs, cfg.PublicDirectTrustedCIDRs),
	)
}

func (e *engine) disableLegacyRelayPlan() bool {
	return !e.relayOnlyMode() && !hasTURNServers(e.cfg.NAT.TURNServers)
}

func mergeStrategyTrustedCIDRs(lists ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, list := range lists {
		for _, value := range list {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
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

func candidatePortValue(port int) uint16 {
	if port <= 0 || port > 65535 {
		return 0
	}
	return uint16(port)
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
