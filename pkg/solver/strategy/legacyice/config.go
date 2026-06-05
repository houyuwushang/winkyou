package legacyice

import (
	"context"
	"fmt"
	"strings"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type AgentRequest struct {
	Controlling              bool
	ForceRelay               bool
	CandidatePortMin         uint16
	CandidatePortMax         uint16
	CandidateCIDRInclude     []string
	CandidateCIDRExclude     []string
	PublicDirectTrustedCIDRs []string
	PublicDirectCandidate    bool
}

type ICEAgentFactory func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error)

type Config struct {
	NewICEAgent                  ICEAgentFactory
	GatherTimeout                time.Duration
	ConnectTimeout               time.Duration
	CheckTimeout                 time.Duration
	ForceRelay                   bool
	RelayDisabled                bool
	CandidateCIDRInclude         []string
	PublicEndpointHints          []string
	PublicEndpointHintPortWindow int
	DirectTrustedCIDRs           []string
	PublicDirectTrustedCIDRs     []string
}

type executionMode string

const (
	modeDirectPrefer executionMode = "direct_prefer"
	modePublicDirect executionMode = "public_direct"
	modeRelayOnly    executionMode = "relay_only"

	planMetadataPublicEndpointHints = "public_endpoint_hints"
)

type executorConfig struct {
	Mode                         executionMode
	ForceRelay                   bool
	CandidateCIDRInclude         []string
	CandidateCIDRExclude         []string
	PublicDirectCandidate        bool
	PublicEndpointHints          []string
	PublicEndpointHintPortWindow int
	DirectTrustedCIDRs           []string
	PublicDirectTrustedCIDRs     []string
}

func (c Config) withDefaults() Config {
	if c.GatherTimeout <= 0 {
		c.GatherTimeout = 10 * time.Second
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 25 * time.Second
	}
	if c.CheckTimeout <= 0 {
		c.CheckTimeout = 12 * time.Second
	}
	return c
}

func executorConfigForPlan(plan solver.Plan, cfg Config) (executorConfig, error) {
	switch plan.ID {
	case planIDDirectPrefer:
		return executorConfig{
			Mode:                     modeDirectPrefer,
			ForceRelay:               cfg.ForceRelay,
			DirectTrustedCIDRs:       append([]string(nil), cfg.DirectTrustedCIDRs...),
			PublicDirectTrustedCIDRs: append([]string(nil), cfg.PublicDirectTrustedCIDRs...),
		}, nil
	case planIDPublicDirect:
		return executorConfig{
			Mode:                         modePublicDirect,
			CandidateCIDRInclude:         append([]string(nil), cfg.CandidateCIDRInclude...),
			PublicDirectCandidate:        true,
			PublicEndpointHints:          publicEndpointHintsForPlan(plan, cfg.PublicEndpointHints),
			PublicEndpointHintPortWindow: cfg.PublicEndpointHintPortWindow,
			DirectTrustedCIDRs:           append([]string(nil), cfg.DirectTrustedCIDRs...),
			PublicDirectTrustedCIDRs:     append([]string(nil), cfg.PublicDirectTrustedCIDRs...),
		}, nil
	case planIDRelayOnly:
		return executorConfig{
			Mode:       modeRelayOnly,
			ForceRelay: true,
		}, nil
	default:
		if mode := plan.Metadata["mode"]; mode == string(modeRelayOnly) {
			return executorConfig{Mode: modeRelayOnly, ForceRelay: true}, nil
		}
		if mode := plan.Metadata["mode"]; mode == string(modeDirectPrefer) {
			return executorConfig{
				Mode:                     modeDirectPrefer,
				ForceRelay:               cfg.ForceRelay,
				DirectTrustedCIDRs:       append([]string(nil), cfg.DirectTrustedCIDRs...),
				PublicDirectTrustedCIDRs: append([]string(nil), cfg.PublicDirectTrustedCIDRs...),
			}, nil
		}
		if mode := plan.Metadata["mode"]; mode == string(modePublicDirect) {
			return executorConfig{
				Mode:                         modePublicDirect,
				CandidateCIDRInclude:         append([]string(nil), cfg.CandidateCIDRInclude...),
				PublicDirectCandidate:        true,
				PublicEndpointHints:          publicEndpointHintsForPlan(plan, cfg.PublicEndpointHints),
				PublicEndpointHintPortWindow: cfg.PublicEndpointHintPortWindow,
				DirectTrustedCIDRs:           append([]string(nil), cfg.DirectTrustedCIDRs...),
				PublicDirectTrustedCIDRs:     append([]string(nil), cfg.PublicDirectTrustedCIDRs...),
			}, nil
		}
		return executorConfig{}, fmt.Errorf("legacyice: unsupported plan %q", plan.ID)
	}
}

func publicEndpointHintsForPlan(plan solver.Plan, defaults []string) []string {
	if plan.Metadata != nil {
		if raw, ok := plan.Metadata[planMetadataPublicEndpointHints]; ok {
			return splitPublicEndpointHintsMetadata(raw)
		}
	}
	return append([]string(nil), defaults...)
}

func joinPublicEndpointHintsMetadata(values []string) string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizePublicEndpointHintValue(value)
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	return strings.Join(normalized, ",")
}

func splitPublicEndpointHintsMetadata(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = normalizePublicEndpointHintValue(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func normalizePublicEndpointHintValue(raw string) string {
	return strings.TrimSpace(raw)
}
