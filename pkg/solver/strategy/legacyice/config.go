package legacyice

import (
	"context"
	"fmt"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type AgentRequest struct {
	Controlling           bool
	ForceRelay            bool
	CandidatePortMin      uint16
	CandidatePortMax      uint16
	CandidateCIDRInclude  []string
	CandidateCIDRExclude  []string
	PublicDirectCandidate bool
}

type ICEAgentFactory func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error)

type Config struct {
	NewICEAgent         ICEAgentFactory
	GatherTimeout       time.Duration
	ConnectTimeout      time.Duration
	CheckTimeout        time.Duration
	ForceRelay          bool
	PublicEndpointHints []string
}

type executionMode string

const (
	modeDirectPrefer executionMode = "direct_prefer"
	modePublicDirect executionMode = "public_direct"
	modeRelayOnly    executionMode = "relay_only"
)

type executorConfig struct {
	Mode                  executionMode
	ForceRelay            bool
	CandidateCIDRExclude  []string
	PublicDirectCandidate bool
	PublicEndpointHints   []string
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
			Mode:       modeDirectPrefer,
			ForceRelay: cfg.ForceRelay,
		}, nil
	case planIDPublicDirect:
		return executorConfig{
			Mode:                  modePublicDirect,
			PublicDirectCandidate: true,
			PublicEndpointHints:   append([]string(nil), cfg.PublicEndpointHints...),
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
			return executorConfig{Mode: modeDirectPrefer, ForceRelay: cfg.ForceRelay}, nil
		}
		if mode := plan.Metadata["mode"]; mode == string(modePublicDirect) {
			return executorConfig{
				Mode:                  modePublicDirect,
				PublicDirectCandidate: true,
				PublicEndpointHints:   append([]string(nil), cfg.PublicEndpointHints...),
			}, nil
		}
		return executorConfig{}, fmt.Errorf("legacyice: unsupported plan %q", plan.ID)
	}
}
