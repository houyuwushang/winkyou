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
	CandidateCIDRExclude  []string
	PublicDirectCandidate bool
}

type ICEAgentFactory func(ctx context.Context, req AgentRequest) (nat.ICEAgent, error)

type Config struct {
	NewICEAgent    ICEAgentFactory
	GatherTimeout  time.Duration
	ConnectTimeout time.Duration
	CheckTimeout   time.Duration
	ForceRelay     bool
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
}

var publicDirectCandidateCIDRExcludes = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"198.18.0.0/15",
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
			CandidateCIDRExclude:  append([]string(nil), publicDirectCandidateCIDRExcludes...),
			PublicDirectCandidate: true,
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
				CandidateCIDRExclude:  append([]string(nil), publicDirectCandidateCIDRExcludes...),
				PublicDirectCandidate: true,
			}, nil
		}
		return executorConfig{}, fmt.Errorf("legacyice: unsupported plan %q", plan.ID)
	}
}
