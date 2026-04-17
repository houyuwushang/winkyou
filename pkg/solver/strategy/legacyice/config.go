package legacyice

import (
	"context"
	"fmt"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver"
)

type AgentRequest struct {
	Controlling bool
	ForceRelay  bool
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
	modeRelayOnly    executionMode = "relay_only"
)

type executorConfig struct {
	Mode       executionMode
	ForceRelay bool
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
	case "legacyice/direct_prefer":
		return executorConfig{
			Mode:       modeDirectPrefer,
			ForceRelay: cfg.ForceRelay,
		}, nil
	case "legacyice/relay_only":
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
		return executorConfig{}, fmt.Errorf("legacyice: unsupported plan %q", plan.ID)
	}
}
