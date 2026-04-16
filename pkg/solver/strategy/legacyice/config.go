package legacyice

import (
	"context"
	"time"

	"winkyou/pkg/nat"
)

type ICEAgentFactory func(ctx context.Context, controlling bool) (nat.ICEAgent, error)

type Config struct {
	NewICEAgent    ICEAgentFactory
	GatherTimeout  time.Duration
	ConnectTimeout time.Duration
	CheckTimeout   time.Duration
	ForceRelay     bool // If true, only relay candidates will be gathered
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
