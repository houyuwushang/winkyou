package client

import (
	"context"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/solver/strategy/legacyice"
)

func (e *engine) newLegacyICEStrategy() *legacyice.Strategy {
	cfg := legacyice.Config{
		GatherTimeout:  e.iceGatherTimeout(),
		ConnectTimeout: e.iceConnectTimeout(),
		CheckTimeout:   e.iceCheckTimeout(),
	}
	cfg.NewICEAgent = func(ctx context.Context, controlling bool) (nat.ICEAgent, error) {
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
			Controlling:    controlling,
			ForceRelay:     e.cfg.NAT.ForceRelay,
		})
	}
	return legacyice.New(cfg)
}

func (e *engine) legacyICERunTimeout() time.Duration {
	return e.iceGatherTimeout() + e.iceConnectTimeout() + e.iceCheckTimeout()
}
