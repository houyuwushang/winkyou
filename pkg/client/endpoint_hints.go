package client

import (
	"context"
	"strings"
	"time"

	"winkyou/pkg/logger"
)

const runtimeEndpointHintRefreshTimeout = 750 * time.Millisecond

func (e *engine) refreshRuntimePublicEndpointHints(ctx context.Context, reason string) {
	if e == nil || !e.cfg.NAT.AutoPublicEndpointHints {
		return
	}

	e.mu.RLock()
	traversal := e.nat
	e.mu.RUnlock()
	if traversal == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	detectCtx, cancel := context.WithTimeout(ctx, runtimeEndpointHintRefreshTimeout)
	defer cancel()

	report, err := traversal.DetectSTUNMapping(detectCtx)
	if err != nil {
		if e.log != nil {
			e.log.Debug("runtime public endpoint hint refresh failed", logger.String("reason", reason), logger.Error(err))
		}
		return
	}

	hints := runtimePublicEndpointHintsFromReport(e.cfg.NAT, report)
	e.mu.Lock()
	e.status.NATType = report.NATType.String()
	e.runtimePublicEndpointHints = append([]string(nil), hints...)
	e.mu.Unlock()

	if e.log == nil {
		return
	}
	if len(hints) > 0 {
		e.log.Info("refreshed runtime public endpoint hints", logger.String("reason", reason), logger.String("hints", strings.Join(hints, ",")))
	} else {
		e.log.Debug("refreshed runtime public endpoint hints without usable hints", logger.String("reason", reason), logger.String("nat_type", report.NATType.String()))
	}
}
