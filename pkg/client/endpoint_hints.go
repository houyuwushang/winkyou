package client

import (
	"context"
	"strings"
	"time"

	"winkyou/pkg/logger"
	"winkyou/pkg/nat"
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
	preservedHints := false
	preservedHintCount := 0
	e.mu.Lock()
	e.status.NATType = report.NATType.String()
	if len(hints) > 0 || len(e.runtimePublicEndpointHints) == 0 {
		e.runtimePublicEndpointHints = append([]string(nil), hints...)
	} else {
		preservedHints = true
		preservedHintCount = len(e.runtimePublicEndpointHints)
	}
	e.mu.Unlock()

	if e.log == nil {
		return
	}
	if len(hints) > 0 {
		e.log.Info("refreshed runtime public endpoint hints", logger.String("reason", reason), logger.String("hints", strings.Join(hints, ",")))
	} else if preservedHints {
		e.log.Debug("refreshed runtime public endpoint hints without usable hints; preserving previous hints", logger.String("reason", reason), logger.String("nat_type", report.NATType.String()), logger.Int("preserved_hint_count", preservedHintCount))
	} else {
		e.log.Debug("refreshed runtime public endpoint hints without usable hints", logger.String("reason", reason), logger.String("nat_type", report.NATType.String()))
	}
}

func (e *engine) learnRuntimePublicEndpointHintFromPeer(endpoint, peerID string) bool {
	if e == nil || !e.cfg.NAT.AutoPublicEndpointHints {
		return false
	}
	hint := nat.PublicEndpointHintFromObservedEndpoint(
		endpoint,
		mergeStrategyTrustedCIDRs(e.cfg.NAT.CandidateCIDRInclude, e.cfg.NAT.DirectTrustedCIDRs, e.cfg.NAT.PublicDirectTrustedCIDRs),
	)
	if hint == "" {
		return false
	}

	e.mu.Lock()
	for _, existing := range e.runtimePublicEndpointHints {
		if strings.TrimSpace(existing) == hint {
			e.mu.Unlock()
			return false
		}
	}
	e.runtimePublicEndpointHints = append(e.runtimePublicEndpointHints, hint)
	e.mu.Unlock()

	if e.log != nil {
		e.log.Info("learned runtime public endpoint hint from in-band path health", logger.String("peer", peerID), logger.String("hint", hint))
	}
	return true
}
