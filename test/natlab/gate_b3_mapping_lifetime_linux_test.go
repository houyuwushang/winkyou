//go:build linux && natlab

package natlab

import (
	"context"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/hardnatbudget"
)

type gateB3LifetimeCase struct {
	seconds    int
	early      bool
	winnerLeft bool
	layer      string
	point      string
}

// Both peers keep the exact same frozen candidate schedule. The emulator
// orders only creation/egress of the first reciprocal NAT tuple: the future
// winner sends first, before the other NAT opens that reverse filter. This
// gives one genuine incoming hit without a candidate-aware drop rule, packet
// duplication, retry or extension of the existing mapping-plan 2s barrier.
type gateB3OrderedEarlyMappingPlan struct {
	base      *gateB3LateHitMappingPlan
	firstLeft bool
	firstSent chan struct{}
	once      sync.Once
}

func (plan *gateB3OrderedEarlyMappingPlan) preferred(ctx context.Context, left bool, target uint16) (uint16, error) {
	plan.base.mu.Lock()
	side := 1
	if left {
		side = 0
	}
	first := plan.base.counts[side] == 0
	plan.base.mu.Unlock()
	if first {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}
	port, err := plan.base.preferred(ctx, left, target)
	if err != nil || !first || left == plan.firstLeft {
		return port, err
	}
	select {
	case <-plan.firstSent:
		return port, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (plan *gateB3OrderedEarlyMappingPlan) forwarded(left bool) {
	if left == plan.firstLeft {
		plan.once.Do(func() { close(plan.firstSent) })
	}
}

func TestLinuxGateB3MappingLifetimeProof(t *testing.T) {
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	t.Run("pure_model", TestGateB3LifetimePureModel)
	t.Run("namespace_restoration_after_child_crash", func(t *testing.T) { testGateB3ChildKillLifetime(t, true) })
	for _, test := range []struct {
		name string
		cfg  gateB3LifetimeCase
		loss uint64
	}{
		{"M_S_early_initiator", gateB3LifetimeCase{seconds: 60, early: true, winnerLeft: true, layer: "M-S"}, 0},
		{"M_S_early_responder", gateB3LifetimeCase{seconds: 60, early: true, winnerLeft: false, layer: "M-S"}, 0},
		{"M_S_tail", gateB3LifetimeCase{seconds: 60, layer: "M-S"}, 0},
		{"M_S_full_exhaustion", gateB3LifetimeCase{seconds: 60, layer: "M-S"}, 1},
		{"M_S_fifty_percent_candidate_loss", gateB3LifetimeCase{seconds: 60, layer: "M-S"}, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			testGateB3FullShapeLifetime(t, test.loss, gateB3ConntrackCap, false, &test.cfg)
		})
	}
	t.Run("M_E_negative_vector_contract", testGateB3ExpiryContract)
	for _, winnerLeft := range []bool{false, true} {
		name := "M_E_responder_winner"
		if winnerLeft {
			name = "M_E_initiator_winner_unmeasured_contract"
		}
		if !t.Run(name, func(t *testing.T) {
			cfg := gateB3LifetimeCase{seconds: 30, early: true, winnerLeft: winnerLeft, layer: "M-E"}
			testGateB3FullShapeLifetime(t, 0, gateB3ConntrackCap, false, &cfg)
		}) {
			// A different observed role/frame shape requires adjudication, not
			// a changed ADR row or progression into M-X to hide this failure.
			return
		}
	}
	for _, point := range []string{"before_selection", "before_winner"} {
		t.Run("M_X_single_side_filter_"+point, func(t *testing.T) {
			cfg := gateB3LifetimeCase{seconds: 60, early: true, winnerLeft: false, layer: "M-X", point: point}
			testGateB3FullShapeLifetime(t, 0, gateB3ConntrackCap, false, &cfg)
		})
	}
}

func configureGateB3LifetimeCase(cfg gateB3LifetimeCase, left, right *gateB2NATConfig) {
	if cfg.early {
		base := newGateB3LateHitMappingPlan()
		base.hitOrdinal = 0
		plan := &gateB3OrderedEarlyMappingPlan{base: base, firstLeft: cfg.winnerLeft, firstSent: make(chan struct{})}
		left.gateB3MappingPlan, left.gateB3MappingPlanLeft = plan, true
		right.gateB3MappingPlan = plan
	}
}

func assertGateB3LifetimeStable(t *testing.T, cfg gateB3LifetimeCase, left, right gateB3EndpointResult,
	leftModel, rightModel *gateB3NATLifetime,
) {
	t.Helper()
	if left.CandidatePackets != hardnatbudget.Hard16CandidatePackets || right.CandidatePackets != hardnatbudget.Hard16CandidatePackets {
		t.Fatal("mapping lifetime did not consume both complete frozen schedules")
	}
	if cfg.early && (left.WinnerPackets != boolGateB3Int(cfg.winnerLeft) || right.WinnerPackets != boolGateB3Int(!cfg.winnerLeft)) {
		t.Fatal("mapping lifetime initial tuple ordering did not select the requested winner direction")
	}
	for side, endpoint := range []gateB3EndpointResult{left, right} {
		model := []*gateB3NATLifetime{leftModel, rightModel}[side]
		model.mu.Lock()
		flow, age, refresh, sentAt, failed := model.winner, model.age, model.refresh, model.sentAt, model.failure != nil
		model.mu.Unlock()
		if failed {
			t.Error("mapping lifetime independent observer failed")
		}
		if cfg.layer == "M-S" && endpoint.WinnerPackets == 1 && (!flow.present || flow.presentAt.IsZero() || !flow.goneAt.IsZero() ||
			refresh != 1 || age >= model.idle || sentAt.Sub(flow.sampledAt) > 1500*time.Millisecond) {
			t.Error("mapping lifetime stable winner lacked unchanged live reverse-flow evidence")
		}
		t.Logf("mapping lifetime endpoint: layer=%s role=%s class=%s stage=%s evidence=%d candidates=%d winner=%d udp=%d frames=%d/%d bytes=%d/%d mapping_age_ms=%d reverse_seen=%t reverse_gone=%t reverse_present_before_winner=%t samples=%d prewinner_tuple_outbounds=%d local_deadline=%t",
			cfg.layer, endpoint.Role, endpoint.ErrorClass, endpoint.ErrorStage, endpoint.EvidencePackets, endpoint.CandidatePackets,
			endpoint.WinnerPackets, endpoint.UDPPackets, endpoint.CarrierFramesRead, endpoint.CarrierFramesWrite,
			endpoint.CarrierBytesRead, endpoint.CarrierBytesWrite, age.Milliseconds(), !flow.presentAt.IsZero(), !flow.goneAt.IsZero(), flow.present, flow.samples, refresh, endpoint.LocalDeadline)
	}
}

func boolGateB3Int(value bool) int {
	if value {
		return 1
	}
	return 0
}
