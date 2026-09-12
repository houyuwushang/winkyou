//go:build linux && natlab

package natlab

import (
	"testing"
	"time"
)

func logGateB3RouterPair(t testing.TB, pair ...*gateB2NATRouter) {
	t.Helper()
	for side, router := range pair {
		if router == nil {
			t.Logf("GATE_B3_NAT_DIAGNOSTIC side=%d available=false", side)
			continue
		}
		snapshot := router.config.gateB3Diagnostic.snapshot()
		t.Logf("GATE_B3_NAT_DIAGNOSTIC side=%d counters=%+v first_failure=%+v query=%+v",
			side, router.Witness(), snapshot.FirstFailure, snapshot.Query)
		for phase, point := range snapshot.Points {
			if point.Seen {
				t.Logf("GATE_B3_NAT_PHASE side=%d phase=%s at_ns=%d error=%+v",
					side, gateB3DiagnosticPhase(phase), point.AtNS, point.Error)
			}
		}
	}
}

// Failure cleanup is independent of scenario/ledger acceptance. Every stage
// runs even when an earlier stage fails. Unknown observations stay invalid;
// none of this changes the original Fatal or treats the scenario as PASS.
func gateB3FailedCaseCleanup(t testing.TB, topology *n2dTopology, observer *gateB2ObserverSet,
	left, right *gateB2NATRouter, initiator, responder *gateB2EndpointProcess,
	monitor *gateB3ConntrackMonitor, guard *gateB3LifetimeGuard, leftModel, rightModel *gateB3NATLifetime,
) {
	t.Helper()
	checks := [gateB3FailureCleanupStageCount]func() bool{
		func() bool {
			initiator.stop()
			responder.stop()
			leftPeak, rightPeak, err := monitor.Stop()
			t.Logf("GATE_B3_NAT_FAILURE_MONITOR peaks=%d/%d valid=%t error=%+v", leftPeak, rightPeak, err == nil, gateB3SafeError(err, nil))
			return err == nil
		},
		func() bool {
			joined := true
			if plan, ok := left.config.gateB3MappingPlan.(*gateB3OrderedEarlyMappingPlan); ok {
				joined = plan.stopObserver()
			}
			var leftErr, rightErr error
			if leftModel != nil {
				leftErr = leftModel.close()
			}
			if rightModel != nil {
				rightErr = rightModel.close()
			}
			t.Logf("GATE_B3_NAT_FAILURE_OBSERVERS denial_joined=%t errors=%+v/%+v", joined, gateB3SafeError(leftErr, nil), gateB3SafeError(rightErr, nil))
			return joined && leftErr == nil && rightErr == nil
		},
		func() bool {
			observerErr, leftErr, rightErr := observer.Close(), left.Close(), right.Close()
			leftClose, rightClose := left.config.gateB3Diagnostic.snapshot().Points[gateB3RouterClose], right.config.gateB3Diagnostic.snapshot().Points[gateB3RouterClose]
			t.Logf("GATE_B3_NAT_FAILURE_CLOSE observer=%+v calls=%s/%s first=%+v/%+v", gateB3SafeError(observerErr, nil),
				gateB2NATDrainClass(leftErr), gateB2NATDrainClass(rightErr), leftClose, rightClose)
			return observerErr == nil && leftClose.Seen && rightClose.Seen && leftClose.Error.Class == "none" && rightClose.Error.Class == "none"
		},
		func() bool {
			before, beforeErr := topology.gateB2PacketCounts()
			time.Sleep(100 * time.Millisecond)
			after, afterErr := topology.gateB2PacketCounts()
			valid := beforeErr == nil && afterErr == nil
			t.Logf("GATE_B3_NAT_FAILURE_PACKETS before=%+v after=%+v valid=%t unchanged=%t errors=%+v/%+v",
				before, after, valid, valid && before == after, gateB3SafeError(beforeErr, nil), gateB3SafeError(afterErr, nil))
			return valid && before == after
		},
		func() bool {
			sockets, processes, err := waitGateB2NoOSResidue(topology, gateB2TerminalMargin)
			t.Logf("GATE_B3_NAT_FAILURE_OS sockets=%d processes=%d valid=%t error=%+v", sockets, processes, err == nil, gateB3SafeError(err, nil))
			return err == nil && sockets == 0 && processes == 0
		},
		func() bool {
			before, after, err := topology.flushConntrack()
			t.Logf("GATE_B3_NAT_FAILURE_CONNTRACK before=%d after=%d valid=%t error=%+v", before, after, err == nil, gateB3SafeError(err, nil))
			return err == nil && after == 0
		},
		func() bool {
			var restored = true
			if guard != nil {
				err := guard.close()
				restored = err == nil
				t.Logf("GATE_B3_NAT_FAILURE_RESTORE valid=%t error=%+v", restored, gateB3SafeError(err, nil))
			}
			cleanupErr := topology.cleanup()
			leakErr := topology.assertNoLeaks()
			t.Logf("GATE_B3_NAT_FAILURE_TOPOLOGY valid=%t errors=%+v/%+v", cleanupErr == nil && leakErr == nil,
				gateB3SafeError(cleanupErr, nil), gateB3SafeError(leakErr, nil))
			return restored && cleanupErr == nil && leakErr == nil
		},
	}
	result := gateB3RunFailureCleanup(checks)
	t.Logf("GATE_B3_NAT_FAILURE_CLEANUP stages=%v ledger_acceptance=false scenario_pass=false", result)
	for _, ok := range result {
		if !ok {
			t.Error("Gate B3 failed-case cleanup has an unsuccessful or unavailable witness (original failure retained)")
			break
		}
	}
}
