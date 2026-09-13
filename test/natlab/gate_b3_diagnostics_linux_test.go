//go:build linux && natlab

package natlab

import (
	"runtime"
	"testing"
	"time"
)

func logGateB3EndpointPair(t testing.TB, pair ...*gateB2EndpointProcess) {
	t.Helper()
	for side, process := range pair {
		if process == nil {
			t.Logf("GATE_B3_ENDPOINT_TERMINAL side=%d available=false", side)
			continue
		}
		snapshot := readGateB3ResultDiagnostic(process.resultPath)
		t.Logf("GATE_B3_ENDPOINT_TERMINAL side=%d non_atomic=true result=%s last_stage=%s error_stage=%s class=%s",
			side, snapshot.State, snapshot.LastStage, snapshot.ErrorStage, snapshot.Class)
	}
}

func logGateB3TailDeliveryPair(t testing.TB, topology *n2dTopology, left, right *gateB2NATRouter, initiator, responder *gateB2EndpointProcess) bool {
	t.Helper()
	ingress := topology.gateB3TailIngressCounts()
	routers := [2]*gateB2NATRouter{left, right}
	processes := [2]*gateB2EndpointProcess{initiator, responder}
	for side, router := range routers {
		peer := routers[1-side]
		if router == nil || peer == nil {
			t.Logf("GATE_B3_TAIL side=%d ordinal=16383 router_available=false", side)
			continue
		}
		var result gateB3EndpointResult
		process := processes[1-side]
		readable := process != nil && readN1JSON(process.resultPath, &result) && result.TailReadWitness
		readCount := int64(-1)
		if readable {
			readCount = int64(result.TailSocketRead)
		}
		peerIngress := int64(-1)
		if ingress[1-side].valid {
			peerIngress = int64(ingress[1-side].packets)
		}
		t.Logf("GATE_B3_TAIL side=%d ordinal=16383 non_atomic=true router_accepted=%d router_queued=%d router_forwarded=%d peer_mapped_read=%d peer_tun_written=%d peer_namespace_delivered=%d peer_namespace_witness=%t peer_socket_read=%d peer_socket_witness=%t queue_capacity=%d queue_sample=%d/%d queue_sampled_peak=%d/%d peer_queue_sample=%d/%d peer_queue_sampled_peak=%d/%d",
			side, router.tailWitness.counts[gateB3TailAccepted].Load(), router.tailWitness.counts[gateB3TailQueued].Load(),
			router.tailWitness.counts[gateB3TailForwarded].Load(), peer.tailWitness.counts[gateB3TailMappedRead].Load(),
			peer.tailWitness.counts[gateB3TailTUNWritten].Load(), peerIngress, ingress[1-side].valid, readCount, readable, router.config.packetQueueCapacity,
			router.tailWitness.level[0].Load(), router.tailWitness.level[1].Load(), router.tailWitness.peak[0].Load(), router.tailWitness.peak[1].Load(),
			peer.tailWitness.level[0].Load(), peer.tailWitness.level[1].Load(), peer.tailWitness.peak[0].Load(), peer.tailWitness.peak[1].Load())
	}
	return ingress[0].valid && ingress[1].valid
}

func logGateB3RouterPair(t testing.TB, pair ...*gateB2NATRouter) {
	t.Helper()
	// Process-wide, point-in-time measurements, not a per-attempt peak and
	// not proof that memory/GC caused a timeout. No forced GC or new worker.
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("GATE_B3_NAT_MEMORY heap_alloc=%d heap_inuse=%d stack_inuse=%d total_alloc=%d num_gc=%d pause_total_ns=%d goroutines=%d",
		memory.HeapAlloc, memory.HeapInuse, memory.StackInuse, memory.TotalAlloc, memory.NumGC, memory.PauseTotalNs, runtime.NumGoroutine())
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
