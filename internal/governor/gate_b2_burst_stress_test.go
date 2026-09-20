package governor_test

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatcontrol"
)

func TestGateB3Hard16CandidateBurstUnderCPUStress(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	var started, stopped sync.Once
	var stop atomic.Bool
	var workers sync.WaitGroup
	start := func() {
		started.Do(func() {
			ready := make(chan struct{}, 2)
			for range 2 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					ready <- struct{}{}
					for !stop.Load() {
					}
				}()
			}
			<-ready
			<-ready
		})
	}
	finish := func() {
		stopped.Do(func() { stop.Store(true); workers.Wait() })
	}
	left, right, closeFixture := newGateB3NATSimFixture(t, 11, 29)
	defer closeFixture()
	defer finish()
	// Preflight/evidence are not the pressure target. Stress starts at the first
	// candidate Write and lasts through both terminals, as in the old-value run.
	left.factory = &gateB2BurstFactory{base: left.factory, start: start}
	right.factory = &gateB2BurstFactory{base: right.factory, start: start}
	outcomes := runGateB3Pair(t, left, right, 12*time.Second, 8*time.Second)
	finish()
	var totalReads uint32
	for label, side := range map[string]*gateB3Side{"left": left, "right": right} {
		side.witness.mu.Lock()
		reads := side.witness.reads
		side.witness.mu.Unlock()
		totalReads += reads
		t.Logf("FLAKE_155_BURST side=%s adapter_candidate_reads=%d", label, reads)
		if snapshot := side.machine.Snapshot(); snapshot.ActiveAttempts != 0 || snapshot.Reserved != (governor.Resources{}) || snapshot.SafetyTrip.BlocksActiveWork {
			t.Errorf("side=%s governor did not drain cleanly", label)
		}
	}
	if totalReads == 0 {
		t.Error("neither endpoint read a candidate during the full-shape burst")
	}
	for _, outcome := range outcomes {
		t.Logf("FLAKE_155_TERMINAL role=%s terminal=%s error=%v candidates=%d", outcome.role, outcome.result.Terminal, outcome.err, outcome.result.Emissions.CandidatePackets)
		if outcome.err != nil || outcome.result.Terminal != "success" || !outcome.result.FinishRecorded || !outcome.result.Bidirectional {
			t.Errorf("side=%s full-shape terminal failed: %v", outcome.role, outcome.err)
		}
	}
}

type gateB2BurstFactory struct {
	base  probeio.Factory
	start func()
}

func (factory *gateB2BurstFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	datagram, err := factory.base.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &gateB2BurstDatagram{Datagram: datagram, start: factory.start}, nil
}

type gateB2BurstDatagram struct {
	probeio.Datagram
	start func()
}

func (datagram *gateB2BurstDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if metadata, err := hardnatcontrol.InspectFrame(packet); err == nil && metadata.Type == hardnatcontrol.FrameCandidate {
		datagram.start()
	}
	return datagram.Datagram.WriteTo(ctx, packet, target)
}
