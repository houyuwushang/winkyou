package client

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only the named relay test opts into CPU load. No fake clocks, packet loss,
// sleeps, product settings, or deadline changes are used to create pressure.
func startRelayCPUPressure(t *testing.T) {
	t.Helper()
	if os.Getenv("WINKYOU_FLAKE_97_CPU_STRESS") != "1" {
		return
	}
	workers := runtime.NumCPU() * 2
	stop := make(chan struct{})
	var group sync.WaitGroup
	var checksum atomic.Uint64
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(seed uint64) {
			defer group.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for index := 0; index < 65536; index++ {
					seed = seed*6364136223846793005 + 1
				}
				checksum.Add(seed)
				runtime.Gosched()
			}
		}(uint64(worker + 1))
	}
	t.Logf("cpu_stress cores=%d gomaxprocs=%d workers=%d iterations_per_yield=65536", runtime.NumCPU(), runtime.GOMAXPROCS(0), workers)
	t.Cleanup(func() {
		close(stop)
		group.Wait()
		t.Log("cpu_stress workers_remaining=0")
	})
}

// Snapshots are read using the same locks as #94 diagnostics. Only fixed test
// roles, protocol stage names, relative times and booleans leave the helper;
// never an endpoint, node ID, key, process identity or runtime path.
func observeRelayTimeline(t *testing.T, engines ...*engine) func() {
	t.Helper()
	started := time.Now()
	done, joined := make(chan struct{}), make(chan struct{})
	var once sync.Once
	last := make([]string, len(engines))
	sample := func() {
		for index, eng := range engines {
			value := relayTimelineSnapshot(eng)
			if value != last[index] {
				t.Logf("relay_timeline side=%d elapsed_ms=%d %s", index+1, time.Since(started).Milliseconds(), value)
				last[index] = value
			}
		}
	}
	sample()
	go func() {
		defer close(joined)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				sample()
				return
			case <-ticker.C:
				sample()
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(done)
			<-joined
			t.Log("relay_timeline observer_workers=0")
		})
	}
}

func relayTimelineSnapshot(eng *engine) string {
	eng.mu.RLock()
	var sessions []*peerSession
	if eng.peerMgr != nil {
		for _, session := range eng.peerMgr.sessions {
			sessions = append(sessions, session)
		}
	}
	eng.mu.RUnlock()
	var parts []string
	for _, session := range sessions {
		runner := peerSessionRunner(session)
		if runner == nil {
			parts = append(parts, "runner=closed")
			continue
		}
		snapshot := runner.Snapshot()
		session.connectMu.Lock()
		flags := fmt.Sprintf("connecting=%t bound=%t retry_pending=%t retry_ms=%d", session.connecting, session.bound, session.retryPending, session.retryDelay.Milliseconds())
		session.connectMu.Unlock()
		parts = append(parts, fmt.Sprintf("state=%s strategy=%s negotiated=%t capability=%t envelope=%s path_commit=%t %s",
			snapshot.State, snapshot.SelectedStrategy, snapshot.SelectionNegotiated, !snapshot.CapabilityExchangeAt.IsZero(),
			snapshot.LastEnvelopeType, !snapshot.LastPathCommitAt.IsZero(), flags))
	}
	sort.Strings(parts)
	return fmt.Sprintf("sessions=%d [%s]", len(sessions), strings.Join(parts, "; "))
}
