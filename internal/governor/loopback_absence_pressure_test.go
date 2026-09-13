package governor_test

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// Opt-in load for #111 only. No network, sleeps, test deadline changes, or
// product hooks. Cleanup joins every worker, including a t.Fatal path.
func startAbsenceCPUPressure(t *testing.T) {
	t.Helper()
	if os.Getenv("WINKYOU_FLAKE_111_CPU_STRESS") != "1" {
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
