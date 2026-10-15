//go:build linux && natlab

package natlab

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	namespaceLeakAttempts = 200
	namespaceLeakSamples  = 2000
	namespaceLeakBlockers = 64
)

func TestLinuxNamespaceHelperThreadLeak(t *testing.T) {
	requireGateB3Environment(t)
	requireGateB3HostConntrackGuard(t)
	var initial unix.Stat_t
	if err := unix.Stat("/proc/1/ns/net", &initial); err != nil {
		t.Fatal("initial namespace identity unavailable")
	}
	name := fmt.Sprintf("wy177-%x-%x", os.Getpid(), scenarioSequence.Add(1))
	if output, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("thread witness namespace creation failed: %v %s", err, output)
	}
	var owned unix.Stat_t
	if err := unix.Stat(gateB3NamespaceHandle(name), &owned); err != nil {
		t.Fatal("thread witness namespace identity unavailable")
	}
	t.Cleanup(func() {
		var current unix.Stat_t
		if unix.Stat(gateB3NamespaceHandle(name), &current) != nil || current.Dev != owned.Dev || current.Ino != owned.Ino {
			t.Error("thread witness namespace identity changed")
			return
		}
		if err := exec.Command("ip", "netns", "del", name).Run(); err != nil {
			t.Error("thread witness namespace cleanup failed")
		}
	})
	var hits uint64
	maxThreads, attempts := 0, 0
	for attempts < namespaceLeakAttempts && hits == 0 {
		attempts++
		threads := 0
		if err := RunInNamespace(name, func() error {
			var err error
			threads, err = namespaceThreadBlockingWave()
			return err
		}); err != nil {
			t.Fatalf("blocking namespace wave failed: %v", err)
		}
		if threads > maxThreads {
			maxThreads = threads
		}
		observed, failures := namespaceThreadSamples(initial.Ino)
		if failures != 0 {
			t.Fatalf("namespace thread observations failed: count=%d", failures)
		}
		hits += observed
	}
	t.Logf("GATE_B3_THREAD_LEAK attempts=%d samples=%d non_init=%d max_os_threads=%d init_net=%d", attempts, attempts*namespaceLeakSamples, hits, maxThreads, initial.Ino)
	if hits == 0 {
		t.Log("GATE_B3_THREAD_LEAK not_reproduced=true hypothesis_unconfirmed=true")
	}
	// The caller deliberately remains in the child namespace throughout all
	// requests. Each I/O witness must instead identify init, independently of
	// whether this Go runtime reproduced the historical thread-leak hypothesis.
	completed := 0
	err := RunInNamespace(name, func() error {
		for i := 0; i < namespaceLeakSamples; i++ {
			var caller unix.Stat_t
			if unix.Stat("/proc/thread-self/ns/net", &caller) != nil || caller.Ino != owned.Ino {
				return fmt.Errorf("host sysctl caller lost child namespace")
			}
			read := (HostSysctl{}).request("/proc/sys/net/netfilter/nf_conntrack_max", nil, false, false)
			if read.err != nil {
				return read.err
			}
			if read.witness.ThreadNet != initial.Ino || read.witness.InitNet != initial.Ino || string(read.value) != "40000\n" {
				return fmt.Errorf("host sysctl read did not witness guarded init scope")
			}
			write := (HostSysctl{}).request("/proc/sys/net/netfilter/nf_conntrack_max", read.value, true, false)
			if write.err != nil {
				return write.err
			}
			if write.witness.ThreadNet != initial.Ino || write.witness.InitNet != initial.Ino {
				return fmt.Errorf("host sysctl write did not witness init scope")
			}
			if unix.Stat("/proc/thread-self/ns/net", &caller) != nil || caller.Ino != owned.Ino {
				return fmt.Errorf("host sysctl request changed caller namespace")
			}
			completed++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("GATE_B3_HOST_SYSCTL_GREEN completed=%d failure=%v", completed, err)
	}
	t.Logf("GATE_B3_HOST_SYSCTL_GREEN samples=%d reads=%d writes=%d init_net=%d eacces=0 caller_unchanged=true", completed, completed, completed, initial.Ino)
}

// Direct blocking read syscalls release each P and force runtime thread growth.
// Channels coordinate entry and drain; no timing delay or host sysctl is used.
func namespaceThreadBlockingWave() (int, error) {
	pipes := make([][2]int, 0, namespaceLeakBlockers)
	for i := 0; i < namespaceLeakBlockers; i++ {
		var pipe [2]int
		if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
			for _, p := range pipes {
				_ = unix.Close(p[0])
				_ = unix.Close(p[1])
			}
			return 0, err
		}
		pipes = append(pipes, pipe)
	}
	entered := make(chan struct{}, namespaceLeakBlockers)
	finished := make(chan error, namespaceLeakBlockers)
	for _, pipe := range pipes {
		go func(fd int) {
			entered <- struct{}{}
			var data [1]byte
			_, err := unix.Read(fd, data[:])
			finished <- err
		}(pipe[0])
	}
	for range pipes {
		<-entered
	}
	tasks, err := os.ReadDir("/proc/self/task")
	for _, pipe := range pipes {
		_ = unix.Close(pipe[1])
	}
	for range pipes {
		if readErr := <-finished; readErr != nil && err == nil {
			err = readErr
		}
	}
	for _, pipe := range pipes {
		_ = unix.Close(pipe[0])
	}
	return len(tasks), err
}

func namespaceThreadSamples(initial uint64) (uint64, uint64) {
	var hits, failures atomic.Uint64
	var done sync.WaitGroup
	done.Add(namespaceLeakSamples)
	for i := 0; i < namespaceLeakSamples; i++ {
		go func() {
			defer done.Done()
			var thread unix.Stat_t
			if err := unix.Stat("/proc/thread-self/ns/net", &thread); err != nil {
				failures.Add(1)
				return
			}
			if thread.Ino != initial {
				hits.Add(1)
			}
		}()
	}
	done.Wait()
	return hits.Load(), failures.Load()
}
