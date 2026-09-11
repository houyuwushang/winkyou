//go:build linux && natlab && c1bproof

package natlab

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Passive, test-only observations of the pidfd-pinned responder. There is no
// signal, retry, packet, product hook or deadline modification here. Neither
// raw /proc content nor identifiers/paths may enter the log.
type gateC1bSignalPipeObservation struct {
	elapsedMillis                     int64
	dead, identity, flagsKnown        bool
	stdinOpen, stdoutOpen, stderrOpen bool
	stdinNonblock, resultAvailable    bool
	stdinReaders, threadSamples       int
}

func observeGateC1bSignalPipes(t *testing.T, descriptor, pid int, namespace, executable os.FileInfo,
	cfg gateC1bHostConfig, started time.Time) {
	t.Helper()
	done := make(chan struct{})
	var observations []gateC1bSignalPipeObservation
	go func() {
		defer close(done)
		defer unix.Close(descriptor)
		for _, offset := range []time.Duration{0, 500 * time.Millisecond, 2250 * time.Millisecond} {
			if delay := time.Until(started.Add(offset)); delay > 0 {
				time.Sleep(delay) // Passive sampler only; no product call waits for it.
			}
			observation := gateC1bSignalPipeObservation{elapsedMillis: time.Since(started).Milliseconds()}
			poll := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
			if count, err := unix.Poll(poll, 0); err != nil {
				observations = append(observations, observation)
				return
			} else if count > 0 && poll[0].Revents&unix.POLLIN != 0 {
				observation.dead = true
				observations = append(observations, observation)
				return
			}
			currentNamespace, namespaceErr := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
			currentExecutable, executableErr := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
			observation.identity = namespaceErr == nil && executableErr == nil &&
				os.SameFile(namespace, currentNamespace) && os.SameFile(executable, currentExecutable)
			if !observation.identity {
				observations = append(observations, observation)
				return // A disappeared or changed process is never sampled by name.
			}
			for fd, state := range []*bool{&observation.stdinOpen, &observation.stdoutOpen, &observation.stderrOpen} {
				_, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
				*state = err == nil
			}
			flags, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/0", pid))
			if err == nil {
				for _, line := range strings.Split(string(flags), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 2 && fields[0] == "flags:" {
						value, parseErr := strconv.ParseUint(fields[1], 8, 64)
						observation.flagsKnown = parseErr == nil
						observation.stdinNonblock = parseErr == nil && value&unix.O_NONBLOCK != 0
					}
				}
			}
			clear(flags)
			threads, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
			if len(threads) > 128 {
				threads = threads[:128] // Hard cap on read-only diagnostic work.
			}
			for _, thread := range threads {
				payload, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/syscall", pid, thread.Name()))
				fields := strings.Fields(string(payload))
				clear(payload)
				if err != nil || len(fields) < 2 {
					continue
				}
				number, numberErr := strconv.ParseUint(fields[0], 0, 64)
				fd, fdErr := strconv.ParseUint(fields[1], 0, 64)
				if numberErr == nil && fdErr == nil {
					observation.threadSamples++
					if number == unix.SYS_READ && fd == 0 {
						observation.stdinReaders++
					}
				}
			}
			var result gateC1bProcessResult
			observation.resultAvailable = readN1JSON(cfg.ResultFile, &result)
			observations = append(observations, observation)
		}
	}()
	t.Cleanup(func() {
		// Joining precedes reading the observations and returning the diagnostic
		// pidfd. This cannot replace or relax the original terminal/residue gates.
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("passive responder pipe diagnostic did not join")
			return
		}
		for _, sample := range observations {
			t.Logf("Gate C1b signal pipe diagnostic: elapsed_ms=%d dead=%t identity=%t flags_known=%t stdin_open=%t stdin_nonblock=%t stdout_open=%t stderr_open=%t stdin_read_syscalls=%d thread_samples=%d result_available=%t",
				sample.elapsedMillis, sample.dead, sample.identity, sample.flagsKnown, sample.stdinOpen,
				sample.stdinNonblock, sample.stdoutOpen, sample.stderrOpen, sample.stdinReaders, sample.threadSamples, sample.resultAvailable)
		}
	})
}
