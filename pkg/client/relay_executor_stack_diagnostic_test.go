package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

var executorStackCase atomic.Uint64

type executorStackSample struct {
	BeginNS   int64    `json:"begin_ns"`
	CaptureNS int64    `json:"capture_ns"`
	Truncated bool     `json:"truncated"`
	Stacks    []string `json:"stacks"`
}

// Separate diagnostic instrument: no runtime/trace, no changes to the original
// fixture or engine. A bounded 500ms stack sampler distinguishes long file
// syscalls from executor/select/lock waits without tracing every CPU yield.
func TestRelayExecutorStackDiagnostic(t *testing.T) {
	root := os.Getenv("WINKYOU_124_EXECUTOR_STACK_DIR")
	if root == "" || os.Getenv("WINKYOU_FLAKE_97_CPU_STRESS") != "1" {
		t.Skip("private opt-in stack diagnosis only")
	}
	index := executorStackCase.Add(1)
	file, err := os.OpenFile(filepath.Join(root, fmt.Sprintf("stack-case-%03d.jsonl", index)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("exclusive private stack file open failed")
	}
	start := time.Now()
	stop, done := make(chan struct{}), make(chan struct{})
	var samples []executorStackSample
	var overflow int
	go func() {
		defer close(done)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		buf := make([]byte, 2<<20)
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if len(samples) >= 256 {
					overflow++
					continue
				}
				at := time.Now()
				n := runtime.Stack(buf, true)
				sample := executorStackSample{BeginNS: at.Sub(start).Nanoseconds(), CaptureNS: time.Since(at).Nanoseconds(), Truncated: n == len(buf)}
				for _, stack := range bytes.Split(buf[:n], []byte("\n\n")) {
					if bytes.Contains(stack, []byte("winkyou/pkg/")) && !bytes.Contains(stack, []byte("TestRelayExecutorStackDiagnostic.func")) && !bytes.Contains(stack, []byte("startRelayCPUPressure.func")) {
						sample.Stacks = append(sample.Stacks, string(stack))
					}
				}
				samples = append(samples, sample)
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
		encoder := json.NewEncoder(file)
		var maxCapture int64
		var truncated bool
		for _, sample := range samples {
			if err := encoder.Encode(sample); err != nil {
				t.Error("private stack evidence write failed")
				break
			}
			if sample.CaptureNS > maxCapture {
				maxCapture = sample.CaptureNS
			}
			truncated = truncated || sample.Truncated
		}
		if err := file.Close(); err != nil {
			t.Error("private stack evidence close failed")
		}
		t.Logf("EXECUTOR_STACK_DIAGNOSTIC index=%d failed=%t samples=%d sampler_workers=0 overflow=%d truncated=%t max_capture_ns=%d", index, t.Failed(), len(samples), overflow, truncated, maxCapture)
		if overflow != 0 || truncated {
			t.Error("incomplete diagnostic evidence; not a product failure classification")
		}
	})
	TestRelayWGGoTwoEnginesExchangeIPv4Packets(t)
}
