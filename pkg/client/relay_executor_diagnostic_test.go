package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/trace"
	"sync/atomic"
	"testing"
)

// Opt-in diagnosis, not another acceptance oracle. Call the original loopback
// fixture verbatim; no product hooks, overlays, timers, budgets or retry changes.
// Each original run including its cleanup gets one exclusive private trace.
var executorDiagnosticCase atomic.Uint64

func TestRelayExecutorDiagnosticTrace(t *testing.T) {
	root := os.Getenv("WINKYOU_124_EXECUTOR_TRACE_DIR")
	if root == "" || os.Getenv("WINKYOU_FLAKE_97_CPU_STRESS") != "1" {
		t.Skip("private opt-in executor diagnosis only")
	}
	index := executorDiagnosticCase.Add(1)
	file, err := os.OpenFile(filepath.Join(root, fmt.Sprintf("case-%03d.out", index)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("exclusive private trace open failed")
	}
	if err := trace.Start(file); err != nil {
		_ = file.Close()
		t.Fatal("private trace start failed")
	}
	region := trace.StartRegion(context.Background(), "original-relay-fixture-and-cleanup")
	t.Cleanup(func() {
		region.End()
		trace.Stop()
		if err := file.Close(); err != nil {
			t.Error("private trace close failed")
		}
		t.Logf("EXECUTOR_DIAGNOSTIC_CASE index=%d failed=%t trace_closed=true", index, t.Failed())
	})
	TestRelayWGGoTwoEnginesExchangeIPv4Packets(t)
}
