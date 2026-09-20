package shortcut

import (
	"context"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/mesh"
)

// This witness records only fixed fixture labels, never wire payloads or IDs.
type shortcutBarrierWitness struct {
	mu      sync.Mutex
	started time.Time
	rows    []shortcutBarrierRow
	stable  map[string]bool
}

type shortcutBarrierRow struct {
	ns                                int64
	kind, signal, node, inbound, next string
}

func newShortcutBarrierWitness(t *testing.T) *shortcutBarrierWitness {
	t.Helper()
	w := &shortcutBarrierWitness{started: time.Now(), stable: make(map[string]bool)}
	t.Cleanup(func() {
		if !t.Failed() && os.Getenv("WINKYOU_FLAKE_158_WITNESS") != "1" {
			return
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, row := range w.rows {
			t.Logf("BARRIER_WITNESS relative_ns=%d kind=%s type=%s node=%s inbound=%s next=%s", row.ns, row.kind, row.signal, row.node, row.inbound, row.next)
		}
	})
	return w
}

func barrierLabel(label string) string {
	switch label {
	case "A", "B", "C":
		return label
	default:
		return "none"
	}
}

func (w *shortcutBarrierWitness) record(kind, signal, node, inbound, next string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rows = append(w.rows, shortcutBarrierRow{time.Since(w.started).Nanoseconds(), kind, signal, barrierLabel(node), barrierLabel(inbound), barrierLabel(next)})
}

func (w *shortcutBarrierWitness) route(event mesh.Event) {
	signal := event.Message.SessionSignal
	if signal == nil || signal.Namespace != Namespace {
		return
	}
	switch signal.Type {
	case typePrepareRequest, typePrepare, typeReady, typeFire, typeInstalled, typeCommit, typeStable, typeFailed, typeAbort:
		w.record(string(event.Kind), signal.Type, event.NodeID, event.InboundPeer, event.NextHop)
	}
}

func (w *shortcutBarrierWitness) manager(event Event) {
	if event.Status.Phase != PhaseStable {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	node := barrierLabel(event.NodeID)
	if w.stable[node] {
		return
	}
	w.stable[node] = true
	w.rows = append(w.rows, shortcutBarrierRow{time.Since(w.started).Nanoseconds(), "manager_stable", typeStable, node, "none", "none"})
}

func startShortcutBarrierStress(t *testing.T) {
	t.Helper()
	if os.Getenv("WINKYOU_FLAKE_158_CPU_STRESS") != "1" {
		return
	}
	if runtime.GOMAXPROCS(0) != 2 {
		t.Fatal("barrier stress requires GOMAXPROCS=2")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var cycles atomic.Uint64
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					cycles.Add(1)
				}
			}
		}()
	}
	t.Cleanup(func() { cancel(); wg.Wait() })
}
