package shortcut

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/peercontrol"
)

// This witness records only fixed fixture labels, never wire payloads or IDs.
type shortcutBarrierWitness struct {
	mu      sync.Mutex
	started time.Time
	rows    []shortcutBarrierRow
	stable  map[string]bool
	phases  map[string]map[Phase]bool
	// Seq is used only to join observations of one logical fixture message.
	// It and the message body are never printed or published.
	bypass map[uint64]uint8
	packet map[string]shortcutPacketGap
}

type shortcutBarrierRow struct {
	ns                                int64
	kind, signal, node, inbound, next string
}

type shortcutPacketGap struct {
	readMax  int64
	writeMax int64
}

func newShortcutBarrierWitness(t *testing.T) *shortcutBarrierWitness {
	t.Helper()
	w := &shortcutBarrierWitness{
		started: time.Now(), stable: make(map[string]bool), phases: make(map[string]map[Phase]bool),
		bypass: make(map[uint64]uint8), packet: make(map[string]shortcutPacketGap),
	}
	t.Cleanup(func() {
		if !t.Failed() && os.Getenv("WINKYOU_FLAKE_158_WITNESS") != "1" {
			return
		}
		w.mu.Lock()
		rows := append([]shortcutBarrierRow(nil), w.rows...)
		w.mu.Unlock()
		for _, row := range rows {
			t.Logf("BARRIER_WITNESS relative_ns=%d kind=%s type=%s node=%s inbound=%s next=%s", row.ns, row.kind, row.signal, row.node, row.inbound, row.next)
		}
		w.logPacketGaps(t)
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

func (w *shortcutBarrierWitness) recordPacketGap(endpoint, direction string, gap time.Duration) {
	if w == nil || gap <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	current := w.packet[endpoint]
	value := gap.Nanoseconds()
	if direction == "read" {
		if value > current.readMax {
			current.readMax = value
		}
	} else if direction == "write" && value > current.writeMax {
		current.writeMax = value
	}
	w.packet[endpoint] = current
}

func (w *shortcutBarrierWitness) recordPacketClose(node, peer string, cause error) {
	class := "closed"
	switch {
	case errors.Is(cause, mesh.ErrPacketNeighborTimeout):
		class = "liveness_timeout"
	case errors.Is(cause, mesh.ErrPacketNeighborReadinessTimeout):
		class = "readiness_timeout"
	case cause != nil:
		class = "other"
	}
	w.record("packet_close", class, node, peer, "")
}

func (w *shortcutBarrierWitness) logPacketGaps(t *testing.T) {
	t.Helper()
	w.mu.Lock()
	packetGaps := make(map[string]shortcutPacketGap, len(w.packet))
	for endpoint, gap := range w.packet {
		packetGaps[endpoint] = gap
	}
	w.mu.Unlock()
	for _, endpoint := range []string{"A", "B", "C"} {
		gap, ok := packetGaps[endpoint]
		if !ok {
			continue
		}
		t.Logf("SHORTCUT_PACKET_GAP endpoint=%s read_max_ns=%d write_max_ns=%d", endpoint, gap.readMax, gap.writeMax)
	}
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
	if signal.Type != typeStable || event.Message.From != "A" || event.Message.To != "B" || event.Message.Seq == 0 {
		return
	}
	var bit uint8
	switch {
	case event.Kind == mesh.EventForwarded && event.NodeID == "A" && event.InboundPeer == "" && event.NextHop == "C":
		bit = 1
	case event.Kind == mesh.EventForwarded && event.NodeID == "C" && event.InboundPeer == "A" && event.NextHop == "B":
		bit = 2
	case event.Kind == mesh.EventDelivered && event.NodeID == "B" && event.InboundPeer == "C":
		bit = 4
	}
	if bit != 0 {
		w.mu.Lock()
		w.bypass[event.Message.Seq] |= bit
		w.mu.Unlock()
	}
}

func (w *shortcutBarrierWitness) stableBypassedBootstrap() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, hops := range w.bypass {
		if hops == 7 {
			return true
		}
	}
	return false
}

func (w *shortcutBarrierWitness) accepts(signal string, dropped, matched int32) bool {
	if dropped < 0 || dropped > 1 || matched < dropped || (matched > 0 && dropped != 1) {
		return false
	}
	if dropped == 1 && matched >= 2 {
		return true
	}
	// Only STABLE may use the newly promoted A-C edge. A zero count by itself
	// is never success: require A->C, C->B and B delivery of the SAME message.
	return signal == typeStable && w.stableBypassedBootstrap()
}

func (w *shortcutBarrierWitness) manager(event Event) {
	if event.Status.Phase == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	node := barrierLabel(event.NodeID)
	if w.phases[node] == nil {
		w.phases[node] = make(map[Phase]bool)
	}
	if w.phases[node][event.Status.Phase] {
		return
	}
	w.phases[node][event.Status.Phase] = true
	w.rows = append(w.rows, shortcutBarrierRow{time.Since(w.started).Nanoseconds(), "manager_phase", string(event.Status.Phase), node, "none", "none"})
	if event.Status.Phase == PhaseStable {
		w.stable[node] = true
	}
}

func shortcutFailureClass(status Status) string {
	if status.Phase == PhaseStable {
		return "success"
	}
	if status.Phase == PhaseFailed {
		failure := strings.ToLower(status.Failure)
		switch {
		case strings.Contains(failure, "packet neighbor liveness timeout"):
			return "packet_neighbor_liveness_timeout"
		case strings.Contains(failure, "packet neighbor readiness timeout"):
			return "packet_neighbor_readiness_timeout"
		case strings.Contains(failure, "context deadline exceeded"):
			return "context_deadline_exceeded"
		case strings.Contains(failure, "solver"):
			return "solver_failure"
		default:
			return "attempt_failed"
		}
	}
	return "not_terminal"
}

func (w *shortcutBarrierWitness) dumpFailure(t *testing.T, label string, managers map[string]*Manager, nodes map[string]*mesh.Node, broker *fakeEdgeBroker) {
	t.Helper()
	w.mu.Lock()
	rows := append([]shortcutBarrierRow(nil), w.rows...)
	w.mu.Unlock()
	for _, row := range rows {
		t.Logf("SHORTCUT_WITNESS relative_ns=%d kind=%s phase=%s node=%s inbound=%s next=%s", row.ns, row.kind, row.signal, row.node, row.inbound, row.next)
	}
	managerIDs := make([]string, 0, len(managers))
	for id := range managers {
		managerIDs = append(managerIDs, id)
	}
	sort.Strings(managerIDs)
	for _, id := range managerIDs {
		status, ok := managers[id].Status(findAttemptID(managers[id]))
		if !ok {
			t.Logf("SHORTCUT_TERMINAL manager=%s phase=unknown failure=missing_status neighbor_ready=unknown solver_terminal=unknown", id)
			continue
		}
		neighborID := status.DirectPeerID
		ready := false
		if node := nodes[id]; node != nil && neighborID != "" {
			_, ready = node.Neighbor(neighborID)
		}
		t.Logf("SHORTCUT_TERMINAL label=%s manager=%s phase=%s failure=%s neighbor_ready=%t solver_terminal=%s", label, id, status.Phase, shortcutFailureClass(status), ready, broker.solverTerminal(id))
	}
	for id, state := range broker.edgeStates() {
		t.Logf("SHORTCUT_EDGE edge=%s state=%s", id, state)
	}
	w.logPacketGaps(t)
	t.Logf("SHORTCUT_FAILURE label=%s", label)
}

// The test fixtures use one attempt per manager. This helper avoids exposing
// attempt identifiers in witness output while still selecting the sole state.
func findAttemptID(manager *Manager) string {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for id := range manager.attempts {
		return id
	}
	return ""
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

func TestShortcutBarrierWitnessRejectsUnprovenBypass(t *testing.T) {
	message := peercontrol.NewSessionSignal("A", "B", peercontrol.SessionSignal{Namespace: Namespace, Type: typeStable, Kind: SignalKind})
	message.Seq = 1
	path := []mesh.Event{
		{Kind: mesh.EventForwarded, NodeID: "A", NextHop: "C", Message: message},
		{Kind: mesh.EventForwarded, NodeID: "C", InboundPeer: "A", NextHop: "B", Message: message},
		{Kind: mesh.EventDelivered, NodeID: "B", InboundPeer: "C", Message: message},
	}
	for _, scenario := range []struct {
		name   string
		mutate func([]mesh.Event) []mesh.Event
		valid  bool
	}{
		{"complete", func(p []mesh.Event) []mesh.Event { return p }, true},
		{"callback_order_not_delivery_order", func(p []mesh.Event) []mesh.Event { return []mesh.Event{p[2], p[1], p[0]} }, true},
		{"no_send", func(p []mesh.Event) []mesh.Event { return p[1:] }, false},
		{"no_forward", func(p []mesh.Event) []mesh.Event { return []mesh.Event{p[0], p[2]} }, false},
		{"no_delivery", func(p []mesh.Event) []mesh.Event { return p[:2] }, false},
		{"different_message", func(p []mesh.Event) []mesh.Event { p[2].Message.Seq++; return p }, false},
		{"different_origin", func(p []mesh.Event) []mesh.Event { p[2].Message.From = "C"; return p }, false},
		{"different_destination", func(p []mesh.Event) []mesh.Event { p[2].Message.To = "A"; return p }, false},
		{"different_hop", func(p []mesh.Event) []mesh.Event { p[2].InboundPeer = "A"; return p }, false},
		{"zero_sequence", func(p []mesh.Event) []mesh.Event {
			for i := range p {
				p[i].Message.Seq = 0
			}
			return p
		}, false},
		{"dropped_not_delivered", func(p []mesh.Event) []mesh.Event { p[2].Kind = mesh.EventDropped; return p }, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			w := newShortcutBarrierWitness(t)
			for _, event := range scenario.mutate(append([]mesh.Event(nil), path...)) {
				w.route(event)
			}
			if got := w.accepts(typeStable, 0, 0); got != scenario.valid {
				t.Fatalf("bypass=%t want=%t", got, scenario.valid)
			}
			if !w.accepts(typeStable, 1, 2) || !w.accepts(typeCommit, 1, 2) {
				t.Fatal("strict dropped-and-reconciled outcome rejected")
			}
			if w.accepts(typeCommit, 0, 0) || w.accepts(typeStable, 2, 2) || w.accepts(typeStable, -1, 0) || w.accepts(typeStable, 1, 0) || w.accepts(typeStable, 0, 1) {
				t.Fatal("invalid count or COMMIT bypass accepted")
			}
		})
	}
}
