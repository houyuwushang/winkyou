package client

import (
	"testing"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/logger"
	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

// TestHandlePeerSolverMessageWaitsForEngineReadiness guards issue #33: the
// coordinator signal stream is live from Register onward, long before the
// peer-session infrastructure exists. A peer solver message arriving in that
// startup window must wait for the explicit readiness barrier instead of
// being silently dropped, because one-shot strategy messages are never
// retransmitted within an attempt.
func TestHandlePeerSolverMessageWaitsForEngineReadiness(t *testing.T) {
	cfg := config.Default()
	cfg.Coordinator.URL = "grpc://127.0.0.1:1"
	engineInstance, err := NewEngine(&cfg, logger.Nop(), "")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng, ok := engineInstance.(*engine)
	if !ok {
		t.Fatalf("NewEngine() returned %T, want *engine", engineInstance)
	}

	capability := rproto.SessionEnvelope{
		SessionID: sessionIDForNodes("node-local", "node-remote"),
		FromNode:  "node-remote",
		ToNode:    "node-local",
		MsgType:   rproto.MsgTypeCapability,
		Seq:       1,
		Payload:   rproto.MustPayload(rproto.Capability{Strategies: []string{"relay_only"}}),
	}
	payload, err := rproto.MarshalEnvelope(capability)
	if err != nil {
		t.Fatalf("MarshalEnvelope() error = %v", err)
	}
	message := solver.Message{
		Kind:       solver.MessageKindEnvelope,
		Type:       rproto.MsgTypeCapability,
		Payload:    payload,
		ReceivedAt: time.Now(),
	}

	dispatched := make(chan struct{})
	go func() {
		defer close(dispatched)
		eng.handlePeerSolverMessage("node-remote", message)
	}()

	// The engine has not finished starting: the dispatch must be parked, not
	// dropped into a missing peer manager.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-dispatched:
		t.Fatal("solver message was dispatched before the engine became ready")
	default:
	}
	eng.mu.RLock()
	pending := eng.peerMgr != nil && len(eng.peerMgr.sessions) != 0
	eng.mu.RUnlock()
	if pending {
		t.Fatal("peer session appeared before readiness barrier opened")
	}

	// Simulate the Start() milestones the barrier represents, then open it.
	eng.mu.Lock()
	eng.status.NodeID = "node-local"
	eng.mu.Unlock()
	eng.initPeerManager()
	eng.markSolverDispatchReady()

	select {
	case <-dispatched:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for parked solver message to dispatch")
	}

	eng.mu.RLock()
	session := (*peerSession)(nil)
	if eng.peerMgr != nil {
		session = eng.peerMgr.sessions["node-remote"]
	}
	eng.mu.RUnlock()
	if session == nil {
		t.Fatal("parked solver message did not create the peer session after readiness")
	}
	runner := peerSessionRunner(session)
	if runner == nil {
		t.Fatal("peer session runner missing after readiness dispatch")
	}
	if _, received := runner.Snapshot().RemoteCapability, !runner.Snapshot().CapabilityExchangeAt.IsZero(); !received {
		t.Fatal("remote capability was not recorded from the parked message")
	}
}

// TestWaitSolverDispatchReadyBounds verifies both barrier outcomes: a nil
// channel (zero-value engines in unit tests) is immediately ready, and an
// unopened barrier fails closed after the bound instead of hanging.
func TestWaitSolverDispatchReadyBounds(t *testing.T) {
	zero := &engine{}
	if !zero.waitSolverDispatchReady(time.Millisecond) {
		t.Fatal("zero-value engine must bypass the dispatch barrier")
	}

	cfg := config.Default()
	cfg.Coordinator.URL = "grpc://127.0.0.1:1"
	engineInstance, err := NewEngine(&cfg, logger.Nop(), "")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng := engineInstance.(*engine)
	start := time.Now()
	if eng.waitSolverDispatchReady(30 * time.Millisecond) {
		t.Fatal("unopened barrier reported ready")
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("barrier returned after %s, want at least the 30ms bound", elapsed)
	}
	eng.markSolverDispatchReady()
	if !eng.waitSolverDispatchReady(time.Millisecond) {
		t.Fatal("opened barrier reported not ready")
	}
}
