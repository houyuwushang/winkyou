package signalrelay

import (
	"context"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/solver"
)

func TestPlanReturnsSignalRelayPlan(t *testing.T) {
	strategy := New(Config{})
	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %d, want 1", len(plans))
	}
	plan := plans[0]
	if plan.ID != PlanID || plan.Strategy != StrategyName {
		t.Fatalf("plan = %#v, want signal_relay plan identity", plan)
	}
	if plan.Metadata["transport"] != StrategyName || plan.Metadata["mode"] != "coordinator_signal" {
		t.Fatalf("metadata = %#v, want coordinator_signal", plan.Metadata)
	}
}

func TestMessageCodecsRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ready := readyPayload{SessionID: "session/node-a/node-b", PlanID: PlanID, SentAt: now}
	readyBytes, err := marshalReadyPayload(ready)
	if err != nil {
		t.Fatalf("marshalReadyPayload() error = %v", err)
	}
	decodedReady, err := unmarshalReadyPayload(readyBytes)
	if err != nil {
		t.Fatalf("unmarshalReadyPayload() error = %v", err)
	}
	if decodedReady.SessionID != ready.SessionID || decodedReady.PlanID != ready.PlanID {
		t.Fatalf("decoded ready = %#v, want %#v", decodedReady, ready)
	}

	packet := packetPayload{SessionID: ready.SessionID, PlanID: PlanID, Seq: 7, Data: []byte("packet"), SentAt: now}
	packetBytes, err := marshalPacketPayload(packet)
	if err != nil {
		t.Fatalf("marshalPacketPayload() error = %v", err)
	}
	decodedPacket, err := unmarshalPacketPayload(packetBytes)
	if err != nil {
		t.Fatalf("unmarshalPacketPayload() error = %v", err)
	}
	if decodedPacket.Seq != packet.Seq || string(decodedPacket.Data) != string(packet.Data) {
		t.Fatalf("decoded packet = %#v, want seq/data", decodedPacket)
	}

	closeMsg := closePayload{SessionID: ready.SessionID, PlanID: PlanID, Reason: "test", SentAt: now}
	closeBytes, err := marshalClosePayload(closeMsg)
	if err != nil {
		t.Fatalf("marshalClosePayload() error = %v", err)
	}
	decodedClose, err := unmarshalClosePayload(closeBytes)
	if err != nil {
		t.Fatalf("unmarshalClosePayload() error = %v", err)
	}
	if decodedClose.Reason != closeMsg.Reason {
		t.Fatalf("decoded close = %#v, want reason %q", decodedClose, closeMsg.Reason)
	}

	msg := NewMessage(MessageTypePacket, packetBytes, now)
	if !IsMessage(msg) || msg.Namespace != Namespace || msg.Type != MessageTypePacket {
		t.Fatalf("NewMessage() = %#v, want signalrelay packet message", msg)
	}
}

func TestExecuteResendsReadyUntilRemoteReady(t *testing.T) {
	strategy := New(Config{ReadyTimeout: time.Second, ReadyRetryInterval: 10 * time.Millisecond})
	plans, err := strategy.Plan(context.Background(), solver.SolveInput{
		SessionID:    "session/node-a/node-b",
		LocalNodeID:  "node-a",
		RemoteNodeID: "node-b",
		Initiator:    true,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	sessionIO := &recordingSessionIO{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resultCh := make(chan solver.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := strategy.Execute(ctx, sessionIO, plans[0])
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	waitForReadySends(t, sessionIO, 2)
	readyBytes, err := marshalReadyPayload(readyPayload{
		SessionID: "session/node-a/node-b",
		PlanID:    PlanID,
		SentAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("marshalReadyPayload() error = %v", err)
	}
	if err := strategy.HandleMessage(context.Background(), sessionIO, NewMessage(MessageTypeReady, readyBytes, time.Now())); err != nil {
		t.Fatalf("HandleMessage(ready) error = %v", err)
	}

	select {
	case result := <-resultCh:
		if result.Transport == nil || result.Summary.ConnectionType != "relay" {
			t.Fatalf("Execute() result = %#v, want relay transport", result.Summary)
		}
	case err := <-errCh:
		t.Fatalf("Execute() error = %v", err)
	case <-ctx.Done():
		t.Fatalf("Execute() did not finish: %v", ctx.Err())
	}
}

type recordingSessionIO struct {
	mu       sync.Mutex
	messages []solver.Message
}

func (io *recordingSessionIO) Send(_ context.Context, msg solver.Message) error {
	io.mu.Lock()
	defer io.mu.Unlock()
	io.messages = append(io.messages, msg)
	return nil
}

func (io *recordingSessionIO) ReportObservation(context.Context, solver.Observation) error {
	return nil
}

func (io *recordingSessionIO) readySendCount() int {
	io.mu.Lock()
	defer io.mu.Unlock()
	count := 0
	for _, msg := range io.messages {
		if msg.Type == MessageTypeReady {
			count++
		}
	}
	return count
}

func waitForReadySends(t *testing.T, io *recordingSessionIO, want int) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := io.readySendCount(); got >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("ready sends = %d, want at least %d", io.readySendCount(), want)
}
