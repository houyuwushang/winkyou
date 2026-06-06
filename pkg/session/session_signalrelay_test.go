package session

import (
	"context"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/signalrelay"
)

func TestSessionSignalRelayBindsAndTransportsPackets(t *testing.T) {
	localBinder := newCapturingBinder()
	remoteBinder := newCapturingBinder()
	localStrategy := signalrelay.New(signalrelay.Config{ReadyTimeout: time.Second})
	remoteStrategy := signalrelay.New(signalrelay.Config{ReadyTimeout: time.Second})
	localResolver := newTestPortfolioResolver(t, []StrategyEntry{{Name: signalrelay.StrategyName, Strategy: localStrategy}})
	remoteResolver := newTestPortfolioResolver(t, []StrategyEntry{{Name: signalrelay.StrategyName, Strategy: remoteStrategy}})

	localSender := &callbackSender{}
	remoteSender := &callbackSender{}
	local, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              localResolver,
		Binder:                localBinder,
		Sender:                localSender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}
	remote, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-b",
		PeerID:                "node-a",
		Initiator:             false,
		Resolver:              remoteResolver,
		Binder:                remoteBinder,
		Sender:                remoteSender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New(remote) error = %v", err)
	}
	localSender.sendFn = func(msg solver.Message) error { return remote.HandleMessage(context.Background(), msg) }
	remoteSender.sendFn = func(msg solver.Message) error { return local.HandleMessage(context.Background(), msg) }

	if err := local.Start(context.Background()); err != nil {
		t.Fatalf("local.Start() error = %v", err)
	}
	if err := remote.Start(context.Background()); err != nil {
		t.Fatalf("remote.Start() error = %v", err)
	}
	waitForState(t, local, StateBound)
	waitForState(t, remote, StateBound)

	if got := local.Snapshot().SelectedStrategy; got != signalrelay.StrategyName {
		t.Fatalf("local selected strategy = %q, want %q", got, signalrelay.StrategyName)
	}
	pathCommitMsg := waitForEnvelopeMessage(t, localSender.Messages, rproto.MsgTypePathCommit)
	envelope, err := rproto.UnmarshalEnvelope(pathCommitMsg.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(path_commit) error = %v", err)
	}
	pathCommit := mustDecodePathCommit(t, envelope.Payload)
	if pathCommit.Strategy != signalrelay.StrategyName || pathCommit.ConnectionType != "relay" {
		t.Fatalf("path_commit = %#v, want signal_relay relay", pathCommit)
	}

	localTransport := localBinder.Transport("node-b")
	remoteTransport := remoteBinder.Transport("node-a")
	if localTransport == nil || remoteTransport == nil {
		t.Fatalf("bound transports = local:%T remote:%T, want both present", localTransport, remoteTransport)
	}

	packetCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	payload := []byte("signal relay packet")
	if err := localTransport.WritePacket(packetCtx, payload); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	buf := make([]byte, 1024)
	n, meta, err := remoteTransport.ReadPacket(packetCtx, buf)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("packet = %q, want %q", string(buf[:n]), string(payload))
	}
	if meta.PathID == "" {
		t.Fatal("PacketMeta.PathID is empty, want signalrelay path id")
	}

	if err := local.Close(); err != nil {
		t.Fatalf("local.Close() error = %v", err)
	}
	if err := remote.Close(); err != nil {
		t.Fatalf("remote.Close() error = %v", err)
	}
}

func TestSessionBoundTransportHandlesMessagesWhileAnotherStrategyIsActive(t *testing.T) {
	bound := &messageBackedTransport{
		namespace: "bound.strategy",
		msgType:   "packet",
		planID:    "bound/plan",
	}
	active := &recordingPlanExecutor{}
	s := &Session{io: &solverIO{}}
	s.setBoundTransportMessageTarget(solver.Result{
		Transport: bound,
		Summary: solver.PathSummary{
			PathID: "bound/path",
			Details: map[string]string{
				"plan_id": bound.planID,
			},
		},
	}, solver.Plan{ID: bound.planID, Strategy: "bound.strategy"})
	s.strategyMu.Lock()
	s.executor = active
	s.activePlan = "other/plan"
	s.strategyMu.Unlock()

	msg := solver.Message{
		Kind:      solver.MessageKindStrategy,
		Namespace: bound.namespace,
		Type:      bound.msgType,
		Payload:   []byte(`{"plan_id":"bound/plan","data":"packet"}`),
	}
	if err := s.HandleMessage(context.Background(), msg); err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if got := bound.handleCount(); got != 1 {
		t.Fatalf("bound transport handle count = %d, want 1", got)
	}
	if got := active.handleCount(); got != 0 {
		t.Fatalf("active executor handle count = %d, want 0", got)
	}
}

type messageBackedTransport struct {
	fakeTransport
	namespace string
	msgType   string
	planID    string

	mu      sync.Mutex
	handled int
}

func (t *messageBackedTransport) AcceptsMessage(msg solver.Message) bool {
	if msg.Kind != solver.MessageKindStrategy || msg.Namespace != t.namespace || msg.Type != t.msgType {
		return false
	}
	planID, ok := strategyMessagePlanID(msg)
	return ok && strategyPlanIDsMatch(planID, t.planID)
}

func (t *messageBackedTransport) HandleMessage(context.Context, solver.SessionIO, solver.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handled++
	return nil
}

func (t *messageBackedTransport) handleCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.handled
}

type recordingPlanExecutor struct {
	mu      sync.Mutex
	handled int
}

func (e *recordingPlanExecutor) Execute(context.Context, solver.SessionIO) (solver.Result, error) {
	return solver.Result{}, nil
}

func (e *recordingPlanExecutor) HandleMessage(context.Context, solver.SessionIO, solver.Message) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handled++
	return nil
}

func (e *recordingPlanExecutor) Close() error { return nil }

func (e *recordingPlanExecutor) handleCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.handled
}
