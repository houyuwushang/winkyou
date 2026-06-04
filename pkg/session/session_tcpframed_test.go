package session

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/solver/strategy/relayonly"
	"winkyou/pkg/solver/strategy/tcpframed"
	"winkyou/pkg/transport"
)

type capturingBinder struct {
	mu         sync.Mutex
	transports map[string]transport.PacketTransport
}

func newCapturingBinder() *capturingBinder {
	return &capturingBinder{transports: make(map[string]transport.PacketTransport)}
}

func (b *capturingBinder) Bind(ctx context.Context, peerID string, pt transport.PacketTransport) error {
	_ = ctx
	b.mu.Lock()
	defer b.mu.Unlock()
	b.transports[peerID] = pt
	return nil
}

func (b *capturingBinder) Unbind(ctx context.Context, peerID string) error {
	_ = ctx
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.transports, peerID)
	return nil
}

func (b *capturingBinder) Transport(peerID string) transport.PacketTransport {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.transports[peerID]
}

func TestSessionTCPFramedLoopbackBindsAndTransportsPackets(t *testing.T) {
	localBinder := newCapturingBinder()
	remoteBinder := newCapturingBinder()
	localStrategy := tcpframed.New(tcpframed.Config{ListenAddr: "127.0.0.1:0", DialTimeout: time.Second})
	remoteStrategy := tcpframed.New(tcpframed.Config{ListenAddr: "127.0.0.1:0", DialTimeout: time.Second})
	localResolver := newTestPortfolioResolver(t, []StrategyEntry{{Name: tcpframed.StrategyName, Strategy: localStrategy}})
	remoteResolver := newTestPortfolioResolver(t, []StrategyEntry{{Name: tcpframed.StrategyName, Strategy: remoteStrategy}})

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

	localSnapshot := local.Snapshot()
	if localSnapshot.SelectedStrategy != tcpframed.StrategyName {
		t.Fatalf("local selected strategy = %q, want %q", localSnapshot.SelectedStrategy, tcpframed.StrategyName)
	}
	if !slices.Equal(localSnapshot.LastStrategyOrder, []string{tcpframed.StrategyName}) {
		t.Fatalf("local strategy order = %#v, want tcp_framed", localSnapshot.LastStrategyOrder)
	}
	pathCommitMsg := waitForEnvelopeMessage(t, localSender.Messages, rproto.MsgTypePathCommit)
	envelope, err := rproto.UnmarshalEnvelope(pathCommitMsg.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope(path_commit) error = %v", err)
	}
	pathCommit := mustDecodePathCommit(t, envelope.Payload)
	if pathCommit.Strategy != tcpframed.StrategyName || pathCommit.ConnectionType != "direct" {
		t.Fatalf("path_commit = %#v, want tcp_framed direct", pathCommit)
	}

	localTransport := localBinder.Transport("node-b")
	remoteTransport := remoteBinder.Transport("node-a")
	if localTransport == nil || remoteTransport == nil {
		t.Fatalf("bound transports = local:%T remote:%T, want both present", localTransport, remoteTransport)
	}

	packetCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	payload := []byte("tcp-framed packet")
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
		t.Fatal("PacketMeta.PathID is empty, want tcpframed path id")
	}

	if err := local.Close(); err != nil {
		t.Fatalf("local.Close() error = %v", err)
	}
	if err := remote.Close(); err != nil {
		t.Fatalf("remote.Close() error = %v", err)
	}
}

func TestSessionTCPFramedFallbackToRelayOnly(t *testing.T) {
	first := &failingFallbackStrategy{name: tcpframed.StrategyName, err: context.DeadlineExceeded}
	second := &successfulFallbackStrategy{name: relayonly.StrategyName, transport: &fakeTransport{}}
	resolver := &orderedFallbackResolver{
		local: rproto.Capability{Strategies: []string{first.name, second.name}},
		candidates: []StrategyCandidate{
			{Name: first.name, Strategy: first, Selection: Selection{StrategyName: first.name, Negotiated: true}},
			{Name: second.name, Strategy: second, Selection: Selection{StrategyName: second.name, Negotiated: true}},
		},
	}
	sender := &fakeSender{}

	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              resolver,
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := s.HandleMessage(context.Background(), envelopeMessage(t, "session/node-a/node-b", "node-b", "node-a", rproto.MsgTypeCapability, 1, rproto.Capability{Strategies: []string{tcpframed.StrategyName, relayonly.StrategyName}}, time.Now())); err != nil {
		t.Fatalf("HandleMessage(capability) error = %v", err)
	}
	waitForState(t, s, StateBound)
	if got := s.Snapshot().SelectedStrategy; got != relayonly.StrategyName {
		t.Fatalf("SelectedStrategy = %q, want %q", got, relayonly.StrategyName)
	}
	if !hasObservation(s.Observations(), tcpframed.StrategyName, "strategy_failed") {
		t.Fatalf("observations = %#v, want tcp_framed strategy_failed", s.Observations())
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
