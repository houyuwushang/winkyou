package session

import (
	"context"
	"sync"
	"testing"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
)

type blockingBindBinder struct {
	started chan struct{}
	once    sync.Once
}

func (b *blockingBindBinder) Bind(ctx context.Context, _ string, _ transport.PacketTransport) error {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return ctx.Err()
}

func (b *blockingBindBinder) Unbind(context.Context, string) error {
	return nil
}

type pathCommitBlockingSender struct {
	started chan struct{}
	once    sync.Once
}

func (s *pathCommitBlockingSender) Send(ctx context.Context, _ string, msg solver.Message) error {
	if msg.Type != rproto.MsgTypePathCommit {
		return nil
	}
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return ctx.Err()
}

type cleanupTrackingBinder struct {
	unbound  chan struct{}
	ctxErr   error
	ctxErrMu sync.Mutex
}

func (b *cleanupTrackingBinder) Bind(context.Context, string, transport.PacketTransport) error {
	return nil
}

func (b *cleanupTrackingBinder) Unbind(ctx context.Context, _ string) error {
	b.ctxErrMu.Lock()
	b.ctxErr = ctx.Err()
	b.ctxErrMu.Unlock()
	close(b.unbound)
	return nil
}

func (b *cleanupTrackingBinder) ContextErr() error {
	b.ctxErrMu.Lock()
	defer b.ctxErrMu.Unlock()
	return b.ctxErr
}

func TestSessionBindUsesRunContextCancellation(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	binder := &blockingBindBinder{started: make(chan struct{})}
	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}, selection: Selection{StrategyName: "legacy_ice_udp"}},
		Binder:                binder,
		Sender:                &fakeSender{},
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.Start(runCtx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case <-binder.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Bind()")
	}
	cancel()
	waitForState(t, s, StateFailed)
}

func TestSessionPathCommitUsesRunContextCancellation(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sender := &pathCommitBlockingSender{started: make(chan struct{})}
	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: &fakeStrategy{name: "legacy_ice_udp", transport: &fakeTransport{}}, selection: Selection{StrategyName: "legacy_ice_udp"}},
		Sender:                sender,
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.Start(runCtx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	select {
	case <-sender.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for path_commit send")
	}
	cancel()
	waitForState(t, s, StateFailed)
}

func TestSessionCloseUsesIndependentCleanupContext(t *testing.T) {
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	binder := &cleanupTrackingBinder{unbound: make(chan struct{})}
	transport := &fakeTransport{}
	s, err := New(Config{
		SessionID:             "session/node-a/node-b",
		LocalNodeID:           "node-a",
		PeerID:                "node-b",
		Initiator:             true,
		Resolver:              &fakeResolver{local: rproto.Capability{Strategies: []string{"legacy_ice_udp"}}, strategy: &fakeStrategy{name: "legacy_ice_udp", transport: transport}, selection: Selection{StrategyName: "legacy_ice_udp"}},
		Binder:                binder,
		Sender:                &fakeSender{},
		RunTimeout:            3 * time.Second,
		CapabilityWaitTimeout: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.Start(runCtx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	waitForState(t, s, StateBound)

	cancel()
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case <-binder.unbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Unbind()")
	}
	if err := binder.ContextErr(); err != nil {
		t.Fatalf("Unbind() context error = %v, want independent live cleanup context", err)
	}
	if !transport.closed {
		t.Fatal("transport.Close() was not called")
	}
}
