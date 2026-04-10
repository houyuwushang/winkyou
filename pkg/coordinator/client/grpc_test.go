package client_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	"winkyou/pkg/coordinator/client"
	"winkyou/pkg/coordinator/server"

	"google.golang.org/grpc"
)

func TestGRPCClientRegisterListGetAndSignal(t *testing.T) {
	listener, stop := startCoordinator(t, newCoordinatorService(t))
	defer stop()

	addr := listener.Addr().String()
	alpha := newTestClient(t, addr)
	defer func() {
		_ = alpha.Close()
	}()
	beta := newTestClient(t, addr)
	defer func() {
		_ = beta.Close()
	}()

	alphaResp, err := alpha.Register(context.Background(), &client.RegisterRequest{
		PublicKey: "alpha-pub",
		Name:      "alpha",
	})
	if err != nil {
		t.Fatalf("alpha Register() error = %v", err)
	}
	betaResp, err := beta.Register(context.Background(), &client.RegisterRequest{
		PublicKey: "beta-pub",
		Name:      "beta",
	})
	if err != nil {
		t.Fatalf("beta Register() error = %v", err)
	}

	peers, err := alpha.ListPeers(context.Background())
	if err != nil {
		t.Fatalf("ListPeers() error = %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("len(peers) = %d, want 2", len(peers))
	}

	peer, err := alpha.GetPeer(context.Background(), betaResp.NodeID)
	if err != nil {
		t.Fatalf("GetPeer() error = %v", err)
	}
	if peer.Name != "beta" {
		t.Fatalf("peer.Name = %q, want beta", peer.Name)
	}

	signalCh := make(chan *client.SignalNotification, 1)
	beta.OnSignal(func(signal *client.SignalNotification) {
		select {
		case signalCh <- signal:
		default:
		}
	})

	if err := alpha.SendSignal(context.Background(), betaResp.NodeID, client.SIGNAL_ICE_OFFER, []byte("offer")); err != nil {
		t.Fatalf("SendSignal() error = %v", err)
	}

	select {
	case signal := <-signalCh:
		if signal.FromNode != alphaResp.NodeID {
			t.Fatalf("signal.FromNode = %q, want %q", signal.FromNode, alphaResp.NodeID)
		}
		if signal.ToNode != betaResp.NodeID {
			t.Fatalf("signal.ToNode = %q, want %q", signal.ToNode, betaResp.NodeID)
		}
		if string(signal.Payload) != "offer" {
			t.Fatalf("signal.Payload = %q, want offer", string(signal.Payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for signal")
	}
}

func TestStartHeartbeatAndStopHeartbeat(t *testing.T) {
	service := newCoordinatorService(t)
	counting := &countingCoordinatorServer{inner: service}
	listener, stop := startCoordinator(t, counting)
	defer stop()

	c := newTestClient(t, listener.Addr().String())
	defer func() {
		_ = c.Close()
	}()

	if _, err := c.Register(context.Background(), &client.RegisterRequest{
		PublicKey: "heartbeat-pub",
		Name:      "heartbeat",
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := c.StartHeartbeat(context.Background(), 20*time.Millisecond); err != nil {
		t.Fatalf("StartHeartbeat() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(&counting.heartbeats) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("heartbeat count = %d, want at least 2", atomic.LoadInt64(&counting.heartbeats))
		}
		time.Sleep(10 * time.Millisecond)
	}

	c.StopHeartbeat()

	before := atomic.LoadInt64(&counting.heartbeats)
	time.Sleep(100 * time.Millisecond)
	after := atomic.LoadInt64(&counting.heartbeats)
	if after != before {
		t.Fatalf("heartbeat count after StopHeartbeat() = %d, want %d", after, before)
	}
}

type countingCoordinatorServer struct {
	coordinatorv1.UnimplementedCoordinatorServer

	inner      coordinatorv1.CoordinatorServer
	heartbeats int64
}

func (s *countingCoordinatorServer) Register(ctx context.Context, req *coordinatorv1.RegisterRequest) (*coordinatorv1.RegisterResponse, error) {
	return s.inner.Register(ctx, req)
}

func (s *countingCoordinatorServer) Heartbeat(ctx context.Context, req *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
	atomic.AddInt64(&s.heartbeats, 1)
	return s.inner.Heartbeat(ctx, req)
}

func (s *countingCoordinatorServer) ListPeers(ctx context.Context, req *coordinatorv1.ListPeersRequest) (*coordinatorv1.ListPeersResponse, error) {
	return s.inner.ListPeers(ctx, req)
}

func (s *countingCoordinatorServer) GetPeer(ctx context.Context, req *coordinatorv1.GetPeerRequest) (*coordinatorv1.PeerInfo, error) {
	return s.inner.GetPeer(ctx, req)
}

func (s *countingCoordinatorServer) Signal(stream grpc.BidiStreamingServer[coordinatorv1.SignalEnvelope, coordinatorv1.SignalEnvelope]) error {
	return s.inner.Signal(stream)
}

func newCoordinatorService(t *testing.T) *server.GRPCService {
	t.Helper()

	domain, err := server.New(&server.Config{
		ListenAddress: "127.0.0.1:9443",
		NetworkCIDR:   "10.99.0.0/24",
		LeaseTTL:      5 * time.Second,
	})
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}
	return server.NewGRPCService(domain)
}

func startCoordinator(t *testing.T, coordinator coordinatorv1.CoordinatorServer) (net.Listener, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	grpcServer := grpc.NewServer()
	coordinatorv1.RegisterCoordinatorServer(grpcServer, coordinator)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	return listener, func() {
		grpcServer.Stop()
		_ = listener.Close()
	}
}

func newTestClient(t *testing.T, addr string) client.CoordinatorClient {
	t.Helper()

	c, err := client.NewClient(&client.Config{URL: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return c
}
