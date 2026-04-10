package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"winkyou/pkg/coordinator/client"
	"winkyou/pkg/coordinator/server"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func TestRegisterNode(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	srv := newTestServer(t, clock, 5*time.Second)

	resp, err := srv.Register(context.Background(), &client.RegisterRequest{
		PublicKey: "pub-1",
		Name:      "alpha",
		Metadata:  map[string]string{"role": "edge"},
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if resp.NodeID == "" {
		t.Fatal("expected non-empty node id")
	}
	if resp.VirtualIP != "10.99.0.1" {
		t.Fatalf("VirtualIP = %q, want 10.99.0.1", resp.VirtualIP)
	}
	if resp.NetworkCIDR != "10.99.0.0/24" {
		t.Fatalf("NetworkCIDR = %q, want 10.99.0.0/24", resp.NetworkCIDR)
	}
}

func TestListPeers(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	srv := newTestServer(t, clock, 5*time.Second)

	registerNode(t, srv, "pub-1", "alpha")
	registerNode(t, srv, "pub-2", "bravo")

	resp, err := srv.ListPeers(context.Background(), &client.ListPeersRequest{})
	if err != nil {
		t.Fatalf("ListPeers() error = %v", err)
	}
	if len(resp.Peers) != 2 {
		t.Fatalf("len(Peers) = %d, want 2", len(resp.Peers))
	}
	if resp.Peers[0].NodeID >= resp.Peers[1].NodeID {
		t.Fatalf("expected peers sorted by node id, got %q then %q", resp.Peers[0].NodeID, resp.Peers[1].NodeID)
	}
}

func TestGetPeerByNodeID(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	srv := newTestServer(t, clock, 5*time.Second)

	reg := registerNode(t, srv, "pub-1", "alpha")

	peer, err := srv.GetPeer(context.Background(), &client.GetPeerRequest{NodeID: reg.NodeID})
	if err != nil {
		t.Fatalf("GetPeer() error = %v", err)
	}
	if peer.NodeID != reg.NodeID {
		t.Fatalf("NodeID = %q, want %q", peer.NodeID, reg.NodeID)
	}
	if peer.Name != "alpha" {
		t.Fatalf("Name = %q, want alpha", peer.Name)
	}
}

func TestForwardSignalDropsOfflineNode(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	srv := newTestServer(t, clock, 2*time.Second)

	from := registerNode(t, srv, "pub-1", "alpha")
	to := registerNode(t, srv, "pub-2", "bravo")

	clock.Advance(3 * time.Second)

	delivered, err := srv.ForwardSignal(context.Background(), &client.SignalNotification{
		FromNode: from.NodeID,
		ToNode:   to.NodeID,
		Type:     client.SignalTypeICEOffer,
		Payload:  []byte("offer"),
	})
	if err != nil {
		t.Fatalf("ForwardSignal() error = %v", err)
	}
	if delivered {
		t.Fatal("expected signal to offline node to be dropped")
	}

	queue, err := srv.Store().DrainSignals(to.NodeID)
	if err != nil {
		t.Fatalf("DrainSignals() error = %v", err)
	}
	if len(queue) != 0 {
		t.Fatalf("len(queue) = %d, want 0", len(queue))
	}

	peer, err := srv.GetPeer(context.Background(), &client.GetPeerRequest{NodeID: to.NodeID})
	if err != nil {
		t.Fatalf("GetPeer() error = %v", err)
	}
	if peer.Online {
		t.Fatal("expected target peer to be offline")
	}
}

func TestGetPeerMissingNode(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	srv := newTestServer(t, clock, 5*time.Second)

	_, err := srv.GetPeer(context.Background(), &client.GetPeerRequest{NodeID: "missing"})
	if !errors.Is(err, server.ErrNodeNotFound) {
		t.Fatalf("GetPeer() error = %v, want ErrNodeNotFound", err)
	}
}

func newTestServer(t *testing.T, clock *fakeClock, leaseTTL time.Duration) *server.Server {
	t.Helper()

	srv, err := server.New(&server.Config{
		ListenAddress: "127.0.0.1:9443",
		NetworkCIDR:   "10.99.0.0/24",
		LeaseTTL:      leaseTTL,
		Now:           clock.Now,
	})
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}
	return srv
}

func registerNode(t *testing.T, srv *server.Server, publicKey, name string) *client.RegisterResponse {
	t.Helper()

	resp, err := srv.Register(context.Background(), &client.RegisterRequest{
		PublicKey: publicKey,
		Name:      name,
	})
	if err != nil {
		t.Fatalf("Register(%q) error = %v", publicKey, err)
	}
	return resp
}
