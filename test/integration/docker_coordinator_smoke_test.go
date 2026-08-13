package integration_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	coordclient "winkyou/pkg/coordinator/client"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDockerCoordinatorTLSAuthSmoke(t *testing.T) {
	coordinatorURL := strings.TrimSpace(os.Getenv("WINKYOU_DOCKER_COORDINATOR_URL"))
	if coordinatorURL == "" {
		t.Skip("set WINKYOU_DOCKER_COORDINATOR_URL to run the Docker coordinator smoke test")
	}
	caFile := requireDockerSmokeEnv(t, "WINKYOU_DOCKER_COORDINATOR_CA_FILE")
	authKey := requireDockerSmokeEnv(t, "WINKYOU_DOCKER_COORDINATOR_AUTH_KEY")

	clientConfig := coordclient.Config{
		URL:     coordinatorURL,
		AuthKey: authKey,
		Timeout: 2 * time.Second,
		TLS:     coordclient.TLSConfig{CAFile: caFile},
	}
	alpha, alphaRegistered := waitForDockerCoordinator(
		t, clientConfig, "docker-smoke-alpha-public-key", "docker-smoke-alpha",
	)
	defer func() { _ = alpha.Close() }()
	beta, betaRegistered := waitForDockerCoordinator(
		t, clientConfig, "docker-smoke-beta-public-key", "docker-smoke-beta",
	)
	defer func() { _ = beta.Close() }()

	peers, err := alpha.ListPeers(context.Background())
	if err != nil {
		t.Fatalf("ListPeers() through Docker coordinator error = %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("len(ListPeers()) = %d, want 2", len(peers))
	}
	peer, err := alpha.GetPeer(context.Background(), betaRegistered.NodeID)
	if err != nil {
		t.Fatalf("GetPeer() through Docker coordinator error = %v", err)
	}
	if peer.Name != "docker-smoke-beta" {
		t.Fatalf("GetPeer().Name = %q, want docker-smoke-beta", peer.Name)
	}

	signalCh := make(chan *coordclient.SignalNotification, 1)
	beta.OnSignal(func(signal *coordclient.SignalNotification) {
		select {
		case signalCh <- signal:
		default:
		}
	})
	if err := alpha.SendSignal(
		context.Background(), betaRegistered.NodeID, coordclient.SignalTypeICEOffer, []byte("docker-smoke-offer"),
	); err != nil {
		t.Fatalf("SendSignal() through Docker coordinator error = %v", err)
	}
	select {
	case signal := <-signalCh:
		if signal.FromNode != alphaRegistered.NodeID || signal.ToNode != betaRegistered.NodeID {
			t.Fatalf("signal nodes = %q -> %q, want %q -> %q", signal.FromNode, signal.ToNode, alphaRegistered.NodeID, betaRegistered.NodeID)
		}
		if string(signal.Payload) != "docker-smoke-offer" {
			t.Fatalf("signal payload = %q, want docker-smoke-offer", string(signal.Payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the authenticated Docker coordinator signal")
	}

	assertDockerCoordinatorRejectsAuth(t, coordclient.Config{
		URL:     coordinatorURL,
		Timeout: 2 * time.Second,
		TLS:     coordclient.TLSConfig{CAFile: caFile},
	})
	assertDockerCoordinatorRejectsAuth(t, coordclient.Config{
		URL:     coordinatorURL,
		AuthKey: "docker-smoke-wrong-key",
		Timeout: 2 * time.Second,
		TLS:     coordclient.TLSConfig{CAFile: caFile},
	})
}

func waitForDockerCoordinator(
	t *testing.T,
	cfg coordclient.Config,
	publicKey string,
	name string,
) (coordclient.CoordinatorClient, *coordclient.RegisterResponse) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		candidate, err := coordclient.NewClient(&cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		registered, err := candidate.Register(ctx, &coordclient.RegisterRequest{
			PublicKey: publicKey,
			Name:      name,
		})
		cancel()
		if err == nil {
			return candidate, registered
		}
		lastErr = err
		_ = candidate.Close()
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("Docker coordinator did not become ready: %v", lastErr)
	return nil, nil
}

func assertDockerCoordinatorRejectsAuth(t *testing.T, cfg coordclient.Config) {
	t.Helper()

	candidate, err := coordclient.NewClient(&cfg)
	if err != nil {
		t.Fatalf("NewClient() for auth rejection error = %v", err)
	}
	defer func() { _ = candidate.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = candidate.ListPeers(ctx)
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("ListPeers() auth rejection code = %s, want %s (err=%v)", got, codes.Unauthenticated, err)
	}
}

func requireDockerSmokeEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required when the Docker coordinator smoke test is enabled", name)
	}
	return value
}
