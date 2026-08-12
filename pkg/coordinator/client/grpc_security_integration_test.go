package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	"winkyou/pkg/coordinator/client"
	"winkyou/pkg/coordinator/server"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestSecureCoordinatorTLSAndSharedAuthIntegration(t *testing.T) {
	const authKey = "test-only-deployment-secret"
	addr, caPath, stop := startSecureCoordinator(t, authKey)
	defer stop()

	secureClient, err := client.NewClient(&client.Config{
		URL:     "grpcs://" + addr,
		AuthKey: authKey,
		Timeout: 2 * time.Second,
		TLS:     client.TLSConfig{CAFile: caPath},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer func() { _ = secureClient.Close() }()

	registered, err := secureClient.Register(context.Background(), &client.RegisterRequest{
		PublicKey: "secure-client-public-key",
		Name:      "secure-client",
	})
	if err != nil {
		t.Fatalf("Register() over TLS with shared auth error = %v", err)
	}
	peers, err := secureClient.ListPeers(context.Background())
	if err != nil {
		t.Fatalf("ListPeers() over TLS with shared auth error = %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("len(peers) = %d, want 1", len(peers))
	}
	if _, err := secureClient.GetPeer(context.Background(), registered.NodeID); err != nil {
		t.Fatalf("GetPeer() over TLS with shared auth error = %v", err)
	}

	rawConn := dialSecureRawClient(t, addr, caPath)
	defer rawConn.Close()
	rawRPC := coordinatorv1.NewCoordinatorClient(rawConn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := rawRPC.ListPeers(ctx, &coordinatorv1.ListPeersRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated ListPeers() code = %s, want %s (err=%v)", status.Code(err), codes.Unauthenticated, err)
	}

	stream, err := rawRPC.Signal(ctx)
	if err != nil {
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("unauthenticated Signal() code = %s, want %s (err=%v)", status.Code(err), codes.Unauthenticated, err)
		}
		return
	}
	err = stream.Send(&coordinatorv1.SignalEnvelope{FromNode: registered.NodeID})
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated Signal stream code = %s, want %s (err=%v)", status.Code(err), codes.Unauthenticated, err)
	}
}

func startSecureCoordinator(t *testing.T, authKey string) (string, string, func()) {
	t.Helper()

	certPath, keyPath := newSecureTestCertificate(t)
	domain, err := server.New(&server.Config{
		ListenAddress: "127.0.0.1:0",
		NetworkCIDR:   "10.98.0.0/24",
		LeaseTTL:      5 * time.Second,
		AuthKey:       authKey,
	})
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = domain.Close()
		t.Fatalf("net.Listen() error = %v", err)
	}

	options, err := server.GRPCServerOptions(authKey, certPath, keyPath)
	if err != nil {
		_ = listener.Close()
		_ = domain.Close()
		t.Fatalf("server.GRPCServerOptions() error = %v", err)
	}
	grpcServer := grpc.NewServer(options...)
	coordinatorv1.RegisterCoordinatorServer(grpcServer, server.NewGRPCService(domain))
	go func() { _ = grpcServer.Serve(listener) }()

	return listener.Addr().String(), certPath, func() {
		grpcServer.Stop()
		_ = listener.Close()
		_ = domain.Close()
	}
}

func dialSecureRawClient(t *testing.T, addr, caPath string) *grpc.ClientConn {
	t.Helper()

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("ReadFile(ca) error = %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM(ca) failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(
		ctx,
		addr,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		})),
	)
	if err != nil {
		t.Fatalf("grpc.DialContext() error = %v", err)
	}
	return conn
}

func newSecureTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "winkyou-test-coordinator"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "coordinator.crt")
	keyPath := filepath.Join(dir, "coordinator.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	return certPath, keyPath
}
