package rendezvouscarrier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestValidateTLSConfigIsExactAndZeroIO(t *testing.T) {
	validPin := base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	for _, config := range []TLSConfig{
		{Verification: TLSSystemRoots, ServerName: "rendezvous.example"},
		{Verification: TLSSPKISHA256, SPKISHA256: validPin},
	} {
		if err := ValidateTLSConfig(config); err != nil {
			t.Errorf("valid TLS config rejected: %v", err)
		}
	}
	for _, config := range []TLSConfig{
		{},
		{Verification: TLSSystemRoots},
		{Verification: TLSSystemRoots, ServerName: "rendezvous.example", SPKISHA256: validPin},
		{Verification: TLSSPKISHA256, ServerName: "rendezvous.example", SPKISHA256: validPin},
		{Verification: TLSSPKISHA256, SPKISHA256: "not-a-pin"},
	} {
		if err := ValidateTLSConfig(config); !errors.Is(err, ErrTLSConfig) {
			t.Errorf("invalid TLS config accepted: %+v / %v", config, err)
		}
	}
}

func TestSPKIPinAcceptsLeafFromCertificateChainAndRequiresTLS13(t *testing.T) {
	certificate, leaf := testTLSCertificateChain(t)
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := base64.RawURLEncoding.EncodeToString(digest[:])
	clear(digest[:])

	client, server := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		secured := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
		serverDone <- secured.Handshake()
		_ = secured.Close()
	}()
	secured, err := secureRendezvous(context.Background(), client, TLSConfig{Verification: TLSSPKISHA256, SPKISHA256: pin})
	if err != nil {
		t.Fatalf("pinned chain handshake: %v", err)
	}
	if secured.(*tls.Conn).ConnectionState().Version != tls.VersionTLS13 || len(secured.(*tls.Conn).ConnectionState().PeerCertificates) != 2 {
		t.Fatal("pinned chain did not preserve the exact TLS 1.3 evidence")
	}
	_ = secured.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	client, server = net.Pipe()
	serverDone = make(chan error, 1)
	go func() {
		secured := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
		serverDone <- secured.Handshake()
		_ = secured.Close()
	}()
	if secured, err := secureRendezvous(context.Background(), client, TLSConfig{Verification: TLSSPKISHA256, SPKISHA256: pin}); secured != nil || !errors.Is(err, ErrTLSHandshake) {
		t.Fatalf("TLS 1.2 endpoint = %#v/%v", secured, err)
	}
	_ = <-serverDone
}

func testTLSCertificateChain(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "test-leaf"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, leafTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "test-intermediate"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, intermediateTemplate, &intermediateKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, intermediateDER}, PrivateKey: key, Leaf: leaf}, leaf
}
