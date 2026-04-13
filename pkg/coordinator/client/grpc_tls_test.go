package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDialTransportCredentials_WithTLSAndMissingCAFile(t *testing.T) {
	_, err := dialTransportCredentials(TLSConfig{CAFile: filepath.Join(t.TempDir(), "missing.pem")}, true)
	if err == nil {
		t.Fatal("expected error when CA file is missing")
	}
}

func TestDialTransportCredentials_WithTLSAndCustomCAFile(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	// test-only minimal PEM body (not a valid cert) should fail append.
	if err := os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	_, err := dialTransportCredentials(TLSConfig{CAFile: caPath}, true)
	if err == nil {
		t.Fatal("expected append cert failure for invalid CA content")
	}
}

func TestNormalizeTargetRecognizesTLSSchemes(t *testing.T) {
	target, tlsEnabled := normalizeTarget("grpcs://coord.example.com:9443")
	if target != "coord.example.com:9443" {
		t.Fatalf("target = %q, want coord.example.com:9443", target)
	}
	if !tlsEnabled {
		t.Fatal("expected tlsEnabled=true for grpcs scheme")
	}

	target, tlsEnabled = normalizeTarget("grpc://127.0.0.1:9443")
	if target != "127.0.0.1:9443" {
		t.Fatalf("target = %q, want 127.0.0.1:9443", target)
	}
	if tlsEnabled {
		t.Fatal("expected tlsEnabled=false for grpc scheme")
	}
}
