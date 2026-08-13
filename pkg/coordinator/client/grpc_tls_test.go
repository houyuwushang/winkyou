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
	target, tlsEnabled, err := normalizeTarget("grpcs://coord.example.com:9443")
	if err != nil {
		t.Fatalf("normalizeTarget(grpcs) error = %v", err)
	}
	if target != "coord.example.com:9443" {
		t.Fatalf("target = %q, want coord.example.com:9443", target)
	}
	if !tlsEnabled {
		t.Fatal("expected tlsEnabled=true for grpcs scheme")
	}

	target, tlsEnabled, err = normalizeTarget("grpc://127.0.0.1:9443")
	if err != nil {
		t.Fatalf("normalizeTarget(loopback grpc) error = %v", err)
	}
	if target != "127.0.0.1:9443" {
		t.Fatalf("target = %q, want 127.0.0.1:9443", target)
	}
	if tlsEnabled {
		t.Fatal("expected tlsEnabled=false for grpc scheme")
	}
}

func TestNormalizeTargetRejectsRemotePlaintext(t *testing.T) {
	for _, raw := range []string{
		"grpc://coord.example.com:9443",
		"http://192.0.2.10:9443",
		"192.0.2.10:9443",
		"grpc://0.0.0.0:9443",
		"grpc://localhost:9443",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := normalizeTarget(raw); err == nil {
				t.Fatalf("normalizeTarget(%q) error = nil, want remote plaintext rejection", raw)
			}
		})
	}
}

func TestNormalizeTargetAllowsExplicitPlaintextLoopback(t *testing.T) {
	for _, raw := range []string{
		"grpc://127.0.0.1:9443",
		"grpc://[::1]:9443",
		"127.0.0.1:9443",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, tlsEnabled, err := normalizeTarget(raw); err != nil {
				t.Fatalf("normalizeTarget(%q) error = %v", raw, err)
			} else if tlsEnabled {
				t.Fatalf("normalizeTarget(%q) tlsEnabled = true, want false", raw)
			}
		})
	}
}

func TestNewClientRequiresSharedAuthForRemoteCoordinator(t *testing.T) {
	if _, err := NewClient(&Config{URL: "grpcs://coord.example.com:9443"}); err == nil {
		t.Fatal("NewClient() error = nil, want missing remote auth rejection")
	}
	if _, err := NewClient(&Config{URL: "grpcs://coord.example.com:9443", AuthKey: "test-secret"}); err != nil {
		t.Fatalf("NewClient() with remote auth error = %v", err)
	}
}
