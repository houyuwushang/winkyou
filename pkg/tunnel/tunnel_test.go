package tunnel

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	k1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error: %v", err)
	}
	k2, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error: %v", err)
	}
	if k1 == k2 {
		t.Error("two generated keys should not be equal")
	}

	// Verify clamping
	if k1[0]&7 != 0 {
		t.Error("key[0] low 3 bits should be cleared")
	}
	if k1[31]&128 != 0 {
		t.Error("key[31] high bit should be cleared")
	}
	if k1[31]&64 == 0 {
		t.Error("key[31] bit 6 should be set")
	}
}

func TestPrivateKeyPublicKeyDerived(t *testing.T) {
	k, _ := GeneratePrivateKey()
	pub := k.PublicKey()
	// Stub derivation: ensure it's deterministic
	pub2 := k.PublicKey()
	if pub != pub2 {
		t.Error("PublicKey() should be deterministic")
	}
}

func TestKeyRoundTrip(t *testing.T) {
	k, _ := GeneratePrivateKey()
	s := k.String()

	parsed, err := ParsePrivateKey(s)
	if err != nil {
		t.Fatalf("ParsePrivateKey(%q) error: %v", s, err)
	}
	if parsed != k {
		t.Error("round-trip private key mismatch")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	k, _ := GeneratePrivateKey()
	pub := k.PublicKey()
	s := pub.String()

	parsed, err := ParsePublicKey(s)
	if err != nil {
		t.Fatalf("ParsePublicKey(%q) error: %v", s, err)
	}
	if parsed != pub {
		t.Error("round-trip public key mismatch")
	}
}

func TestParseInvalidKey(t *testing.T) {
	// Not valid base64
	_, err := ParsePrivateKey("not-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Wrong length
	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err = ParsePrivateKey(short)
	if err == nil {
		t.Error("expected error for wrong-length key")
	}
}

func TestKeyStringLength(t *testing.T) {
	k, _ := GeneratePrivateKey()
	s := k.String()
	// 32 bytes base64 = 44 chars
	if len(s) != 44 {
		t.Errorf("String() length = %d, want 44", len(s))
	}
}

func TestNewTunnel(t *testing.T) {
	tun, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if tun == nil {
		t.Fatal("New() returned nil")
	}
}

func TestStubTunnelStart(t *testing.T) {
	tun, _ := New(Config{})
	err := tun.Start()
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Start() error = %v, want ErrNotImplemented", err)
	}
}

func TestStubTunnelGetStats(t *testing.T) {
	tun, _ := New(Config{})
	stats := tun.GetStats()
	if stats == nil {
		t.Error("GetStats() returned nil")
	}
}

func TestStubTunnelEvents(t *testing.T) {
	tun, _ := New(Config{})
	ch := tun.Events()
	if ch == nil {
		t.Error("Events() returned nil channel")
	}
}

func TestStubTunnelGetPeers(t *testing.T) {
	tun, _ := New(Config{})
	peers := tun.GetPeers()
	if peers != nil && len(peers) != 0 {
		t.Error("GetPeers() should return nil or empty slice")
	}
}
