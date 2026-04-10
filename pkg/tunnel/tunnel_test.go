package tunnel

import (
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// --- Key tests (unchanged) ---

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
	_, err := ParsePrivateKey("not-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err = ParsePrivateKey(short)
	if err == nil {
		t.Error("expected error for wrong-length key")
	}
}

func TestKeyStringLength(t *testing.T) {
	k, _ := GeneratePrivateKey()
	s := k.String()
	if len(s) != 44 {
		t.Errorf("String() length = %d, want 44", len(s))
	}
}

// --- Tunnel constructor ---

func TestNewTunnel(t *testing.T) {
	tun, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if tun == nil {
		t.Fatal("New() returned nil")
	}
}

// --- Start / Stop lifecycle ---

func TestStartStop(t *testing.T) {
	tun, _ := New(Config{})

	if err := tun.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Double start should fail.
	err := tun.Start()
	if err == nil {
		t.Error("second Start() should return error")
	}

	// Stop should succeed.
	if err := tun.Stop(); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	// Stop is idempotent.
	if err := tun.Stop(); err != nil {
		t.Fatalf("second Stop() error: %v", err)
	}

	// Can restart after stop.
	if err := tun.Start(); err != nil {
		t.Fatalf("Start() after Stop() error: %v", err)
	}
}

// --- GetStats / GetPeers basic ---

func TestGetStatsEmpty(t *testing.T) {
	tun, _ := New(Config{})
	stats := tun.GetStats()
	if stats == nil {
		t.Fatal("GetStats() returned nil")
	}
	if stats.Peers != 0 {
		t.Errorf("Peers = %d, want 0", stats.Peers)
	}
}

func TestGetPeersEmpty(t *testing.T) {
	tun, _ := New(Config{})
	peers := tun.GetPeers()
	if len(peers) != 0 {
		t.Errorf("GetPeers() length = %d, want 0", len(peers))
	}
}

func TestEvents(t *testing.T) {
	tun, _ := New(Config{})
	ch := tun.Events()
	if ch == nil {
		t.Error("Events() returned nil channel")
	}
}

// --- AddPeer ---

func TestAddPeerSuccess(t *testing.T) {
	tun, _ := New(Config{})

	pk := makeTestKey(1)
	err := tun.AddPeer(&PeerConfig{
		PublicKey:  pk,
		AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(24, 32)}},
		Endpoint:   &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 51820},
	})
	if err != nil {
		t.Fatalf("AddPeer() error: %v", err)
	}

	// Verify via GetPeers.
	peers := tun.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("GetPeers() length = %d, want 1", len(peers))
	}
	if peers[0].PublicKey != pk {
		t.Error("PublicKey mismatch")
	}
	if peers[0].Endpoint == nil || !peers[0].Endpoint.IP.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Error("Endpoint not set correctly")
	}
	if len(peers[0].AllowedIPs) != 1 {
		t.Error("AllowedIPs not stored")
	}

	// Verify stats.
	stats := tun.GetStats()
	if stats.Peers != 1 {
		t.Errorf("Peers = %d, want 1", stats.Peers)
	}

	// Verify event.
	ev := drainEvent(t, tun)
	if ev.Type != EventPeerAdded {
		t.Errorf("event Type = %v, want EventPeerAdded", ev.Type)
	}
	if ev.PeerKey != pk {
		t.Error("event PeerKey mismatch")
	}
}

func TestAddPeerNil(t *testing.T) {
	tun, _ := New(Config{})
	err := tun.AddPeer(nil)
	if err == nil {
		t.Error("AddPeer(nil) should return error")
	}
}

func TestAddPeerEmptyKey(t *testing.T) {
	tun, _ := New(Config{})
	err := tun.AddPeer(&PeerConfig{})
	if err == nil {
		t.Error("AddPeer with empty key should return error")
	}
}

func TestAddPeerDuplicate(t *testing.T) {
	tun, _ := New(Config{})
	pk := makeTestKey(2)

	err := tun.AddPeer(&PeerConfig{PublicKey: pk})
	if err != nil {
		t.Fatalf("first AddPeer() error: %v", err)
	}
	_ = drainEvent(t, tun)

	err = tun.AddPeer(&PeerConfig{PublicKey: pk})
	if err == nil {
		t.Error("duplicate AddPeer should return error")
	}
}

// --- RemovePeer ---

func TestRemovePeer(t *testing.T) {
	tun, _ := New(Config{})
	pk := makeTestKey(3)

	tun.AddPeer(&PeerConfig{PublicKey: pk})
	_ = drainEvent(t, tun) // consume add event

	err := tun.RemovePeer(pk)
	if err != nil {
		t.Fatalf("RemovePeer() error: %v", err)
	}

	peers := tun.GetPeers()
	if len(peers) != 0 {
		t.Errorf("GetPeers() length = %d, want 0", len(peers))
	}

	ev := drainEvent(t, tun)
	if ev.Type != EventPeerRemoved {
		t.Errorf("event Type = %v, want EventPeerRemoved", ev.Type)
	}
}

func TestRemovePeerNotFound(t *testing.T) {
	tun, _ := New(Config{})
	err := tun.RemovePeer(makeTestKey(99))
	if err == nil {
		t.Error("RemovePeer for non-existent peer should return error")
	}
}

// --- UpdatePeerEndpoint ---

func TestUpdatePeerEndpoint(t *testing.T) {
	tun, _ := New(Config{})
	pk := makeTestKey(4)

	tun.AddPeer(&PeerConfig{
		PublicKey: pk,
		Endpoint:  &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1000},
	})
	_ = drainEvent(t, tun)

	newEP := &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2000}
	err := tun.UpdatePeerEndpoint(pk, newEP)
	if err != nil {
		t.Fatalf("UpdatePeerEndpoint() error: %v", err)
	}

	peers := tun.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("GetPeers() length = %d, want 1", len(peers))
	}
	if !peers[0].Endpoint.IP.Equal(net.IPv4(2, 2, 2, 2)) {
		t.Errorf("Endpoint IP = %v, want 2.2.2.2", peers[0].Endpoint.IP)
	}
	if peers[0].Endpoint.Port != 2000 {
		t.Errorf("Endpoint Port = %d, want 2000", peers[0].Endpoint.Port)
	}

	ev := drainEvent(t, tun)
	if ev.Type != EventPeerEndpointChanged {
		t.Errorf("event Type = %v, want EventPeerEndpointChanged", ev.Type)
	}
}

func TestUpdatePeerEndpointNotFound(t *testing.T) {
	tun, _ := New(Config{})
	err := tun.UpdatePeerEndpoint(makeTestKey(99), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1})
	if err == nil {
		t.Error("UpdatePeerEndpoint for non-existent peer should return error")
	}
}

// --- GetPeers deep copy ---

func TestGetPeersDeepCopy(t *testing.T) {
	tun, _ := New(Config{})
	pk := makeTestKey(5)

	tun.AddPeer(&PeerConfig{
		PublicKey: pk,
		Endpoint:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000},
		AllowedIPs: []net.IPNet{{
			IP:   net.IPv4(10, 0, 0, 0),
			Mask: net.CIDRMask(24, 32),
		}},
	})
	_ = drainEvent(t, tun)

	peers1 := tun.GetPeers()
	if len(peers1) != 1 {
		t.Fatalf("GetPeers() length = %d, want 1", len(peers1))
	}

	// Mutate the returned copy.
	peers1[0].Endpoint.Port = 9999
	peers1[0].AllowedIPs[0].IP[3] = 0xFF

	// Fetch again; internal state should be unchanged.
	peers2 := tun.GetPeers()
	if peers2[0].Endpoint.Port != 5000 {
		t.Errorf("internal Endpoint.Port was mutated: got %d, want 5000", peers2[0].Endpoint.Port)
	}
	if peers2[0].AllowedIPs[0].IP[3] != 0 {
		t.Error("internal AllowedIPs was mutated")
	}
}

// --- GetPeers sorted ---

func TestGetPeersSorted(t *testing.T) {
	tun, _ := New(Config{})

	// Add peers in reverse key order.
	pk3 := makeTestKey(3)
	pk1 := makeTestKey(1)
	pk2 := makeTestKey(2)
	tun.AddPeer(&PeerConfig{PublicKey: pk3})
	tun.AddPeer(&PeerConfig{PublicKey: pk1})
	tun.AddPeer(&PeerConfig{PublicKey: pk2})

	peers := tun.GetPeers()
	if len(peers) != 3 {
		t.Fatalf("GetPeers() length = %d, want 3", len(peers))
	}
	// Should be sorted by PublicKey bytes.
	if peers[0].PublicKey != pk1 {
		t.Error("peers not sorted correctly")
	}
	if peers[1].PublicKey != pk2 {
		t.Error("peers not sorted correctly")
	}
	if peers[2].PublicKey != pk3 {
		t.Error("peers not sorted correctly")
	}
}

// --- Concurrent safety ---

func TestConcurrentAccess(t *testing.T) {
	tun, _ := New(Config{})
	tun.Start()

	var wg sync.WaitGroup
	// Concurrent readers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = tun.GetPeers()
				_ = tun.GetStats()
			}
		}()
	}
	// Concurrent writer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			pk := makeTestKey(byte(j + 100))
			tun.AddPeer(&PeerConfig{PublicKey: pk})
			tun.RemovePeer(pk)
		}
	}()
	wg.Wait()

	tun.Stop()
}

// --- Multiple peers stats ---

func TestGetStatsMultiplePeers(t *testing.T) {
	tun, _ := New(Config{})
	for i := 0; i < 5; i++ {
		tun.AddPeer(&PeerConfig{PublicKey: makeTestKey(byte(i + 10))})
	}
	stats := tun.GetStats()
	if stats.Peers != 5 {
		t.Errorf("Peers = %d, want 5", stats.Peers)
	}
}

// --- ErrNotImplemented still exported ---

func TestErrNotImplementedExists(t *testing.T) {
	if ErrNotImplemented == nil {
		t.Error("ErrNotImplemented should not be nil")
	}
	_ = errors.Is(ErrNotImplemented, ErrNotImplemented) // just verify it's usable
}

// --- Helpers ---

// makeTestKey creates a PublicKey with byte b in position 0 and zeros elsewhere.
func makeTestKey(b byte) PublicKey {
	var pk PublicKey
	pk[0] = b
	return pk
}

// drainEvent reads one event from the tunnel's Events channel with a short timeout.
func drainEvent(t *testing.T, tun Tunnel) TunnelEvent {
	t.Helper()
	select {
	case ev := <-tun.Events():
		return ev
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
		return TunnelEvent{} // unreachable
	}
}
