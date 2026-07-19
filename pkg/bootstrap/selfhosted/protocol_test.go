package selfhosted

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestPairKeyAndSessionAreSymmetric(t *testing.T) {
	left, err := pairKey("A", "B", []byte("mesh secret"))
	if err != nil {
		t.Fatal(err)
	}
	right, err := pairKey("B", "A", []byte("mesh secret"))
	if err != nil {
		t.Fatal(err)
	}
	if left != right || pairSession(left) != pairSession(right) {
		t.Fatal("ordered pair derived different recovery material")
	}
	other, err := pairKey("A", "C", []byte("mesh secret"))
	if err != nil {
		t.Fatal(err)
	}
	if left == other || pairSession(left) == pairSession(other) {
		t.Fatal("different peer pair reused recovery material")
	}
}

func TestHelloRoundTripAndAuthentication(t *testing.T) {
	key, err := pairKey("A", "B", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	frame := helloFrame{
		Kind: helloAckKind, Session: pairSession(key),
		Nonce: [helloNonceSize]byte{1, 2, 3}, Echo: [helloNonceSize]byte{9, 8, 7}, NodeID: "A",
	}
	raw, err := encodeHello(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeHello(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != frame {
		t.Fatalf("decoded frame = %#v, want %#v", decoded, frame)
	}
	raw[len(raw)-1] ^= 1
	if _, err := decodeHello(key, raw); err == nil {
		t.Fatal("tampered hello was accepted")
	}
}

func TestAuthenticatePeerOnPunchedConnection(t *testing.T) {
	left, right := udpConnectedPair(t)
	defer left.Close()
	defer right.Close()
	key, err := pairKey("A", "B", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	session := pairSession(key)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	errors := make(chan error, 2)
	leftConfig := helloConfig{
		Interval: 10 * time.Millisecond, Settle: 50 * time.Millisecond,
		Rand: bytes.NewReader(bytes.Repeat([]byte{1}, helloNonceSize)),
	}
	rightConfig := helloConfig{
		Interval: 10 * time.Millisecond, Settle: 50 * time.Millisecond,
		Rand: bytes.NewReader(bytes.Repeat([]byte{2}, helloNonceSize)),
	}
	go func() { errors <- authenticatePeer(ctx, left, "A", "B", key, session, leftConfig) }()
	go func() { errors <- authenticatePeer(ctx, right, "B", "A", key, session, rightConfig) }()
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatalf("authenticatePeer() error = %v", err)
		}
	}
}

func TestAuthenticatePeerRejectsReplayedHelloWithoutFreshAck(t *testing.T) {
	left, right := udpConnectedPair(t)
	defer left.Close()
	defer right.Close()
	key, err := pairKey("A", "B", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	session := pairSession(key)
	captured, err := encodeHello(key, helloFrame{
		Kind: helloKind, Session: session,
		Nonce: [helloNonceSize]byte{9, 8, 7}, NodeID: "B",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- authenticatePeer(ctx, left, "A", "B", key, session, helloConfig{
			Interval: 10 * time.Millisecond, Settle: 20 * time.Millisecond,
			Rand: bytes.NewReader(bytes.Repeat([]byte{1}, helloNonceSize)),
		})
	}()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("captured HELLO authenticated without an ACK for the fresh nonce")
			}
			return
		case <-ticker.C:
			if _, err := right.Write(captured); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestAuthenticatePeerRejectsWrongPairKey(t *testing.T) {
	left, right := udpConnectedPair(t)
	defer left.Close()
	defer right.Close()
	leftKey, _ := pairKey("A", "B", []byte("left"))
	rightKey, _ := pairKey("A", "B", []byte("right"))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	errors := make(chan error, 2)
	config := helloConfig{Interval: 10 * time.Millisecond, Settle: 20 * time.Millisecond}
	go func() { errors <- authenticatePeer(ctx, left, "A", "B", leftKey, pairSession(leftKey), config) }()
	go func() { errors <- authenticatePeer(ctx, right, "B", "A", rightKey, pairSession(rightKey), config) }()
	for range 2 {
		if err := <-errors; err == nil {
			t.Fatal("mismatched pair keys authenticated")
		}
	}
}

func udpConnectedPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	leftUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	rightUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = leftUDP.Close()
		t.Fatal(err)
	}
	return &testConnectedUDP{UDPConn: leftUDP, remote: rightUDP.LocalAddr().(*net.UDPAddr)},
		&testConnectedUDP{UDPConn: rightUDP, remote: leftUDP.LocalAddr().(*net.UDPAddr)}
}

type testConnectedUDP struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func (c *testConnectedUDP) Read(buffer []byte) (int, error) {
	for {
		n, source, err := c.ReadFromUDP(buffer)
		if err != nil {
			return n, err
		}
		if source.IP.Equal(c.remote.IP) && source.Port == c.remote.Port {
			return n, nil
		}
	}
}

func (c *testConnectedUDP) Write(buffer []byte) (int, error) {
	return c.WriteToUDP(buffer, c.remote)
}

func (c *testConnectedUDP) RemoteAddr() net.Addr { return c.remote }
