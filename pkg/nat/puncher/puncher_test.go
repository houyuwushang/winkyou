package puncher

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

func TestEncodeDecodePunchRoundTrip(t *testing.T) {
	orig := punchPacket{
		Kind:    punchAck,
		Session: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Nonce:   [8]byte{9, 10, 11, 12, 13, 14, 15, 16},
	}
	dec, ok := decodePunch(encodePunch(orig))
	if !ok {
		t.Fatal("decode failed")
	}
	if dec != orig {
		t.Fatalf("round trip = %+v, want %+v", dec, orig)
	}
}

func TestDecodePunchRejectsBad(t *testing.T) {
	if _, ok := decodePunch([]byte{1, 2, 3}); ok {
		t.Fatal("accepted short packet")
	}
	if _, ok := decodePunch(make([]byte, punchPacketLen)); ok {
		t.Fatal("accepted packet with wrong magic")
	}
}

func TestBirthdayTargets(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	ports := BirthdayTargets(r, 100, 1024, 65535)
	if len(ports) != 100 {
		t.Fatalf("got %d ports, want 100", len(ports))
	}
	seen := make(map[int]bool, len(ports))
	for _, p := range ports {
		if p < 1024 || p > 65535 {
			t.Fatalf("port %d out of range", p)
		}
		if seen[p] {
			t.Fatalf("duplicate port %d", p)
		}
		seen[p] = true
	}
}

func TestBirthdayTargetsClampsToRange(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	ports := BirthdayTargets(r, 100, 5000, 5009) // range holds only 10
	if len(ports) != 10 {
		t.Fatalf("got %d ports, want 10 (range size)", len(ports))
	}
}

func TestPunchValidatesConfig(t *testing.T) {
	ctx := context.Background()
	if _, err := Punch(ctx, Config{RemoteIP: net.IPv4(127, 0, 0, 1)}); err == nil {
		t.Fatal("expected error for missing target ports")
	}
	if _, err := Punch(ctx, Config{TargetPorts: []int{80}}); err == nil {
		t.Fatal("expected error for missing remote IP")
	}
	if _, err := Punch(nil, Config{}); err == nil {
		t.Fatal("expected error for nil context")
	}
	if _, err := Punch(ctx, Config{RemoteIP: net.IPv4(127, 0, 0, 1), TargetPorts: []int{65536}}); err == nil {
		t.Fatal("expected error for invalid target port")
	}
	if _, err := Punch(ctx, Config{
		RemoteIP: net.IPv4(127, 0, 0, 1), BirthdayN: 1,
		BirthdayLo: 60000, BirthdayHi: 50000,
	}); err == nil {
		t.Fatal("expected error for reversed birthday range")
	}
}

func TestPunchAcceptsSinglePortBirthdayRange(t *testing.T) {
	session := [8]byte{3, 1, 4, 1, 5, 9, 2, 6}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerPort := peer.LocalAddr().(*net.UDPAddr).Port
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxPunchPacket)
		for {
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			n, source, readErr := peer.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			packet, ok := decodePunch(buffer[:n])
			if !ok || packet.Kind != punchProbe || packet.Session != session {
				continue
			}
			_, _ = peer.WriteToUDP(encodePunch(punchPacket{
				Kind: punchAck, Session: session, Nonce: packet.Nonce,
			}), source)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := Punch(ctx, Config{
		RemoteIP: net.IPv4(127, 0, 0, 1), Session: session,
		SocketCount: 1, BirthdayN: 1, BirthdayLo: peerPort, BirthdayHi: peerPort,
		RoundDelay: 10 * time.Millisecond, GracePeriod: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = result.Conn.Close()
	_ = peer.Close()
	<-done
}

// TestPunchHitsResponder verifies the core hit path end to end over loopback:
// the sender reaches a responder, the responder acks, and Punch reports the
// winning socket plus the peer's learned source address.
func TestPunchHitsResponder(t *testing.T) {
	session := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peerPort := peer.LocalAddr().(*net.UDPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxPunchPacket)
		for {
			_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, src, err := peer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt, ok := decodePunch(buf[:n])
			if !ok || pkt.Session != session || pkt.Kind != punchProbe {
				continue
			}
			ack := encodePunch(punchPacket{Kind: punchAck, Session: session, Nonce: pkt.Nonce})
			_, _ = peer.WriteToUDP(ack, src)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Punch(ctx, Config{
		RemoteIP:    net.IPv4(127, 0, 0, 1),
		TargetPorts: []int{peerPort},
		Session:     session,
		SocketCount: 4,
		Burst:       1,
		RoundDelay:  50 * time.Millisecond,
		Method:      "test",
	})
	if err != nil {
		peer.Close()
		<-done
		t.Fatalf("Punch: %v", err)
	}
	if res.Conn == nil {
		t.Fatal("nil winning conn")
	}
	if res.RemoteAddr == nil || res.RemoteAddr.Port != peerPort {
		t.Fatalf("RemoteAddr = %v, want loopback port %d", res.RemoteAddr, peerPort)
	}

	// The winning socket must be usable as a normal data plane after Punch
	// returns. In particular, punchReader's short polling deadline must not leak
	// into the handed-off connection.
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		n, _, readErr := res.Conn.ReadFromUDP(buf)
		if readErr == nil && string(buf[:n]) != "app-data" {
			readErr = fmt.Errorf("post-punch payload = %q, want app-data", buf[:n])
		}
		readDone <- readErr
	}()
	time.Sleep(50 * time.Millisecond)
	dataAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: res.LocalAddr.Port}
	if _, err := peer.WriteToUDP([]byte("app-data"), dataAddr); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("winning socket data-plane handoff failed: %v", err)
		}
	case <-time.After(time.Second):
		res.Conn.Close()
		t.Fatal("winning socket data-plane handoff timed out")
	}
	res.Conn.Close()
	peer.Close()
	<-done
}

func TestPunchTimesOutWithNoPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	_, err := Punch(ctx, Config{
		RemoteIP:    net.IPv4(127, 0, 0, 1),
		TargetPorts: []int{1}, // nothing listens on port 1
		Session:     [8]byte{9, 9, 9, 9, 9, 9, 9, 9},
		SocketCount: 2,
		Burst:       1,
		RoundDelay:  50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestPunchBirthdayAlsoTriesCachedTarget(t *testing.T) {
	session := [8]byte{4, 3, 2, 1, 8, 7, 6, 5}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerPort := peer.LocalAddr().(*net.UDPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxPunchPacket)
		for {
			_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, source, readErr := peer.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			packet, ok := decodePunch(buffer[:n])
			if !ok || packet.Session != session || packet.Kind != punchProbe {
				continue
			}
			ack := encodePunch(punchPacket{Kind: punchAck, Session: session, Nonce: packet.Nonce})
			_, _ = peer.WriteToUDP(ack, source)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := Punch(ctx, Config{
		RemoteIP: net.IPv4(127, 0, 0, 1), TargetPorts: []int{peerPort},
		Session: session, SocketCount: 1, BirthdayN: 1,
		BirthdayLo: 1, BirthdayHi: 1, RoundDelay: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Punch with cached target plus birthday spray: %v", err)
	}
	_ = result.Conn.Close()
	_ = peer.Close()
	<-done
}

func TestPunchReaderKeepsAckingAfterReportingHit(t *testing.T) {
	session := [8]byte{7, 6, 5, 4, 3, 2, 1, 0}
	readerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer readerConn.Close()
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan *Result, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		punchReader(ctx, readerConn, Config{Session: session, Method: "test"}, resultCh, &peerSet{m: make(map[string]*net.UDPAddr)})
	}()

	readerAddr := readerConn.LocalAddr().(*net.UDPAddr)
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	hitNonce := [8]byte{1}
	if _, err := peerConn.WriteToUDP(encodePunch(punchPacket{Kind: punchAck, Session: session, Nonce: hitNonce}), readerAddr); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-resultCh:
		if result.RemoteAddr == nil || result.RemoteAddr.Port != peerAddr.Port {
			t.Fatalf("reported remote = %v, want %v", result.RemoteAddr, peerAddr)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not report hit")
	}

	probeNonce := [8]byte{9, 8, 7}
	if _, err := peerConn.WriteToUDP(encodePunch(punchPacket{Kind: punchProbe, Session: session, Nonce: probeNonce}), readerAddr); err != nil {
		t.Fatal(err)
	}
	if err := peerConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxPunchPacket)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("winning reader stopped during grace window: %v", err)
	}
	ack, ok := decodePunch(buf[:n])
	if !ok || ack.Kind != punchAck || ack.Session != session || ack.Nonce != probeNonce {
		t.Fatalf("post-hit response = %#v, decoded=%v; want matching ack", ack, ok)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader did not stop after cancellation")
	}
}

func TestPunchKeepsLearnedEndpointOnTheObservingSocket(t *testing.T) {
	session := [8]byte{8, 6, 7, 5, 3, 0, 9, 1}
	loopback := net.IPv4(127, 0, 0, 1)
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	learner, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer learner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	punchDone := make(chan error, 1)
	go func() {
		_, punchErr := Punch(ctx, Config{
			RemoteIP: loopback, TargetPorts: []int{target.LocalAddr().(*net.UDPAddr).Port},
			Session: session, SocketCount: 2, Burst: 1, RoundDelay: 10 * time.Millisecond,
		})
		punchDone <- punchErr
	}()

	// Discover both local source sockets from their ordinary target probes.
	sources := make(map[int]*net.UDPAddr)
	buffer := make([]byte, maxPunchPacket)
	deadline := time.Now().Add(time.Second)
	for len(sources) < 2 && time.Now().Before(deadline) {
		_ = target.SetReadDeadline(deadline)
		n, source, readErr := target.ReadFromUDP(buffer)
		if readErr != nil {
			t.Fatalf("collect punch sources: %v", readErr)
		}
		packet, ok := decodePunch(buffer[:n])
		if ok && packet.Kind == punchProbe && packet.Session == session {
			sources[source.Port] = source
		}
	}
	if len(sources) != 2 {
		t.Fatalf("observed %d source sockets, want 2", len(sources))
	}
	var observing *net.UDPAddr
	for _, source := range sources {
		observing = source
		break
	}

	// Only this socket receives the learner's probe. Its private learned set must
	// not cause the other source socket to punch the learner as well.
	_, err = learner.WriteToUDP(encodePunch(punchPacket{
		Kind: punchProbe, Session: session, Nonce: [8]byte{1},
	}), observing)
	if err != nil {
		t.Fatal(err)
	}
	probeSources := make(map[int]struct{})
	deadline = time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		_ = learner.SetReadDeadline(deadline)
		n, source, readErr := learner.ReadFromUDP(buffer)
		if readErr != nil {
			var networkError net.Error
			if errors.As(readErr, &networkError) && networkError.Timeout() {
				break
			}
			t.Fatal(readErr)
		}
		packet, ok := decodePunch(buffer[:n])
		if ok && packet.Kind == punchProbe && packet.Session == session {
			probeSources[source.Port] = struct{}{}
		}
	}
	if len(probeSources) != 1 {
		t.Fatalf("learned endpoint was punched from %d source sockets, want 1: %v", len(probeSources), probeSources)
	}
	if _, ok := probeSources[observing.Port]; !ok {
		t.Fatalf("learned endpoint probe source = %v, want observing port %d", probeSources, observing.Port)
	}

	cancel()
	if err := <-punchDone; err == nil {
		t.Fatal("punch without an ack unexpectedly succeeded")
	}
}
