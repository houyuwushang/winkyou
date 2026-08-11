package puncher

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"winkyou/pkg/netutil"
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
	if _, err := Punch(ctx, Config{RemoteIP: net.IPv4(127, 0, 0, 1), TargetPorts: []int{80}, Role: Role(99)}); err == nil {
		t.Fatal("expected error for invalid role")
	}
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

func TestPunchBindingUsesExactLocalInterfaceIP(t *testing.T) {
	binding := testPunchBinding(t)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: binding.LocalIP, Port: 0})
	if err != nil {
		t.Fatalf("peer listen on %s: %v", binding.LocalIP, err)
	}
	peerPort := peer.LocalAddr().(*net.UDPAddr).Port
	session := [8]byte{7, 7, 2, 2, 6, 6, 1, 1}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxPunchPacket)
		for {
			_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, src, readErr := peer.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			packet, ok := decodePunch(buf[:n])
			if !ok || packet.Session != session || packet.Kind != punchProbe {
				continue
			}
			_, _ = peer.WriteToUDP(encodePunch(punchPacket{Kind: punchAck, Session: session, Nonce: packet.Nonce}), src)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := Punch(ctx, Config{
		RemoteIP: binding.LocalIP, TargetPorts: []int{peerPort}, Session: session,
		SocketCount: 2, RoundDelay: 20 * time.Millisecond, GracePeriod: 10 * time.Millisecond,
		Binding: binding,
	})
	if err != nil {
		_ = peer.Close()
		<-done
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("platform requires additional privilege for interface binding: %v", err)
		}
		t.Fatalf("Punch() error = %v", err)
	}
	if result.LocalAddr == nil || !result.LocalAddr.IP.Equal(binding.LocalIP) {
		t.Fatalf("Punch() local = %v, want source IP %s", result.LocalAddr, binding.LocalIP)
	}
	_ = result.Conn.Close()
	_ = peer.Close()
	<-done
}

func testPunchBinding(t *testing.T) *netutil.UDPBinding {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		binding, err := netutil.ResolveUDPBinding(iface.Name)
		if err == nil {
			return binding
		}
	}
	t.Skip("host has no active non-loopback interface with a usable IPv4 address")
	return nil
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
		punchReader(ctx, readerConn, Config{Session: session, Method: "test"}, resultCh, &peerSet{m: make(map[string]*net.UDPAddr)}, newPunchEvents(1))
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

func TestCoordinatedRolesConvergeCrossedWinners(t *testing.T) {
	session := [8]byte{4, 2, 4, 2, 6, 4, 2, 1}
	a0 := listenTestUDP(t)
	a1 := listenTestUDP(t)
	b0 := listenTestUDP(t)
	b1 := listenTestUDP(t)
	all := []*net.UDPConn{a0, a1, b0, b1}
	for _, conn := range all {
		defer conn.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	selectorConfig := Config{Session: session, Role: RoleSelector, Method: "coordinated-test", RoundDelay: 10 * time.Millisecond}
	receiverConfig := Config{Session: session, Role: RoleReceiver, Method: "coordinated-test", RoundDelay: 10 * time.Millisecond}
	selectorResults := make(chan *Result, 2)
	receiverResults := make(chan *Result, 2)
	selectorEvents := newPunchEvents(2)
	receiverEvents := newPunchEvents(2)

	var readers sync.WaitGroup
	startReader := func(conn *net.UDPConn, config Config, results chan<- *Result, events *punchEvents) {
		readers.Add(1)
		go func() {
			defer readers.Done()
			punchReader(ctx, conn, config, results, &peerSet{m: make(map[string]*net.UDPAddr)}, events)
		}()
	}
	startReader(a0, selectorConfig, selectorResults, selectorEvents)
	startReader(a1, selectorConfig, selectorResults, selectorEvents)
	startReader(b0, receiverConfig, receiverResults, receiverEvents)
	startReader(b1, receiverConfig, receiverResults, receiverEvents)

	selectorDone := make(chan *Result, 1)
	receiverDone := make(chan *Result, 1)
	go func() {
		result, _ := chooseResult(ctx, selectorConfig, selectorResults, selectorEvents)
		selectorDone <- result
	}()
	go func() {
		result, _ := chooseResult(ctx, receiverConfig, receiverResults, receiverEvents)
		receiverDone <- result
	}()

	// Manufacture the exact crossed-first-hit race from the field run. The
	// selector sees A0<->B0 first, while the receiver's legacy result channel
	// sees B1<->A1 first. Only SELECT/ACK/DONE may decide the receiver winner.
	writePunchTestPacket(t, b0, a0, punchPacket{Kind: punchAck, Session: session, Nonce: [8]byte{1}})
	writePunchTestPacket(t, a1, b1, punchPacket{Kind: punchAck, Session: session, Nonce: [8]byte{2}})

	// Wait for the manufactured B1 hit before asserting the coordinated result.
	// The old non-blocking check raced the B1 reader against the faster A0/B0
	// SELECT/ACK/DONE exchange and intermittently claimed the packet was absent
	// even though it was still queued in the loopback socket.
	legacyHit := waitPunchResult(t, receiverResults)
	if legacyHit.Conn != b1 {
		t.Fatalf("manufactured receiver first hit used %v, want B1", legacyHit.LocalAddr)
	}

	selector := waitPunchResult(t, selectorDone)
	receiver := waitPunchResult(t, receiverDone)
	if selector.Conn != a0 || !udpAddrEqual(selector.RemoteAddr, udpAddrOf(b0)) {
		t.Fatalf("selector tuple = %v -> %v, want A0 -> B0", selector.LocalAddr, selector.RemoteAddr)
	}
	if receiver.Conn != b0 || !udpAddrEqual(receiver.RemoteAddr, udpAddrOf(a0)) {
		t.Fatalf("receiver tuple = %v -> %v, want B0 -> A0; crossed local hit on B1 must not win", receiver.LocalAddr, receiver.RemoteAddr)
	}
	// Match Punch teardown: readers stop, deadlines are cleared, and every loser
	// closes. The reciprocal winners must still carry application datagrams in
	// both directions after that teardown.
	cancel()
	readers.Wait()
	_ = a1.Close()
	_ = b1.Close()
	_ = selector.Conn.SetDeadline(time.Time{})
	_ = receiver.Conn.SetDeadline(time.Time{})
	assertPunchData(t, selector.Connected(), receiver.Connected(), "selector-to-receiver")
	assertPunchData(t, receiver.Connected(), selector.Connected(), "receiver-to-selector")
}

func TestCoordinatedPunchPairEndToEnd(t *testing.T) {
	session := [8]byte{7, 1, 7, 2, 7, 3, 7, 4}
	aPort := reserveTestUDPPort(t)
	bPort := reserveTestUDPPort(t)
	for bPort == aPort {
		bPort = reserveTestUDPPort(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type outcome struct {
		result *Result
		err    error
	}
	outcomes := make(chan outcome, 2)
	run := func(role Role, localPort, remotePort int) {
		result, err := Punch(ctx, Config{
			RemoteIP: net.IPv4(127, 0, 0, 1), TargetPorts: []int{remotePort},
			Session: session, Role: role, LocalPort: localPort,
			Burst: 1, RoundDelay: 10 * time.Millisecond, GracePeriod: 30 * time.Millisecond,
			Method: "coordinated-e2e",
		})
		outcomes <- outcome{result: result, err: err}
	}
	go run(RoleReceiver, bPort, aPort)
	go run(RoleSelector, aPort, bPort)

	var selector, receiver *Result
	for range 2 {
		select {
		case got := <-outcomes:
			if got.err != nil || got.result == nil {
				t.Fatalf("coordinated Punch outcome = %+v, %v", got.result, got.err)
			}
			switch got.result.LocalAddr.Port {
			case aPort:
				selector = got.result
			case bPort:
				receiver = got.result
			default:
				t.Fatalf("unexpected local winner port %d", got.result.LocalAddr.Port)
			}
		case <-ctx.Done():
			t.Fatalf("coordinated Punch pair timed out: %v", ctx.Err())
		}
	}
	if selector == nil || receiver == nil || selector.RemoteAddr.Port != bPort || receiver.RemoteAddr.Port != aPort {
		t.Fatalf("non-reciprocal coordinated results: selector=%+v receiver=%+v", selector, receiver)
	}
	defer selector.Conn.Close()
	defer receiver.Conn.Close()
	assertPunchData(t, selector.Connected(), receiver.Connected(), "full-punch-selector-to-receiver")
	assertPunchData(t, receiver.Connected(), selector.Connected(), "full-punch-receiver-to-selector")
}

func TestReceiverOnlyAcknowledgesAdoptedTupleAndToken(t *testing.T) {
	session := [8]byte{6, 2, 6, 4, 3, 3, 8, 3}
	token := [8]byte{1, 3, 3, 7}
	wrongToken := [8]byte{9, 9, 9}
	receiver0 := listenTestUDP(t)
	receiver1 := listenTestUDP(t)
	selector := listenTestUDP(t)
	wrongSource := listenTestUDP(t)
	for _, conn := range []*net.UDPConn{receiver0, receiver1, selector, wrongSource} {
		defer conn.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	config := Config{Session: session, Role: RoleReceiver, Method: "receiver-state-test"}
	events := newPunchEvents(2)
	results := make(chan *Result, 2)
	var readers sync.WaitGroup
	for _, conn := range []*net.UDPConn{receiver0, receiver1} {
		readers.Add(1)
		go func(conn *net.UDPConn) {
			defer readers.Done()
			punchReader(ctx, conn, config, results, &peerSet{m: make(map[string]*net.UDPAddr)}, events)
		}(conn)
	}

	writePunchTestPacket(t, selector, receiver0, punchPacket{Kind: punchSelect, Session: session, Nonce: token})
	readPunchTestPacket(t, selector, punchSelectAck, token)

	// A competing local socket/source/token must not receive SELECT_ACK.
	writePunchTestPacket(t, wrongSource, receiver1, punchPacket{Kind: punchSelect, Session: session, Nonce: wrongToken})
	expectNoPunchTestPacket(t, wrongSource)
	// DONE must match both the adopted token and exact remote source.
	writePunchTestPacket(t, selector, receiver0, punchPacket{Kind: punchDone, Session: session, Nonce: wrongToken})
	expectNoPunchTestPacket(t, selector)
	writePunchTestPacket(t, wrongSource, receiver0, punchPacket{Kind: punchDone, Session: session, Nonce: token})
	expectNoPunchTestPacket(t, wrongSource)

	writePunchTestPacket(t, selector, receiver0, punchPacket{Kind: punchDone, Session: session, Nonce: token})
	readPunchTestPacket(t, selector, punchDoneAck, token)
	winner := receiveWinner(ctx, config, events)
	if winner == nil || winner.Conn != receiver0 || !udpAddrEqual(winner.RemoteAddr, udpAddrOf(selector)) {
		t.Fatalf("receiver winner = %+v, want receiver0 <-> selector", winner)
	}

	// Punch keeps readers alive for GracePeriod after commit. Matching duplicate
	// control packets must continue receiving ACKs during that interval.
	writePunchTestPacket(t, selector, receiver0, punchPacket{Kind: punchSelect, Session: session, Nonce: token})
	readPunchTestPacket(t, selector, punchSelectAck, token)
	writePunchTestPacket(t, selector, receiver0, punchPacket{Kind: punchDone, Session: session, Nonce: token})
	readPunchTestPacket(t, selector, punchDoneAck, token)

	cancel()
	readers.Wait()
}

func TestSelectorRetransmitsControlUntilAcknowledged(t *testing.T) {
	tests := []struct {
		name      string
		request   punchKind
		response  punchKind
		repliesOf func(*punchEvents) <-chan punchEvent
	}{
		{name: "select", request: punchSelect, response: punchSelectAck, repliesOf: func(events *punchEvents) <-chan punchEvent { return events.selectAck }},
		{name: "done", request: punchDone, response: punchDoneAck, repliesOf: func(events *punchEvents) <-chan punchEvent { return events.doneAck }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := [8]byte{8, 5, 3, 0, 9, 7, 5, byte(test.request)}
			token := [8]byte{2, 7, 1, 8, 2, 8, byte(test.request)}
			selector := listenTestUDP(t)
			defer selector.Close()
			peer := listenTestUDP(t)
			defer peer.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			config := Config{Session: session, Role: RoleSelector, Method: "retransmit-test", RoundDelay: 20 * time.Millisecond}
			events := newPunchEvents(1)
			readerDone := make(chan struct{})
			go func() {
				defer close(readerDone)
				punchReader(ctx, selector, config, make(chan *Result, 1), &peerSet{m: make(map[string]*net.UDPAddr)}, events)
			}()

			exchanged := make(chan bool, 1)
			result := &Result{Conn: selector, LocalAddr: udpAddrOf(selector), RemoteAddr: udpAddrOf(peer), Method: config.Method}
			go func() {
				exchanged <- exchangeControl(ctx, config, test.repliesOf(events), result, test.request, token)
			}()

			// Drop the first request and answer only the retransmission.
			first, _ := readRawPunchTestPacket(t, peer)
			if first.Kind != test.request || first.Nonce != token {
				t.Fatalf("first request = %#v, want kind=%d token=%x", first, test.request, token)
			}
			second, source := readRawPunchTestPacket(t, peer)
			if second.Kind != test.request || second.Nonce != token {
				t.Fatalf("retransmission = %#v, want kind=%d token=%x", second, test.request, token)
			}
			if _, err := peer.WriteToUDP(encodePunch(punchPacket{Kind: test.response, Session: session, Nonce: token}), source); err != nil {
				t.Fatal(err)
			}
			select {
			case ok := <-exchanged:
				if !ok {
					t.Fatal("control exchange failed after valid retransmission response")
				}
			case <-time.After(time.Second):
				t.Fatal("control exchange did not accept retransmission response")
			}
			cancel()
			<-readerDone
		})
	}
}

func TestCommittedReceiverResultWinsContextRace(t *testing.T) {
	local := listenTestUDP(t)
	defer local.Close()
	remote := listenTestUDP(t)
	defer remote.Close()
	events := newPunchEvents(1)
	event := punchEvent{conn: local, remote: udpAddrOf(remote), token: [8]byte{5, 4, 3, 2, 1}}
	if !events.adoptReceiverSelection(event) || !events.commitReceiverSelection(event) {
		t.Fatal("could not prepare committed receiver selection")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := receiveWinner(ctx, Config{Role: RoleReceiver, Method: "deadline-race"}, events)
	if result == nil || result.Conn != local || !udpAddrEqual(result.RemoteAddr, udpAddrOf(remote)) {
		t.Fatalf("committed result lost to context cancellation: %+v", result)
	}
}

func TestQueuedControlAckWinsContextRace(t *testing.T) {
	local := listenTestUDP(t)
	defer local.Close()
	remote := listenTestUDP(t)
	defer remote.Close()
	token := [8]byte{7, 7, 1}
	replies := make(chan punchEvent, 1)
	replies <- punchEvent{conn: local, remote: udpAddrOf(remote), token: token}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := &Result{Conn: local, LocalAddr: udpAddrOf(local), RemoteAddr: udpAddrOf(remote)}
	if !exchangeControl(ctx, Config{Role: RoleSelector, RoundDelay: time.Millisecond}, replies, result, punchDone, token) {
		t.Fatal("queued exact DONE_ACK lost to context cancellation")
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func reserveTestUDPPort(t *testing.T) int {
	t.Helper()
	conn := listenTestUDP(t)
	port := udpAddrOf(conn).Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func udpAddrOf(conn *net.UDPConn) *net.UDPAddr {
	addr, _ := conn.LocalAddr().(*net.UDPAddr)
	return addr
}

func writePunchTestPacket(t *testing.T, source, destination *net.UDPConn, packet punchPacket) {
	t.Helper()
	if _, err := source.WriteToUDP(encodePunch(packet), udpAddrOf(destination)); err != nil {
		t.Fatal(err)
	}
}

func readPunchTestPacket(t *testing.T, conn *net.UDPConn, kind punchKind, token [8]byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxPunchPacket)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	packet, ok := decodePunch(buffer[:n])
	if !ok || packet.Kind != kind || packet.Nonce != token {
		t.Fatalf("control response = %#v decoded=%t, want kind=%d token=%x", packet, ok, kind, token)
	}
}

func readRawPunchTestPacket(t *testing.T, conn *net.UDPConn) (punchPacket, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxPunchPacket)
	n, source, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	packet, ok := decodePunch(buffer[:n])
	if !ok {
		t.Fatalf("could not decode control packet from %v", source)
	}
	return packet, source
}

func expectNoPunchTestPacket(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxPunchPacket)
	if n, source, err := conn.ReadFromUDP(buffer); err == nil {
		packet, _ := decodePunch(buffer[:n])
		t.Fatalf("unexpected response from %v: %#v", source, packet)
	} else {
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("wait for absent response: %v", err)
		}
	}
}

func waitPunchResult(t *testing.T, result <-chan *Result) *Result {
	t.Helper()
	select {
	case value := <-result:
		if value == nil {
			t.Fatal("coordinated winner selection returned nil")
		}
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("coordinated winner selection timed out")
		return nil
	}
}

func assertPunchData(t *testing.T, source, destination *ConnectedConn, payload string) {
	t.Helper()
	if err := destination.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, err := destination.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != payload {
		t.Fatalf("received %q, want %q", got, payload)
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
