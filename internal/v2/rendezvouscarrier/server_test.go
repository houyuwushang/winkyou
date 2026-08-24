package rendezvouscarrier

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testRendezvousServer struct {
	t        testing.TB
	listener net.Listener
	early    bool

	mu       sync.Mutex
	pairs    map[string]*testPair
	closed   bool
	accepted atomic.Int32
	active   atomic.Int32
	wg       sync.WaitGroup
}

type testPair struct {
	sides     map[PresenceSlot]*testSide
	activated map[PresenceSlot]bool
}

type testSide struct {
	conn  net.Conn
	write sync.Mutex
}

func startTestRendezvousServer(t testing.TB, earlyHandshake bool) *testRendezvousServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test rendezvous: %v", err)
	}
	server := &testRendezvousServer{
		t: t, listener: listener, early: earlyHandshake, pairs: make(map[string]*testPair),
	}
	server.wg.Add(1)
	go server.accept()
	t.Cleanup(server.Close)
	return server
}

func (server *testRendezvousServer) Endpoint() string {
	return server.listener.Addr().String()
}

func (server *testRendezvousServer) accept() {
	defer server.wg.Done()
	for server.accepted.Load() < 2 {
		connection, err := server.listener.Accept()
		if err != nil {
			server.mu.Lock()
			closed := server.closed
			server.mu.Unlock()
			if !closed {
				server.t.Errorf("accept test rendezvous: %v", err)
			}
			return
		}
		server.accepted.Add(1)
		server.active.Add(1)
		server.wg.Add(1)
		go server.serve(connection)
	}
	// One test server owns exactly one pair. Closing the listener after the
	// second accepted connection prevents an accidental third test client from
	// growing state or waiting in an unbounded backlog.
	_ = server.listener.Close()
}

func (server *testRendezvousServer) serve(connection net.Conn) {
	defer server.wg.Done()
	defer server.active.Add(-1)
	defer connection.Close()
	frame, _, err := decodeFrame(connection)
	if err != nil || frame.kind != wirePresence {
		clear(frame.payload)
		return
	}
	association, slot, err := parsePresencePayload(frame.payload)
	clear(frame.payload)
	if err != nil {
		return
	}
	side := &testSide{conn: connection}
	server.mu.Lock()
	pair := server.pairs[association]
	if pair == nil {
		pair = &testPair{sides: make(map[PresenceSlot]*testSide), activated: make(map[PresenceSlot]bool)}
		server.pairs[association] = pair
	}
	if pair.sides[slot] != nil {
		server.mu.Unlock()
		return
	}
	pair.sides[slot] = side
	early := server.early && len(pair.sides) == 1
	peerA, peerB := pair.sides[PresenceSlotA], pair.sides[PresenceSlotB]
	server.mu.Unlock()
	if early {
		_ = writeTestFrame(side, wireHandshake, make([]byte, 48))
	}
	if peerA != nil && peerB != nil {
		if writeTestFrame(peerA, wirePresenceReady, nil) != nil || writeTestFrame(peerB, wirePresenceReady, nil) != nil {
			return
		}
	}

	// Presence was the first inbound frame. At most seven post-presence frames
	// remain under the same per-direction ceiling enforced by the adapter.
	for remaining := MaxFramesPerDirection - 1; remaining > 0; remaining-- {
		frame, _, err := decodeFrame(connection)
		if err != nil {
			return
		}
		if frame.kind == wireActivate {
			clear(frame.payload)
			server.mu.Lock()
			pair.activated[slot] = true
			both := pair.activated[PresenceSlotA] && pair.activated[PresenceSlotB]
			peerA, peerB = pair.sides[PresenceSlotA], pair.sides[PresenceSlotB]
			server.mu.Unlock()
			if both {
				if writeTestFrame(peerA, wireActivateReady, nil) != nil || writeTestFrame(peerB, wireActivateReady, nil) != nil {
					return
				}
			}
			continue
		}
		server.mu.Lock()
		active := pair.activated[PresenceSlotA] && pair.activated[PresenceSlotB]
		peerSlot := PresenceSlotA
		if slot == PresenceSlotA {
			peerSlot = PresenceSlotB
		}
		peer := pair.sides[peerSlot]
		server.mu.Unlock()
		if !active || peer == nil || (frame.kind != wireHandshake && frame.kind != wireControl) {
			clear(frame.payload)
			return
		}
		err = writeTestFrame(peer, frame.kind, frame.payload)
		clear(frame.payload)
		if err != nil {
			return
		}
	}
}

func writeTestFrame(side *testSide, kind byte, payload []byte) error {
	if side == nil || side.conn == nil {
		return net.ErrClosed
	}
	frame, err := encodeFrame(kind, payload)
	if err != nil {
		return err
	}
	defer clear(frame)
	side.write.Lock()
	defer side.write.Unlock()
	_ = side.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = side.conn.Write(frame)
	return err
}

func (server *testRendezvousServer) Inject(association string, slot PresenceSlot, kind byte, payload []byte) error {
	server.mu.Lock()
	pair := server.pairs[association]
	var side *testSide
	if pair != nil {
		side = pair.sides[slot]
	}
	server.mu.Unlock()
	return writeTestFrame(side, kind, payload)
}

func (server *testRendezvousServer) ClosePeer(association string, slot PresenceSlot) {
	server.mu.Lock()
	pair := server.pairs[association]
	var side *testSide
	if pair != nil {
		side = pair.sides[slot]
	}
	server.mu.Unlock()
	if side != nil {
		_ = side.conn.Close()
	}
}

func (server *testRendezvousServer) Close() {
	server.mu.Lock()
	if server.closed {
		server.mu.Unlock()
		return
	}
	server.closed = true
	server.mu.Unlock()
	_ = server.listener.Close()
	server.mu.Lock()
	for _, pair := range server.pairs {
		for _, side := range pair.sides {
			_ = side.conn.Close()
		}
	}
	server.mu.Unlock()
	server.wg.Wait()
}

func (server *testRendezvousServer) waitForActive(want int32) error {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if server.active.Load() == want {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errors.New("test rendezvous active connection count did not converge")
}
