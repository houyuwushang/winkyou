//go:build linux && natlab

package rendezvouscarrier

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// N2DTestServer is the bounded opaque-frame relay used only by the N2d
// namespace harness. The caller owns and supplies a listener that was opened
// inside the isolated public namespace; this helper cannot listen or dial.
type N2DTestServer struct {
	listener net.Listener

	mu     sync.Mutex
	pairs  map[string]*n2dTestPair
	closed bool
	err    error

	accepted atomic.Int32
	active   atomic.Int32
	wg       sync.WaitGroup
}

type n2dTestPair struct {
	sides     map[PresenceSlot]*n2dTestSide
	activated map[PresenceSlot]bool
}

type n2dTestSide struct {
	connection  net.Conn
	slot        PresenceSlot
	writeMu     sync.Mutex
	readFrames  atomic.Int32
	wroteFrames atomic.Int32
}

// N2DTestServerStats contains counters only. It deliberately excludes listener
// and peer addresses, association identifiers, payloads, and host metadata.
type N2DTestServerStats struct {
	Accepted     int32
	Active       int32
	SlotARead    int32
	SlotAWritten int32
	SlotBRead    int32
	SlotBWritten int32
}

// StartN2DTestServer starts one two-party relay on a caller-owned TEST-NET TCP
// listener. The listener is rejected if it is loopback, unspecified, or not an
// RFC 5737 documentation address.
func StartN2DTestServer(listener net.Listener) (*N2DTestServer, error) {
	if listener == nil || !n2dDocumentationListener(listener.Addr()) {
		return nil, ErrInvalidConfig
	}
	server := &N2DTestServer{listener: listener, pairs: make(map[string]*n2dTestPair)}
	server.wg.Add(1)
	go server.accept()
	return server, nil
}

func n2dDocumentationListener(address net.Addr) bool {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok || tcpAddress == nil || tcpAddress.Port == 0 {
		return false
	}
	parsed, ok := netip.AddrFromSlice(tcpAddress.IP)
	if !ok {
		return false
	}
	parsed = parsed.Unmap()
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	} {
		if prefix.Contains(parsed) {
			return true
		}
	}
	return false
}

func (server *N2DTestServer) accept() {
	defer server.wg.Done()
	for server.accepted.Load() < 2 {
		connection, err := server.listener.Accept()
		if err != nil {
			server.mu.Lock()
			closed := server.closed
			if !closed && !errors.Is(err, net.ErrClosed) {
				server.err = errors.Join(server.err, ErrCarrierTransport)
			}
			server.mu.Unlock()
			return
		}
		server.accepted.Add(1)
		server.active.Add(1)
		server.wg.Add(1)
		go server.serve(connection)
	}
	// One N2d server owns one pair. Refuse a third connection at the OS
	// boundary instead of growing a mailbox or cross-attempt queue.
	_ = server.listener.Close()
}

func (server *N2DTestServer) serve(connection net.Conn) {
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
	side := &n2dTestSide{connection: connection, slot: slot}
	side.readFrames.Add(1)
	server.mu.Lock()
	pair := server.pairs[association]
	if pair == nil {
		pair = &n2dTestPair{sides: make(map[PresenceSlot]*n2dTestSide), activated: make(map[PresenceSlot]bool)}
		server.pairs[association] = pair
	}
	if pair.sides[slot] != nil {
		server.mu.Unlock()
		return
	}
	pair.sides[slot] = side
	peerA, peerB := pair.sides[PresenceSlotA], pair.sides[PresenceSlotB]
	server.mu.Unlock()
	if peerA != nil && peerB != nil {
		if n2dWriteTestFrame(peerA, wirePresenceReady, nil) != nil || n2dWriteTestFrame(peerB, wirePresenceReady, nil) != nil {
			return
		}
	}

	for remaining := MaxFramesPerDirection - 1; remaining > 0; remaining-- {
		frame, _, err = decodeFrame(connection)
		if err != nil {
			return
		}
		side.readFrames.Add(1)
		if frame.kind == wireActivate {
			clear(frame.payload)
			server.mu.Lock()
			pair.activated[slot] = true
			both := pair.activated[PresenceSlotA] && pair.activated[PresenceSlotB]
			peerA, peerB = pair.sides[PresenceSlotA], pair.sides[PresenceSlotB]
			server.mu.Unlock()
			if both {
				if n2dWriteTestFrame(peerA, wireActivateReady, nil) != nil || n2dWriteTestFrame(peerB, wireActivateReady, nil) != nil {
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
		err = n2dWriteTestFrame(peer, frame.kind, frame.payload)
		clear(frame.payload)
		if err != nil {
			return
		}
	}
}

func n2dWriteTestFrame(side *n2dTestSide, kind byte, payload []byte) error {
	if side == nil || side.connection == nil {
		return net.ErrClosed
	}
	frame, err := encodeFrame(kind, payload)
	if err != nil {
		return err
	}
	defer clear(frame)
	side.writeMu.Lock()
	defer side.writeMu.Unlock()
	_ = side.connection.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := side.connection.Write(frame); err != nil {
		return err
	}
	side.wroteFrames.Add(1)
	return nil
}

// ClosePeer injects a bounded peer disappearance without exposing the stream.
func (server *N2DTestServer) ClosePeer(association string, slot PresenceSlot) {
	if server == nil {
		return
	}
	server.mu.Lock()
	pair := server.pairs[association]
	var side *n2dTestSide
	if pair != nil {
		side = pair.sides[slot]
	}
	server.mu.Unlock()
	if side != nil {
		_ = side.connection.Close()
	}
}

func (server *N2DTestServer) Stats() N2DTestServerStats {
	if server == nil {
		return N2DTestServerStats{}
	}
	stats := N2DTestServerStats{Accepted: server.accepted.Load(), Active: server.active.Load()}
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, pair := range server.pairs {
		if side := pair.sides[PresenceSlotA]; side != nil {
			stats.SlotARead += side.readFrames.Load()
			stats.SlotAWritten += side.wroteFrames.Load()
		}
		if side := pair.sides[PresenceSlotB]; side != nil {
			stats.SlotBRead += side.readFrames.Load()
			stats.SlotBWritten += side.wroteFrames.Load()
		}
	}
	return stats
}

func (server *N2DTestServer) WaitForActive(want int32, timeout time.Duration) bool {
	if server == nil || timeout <= 0 {
		return false
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if server.active.Load() == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return server.active.Load() == want
}

func (server *N2DTestServer) Close() error {
	if server == nil {
		return nil
	}
	server.mu.Lock()
	if server.closed {
		err := server.err
		server.mu.Unlock()
		return err
	}
	server.closed = true
	_ = server.listener.Close()
	for _, pair := range server.pairs {
		for _, side := range pair.sides {
			_ = side.connection.Close()
		}
	}
	server.mu.Unlock()
	server.wg.Wait()
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.err
}
