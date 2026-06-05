package multipath

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
)

func TestWriteUsesPrimaryPath(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{})
	defer mp.Close()

	if err := mp.WritePacket(context.Background(), []byte("hello")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if got := primary.writeCount(); got != 1 {
		t.Fatalf("primary writes = %d, want 1", got)
	}
	if got := standby.writeCount(); got != 0 {
		t.Fatalf("standby writes = %d, want 0", got)
	}
}

func TestWriteFallsBackToStandby(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	primary.writeErr = errors.New("primary down")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{})
	defer mp.Close()

	if err := mp.WritePacket(context.Background(), []byte("hello")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if got := standby.writeCount(); got != 1 {
		t.Fatalf("standby writes = %d, want 1", got)
	}
	stats := mp.MultipathStats()
	if stats.ActivePathID != "standby" {
		t.Fatalf("active path = %q, want standby", stats.ActivePathID)
	}
	if stats.LastFailoverAt.IsZero() {
		t.Fatal("LastFailoverAt is zero, want failover timestamp")
	}
}

func TestReadFanInReturnsStandbyPacket(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{})
	defer mp.Close()

	standby.deliver([]byte("from-standby"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	buf := make([]byte, 64)
	n, meta, err := mp.ReadPacket(ctx, buf)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if got := string(buf[:n]); got != "from-standby" {
		t.Fatalf("ReadPacket() payload = %q, want from-standby", got)
	}
	if meta.PathID != "standby" {
		t.Fatalf("ReadPacket() path id = %q, want standby", meta.PathID)
	}
}

func TestCloseClosesAllChildren(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{})

	if err := mp.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := mp.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if !primary.isClosed() || !standby.isClosed() {
		t.Fatalf("closed states primary=%t standby=%t, want both closed", primary.isClosed(), standby.isClosed())
	}
}

func TestShadowWriteCopiesToProtectedDirect(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{ShadowWrite: true})
	defer mp.Close()

	if err := mp.WritePacket(context.Background(), []byte("shadow")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if got := primary.writeCount(); got != 1 {
		t.Fatalf("primary writes = %d, want 1", got)
	}
	if got := standby.writeCount(); got != 1 {
		t.Fatalf("standby writes = %d, want 1", got)
	}
}

func newTestTransport(t *testing.T, paths []Path, policy solver.PathPolicy) *Transport {
	t.Helper()
	mp, err := New(paths, policy)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return mp
}

func testPath(id string, role solver.PathRole, child transport.PacketTransport, priority int) Path {
	return Path{
		ID:        id,
		Role:      role,
		Transport: child,
		Priority:  priority,
		Summary: solver.PathSummary{
			PathID: id,
			Role:   role,
		},
	}
}

type fakePacketTransport struct {
	id        string
	local     net.Addr
	remote    net.Addr
	readCh    chan []byte
	closedCh  chan struct{}
	closeOnce sync.Once

	mu       sync.Mutex
	writeErr error
	writes   [][]byte
	closed   bool
}

func newFakePacketTransport(id string) *fakePacketTransport {
	return &fakePacketTransport{
		id:       id,
		local:    &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000},
		remote:   &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2000},
		readCh:   make(chan []byte, 8),
		closedCh: make(chan struct{}),
	}
}

func (f *fakePacketTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	select {
	case pkt := <-f.readCh:
		copy(dst, pkt)
		return len(pkt), transport.PacketMeta{PathID: f.id, ReceivedAt: time.Now()}, nil
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	case <-f.closedCh:
		return 0, transport.PacketMeta{}, net.ErrClosed
	}
}

func (f *fakePacketTransport) WritePacket(ctx context.Context, pkt []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, append([]byte(nil), pkt...))
	return nil
}

func (f *fakePacketTransport) LocalAddr() net.Addr { return f.local }

func (f *fakePacketTransport) RemoteAddr() net.Addr { return f.remote }

func (f *fakePacketTransport) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.closedCh)
	})
	return nil
}

func (f *fakePacketTransport) deliver(pkt []byte) {
	f.readCh <- append([]byte(nil), pkt...)
}

func (f *fakePacketTransport) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakePacketTransport) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}
