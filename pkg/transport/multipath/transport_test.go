package multipath

import (
	"context"
	"errors"
	"net"
	"strings"
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
	stats := mp.MultipathStats()
	if stats.PrimaryPathID != "primary" || stats.ProtectedDirectPathID != "standby" || stats.ActivePathID != "primary" {
		t.Fatalf("path ids = primary:%q protected:%q active:%q, want primary/standby/primary", stats.PrimaryPathID, stats.ProtectedDirectPathID, stats.ActivePathID)
	}
	if len(stats.StandbyPathIDs) != 1 || stats.StandbyPathIDs[0] != "standby" {
		t.Fatalf("standby path ids = %#v, want [standby]", stats.StandbyPathIDs)
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

func TestWriteFailsOverToProtectedDirectAfterPrimaryClose(t *testing.T) {
	primary := newFakePacketTransport("primary")
	direct := newFakePacketTransport("direct")
	mp := newTestTransport(t, []Path{
		testPath("relay", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("direct", solver.PathRoleProtectedDirect, direct, 10),
	}, solver.PathPolicy{})
	defer mp.Close()

	if err := primary.Close(); err != nil {
		t.Fatalf("primary Close() error = %v", err)
	}
	if err := mp.WritePacket(context.Background(), []byte("failover")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if got := direct.writeCount(); got != 1 {
		t.Fatalf("direct writes = %d, want 1", got)
	}
	if active := mp.ActivePathID(); active != "direct" {
		t.Fatalf("active path = %q, want direct", active)
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

func TestReadFromStandbyPromotesWhenPrimaryUnhealthy(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{})
	defer mp.Close()

	var controller HealthController = mp
	controller.MarkPathUnhealthy("primary", "health_stale")
	standby.deliver([]byte("standby-alive"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	buf := make([]byte, 64)
	if _, _, err := mp.ReadPacket(ctx, buf); err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if active := controller.ActivePathID(); active != "standby" {
		t.Fatalf("active path = %q, want standby", active)
	}
	stats := mp.MultipathStats()
	if stats.LastFailoverWhy != "read_from_standby" {
		t.Fatalf("last failover reason = %q, want read_from_standby", stats.LastFailoverWhy)
	}
}

func TestWriteFailsOverFromStaleActivePath(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{ActivePathSilenceTimeout: 10 * time.Millisecond})
	defer mp.Close()

	primary.deliver([]byte("primary-alive"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	buf := make([]byte, 64)
	if _, _, err := mp.ReadPacket(ctx, buf); err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	if err := mp.WritePacket(context.Background(), []byte("after-silence")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if got := primary.writeCount(); got != 0 {
		t.Fatalf("primary writes = %d, want 0 after stale failover", got)
	}
	if got := standby.writeCount(); got != 1 {
		t.Fatalf("standby writes = %d, want 1 after stale failover", got)
	}
	stats := mp.MultipathStats()
	if stats.ActivePathID != "standby" || stats.LastFailoverWhy != "active_path_rx_silence:primary" {
		t.Fatalf("multipath stats = %#v, want standby after active silence", stats)
	}
	primaryStats := findPathStats(t, stats, "primary")
	if primaryStats.Healthy || primaryStats.LastError != "active_path_rx_silence" {
		t.Fatalf("primary stats = %#v, want stale unhealthy", primaryStats)
	}
}

func TestHealthLoopFailsOverFromStaleActivePathWithoutWrite(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{ActivePathSilenceTimeout: 10 * time.Millisecond})
	defer mp.Close()

	primary.deliver([]byte("primary-alive"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	buf := make([]byte, 64)
	if _, _, err := mp.ReadPacket(ctx, buf); err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}

	waitFor(t, 2*time.Second, func() bool {
		return mp.ActivePathID() == "standby"
	})
	if got := primary.writeCount(); got != 0 {
		t.Fatalf("primary writes = %d, want 0", got)
	}
	if got := standby.writeCount(); got != 0 {
		t.Fatalf("standby writes = %d, want 0", got)
	}
	stats := mp.MultipathStats()
	if stats.LastFailoverWhy != "active_path_rx_silence:primary" {
		t.Fatalf("last failover reason = %q, want active path silence", stats.LastFailoverWhy)
	}
}

func TestReadFromStandbyFailsOverAfterActiveSilence(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{ActivePathSilenceTimeout: 10 * time.Millisecond})
	defer mp.Close()

	primary.deliver([]byte("primary-alive"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	buf := make([]byte, 64)
	if _, _, err := mp.ReadPacket(ctx, buf); err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	standby.deliver([]byte("standby-alive"))
	if _, meta, err := mp.ReadPacket(ctx, buf); err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	} else if meta.PathID != "standby" {
		t.Fatalf("ReadPacket() path id = %q, want standby", meta.PathID)
	}
	if active := mp.ActivePathID(); active != "standby" {
		t.Fatalf("active path = %q, want standby", active)
	}
}

func TestWriteReturnsClearErrorWhenAllPathsFail(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	primary.writeErr = errors.New("primary down")
	standby.writeErr = errors.New("standby down")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{})
	defer mp.Close()

	err := mp.WritePacket(context.Background(), []byte("hello"))
	if err == nil {
		t.Fatal("WritePacket() error = nil, want all paths failed")
	}
	if !strings.Contains(err.Error(), "all paths failed") || !strings.Contains(err.Error(), "primary,standby") {
		t.Fatalf("WritePacket() error = %q, want clear failed paths", err)
	}
}

func TestHealthControllerMarksPathHealthy(t *testing.T) {
	primary := newFakePacketTransport("primary")
	standby := newFakePacketTransport("standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("standby", solver.PathRoleProtectedDirect, standby, 10),
	}, solver.PathPolicy{})
	defer mp.Close()

	var controller HealthController = mp
	controller.MarkPathUnhealthy("primary", "manual")
	if stat := findPathStats(t, mp.MultipathStats(), "primary"); stat.Healthy || stat.LastError != "manual" {
		t.Fatalf("primary stats after unhealthy = %#v", stat)
	}
	controller.MarkPathHealthy("primary")
	if stat := findPathStats(t, mp.MultipathStats(), "primary"); !stat.Healthy || stat.LastError != "" {
		t.Fatalf("primary stats after healthy = %#v", stat)
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

func TestShadowWriteCopiesToStandbyPaths(t *testing.T) {
	primary := newFakePacketTransport("primary")
	directStandby := newFakePacketTransport("direct-standby")
	relayStandby := newFakePacketTransport("relay-standby")
	mp := newTestTransport(t, []Path{
		testPath("primary", solver.PathRolePrimaryCandidate, primary, 100),
		testPath("direct-standby", solver.PathRoleProtectedDirect, directStandby, 10),
		testPath("relay-standby", solver.PathRoleStandby, relayStandby, 5),
	}, solver.PathPolicy{ShadowWrite: true})
	defer mp.Close()

	if err := mp.WritePacket(context.Background(), []byte("shadow")); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	if got := primary.writeCount(); got != 1 {
		t.Fatalf("primary writes = %d, want 1", got)
	}
	if got := directStandby.writeCount(); got != 1 {
		t.Fatalf("direct standby writes = %d, want 1", got)
	}
	if got := relayStandby.writeCount(); got != 1 {
		t.Fatalf("relay standby writes = %d, want 1", got)
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

func findPathStats(t *testing.T, stats Stats, pathID string) PathStats {
	t.Helper()
	for _, stat := range stats.Paths {
		if stat.ID == pathID {
			return stat
		}
	}
	t.Fatalf("path stats for %q not found in %#v", pathID, stats.Paths)
	return PathStats{}
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

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition was not met within %s", timeout)
}
