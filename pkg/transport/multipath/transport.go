package multipath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
)

const maxPacketSize = 64 * 1024

type Path struct {
	ID        string
	Role      solver.PathRole
	Summary   solver.PathSummary
	Transport transport.PacketTransport
	Priority  int
}

type StatsProvider interface {
	MultipathStats() Stats
}

type HealthController interface {
	MarkPathUnhealthy(pathID string, reason string)
	MarkPathHealthy(pathID string)
	ActivePathID() string
}

type Stats struct {
	ActivePathID          string
	PrimaryPathID         string
	ChildPathCount        int
	ProtectedDirectPathID string
	StandbyPathIDs        []string
	Paths                 []PathStats
	LastFailoverAt        time.Time
	LastFailoverWhy       string
}

type PathStats struct {
	ID         string
	Role       solver.PathRole
	Healthy    bool
	TXPackets  int64
	RXPackets  int64
	ErrorCount int64
	LastError  string
}

type Transport struct {
	mu        sync.RWMutex
	paths     []*pathState
	activeID  string
	primaryID string
	policy    solver.PathPolicy
	readCh    chan readResult
	closeCh   chan struct{}
	closeOnce sync.Once
	closed    bool

	lastFailoverAt  time.Time
	lastFailoverWhy string
}

type pathState struct {
	path       Path
	healthy    bool
	txPackets  int64
	rxPackets  int64
	errorCount int64
	lastError  string
}

type readResult struct {
	pathID string
	n      int
	packet []byte
	meta   transport.PacketMeta
	err    error
}

func New(paths []Path, policy solver.PathPolicy) (*Transport, error) {
	if len(paths) == 0 {
		return nil, errors.New("multipath: at least one path is required")
	}
	t := &Transport{
		paths:   make([]*pathState, 0, len(paths)),
		policy:  policy,
		readCh:  make(chan readResult, len(paths)),
		closeCh: make(chan struct{}),
	}
	for i, path := range paths {
		if path.Transport == nil {
			return nil, fmt.Errorf("multipath: path %d has nil transport", i)
		}
		if path.ID == "" {
			path.ID = path.Summary.PathID
		}
		if path.ID == "" {
			path.ID = fmt.Sprintf("path-%d", i)
		}
		if path.Role == "" {
			path.Role = path.Summary.Role
		}
		state := &pathState{path: path, healthy: true}
		t.paths = append(t.paths, state)
		if t.activeID == "" || path.Priority > t.activePathLocked().path.Priority {
			t.activeID = path.ID
		}
	}
	for _, state := range t.paths {
		go t.readLoop(state)
	}
	t.primaryID = t.activeID
	return t, nil
}

func (t *Transport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	select {
	case result := <-t.readCh:
		if result.err != nil {
			return 0, transport.PacketMeta{}, result.err
		}
		if len(result.packet) > len(dst) {
			return 0, transport.PacketMeta{}, fmt.Errorf("multipath: packet size %d exceeds destination size %d", len(result.packet), len(dst))
		}
		copy(dst, result.packet)
		if result.meta.PathID == "" {
			result.meta.PathID = result.pathID
		}
		if result.meta.ReceivedAt.IsZero() {
			result.meta.ReceivedAt = time.Now()
		}
		if t.shouldPromoteReadPath(result.pathID) {
			t.promote(result.pathID, "read_from_standby")
		}
		return result.n, result.meta, nil
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	case <-t.closeCh:
		return 0, transport.PacketMeta{}, net.ErrClosed
	}
}

func (t *Transport) WritePacket(ctx context.Context, pkt []byte) error {
	active := t.activePath()
	if active == nil {
		return errors.New("multipath: no active path")
	}
	if err := t.writePath(ctx, active, pkt); err == nil {
		t.shadowWrite(ctx, active.path.ID, pkt)
		return nil
	} else {
		t.markPathUnhealthy(active.path.ID, err.Error())
	}

	failedPathIDs := []string{active.path.ID}
	for {
		standby := t.selectStandby(failedPathIDs...)
		if standby == nil {
			return fmt.Errorf("multipath: all paths failed or unhealthy; failed paths: %s", strings.Join(failedPathIDs, ","))
		}
		if err := t.writePath(ctx, standby, pkt); err != nil {
			t.markPathUnhealthy(standby.path.ID, err.Error())
			failedPathIDs = append(failedPathIDs, standby.path.ID)
			continue
		}
		t.promote(standby.path.ID, "write_error:"+active.path.ID)
		return nil
	}
}

func (t *Transport) LocalAddr() net.Addr {
	if active := t.activePath(); active != nil {
		return active.path.Transport.LocalAddr()
	}
	return nil
}

func (t *Transport) RemoteAddr() net.Addr {
	if active := t.activePath(); active != nil {
		return active.path.Transport.RemoteAddr()
	}
	return nil
}

func (t *Transport) Close() error {
	var result error
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		close(t.closeCh)
		for _, state := range t.paths {
			if err := state.path.Transport.Close(); err != nil && result == nil {
				result = err
			}
		}
	})
	return result
}

func (t *Transport) MultipathStats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	stats := Stats{
		ActivePathID:    t.activeID,
		PrimaryPathID:   t.primaryID,
		ChildPathCount:  len(t.paths),
		LastFailoverAt:  t.lastFailoverAt,
		LastFailoverWhy: t.lastFailoverWhy,
		Paths:           make([]PathStats, 0, len(t.paths)),
	}
	for _, state := range t.paths {
		if state.path.ID != t.primaryID {
			stats.StandbyPathIDs = append(stats.StandbyPathIDs, state.path.ID)
		}
		if stats.ProtectedDirectPathID == "" && isProtectedDirectPath(state.path) {
			stats.ProtectedDirectPathID = state.path.ID
		}
		stats.Paths = append(stats.Paths, PathStats{
			ID:         state.path.ID,
			Role:       state.path.Role,
			Healthy:    state.healthy,
			TXPackets:  state.txPackets,
			RXPackets:  state.rxPackets,
			ErrorCount: state.errorCount,
			LastError:  state.lastError,
		})
	}
	return stats
}

func (t *Transport) MarkPathUnhealthy(pathID string, reason string) {
	t.markPathUnhealthy(pathID, reason)
}

func (t *Transport) MarkPathHealthy(pathID string) {
	t.markPathHealthy(pathID)
}

func (t *Transport) ActivePathID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.activeID
}

func (t *Transport) readLoop(state *pathState) {
	for {
		buf := make([]byte, maxPacketSize)
		n, meta, err := state.path.Transport.ReadPacket(context.Background(), buf)
		if err != nil {
			t.markPathUnhealthy(state.path.ID, err.Error())
			return
		}
		packet := append([]byte(nil), buf[:n]...)
		t.mu.Lock()
		state.healthy = true
		state.lastError = ""
		state.rxPackets++
		t.mu.Unlock()
		select {
		case <-t.closeCh:
			return
		case t.readCh <- readResult{pathID: state.path.ID, n: n, packet: packet, meta: meta}:
		}
	}
}

func (t *Transport) writePath(ctx context.Context, state *pathState, pkt []byte) error {
	if err := state.path.Transport.WritePacket(ctx, pkt); err != nil {
		return err
	}
	t.mu.Lock()
	state.healthy = true
	state.lastError = ""
	state.txPackets++
	t.mu.Unlock()
	return nil
}

func (t *Transport) shadowWrite(ctx context.Context, activeID string, pkt []byte) {
	if !t.policy.ShadowWrite {
		return
	}
	for _, state := range t.snapshotPaths() {
		if state.path.ID == activeID || !isProtectedDirectPath(state.path) {
			continue
		}
		if err := t.writePath(ctx, state, pkt); err != nil {
			t.markPathUnhealthy(state.path.ID, err.Error())
		}
	}
}

func (t *Transport) activePath() *pathState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.activePathLocked()
}

func (t *Transport) activePathLocked() *pathState {
	for _, state := range t.paths {
		if state.path.ID == t.activeID {
			return state
		}
	}
	return nil
}

func (t *Transport) snapshotPaths() []*pathState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]*pathState(nil), t.paths...)
}

func (t *Transport) selectStandby(excludeIDs ...string) *pathState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	excluded := make(map[string]struct{}, len(excludeIDs))
	for _, id := range excludeIDs {
		excluded[id] = struct{}{}
	}
	var best *pathState
	for _, state := range t.paths {
		if _, ok := excluded[state.path.ID]; ok || !state.healthy {
			continue
		}
		if best == nil {
			best = state
			continue
		}
		if isProtectedDirectPath(state.path) && !isProtectedDirectPath(best.path) {
			best = state
			continue
		}
		if state.path.Role == best.path.Role && state.path.Priority > best.path.Priority {
			best = state
		}
	}
	return best
}

func isProtectedDirectPath(path Path) bool {
	summary := path.Summary
	if summary.Role == "" {
		summary.Role = path.Role
	}
	return solver.IsProtectedDirectPath(summary)
}

func (t *Transport) shouldPromoteReadPath(pathID string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if pathID == "" || pathID == t.activeID {
		return false
	}
	incoming := t.pathByIDLocked(pathID)
	if incoming == nil || !incoming.healthy {
		return false
	}
	primary := t.pathByIDLocked(t.primaryID)
	return primary != nil && !primary.healthy
}

func (t *Transport) pathByIDLocked(pathID string) *pathState {
	for _, state := range t.paths {
		if state.path.ID == pathID {
			return state
		}
	}
	return nil
}

func (t *Transport) markPathUnhealthy(pathID, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, state := range t.paths {
		if state.path.ID != pathID {
			continue
		}
		state.healthy = false
		state.errorCount++
		state.lastError = reason
		return
	}
}

func (t *Transport) markPathHealthy(pathID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, state := range t.paths {
		if state.path.ID != pathID {
			continue
		}
		state.healthy = true
		state.lastError = ""
		return
	}
}

func (t *Transport) promote(pathID, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.activeID == pathID {
		return
	}
	t.activeID = pathID
	t.lastFailoverAt = time.Now()
	t.lastFailoverWhy = reason
}
