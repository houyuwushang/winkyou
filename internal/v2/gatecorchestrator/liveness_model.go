package gatecorchestrator

import (
	"context"
	"math"
	"sync"
	"time"
)

// Counts only: no nonce, sequence, IDs, digests, endpoints or peer timestamps.
type LivenessWitness struct {
	PingAdmitted              uint64        `json:"ping_admitted"`
	PongAdmitted              uint64        `json:"pong_admitted"`
	PongValidated             uint64        `json:"pong_validated"`
	LivenessAdmissionRejected uint64        `json:"liveness_admission_rejected"`
	PingAdmissionRejected     uint64        `json:"ping_admission_rejected"`
	PongAdmissionRejected     uint64        `json:"pong_admission_rejected"`
	PendingExpired            uint64        `json:"pending_expired"`
	ReplayDropped             uint64        `json:"replay_dropped"`
	PongDropped               uint64        `json:"pong_dropped"`
	InboundDropped            uint64        `json:"inbound_dropped"`
	OutboundDropped           uint64        `json:"outbound_dropped"`
	OutboundExpired           uint64        `json:"outbound_expired"`
	InnerInjected             uint64        `json:"inner_injected"`
	AdmissionBypass           uint64        `json:"admission_bypass"`
	WriterFailures            uint64        `json:"writer_failures"`
	UTCRollbacks              uint64        `json:"utc_rollbacks"`
	ElapsedNS                 time.Duration `json:"elapsed_ns"`
	BindingVerified           bool          `json:"binding_verified"`
	Drained                   bool          `json:"drained"`
}

type pendingLiveness struct {
	message livenessMessage
	sent    time.Duration
	valid   bool
}
type livenessEmission struct {
	packet   []byte
	until    time.Duration
	teardown bool
}

type livenessModel struct {
	mu                                      sync.Mutex
	clock                                   livenessClockGuard
	budget                                  livenessBudget
	binding                                 echoBinding
	absUntil, leaseUntil, nextSlot, elapsed time.Duration
	sequence, peerHigh                      uint64
	pending                                 pendingLiveness
	window                                  [4]time.Duration
	windowUsed                              int
	// Two queued intents and at most one being written, no unbounded token map.
	intents    [3]*livenessEmission
	writing    bool
	writeUntil time.Duration
	closed     bool
	terminal   error
	witness    LivenessWitness
}

func newLivenessModel(binding echoBinding, budget livenessBudget, clock LivenessClock, absolute time.Time) (*livenessModel, error) {
	guard, err := newLivenessClock(clock)
	if err != nil {
		return nil, err
	}
	remaining := absolute.Sub(guard.utc0)
	if !validEchoBinding(binding) || remaining <= 0 || remaining > budget.ceiling || budget.pings == 0 {
		return nil, errLivenessUnavailable
	}
	return &livenessModel{clock: guard, budget: budget, binding: binding, absUntil: remaining, leaseUntil: min(remaining, budget.lease), nextSlot: livenessInterval, witness: LivenessWitness{BindingVerified: true}}, nil
}

func (m *livenessModel) checkLocked() error {
	if m.terminal != nil {
		return m.terminal
	}
	if m.closed {
		return context.Canceled
	}
	now, err := m.clock.read()
	m.witness.UTCRollbacks = m.clock.rollbacks
	if err != nil {
		m.terminal = err
		return err
	}
	m.elapsed = now
	m.witness.ElapsedNS = now
	if now >= m.absUntil {
		m.terminal = context.DeadlineExceeded
		return m.terminal
	}
	if now >= m.leaseUntil {
		m.terminal = errLivenessTimeout
		return m.terminal
	}
	if m.pending.valid && now >= m.pending.sent+livenessResponseWindow {
		m.pending = pendingLiveness{}
		m.witness.PendingExpired++
	}
	return nil
}
func (m *livenessModel) permit() error { m.mu.Lock(); defer m.mu.Unlock(); return m.checkLocked() }
func (m *livenessModel) currentElapsed() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.elapsed
}

// A rejected event is consumed, but does not trip, borrow or revoke the lease.
func (m *livenessModel) admitLocked(kind livenessKind) bool {
	kept := 0
	for i := 0; i < m.windowUsed; i++ {
		if m.elapsed-m.window[i] < livenessInterval {
			m.window[kept] = m.window[i]
			kept++
		}
	}
	m.windowUsed = kept
	w := &m.witness
	full := m.windowUsed == len(m.window) || w.PingAdmitted+w.PongAdmitted >= m.budget.total ||
		(kind == livenessPing && w.PingAdmitted >= m.budget.pings) || (kind == livenessPong && w.PongAdmitted >= m.budget.pongs)
	if full {
		w.LivenessAdmissionRejected++
		if kind == livenessPing {
			w.PingAdmissionRejected++
		} else {
			w.PongAdmissionRejected++
		}
		return false
	}
	m.window[m.windowUsed] = m.elapsed
	m.windowUsed++
	if kind == livenessPing {
		w.PingAdmitted++
	} else {
		w.PongAdmitted++
	}
	return true
}

// preparePing consumes the fixed slot before random generation. No missed-slot
// catch-up, pending replacement or admission-rejected backfill is possible.
func (m *livenessModel) preparePing() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(); err != nil {
		return 0, err
	}
	if m.elapsed < m.nextSlot {
		return 0, nil
	}
	m.nextSlot = (m.elapsed/livenessInterval + 1) * livenessInterval
	if m.pending.valid || m.elapsed+livenessResponseWindow > min(m.absUntil, m.leaseUntil) {
		return 0, nil
	}
	if m.sequence == math.MaxUint64 || m.sequence >= m.budget.pings {
		m.terminal = errLivenessProtocol
		return 0, m.terminal
	}
	m.sequence++
	return m.sequence, nil
}

func (m *livenessModel) ping(sequence uint64, nonce [16]byte) (*livenessEmission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(); err != nil {
		return nil, err
	}
	if sequence != m.sequence || sequence == 0 || m.pending.valid {
		return nil, errLivenessBudget
	}
	message := livenessMessage{kind: livenessPing, sequence: sequence, nonce: nonce}
	if !m.admitLocked(livenessPing) {
		return nil, nil
	}
	emission, err := m.intentLocked(message)
	if emission != nil {
		m.pending = pendingLiveness{message: message, sent: m.elapsed, valid: true}
	}
	return emission, err
}

func (m *livenessModel) receive(packet []byte) (*livenessEmission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(); err != nil {
		return nil, err
	}
	message, err := parseLivenessPacket(packet, m.binding)
	if err != nil {
		m.terminal = err
		return nil, err
	}
	if message.kind == livenessPong {
		pending := m.pending
		if !pending.valid || message.sequence != pending.message.sequence || message.nonce != pending.message.nonce {
			m.witness.PongDropped++
			return nil, nil
		}
		m.leaseUntil = min(m.absUntil, pending.sent+m.budget.lease)
		m.pending = pendingLiveness{}
		m.witness.PongValidated++
		return nil, nil
	}
	if message.sequence > m.budget.pongs {
		m.terminal = errLivenessProtocol
		return nil, m.terminal
	}
	if message.sequence <= m.peerHigh {
		m.witness.ReplayDropped++
		return nil, nil
	}
	m.peerHigh = message.sequence // consumed BEFORE admission, even when rejected
	if !m.admitLocked(livenessPong) {
		return nil, nil
	}
	message.kind = livenessPong
	return m.intentLocked(message)
}

func (m *livenessModel) intentLocked(message livenessMessage) (*livenessEmission, error) {
	packet, err := buildLivenessPacket(m.binding, message)
	if err != nil {
		return nil, err
	}
	for i, intent := range m.intents {
		if intent == nil {
			e := &livenessEmission{packet: packet, until: min(m.elapsed+livenessWriteWindow, m.absUntil, m.leaseUntil)}
			m.intents[i] = e
			return e, nil
		}
	}
	m.witness.OutboundDropped++
	return nil, nil // charged intent, no refund
}

func (m *livenessModel) discard(e *livenessEmission) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, intent := range m.intents {
		if intent == e {
			m.intents[i] = nil
			clear(e.packet)
			m.witness.OutboundDropped++
			return
		}
	}
}

func (m *livenessModel) beginWrite(e *livenessEmission) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkLocked(); err != nil {
		return false, err
	}
	found := -1
	for i, intent := range m.intents {
		if intent != nil && intent == e {
			found = i
			break
		}
	}
	if found < 0 || m.writing {
		m.witness.AdmissionBypass++
		m.terminal = errLivenessBudget
		return false, m.terminal
	}
	m.intents[found] = nil
	if m.elapsed >= e.until {
		m.witness.OutboundExpired++
		return false, nil
	}
	m.writing, m.writeUntil = true, e.until
	return true, nil
}

func (m *livenessModel) endWrite(injected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writing = false
	if injected {
		m.witness.InnerInjected++
	}
}
func (m *livenessModel) snapshot() LivenessWitness {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.witness
}
