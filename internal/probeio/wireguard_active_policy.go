package probeio

import (
	"errors"
	"sync"
	"time"
)

// SessionViolation is a closed vocabulary, not caller-supplied diagnostic text.
type SessionViolation uint8

const (
	SessionControlLimit SessionViolation = iota + 1
	SessionControlInvalid
	SessionWriterFailure
	SessionAdmissionBypass
	SessionDrainFailure
)

var (
	ErrSessionControlLimit   = errors.New("probeio: active automatic control limit")
	ErrSessionControlInvalid = errors.New("probeio: invalid active WireGuard packet")
)

// ActiveSessionPolicy can only narrow an already-detached session. The owner
// supplies a local permit, monotonic accounting clock and session-bound reporter;
// no attempt, endpoint, socket, remote deadline or raw transport is accepted.
type ActiveSessionPolicy struct {
	Ceiling time.Duration
	Permit  func() error
	Elapsed func() time.Duration // validated local monotonic elapsed, never RTC/origin-max
	Report  func(SessionViolation) error
}

type ActiveSessionWitness struct {
	PermitChecks         uint64
	ControlAdmitted      uint64
	ControlRejected      uint64
	InvalidPackets       uint64
	WriterFailures       uint64
	ControlLimit         uint64
	HandshakeInitiations uint64
	HandshakeResponses   uint64
	CookieReplies        uint64
	EmptyKeepalives      uint64
}

type activeSessionPolicy struct {
	mu      sync.Mutex
	policy  ActiveSessionPolicy
	window  [4]time.Duration
	used    int
	last    time.Duration
	witness ActiveSessionWitness
}

// ArmActivePolicy is single-use and never legal before durable FINISH/detach.
// Nil policy is represented by not calling it, preserving the old gate exactly.
func (gate *WireGuardSessionGate) ArmActivePolicy(policy ActiveSessionPolicy) error {
	if gate == nil || policy.Permit == nil || policy.Elapsed == nil || policy.Report == nil ||
		policy.Ceiling < 5*time.Second || policy.Ceiling > 24*time.Hour {
		return ErrWireGuardGateState
	}
	limit := uint64(policy.Ceiling / time.Second)
	if policy.Ceiling%time.Second != 0 {
		limit++
	}
	gate.writeMu.Lock()
	defer gate.writeMu.Unlock()
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.state != WireGuardGateActive || !gate.finishRecorded || !gate.detached || gate.activePolicy != nil {
		return ErrWireGuardGateState
	}
	gate.activePolicy = &activeSessionPolicy{policy: policy, witness: ActiveSessionWitness{ControlLimit: 4 * limit}}
	return nil
}

func (p *activeSessionPolicy) beforeWrite(packet []byte) error {
	p.mu.Lock()
	p.witness.PermitChecks++
	p.mu.Unlock()
	if err := p.policy.Permit(); err != nil {
		return err
	}
	now := p.policy.Elapsed()
	typ, err := wireGuardMessageType(packet)
	control := false
	switch typ {
	case WireGuardHandshakeInitiation:
		control = true
		if len(packet) != 148 {
			err = ErrSessionControlInvalid
		}
	case WireGuardHandshakeResponse:
		control = true
		if len(packet) != 92 {
			err = ErrSessionControlInvalid
		}
	case WireGuardCookieReply:
		control = true
		if len(packet) != 64 {
			err = ErrSessionControlInvalid
		}
	case WireGuardTransportData:
		control = len(packet) == 32
		if len(packet) < 32 {
			err = ErrSessionControlInvalid
		}
	default:
		err = ErrSessionControlInvalid
	}
	if err != nil {
		p.mu.Lock()
		p.witness.InvalidPackets++
		p.mu.Unlock()
		return errors.Join(ErrSessionControlInvalid, p.policy.Report(SessionControlInvalid))
	}
	if !control {
		return nil
	}
	p.mu.Lock()
	kept := 0
	for i := 0; i < p.used; i++ {
		if now-p.window[i] < time.Second {
			p.window[kept] = p.window[i]
			kept++
		}
	}
	p.used = kept
	if now < p.last || now < 0 || p.used == len(p.window) || p.witness.ControlAdmitted >= p.witness.ControlLimit {
		p.witness.ControlRejected++
		p.mu.Unlock()
		return errors.Join(ErrSessionControlLimit, p.policy.Report(SessionControlLimit))
	}
	p.last = now
	p.window[p.used] = now
	p.used++
	p.witness.ControlAdmitted++
	switch typ {
	case WireGuardHandshakeInitiation:
		p.witness.HandshakeInitiations++
	case WireGuardHandshakeResponse:
		p.witness.HandshakeResponses++
	case WireGuardCookieReply:
		p.witness.CookieReplies++
	case WireGuardTransportData:
		p.witness.EmptyKeepalives++
	}
	p.mu.Unlock()
	return nil
}

func (p *activeSessionPolicy) writerFailed() error {
	p.mu.Lock()
	p.witness.WriterFailures++
	p.mu.Unlock()
	return p.policy.Report(SessionWriterFailure)
}

func (p *activeSessionPolicy) snapshot() *ActiveSessionWitness {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	copy := p.witness
	return &copy
}
