package probeio

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"winkyou/pkg/transport"
)

const (
	WireGuardChallengeTimeout = 3 * time.Second
	WireGuardChallengePackets = 3
	wireGuardReadDrainTimeout = 300 * time.Millisecond
)

type WireGuardRole string

const (
	WireGuardInitiator WireGuardRole = "initiator"
	WireGuardResponder WireGuardRole = "responder"
)

type WireGuardMessageType uint32

const (
	WireGuardHandshakeInitiation WireGuardMessageType = 1
	WireGuardHandshakeResponse   WireGuardMessageType = 2
	WireGuardCookieReply         WireGuardMessageType = 3
	WireGuardTransportData       WireGuardMessageType = 4
)

type WireGuardGateState string

const (
	WireGuardGateStandby         WireGuardGateState = "standby"
	WireGuardGateChallengeCapped WireGuardGateState = "challenge_capped"
	wireGuardGateChallengeDrain  WireGuardGateState = "challenge_drain"
	WireGuardGateChallengePassed WireGuardGateState = "challenge_passed"
	WireGuardGateFinishDetached  WireGuardGateState = "finish_detached"
	WireGuardGateActive          WireGuardGateState = "active"
	WireGuardGateClosed          WireGuardGateState = "closed"
)

// WireGuardSessionGateWitness intentionally contains only local bounded
// counters and message types. It carries no peer, attempt, endpoint, path, or
// key material.
type WireGuardSessionGateWitness struct {
	State           WireGuardGateState
	Outbound        []WireGuardMessageType
	Inbound         []WireGuardMessageType
	FinishRecorded  bool
	AttemptDetached bool
	ActiveWrites    int
	ActiveReads     int
	Closed          bool
}

// WireGuardSessionGate is the only production consumer wrapper accepted by a
// wireguard-direct-session/1 TransportLease. During the pre-FINISH challenge
// it enforces an I/O-before-write cap and the exact current wireguard-go packet
// trace. After a durable FINISH callback and lease detach it switches to the
// caller's independently bounded foreground-session context.
type WireGuardSessionGate struct {
	mu      sync.Mutex
	writeMu sync.Mutex
	readMu  sync.Mutex

	lease     *TransportLease
	transport transport.PacketTransport
	role      WireGuardRole
	state     WireGuardGateState

	attemptCtx    context.Context
	attemptCancel context.CancelFunc
	challengeCtx  context.Context
	challengeStop context.CancelFunc
	activeCtx     context.Context
	activeStop    context.CancelFunc

	outbound       []WireGuardMessageType
	inbound        []WireGuardMessageType
	inFlight       int
	finishRecorded bool
	detached       bool
	activeWrites   int
	activeReads    int

	closeOnce sync.Once
	closeErr  error
}

// AdoptWireGuardSession adopts and marks standby the exact production lease.
// It returns no raw lease transport. The absolute deadline is the already
// frozen Gate B active envelope, not a new budget.
func (lease *TransportLease) AdoptWireGuardSession(
	ctx context.Context,
	binding TransportLeaseBinding,
	role WireGuardRole,
	absoluteDeadline time.Time,
) (*WireGuardSessionGate, error) {
	if lease == nil || ctx == nil || binding.ConsumerKind != WireGuardDirectSessionConsumer ||
		(role != WireGuardInitiator && role != WireGuardResponder) || absoluteDeadline.IsZero() ||
		!absoluteDeadline.After(time.Now()) {
		return nil, ErrWireGuardGateState
	}
	if _, ok := ctx.Deadline(); ok {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(ErrWireGuardGateState, err)
		}
	}
	owned, err := lease.Adopt(ctx, binding)
	if err != nil {
		return nil, err
	}
	if err := lease.MarkStandby(); err != nil {
		_ = owned.Close()
		return nil, err
	}
	attemptCtx, attemptCancel := context.WithDeadline(ctx, absoluteDeadline)
	gate := &WireGuardSessionGate{
		lease: lease, transport: owned, role: role, state: WireGuardGateStandby,
		attemptCtx: attemptCtx, attemptCancel: attemptCancel,
	}
	return gate, nil
}

// BeginChallenge makes packet I/O available under the fixed three-second,
// three-packet-per-direction ceiling.
func (gate *WireGuardSessionGate) BeginChallenge() error {
	if gate == nil {
		return ErrWireGuardGateState
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.state != WireGuardGateStandby || gate.attemptCtx == nil || gate.attemptCtx.Err() != nil {
		return ErrWireGuardGateState
	}
	gate.challengeCtx, gate.challengeStop = context.WithTimeout(gate.attemptCtx, WireGuardChallengeTimeout)
	gate.state = WireGuardGateChallengeCapped
	return nil
}

// CompleteChallenge accepts only the frozen option-B trace: the initiator
// writes initiation then the empty transport keepalive and reads one response;
// the responder reads initiation/keepalive and writes one response.
func (gate *WireGuardSessionGate) CompleteChallenge() error {
	if gate == nil {
		return ErrWireGuardGateState
	}
	gate.mu.Lock()
	if gate.state != WireGuardGateChallengeCapped || gate.challengeCtx == nil ||
		gate.challengeCtx.Err() != nil || !gate.traceCompleteLocked() {
		gate.mu.Unlock()
		return ErrWireGuardGateState
	}
	// wireguard-go keeps one receive call pending. Freeze the transition first,
	// cancel that controlled read, and wait for it to leave before changing the
	// lease state. New reads see challenge_drain and cannot start another I/O.
	gate.state = wireGuardGateChallengeDrain
	stop := gate.challengeStop
	gate.mu.Unlock()
	if stop != nil {
		stop()
	}
	drainDeadline := time.NewTimer(wireGuardReadDrainTimeout)
	defer drainDeadline.Stop()
	drainPoll := time.NewTicker(time.Millisecond)
	defer drainPoll.Stop()
	for {
		gate.mu.Lock()
		inFlight := gate.inFlight
		state := gate.state
		gate.mu.Unlock()
		if state != wireGuardGateChallengeDrain {
			return ErrWireGuardGateState
		}
		if inFlight == 0 {
			break
		}
		select {
		case <-drainDeadline.C:
			_ = gate.Close()
			return ErrWireGuardGateState
		case <-drainPoll.C:
		}
	}
	if err := gate.lease.MarkChallengePassed(); err != nil {
		_ = gate.Close()
		return err
	}
	gate.mu.Lock()
	if gate.state != wireGuardGateChallengeDrain {
		gate.mu.Unlock()
		_ = gate.Close()
		return ErrWireGuardGateState
	}
	gate.state = WireGuardGateChallengePassed
	gate.mu.Unlock()
	return nil
}

// FinishAndActivate runs the durable FINISH callback before detaching the
// attempt. A failed callback or detach closes the transport and never unlocks
// the challenge cap. sessionCtx must carry the local trusted absolute session
// ceiling.
func (gate *WireGuardSessionGate) FinishAndActivate(sessionCtx context.Context, durableFinish func() error) error {
	if gate == nil || sessionCtx == nil || durableFinish == nil {
		return ErrWireGuardGateState
	}
	deadline, bounded := sessionCtx.Deadline()
	if !bounded || !deadline.After(time.Now()) || sessionCtx.Err() != nil {
		return ErrWireGuardGateState
	}
	gate.mu.Lock()
	if gate.state != WireGuardGateChallengePassed || gate.inFlight != 0 || gate.attemptCtx == nil ||
		gate.attemptCtx.Err() != nil {
		gate.mu.Unlock()
		return ErrWireGuardGateState
	}
	gate.mu.Unlock()
	if err := durableFinish(); err != nil {
		_ = gate.Close()
		return errors.Join(ErrWireGuardGateState, err)
	}
	gate.mu.Lock()
	gate.finishRecorded = true
	gate.mu.Unlock()
	if err := gate.lease.DetachAfterFinish(); err != nil {
		_ = gate.Close()
		return err
	}
	activeCtx, activeStop := context.WithCancel(sessionCtx)
	gate.mu.Lock()
	if gate.state != WireGuardGateChallengePassed {
		gate.mu.Unlock()
		activeStop()
		_ = gate.Close()
		return ErrWireGuardGateState
	}
	gate.state = WireGuardGateFinishDetached
	gate.detached = true
	gate.activeCtx = activeCtx
	gate.activeStop = activeStop
	gate.state = WireGuardGateActive
	gate.mu.Unlock()
	return nil
}

func (gate *WireGuardSessionGate) WritePacket(ctx context.Context, packet []byte) error {
	if gate == nil || ctx == nil {
		return ErrWireGuardGateState
	}
	gate.writeMu.Lock()
	defer gate.writeMu.Unlock()

	gate.mu.Lock()
	state := gate.state
	if state == WireGuardGateChallengeCapped {
		if len(gate.outbound) >= WireGuardChallengePackets {
			gate.mu.Unlock()
			return gate.fail(ErrWireGuardGateLimit)
		}
		messageType, err := wireGuardMessageType(packet)
		if err != nil || messageType == WireGuardCookieReply || containsWireGuardType(gate.outbound, messageType) {
			gate.mu.Unlock()
			return gate.fail(ErrWireGuardGate)
		}
		gate.inFlight++
		gate.mu.Unlock()
		opCtx, done, err := gate.operationContext(ctx, state)
		if err != nil {
			gate.finishOperation()
			return gate.fail(err)
		}
		err = gate.transport.WritePacket(opCtx, packet)
		done()
		gate.mu.Lock()
		gate.inFlight--
		if err == nil && gate.state == WireGuardGateChallengeCapped {
			gate.outbound = append(gate.outbound, messageType)
		}
		gate.mu.Unlock()
		if err != nil {
			return gate.fail(err)
		}
		return nil
	}
	if state != WireGuardGateActive {
		gate.mu.Unlock()
		return ErrWireGuardGateState
	}
	gate.inFlight++
	gate.mu.Unlock()
	opCtx, done, err := gate.operationContext(ctx, state)
	if err != nil {
		gate.finishOperation()
		return gate.fail(err)
	}
	err = gate.transport.WritePacket(opCtx, packet)
	done()
	gate.mu.Lock()
	gate.inFlight--
	if err == nil && gate.state == WireGuardGateActive {
		gate.activeWrites++
	}
	gate.mu.Unlock()
	if err != nil {
		return gate.fail(err)
	}
	return nil
}

func (gate *WireGuardSessionGate) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	if gate == nil || ctx == nil {
		return 0, transport.PacketMeta{}, ErrWireGuardGateState
	}
	gate.readMu.Lock()
	defer gate.readMu.Unlock()

	gate.mu.Lock()
	state := gate.state
	if state == wireGuardGateChallengeDrain || state == WireGuardGateChallengePassed || state == WireGuardGateFinishDetached {
		gate.mu.Unlock()
		// No underlying packet I/O is legal between the completed challenge and
		// durable FINISH. Keep wireguard-go's bounded polling reader alive until
		// it re-enters after the active transition.
		<-ctx.Done()
		return 0, transport.PacketMeta{}, ctx.Err()
	}
	if state == WireGuardGateChallengeCapped && len(gate.inbound) >= WireGuardChallengePackets {
		gate.mu.Unlock()
		return 0, transport.PacketMeta{}, gate.fail(ErrWireGuardGateLimit)
	}
	if state != WireGuardGateChallengeCapped && state != WireGuardGateActive {
		gate.mu.Unlock()
		return 0, transport.PacketMeta{}, ErrWireGuardGateState
	}
	gate.inFlight++
	gate.mu.Unlock()
	opCtx, done, err := gate.operationContext(ctx, state)
	if err != nil {
		gate.finishOperation()
		return 0, transport.PacketMeta{}, gate.fail(err)
	}
	n, meta, err := gate.transport.ReadPacket(opCtx, dst)
	done()
	if err != nil {
		gate.finishOperation()
		if benign, ok := gate.benignReadContextEnd(ctx, state, err); ok {
			return n, meta, benign
		}
		return n, meta, gate.fail(err)
	}

	gate.mu.Lock()
	gate.inFlight--
	if state == WireGuardGateChallengeCapped {
		messageType, parseErr := wireGuardMessageType(dst[:n])
		if parseErr != nil || messageType == WireGuardCookieReply || containsWireGuardType(gate.inbound, messageType) ||
			gate.state != WireGuardGateChallengeCapped {
			gate.mu.Unlock()
			return n, meta, gate.fail(ErrWireGuardGate)
		}
		gate.inbound = append(gate.inbound, messageType)
	} else if gate.state == WireGuardGateActive {
		gate.activeReads++
	}
	gate.mu.Unlock()
	return n, meta, nil
}

func (gate *WireGuardSessionGate) LocalAddr() net.Addr {
	if gate == nil || gate.transport == nil {
		return nil
	}
	return gate.transport.LocalAddr()
}

func (gate *WireGuardSessionGate) RemoteAddr() net.Addr {
	if gate == nil || gate.transport == nil {
		return nil
	}
	return gate.transport.RemoteAddr()
}

func (gate *WireGuardSessionGate) Close() error {
	if gate == nil {
		return nil
	}
	gate.closeOnce.Do(func() {
		gate.mu.Lock()
		gate.state = WireGuardGateClosed
		attemptCancel := gate.attemptCancel
		challengeStop := gate.challengeStop
		activeStop := gate.activeStop
		gate.mu.Unlock()
		if challengeStop != nil {
			challengeStop()
		}
		if attemptCancel != nil {
			attemptCancel()
		}
		if activeStop != nil {
			activeStop()
		}
		if gate.transport != nil {
			gate.closeErr = gate.transport.Close()
		}
	})
	return gate.closeErr
}

func (gate *WireGuardSessionGate) Witness() WireGuardSessionGateWitness {
	if gate == nil {
		return WireGuardSessionGateWitness{State: WireGuardGateClosed, Closed: true}
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return WireGuardSessionGateWitness{
		State: gate.state, Outbound: append([]WireGuardMessageType(nil), gate.outbound...),
		Inbound: append([]WireGuardMessageType(nil), gate.inbound...), FinishRecorded: gate.finishRecorded,
		AttemptDetached: gate.detached, ActiveWrites: gate.activeWrites, ActiveReads: gate.activeReads,
		Closed: gate.state == WireGuardGateClosed,
	}
}

func (gate *WireGuardSessionGate) operationContext(callCtx context.Context, state WireGuardGateState) (context.Context, func(), error) {
	gate.mu.Lock()
	var phaseCtx context.Context
	switch state {
	case WireGuardGateChallengeCapped:
		phaseCtx = gate.challengeCtx
	case WireGuardGateActive:
		phaseCtx = gate.activeCtx
	}
	gate.mu.Unlock()
	if phaseCtx == nil || phaseCtx.Err() != nil || callCtx.Err() != nil {
		return nil, nil, ErrWireGuardGateState
	}
	opCtx, cancel := context.WithCancel(phaseCtx)
	stop := context.AfterFunc(callCtx, cancel)
	return opCtx, func() {
		stop()
		cancel()
	}, nil
}

func (gate *WireGuardSessionGate) finishOperation() {
	gate.mu.Lock()
	if gate.inFlight > 0 {
		gate.inFlight--
	}
	gate.mu.Unlock()
}

func (gate *WireGuardSessionGate) benignReadContextEnd(callCtx context.Context, state WireGuardGateState, err error) (error, bool) {
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return nil, false
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if state == WireGuardGateChallengeCapped && gate.state == wireGuardGateChallengeDrain {
		// CompleteChallenge deliberately canceled the one pending receive. Return
		// a polling sentinel so the tunnel reader exits/re-evaluates without
		// closing the lease-owned transport.
		return context.DeadlineExceeded, true
	}
	if state == WireGuardGateChallengeCapped && gate.state == WireGuardGateActive {
		// A read started during the capped phase may still be blocked when the
		// durable FINISH transition replaces its phase context. Surface a poll
		// timeout so wireguard-go's bind loop immediately starts an active read.
		return context.DeadlineExceeded, true
	}
	if callCtx == nil || callCtx.Err() == nil {
		return nil, false
	}
	var phaseCtx context.Context
	switch state {
	case WireGuardGateChallengeCapped:
		phaseCtx = gate.challengeCtx
	case WireGuardGateActive:
		phaseCtx = gate.activeCtx
	}
	if gate.state == state && phaseCtx != nil && phaseCtx.Err() == nil {
		return callCtx.Err(), true
	}
	return nil, false
}

func (gate *WireGuardSessionGate) fail(cause error) error {
	_ = gate.Close()
	if errors.Is(cause, ErrWireGuardGateLimit) {
		return ErrWireGuardGateLimit
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return errors.Join(ErrWireGuardGate, cause)
	}
	return ErrWireGuardGate
}

func (gate *WireGuardSessionGate) traceCompleteLocked() bool {
	if gate.role == WireGuardInitiator {
		return equalWireGuardTrace(gate.outbound, []WireGuardMessageType{
			WireGuardHandshakeInitiation, WireGuardTransportData,
		}) && equalWireGuardTrace(gate.inbound, []WireGuardMessageType{WireGuardHandshakeResponse})
	}
	return equalWireGuardTrace(gate.outbound, []WireGuardMessageType{WireGuardHandshakeResponse}) &&
		equalWireGuardTrace(gate.inbound, []WireGuardMessageType{
			WireGuardHandshakeInitiation, WireGuardTransportData,
		})
}

func wireGuardMessageType(packet []byte) (WireGuardMessageType, error) {
	if len(packet) < 4 {
		return 0, ErrWireGuardGate
	}
	messageType := WireGuardMessageType(binary.LittleEndian.Uint32(packet[:4]))
	switch messageType {
	case WireGuardHandshakeInitiation, WireGuardHandshakeResponse, WireGuardCookieReply, WireGuardTransportData:
		return messageType, nil
	default:
		return 0, ErrWireGuardGate
	}
}

func containsWireGuardType(trace []WireGuardMessageType, candidate WireGuardMessageType) bool {
	for _, messageType := range trace {
		if messageType == candidate {
			return true
		}
	}
	return false
}

func equalWireGuardTrace(actual, expected []WireGuardMessageType) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

var _ transport.PacketTransport = (*WireGuardSessionGate)(nil)
