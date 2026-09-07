package probeio

import (
	"bytes"
	"context"
	"errors"
	"time"
)

const consumerFinishedFrameBytes = 40

func isConsumerFinishedFrame(frame []byte) bool { return bytes.HasPrefix(frame, []byte("WYCF")) }

// Called with gate.mu held by the binder reader. Buffering spends an allowance
// but confers no authentication, FINISH, detach, or active-data authority.
func (gate *WireGuardSessionGate) bufferCompletionLocked(started WireGuardGateState, frame []byte) error {
	if started != WireGuardGateChallengeCapped ||
		(gate.state != WireGuardGateChallengeCapped && gate.state != wireGuardGateChallengeDrain) ||
		gate.role != WireGuardInitiator || !gate.consumerReady || gate.completionReads != 0 ||
		len(frame) != consumerFinishedFrameBytes || !containsWireGuardType(gate.inbound, WireGuardHandshakeResponse) {
		return ErrWireGuardGate
	}
	if len(gate.inbound)+gate.readinessReads+gate.completionReads >= WireGuardChallengePackets {
		return ErrWireGuardGateLimit
	}
	gate.completionReads++
	gate.completionFrame = append([]byte(nil), frame...)
	return nil
}

func (gate *WireGuardSessionGate) finishWithConfirmation(sessionCtx context.Context, durableFinish func() error) error {
	if gate == nil || sessionCtx == nil || durableFinish == nil {
		return ErrWireGuardGateState
	}
	gate.finishMu.Lock()
	defer gate.finishMu.Unlock()
	fail := func(point string, cause error) error {
		gate.recordCompletionFailure(point, cause, sessionCtx)
		return gate.fail(cause)
	}
	deadline, bounded := sessionCtx.Deadline()
	if !bounded || !deadline.After(time.Now()) || sessionCtx.Err() != nil {
		gate.recordCompletionFailure("session_precondition", ErrWireGuardGateState, sessionCtx)
		return ErrWireGuardGateState
	}
	gate.mu.Lock()
	if gate.state != WireGuardGateChallengePassed || gate.inFlight != 0 || gate.completionCodec == nil ||
		gate.attemptCtx.Err() != nil {
		gate.mu.Unlock()
		return fail("challenge_precondition", ErrWireGuardGateState)
	}
	gate.state = wireGuardGateFinishConfirming
	codec := gate.completionCodec
	// CompleteChallenge already admitted the frozen WG trace. R1 confirmation
	// uses only the original absolute/caller and session bounds (ADR 19.9).
	completionCtx, cancelCompletion := context.WithCancel(gate.attemptCtx)
	gate.mu.Unlock()
	stopCompletion := context.AfterFunc(sessionCtx, cancelCompletion)
	defer func() { stopCompletion(); cancelCompletion(); _ = codec.Close() }()
	gate.readMu.Lock()
	defer gate.readMu.Unlock()
	gate.writeMu.Lock()
	defer gate.writeMu.Unlock()

	if err := errors.Join(completionCtx.Err(), gate.attemptCtx.Err(), sessionCtx.Err()); err != nil {
		return fail("before_confirmation", err)
	}
	if gate.role == WireGuardInitiator {
		if err := gate.receiveCompletion(completionCtx, codec); err != nil {
			return fail("receive_confirmation", err)
		}
	}
	if err := errors.Join(completionCtx.Err(), gate.attemptCtx.Err(), sessionCtx.Err()); err != nil {
		return fail("before_durable_finish", err)
	}
	if err := durableFinish(); err != nil {
		gate.recordCompletionFailure("durable_finish", err, sessionCtx)
		return gate.fail(errors.Join(ErrWireGuardGateState, err))
	}
	gate.mu.Lock()
	gate.finishRecorded = true
	gate.mu.Unlock()
	if err := errors.Join(completionCtx.Err(), gate.attemptCtx.Err(), sessionCtx.Err()); err != nil {
		return fail("after_durable_finish", err)
	}
	if gate.role == WireGuardResponder {
		if err := gate.sendCompletion(completionCtx, codec); err != nil {
			return fail("send_confirmation", err)
		}
	}
	if err := errors.Join(completionCtx.Err(), gate.attemptCtx.Err(), sessionCtx.Err()); err != nil {
		return fail("before_detach", err)
	}
	if err := gate.lease.DetachAfterFinish(); err != nil {
		return fail("detach", err)
	}
	activeCtx, activeStop := context.WithCancel(sessionCtx)
	gate.mu.Lock()
	// Check both parents synchronously too: child/AfterFunc cancellation
	// propagation must not grant detach or activation while still pending.
	completionErr := errors.Join(completionCtx.Err(), gate.attemptCtx.Err(), sessionCtx.Err())
	if gate.state != wireGuardGateFinishConfirming || completionErr != nil {
		gate.mu.Unlock()
		activeStop()
		return fail("activation", errors.Join(ErrWireGuardGateState, completionErr))
	}
	gate.state = WireGuardGateFinishDetached
	gate.detached = true
	gate.activeCtx, gate.activeStop = activeCtx, activeStop
	gate.state = WireGuardGateActive
	close(gate.activeReady)
	gate.mu.Unlock()
	return nil
}

func (gate *WireGuardSessionGate) receiveCompletion(ctx context.Context, codec ConsumerReadinessCodec) error {
	gate.mu.Lock()
	frame := gate.completionFrame
	gate.completionFrame = nil
	gate.mu.Unlock()
	if frame == nil {
		var buffer [consumerFinishedFrameBytes + 1]byte
		gate.mu.Lock()
		if len(gate.inbound)+gate.readinessReads+gate.completionReads >= WireGuardChallengePackets {
			gate.mu.Unlock()
			return ErrWireGuardGateLimit
		}
		gate.inFlight++
		gate.mu.Unlock()
		n, _, err := gate.transport.ReadPacket(ctx, buffer[:])
		gate.finishOperation()
		if err != nil {
			return err
		}
		gate.mu.Lock()
		gate.completionReads++
		gate.mu.Unlock()
		if n != consumerFinishedFrameBytes {
			return ErrWireGuardGate
		}
		frame = append([]byte(nil), buffer[:n]...)
	}
	defer clear(frame)
	if err := codec.OpenFinish(frame); err != nil {
		return err
	}
	gate.mu.Lock()
	gate.peerFinishConfirmed = true
	gate.mu.Unlock()
	return nil
}

func (gate *WireGuardSessionGate) sendCompletion(ctx context.Context, codec ConsumerReadinessCodec) error {
	frame, err := codec.SealFinish()
	if err != nil {
		return err
	}
	defer clear(frame)
	if len(frame) != consumerFinishedFrameBytes {
		return ErrWireGuardGate
	}
	gate.mu.Lock()
	if !gate.finishRecorded || gate.state != wireGuardGateFinishConfirming {
		gate.mu.Unlock()
		return ErrWireGuardGateState
	}
	if len(gate.outbound)+gate.readinessWrites+gate.completionWrites >= WireGuardChallengePackets {
		gate.mu.Unlock()
		return ErrWireGuardGateLimit
	}
	gate.completionWrites++ // even after FINISH this is capped establishment I/O
	gate.inFlight++
	gate.mu.Unlock()
	err = gate.transport.WritePacket(ctx, frame)
	gate.finishOperation()
	return err
}
