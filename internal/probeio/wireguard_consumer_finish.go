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
	deadline, bounded := sessionCtx.Deadline()
	if !bounded || !deadline.After(time.Now()) || sessionCtx.Err() != nil {
		return ErrWireGuardGateState
	}
	gate.mu.Lock()
	if gate.state != WireGuardGateChallengePassed || gate.inFlight != 0 || gate.completionCodec == nil ||
		gate.challengeCtx == nil || gate.challengeCtx.Err() != nil || gate.attemptCtx.Err() != nil {
		gate.mu.Unlock()
		return gate.fail(ErrWireGuardGateState)
	}
	gate.state = wireGuardGateFinishConfirming
	codec := gate.completionCodec
	opCtx, cancel := context.WithCancel(gate.challengeCtx) // original deadline; never restarted
	gate.mu.Unlock()
	stop := context.AfterFunc(sessionCtx, cancel)
	defer func() { stop(); cancel(); _ = codec.Close() }()
	gate.readMu.Lock()
	defer gate.readMu.Unlock()
	gate.writeMu.Lock()
	defer gate.writeMu.Unlock()

	if gate.role == WireGuardInitiator {
		if err := gate.receiveCompletion(opCtx, codec); err != nil {
			return gate.fail(err)
		}
	}
	if opCtx.Err() != nil {
		return gate.fail(opCtx.Err())
	}
	if err := durableFinish(); err != nil {
		return gate.fail(errors.Join(ErrWireGuardGateState, err))
	}
	gate.mu.Lock()
	gate.finishRecorded = true
	gate.mu.Unlock()
	if opCtx.Err() != nil {
		return gate.fail(opCtx.Err())
	}
	if gate.role == WireGuardResponder {
		if err := gate.sendCompletion(opCtx, codec); err != nil {
			return gate.fail(err)
		}
	}
	if opCtx.Err() != nil {
		return gate.fail(opCtx.Err())
	}
	if err := gate.lease.DetachAfterFinish(); err != nil {
		return gate.fail(err)
	}
	activeCtx, activeStop := context.WithCancel(sessionCtx)
	gate.mu.Lock()
	if gate.state != wireGuardGateFinishConfirming || opCtx.Err() != nil {
		gate.mu.Unlock()
		activeStop()
		return gate.fail(ErrWireGuardGateState)
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
