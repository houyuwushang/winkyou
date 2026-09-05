package probeio

import "context"

const consumerReadinessFrameBytes = 40

// ConsumerReadinessCodec is the post-VERIFY, one-shot codec owned by Gate B.
// No key, raw transport, target, or protocol state is exposed to the consumer.
type ConsumerReadinessCodec interface {
	Seal() ([]byte, error)
	Open([]byte) error
	SealFinish() ([]byte, error)
	OpenFinish([]byte) error
	Close() error
}

// ConsumerReady is called only after the local WireGuard AddPeer has returned.
// It shares the existing challenge deadline and datagram cap, rather than
// opening an auxiliary handshake budget. It never retries either datagram.
func (gate *WireGuardSessionGate) ConsumerReady(ctx context.Context, codec ConsumerReadinessCodec) error {
	if gate == nil || ctx == nil || codec == nil {
		if codec != nil {
			_ = codec.Close()
		}
		return ErrWireGuardGateState
	}
	gate.mu.Lock()
	if gate.state != WireGuardGateChallengeCapped || gate.readyStarted {
		gate.mu.Unlock()
		_ = codec.Close()
		return gate.fail(ErrWireGuardGateState)
	}
	gate.readyStarted = true
	gate.completionCodec = codec // sole ownership continues through R1 completion
	gate.mu.Unlock()
	gate.readMu.Lock()
	defer gate.readMu.Unlock()
	gate.writeMu.Lock()
	defer gate.writeMu.Unlock()
	opCtx, done, err := gate.operationContext(ctx, WireGuardGateChallengeCapped)
	if err != nil {
		return gate.fail(err)
	}
	defer done()
	write := func() error {
		frame, err := codec.Seal()
		if err != nil || len(frame) != consumerReadinessFrameBytes {
			return ErrWireGuardGate
		}
		defer clear(frame)
		gate.mu.Lock()
		if gate.state != WireGuardGateChallengeCapped || len(gate.outbound)+gate.readinessWrites >= WireGuardChallengePackets {
			gate.mu.Unlock()
			return ErrWireGuardGateLimit
		}
		gate.readinessWrites++ // spend before I/O; a failed write is not refunded
		gate.mu.Unlock()
		return gate.transport.WritePacket(opCtx, frame)
	}
	read := func() error {
		// One extra byte detects overlong datagrams even for truncating transports.
		var frame [consumerReadinessFrameBytes + 1]byte
		n, _, err := gate.transport.ReadPacket(opCtx, frame[:])
		if err != nil {
			return err
		}
		gate.mu.Lock()
		gate.readinessReads++
		gate.mu.Unlock()
		if n != consumerReadinessFrameBytes {
			return ErrWireGuardGate
		}
		return codec.Open(frame[:n])
	}
	if gate.role == WireGuardInitiator {
		err = write()
		if err == nil {
			err = read()
		}
	} else {
		err = read()
		if err == nil {
			err = write()
		}
	}
	if err != nil {
		return gate.fail(err)
	}
	gate.mu.Lock()
	if gate.state != WireGuardGateChallengeCapped || opCtx.Err() != nil {
		gate.mu.Unlock()
		return gate.fail(ErrWireGuardGateState)
	}
	gate.consumerReady = true
	close(gate.readyDone)
	gate.mu.Unlock()
	return nil
}

func (gate *WireGuardSessionGate) waitConsumerReady(ctx context.Context) error {
	gate.mu.Lock()
	if gate.consumerReady {
		gate.mu.Unlock()
		return nil
	}
	phaseCtx := gate.challengeCtx
	ready := gate.readyDone
	gate.mu.Unlock()
	if phaseCtx == nil {
		return ErrWireGuardGateState
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-phaseCtx.Done():
		return gate.fail(phaseCtx.Err())
	case <-ready:
		return nil
	}
}
