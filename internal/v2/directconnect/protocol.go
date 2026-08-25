package directconnect

import (
	"context"
	"errors"
	"net/netip"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
)

func (runtime *runtime) handshake(ctx context.Context) (directattempt.Binding, error) {
	pairingContext, err := runtime.artifact.PairingContext()
	if err != nil {
		return directattempt.Binding{}, err
	}
	digest, err := runtime.artifact.ContextDigest()
	if err != nil {
		return directattempt.Binding{}, err
	}
	prologue, err := directattempt.BuildNoisePrologue(pairingContext)
	if err != nil {
		clear(digest[:])
		return directattempt.Binding{}, err
	}
	defer clear(prologue)
	psk, err := runtime.artifact.TakePSK()
	if err != nil {
		clear(digest[:])
		return directattempt.Binding{}, err
	}
	defer clear(psk[:])
	config := noisecore.Config{Prologue: prologue, PSK: staticPSK(psk)}
	var session *noisecore.Session
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		session, err = noisecore.NewInitiator(config)
	} else {
		session, err = noisecore.NewResponder(config)
	}
	if err != nil {
		clear(digest[:])
		return directattempt.Binding{}, err
	}
	defer session.Close()
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		first, err := session.WriteMessage(nil)
		if err != nil {
			clear(digest[:])
			return directattempt.Binding{}, err
		}
		if err := runtime.carrier.SendHandshake(ctx, first); err != nil {
			clear(first)
			clear(digest[:])
			return directattempt.Binding{}, err
		}
		clear(first)
		runtime.emissions.HandshakeFrames++
		second, err := runtime.carrier.ReceiveHandshake(ctx)
		if err != nil {
			clear(digest[:])
			return directattempt.Binding{}, err
		}
		payload, readErr := session.ReadMessage(second)
		clear(second)
		payloadBytes := len(payload)
		clear(payload)
		if readErr != nil || payloadBytes != 0 {
			clear(digest[:])
			return directattempt.Binding{}, errors.Join(readErr, noisecore.ErrInvalidMessage)
		}
	} else {
		first, err := runtime.carrier.ReceiveHandshake(ctx)
		if err != nil {
			clear(digest[:])
			return directattempt.Binding{}, err
		}
		payload, readErr := session.ReadMessage(first)
		clear(first)
		payloadBytes := len(payload)
		clear(payload)
		if readErr != nil || payloadBytes != 0 {
			clear(digest[:])
			return directattempt.Binding{}, errors.Join(readErr, noisecore.ErrInvalidMessage)
		}
		second, err := session.WriteMessage(nil)
		if err != nil {
			clear(digest[:])
			return directattempt.Binding{}, err
		}
		if err := runtime.carrier.SendHandshake(ctx, second); err != nil {
			clear(second)
			clear(digest[:])
			return directattempt.Binding{}, err
		}
		clear(second)
		runtime.emissions.HandshakeFrames++
	}
	hash, err := session.HandshakeHash()
	if err != nil {
		clear(digest[:])
		return directattempt.Binding{}, err
	}
	packets, err := session.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		clear(digest[:])
		clear(hash[:])
		return directattempt.Binding{}, err
	}
	if err := runtime.carrier.MarkHandshakeComplete(); err != nil {
		_ = packets.Close()
		clear(digest[:])
		clear(hash[:])
		return directattempt.Binding{}, err
	}
	binding := directattempt.Binding{
		AttemptID:     runtime.artifact.AttemptID,
		ContextDigest: digest,
		HandshakeHash: hash,
		Generation:    directattempt.Generation,
	}
	clear(digest[:])
	clear(hash[:])
	runtime.protocol, err = directattempt.NewProtocol(runtime.artifact.LocalRole, binding, packets)
	if err != nil {
		_ = packets.Close()
		return directattempt.Binding{}, err
	}
	return binding, nil
}

func (runtime *runtime) sendControl(ctx context.Context, frameType directattempt.FrameType) error {
	frame, err := runtime.protocol.Seal(frameType, nil)
	if err != nil {
		return err
	}
	defer clear(frame)
	if err := runtime.carrier.SendControl(ctx, frame); err != nil {
		return err
	}
	runtime.emissions.ControlFrames++
	return nil
}

func (runtime *runtime) exchangeControl(ctx context.Context, frameType directattempt.FrameType) error {
	if err := runtime.sendControl(ctx, frameType); err != nil {
		return err
	}
	opened, err := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
	if err != nil {
		return err
	}
	if opened.Type == directattempt.FrameCancel {
		return directattempt.ErrCancelled
	}
	if opened.Type != frameType {
		return directattempt.ErrInvalidTransition
	}
	return nil
}

func (runtime *runtime) exchangeReady(ctx context.Context, binding directattempt.Binding, endpoint netip.AddrPort) (*directattempt.ReadyPayload, error) {
	ready, err := directattempt.NewReadyPayload(binding, runtime.artifact.LocalRole, endpoint)
	if err != nil {
		return nil, err
	}
	frame, err := runtime.protocol.Seal(directattempt.FrameReady, &ready)
	if err != nil {
		return nil, err
	}
	defer clear(frame)
	if err := runtime.carrier.SendControl(ctx, frame); err != nil {
		return nil, err
	}
	runtime.emissions.ControlFrames++
	opened, err := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
	if err != nil {
		return nil, err
	}
	if opened.Type == directattempt.FrameCancel {
		return nil, directattempt.ErrCancelled
	}
	if opened.Type != directattempt.FrameReady || opened.Ready == nil {
		return nil, directattempt.ErrInvalidReady
	}
	peer := *opened.Ready
	return &peer, nil
}

func (runtime *runtime) punch(ctx context.Context, peer netip.AddrPort) error {
	punchCtx, cancel := context.WithTimeout(ctx, punchDeadline)
	defer cancel()
	firstType := directattempt.FrameSYN
	if runtime.artifact.LocalRole == directattempt.RoleResponder {
		firstType = directattempt.FrameSYNACK
	}
	first, err := runtime.protocol.Seal(firstType, nil)
	if err != nil {
		return err
	}
	if err := runtime.socket.SendProbe(punchCtx, peer, first); err != nil {
		clear(first)
		return err
	}
	clear(first)
	runtime.emissions.DirectPackets++
	runtime.emissions.UDPPacketsTotal++
	if err := runtime.emit(StagePunchSent); err != nil {
		return err
	}

	buffer := make([]byte, directattempt.MaxFrameBytes)
	defer clear(buffer)
	if runtime.artifact.LocalRole == directattempt.RoleInitiator {
		_, _, err := runtime.socket.ReceiveReply(punchCtx, buffer, func(packet []byte, from netip.AddrPort) error {
			if from != peer {
				return directattempt.ErrInvalidFrame
			}
			opened, err := runtime.protocol.Open(packet)
			if err != nil || opened.Type != directattempt.FrameSYNACK {
				return errors.Join(err, directattempt.ErrInvalidTransition)
			}
			return nil
		})
		if err != nil {
			return err
		}
		ack, err := runtime.protocol.Seal(directattempt.FrameACK, nil)
		if err != nil {
			return err
		}
		if err := runtime.socket.SendProbe(punchCtx, peer, ack); err != nil {
			clear(ack)
			return err
		}
		clear(ack)
		runtime.emissions.DirectPackets++
		runtime.emissions.UDPPacketsTotal++
		return nil
	}

	for received := 0; received < 2; received++ {
		complete := false
		_, _, err := runtime.socket.ReceiveReply(punchCtx, buffer, func(packet []byte, from netip.AddrPort) error {
			if from != peer {
				return directattempt.ErrInvalidFrame
			}
			opened, err := runtime.protocol.Open(packet)
			if err != nil {
				return err
			}
			switch opened.Type {
			case directattempt.FrameSYN:
			case directattempt.FrameACK:
				complete = true
			default:
				return directattempt.ErrInvalidTransition
			}
			return nil
		})
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
	}
	return directattempt.ErrInvalidTransition
}

func (runtime *runtime) cleanup(reason governor.PairingTerminalReason) error {
	if runtime == nil {
		return nil
	}
	var cleanupErr error
	if runtime.promotion != nil && runtime.promotion.Transport != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.promotion.Transport.Close())
		runtime.promotion = nil
	} else if runtime.socket != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.socket.Close())
	}
	runtime.socket = nil
	if runtime.protocol != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.protocol.Close())
		runtime.protocol = nil
	}
	if runtime.carrier != nil {
		_ = runtime.carrier.Close()
		witness := runtime.carrier.Witness()
		runtime.emissions.CarrierFramesRead = witness.FramesRead
		runtime.emissions.CarrierFramesWrite = witness.FramesWritten
		runtime.emissions.CarrierBytesRead = witness.BytesRead
		runtime.emissions.CarrierBytesWrite = witness.BytesWritten
		if !witness.Drained || !witness.Closed {
			cleanupErr = errors.Join(cleanupErr, errors.New("carrier drain witness is incomplete"))
		}
		runtime.carrier = nil
	}
	if runtime.authorization != nil {
		if err := runtime.authorization.Finish(reason); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			runtime.finishRecorded = true
		}
		runtime.authorization = nil
	}
	if runtime.controller != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.controller.Close())
		runtime.controller = nil
		runtime.attempt = nil
	} else if runtime.attempt != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.attempt.Close())
		runtime.attempt = nil
	}
	if runtime.peer != nil {
		cleanupErr = errors.Join(cleanupErr, runtime.peer.Close())
		runtime.peer = nil
	}
	return cleanupErr
}

func (runtime *runtime) result() Result {
	return Result{
		AttemptKind:      "direct_oob_artifact",
		Terminal:         "success",
		Bidirectional:    true,
		PromotedTerminal: true,
		CredentialBurned: runtime.burned,
		FinishRecorded:   runtime.finishRecorded,
		Emissions:        runtime.emissions,
		ReservedEnvelope: runtime.request.Envelope,
		PairingLedger:    runtime.config.Ledger.Status(),
		SafetyTrip:       runtime.config.Machine.Snapshot().SafetyTrip,
	}
}
