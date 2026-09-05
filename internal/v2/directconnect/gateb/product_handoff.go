package gateb

import (
	"context"
	"errors"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/directattempt"
)

func (handoff *ProductHandoff) BeginWireGuardChallenge() error {
	if handoff == nil {
		return probeio.ErrWireGuardGateState
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed || handoff.establishmentDone || handoff.gate == nil {
		return probeio.ErrWireGuardGateState
	}
	return handoff.gate.BeginChallenge()
}

func (handoff *ProductHandoff) MarkWireGuardChallengePassed() error {
	if handoff == nil {
		return probeio.ErrWireGuardGateState
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed || handoff.establishmentDone || handoff.gate == nil || handoff.runtime == nil {
		return probeio.ErrWireGuardGateState
	}
	if err := handoff.gate.CompleteChallenge(); err != nil {
		return err
	}
	handoff.runtime.challengeComplete.Store(true)
	if err := handoff.runtime.emit(StageDataPlaneChallenge); err != nil {
		return handoff.runtime.failure(ClassDataPlaneChallengeFailed, StageDataPlaneChallenge, err)
	}
	return nil
}

// FinishAndDetach appends durable success FINISH through the existing
// authorization, detaches the transport lease, drains the OOB carrier, and
// releases the attempt. The WireGuard gate remains active under sessionCtx.
func (handoff *ProductHandoff) FinishAndDetach(sessionCtx context.Context) (ProductHandoffWitness, error) {
	if handoff == nil {
		return ProductHandoffWitness{}, probeio.ErrWireGuardGateState
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed || handoff.establishmentDone || handoff.gate == nil || handoff.runtime == nil ||
		handoff.runtime.authorization == nil {
		return ProductHandoffWitness{}, probeio.ErrWireGuardGateState
	}
	runtime := handoff.runtime
	authorization := runtime.authorization
	err := handoff.gate.FinishAndActivate(sessionCtx, func() error {
		finishErr := authorization.Finish(governor.PairingTerminalSuccess)
		runtime.authorization = nil
		if finishErr == nil {
			runtime.finishRecorded = true
		}
		return finishErr
	})
	if err != nil {
		cleanupErr := runtime.cleanup(governor.PairingTerminalProtocolError)
		runtime.artifact.Close()
		handoff.establishmentDone = true
		handoff.closed = true
		_ = terminalProgress(runtime.config.Progress)
		return handoff.witnessLocked(), errors.Join(err, cleanupErr)
	}
	runtime.success = true
	if err := runtime.releaseProductEstablishment(); err != nil {
		_ = handoff.gate.Close()
		runtime.artifact.Close()
		handoff.establishmentDone = true
		handoff.closed = true
		_ = terminalProgress(runtime.config.Progress)
		return handoff.witnessLocked(), err
	}
	runtime.artifact.Close()
	handoff.establishmentDone = true
	return handoff.witnessLocked(), nil
}

// Abort consumes the handoff without retrying or changing any attempt input.
// It records the existing stable Gate B terminal reason before releasing any
// attempt-owned resources whenever the ledger remains writable.
func (handoff *ProductHandoff) Abort(cause error) (ProductHandoffWitness, error) {
	if handoff == nil {
		return ProductHandoffWitness{}, nil
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed {
		return handoff.witnessLocked(), nil
	}
	if cause == nil {
		cause = context.Canceled
	}
	runtime := handoff.runtime
	classified := runtime.classify(runtime.stage, cause)
	cleanupErr := runtime.cleanup(terminalReason(classified))
	runtime.artifact.Close()
	handoff.establishmentDone = true
	handoff.closed = true
	progressErr := terminalProgress(runtime.config.Progress)
	return handoff.witnessLocked(), errors.Join(classified, cleanupErr, progressErr)
}

// CloseSession closes only the already-detached production transport. It does
// not create a new attempt and is valid only after FinishAndDetach.
func (handoff *ProductHandoff) CloseSession() error {
	if handoff == nil {
		return nil
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.closed {
		return nil
	}
	if !handoff.establishmentDone || handoff.gate == nil {
		return probeio.ErrWireGuardGateState
	}
	handoff.closed = true
	return handoff.gate.Close()
}

func (handoff *ProductHandoff) Witness() ProductHandoffWitness {
	if handoff == nil {
		return ProductHandoffWitness{}
	}
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	return handoff.witnessLocked()
}

func (handoff *ProductHandoff) witnessLocked() ProductHandoffWitness {
	if handoff == nil || handoff.runtime == nil {
		return ProductHandoffWitness{}
	}
	runtime := handoff.runtime
	witness := ProductHandoffWitness{
		FinishRecorded:  runtime.finishRecorded,
		AttemptReleased: runtime.attempt == nil && runtime.peer == nil,
	}
	if runtime.carrier != nil {
		witness.Carrier = runtime.carrier.Witness()
		witness.OOBDrained = witness.Carrier.Closed && witness.Carrier.Drained
	}
	if handoff.gate != nil {
		witness.Transport = handoff.gate.Witness()
	}
	return witness
}

func (runtime *runtime) releaseProductEstablishment() error {
	if runtime == nil || runtime.wireGuardGate == nil || !runtime.finishRecorded {
		return probeio.ErrWireGuardGateState
	}
	var releaseErr error
	if runtime.plannerSource != nil {
		runtime.plannerSource.Close()
		runtime.plannerSource = nil
	}
	if runtime.protocol != nil {
		releaseErr = errors.Join(releaseErr, runtime.protocol.Close())
		runtime.protocol = nil
	}
	if runtime.carrier != nil {
		if runtime.artifact.GateBLocalRole() == directattempt.RoleResponder {
			select {
			case <-runtime.carrier.Done():
			case <-runtime.activeContext.Done():
			}
		}
		_ = runtime.carrier.Close()
		witness := runtime.carrier.Witness()
		runtime.emissions.CarrierFramesRead = witness.FramesRead
		runtime.emissions.CarrierFramesWrite = witness.FramesWritten
		runtime.emissions.CarrierBytesRead = witness.BytesRead
		runtime.emissions.CarrierBytesWrite = witness.BytesWritten
		if !witness.Closed || !witness.Drained {
			releaseErr = errors.Join(releaseErr, errors.New("carrier drain incomplete"))
		}
	}
	for _, socket := range runtime.sockets {
		if socket == nil {
			continue
		}
		if err := socket.Close(); err != nil && !errors.Is(err, probeio.ErrSocketClosed) && !errors.Is(err, probeio.ErrLeaseClosed) {
			releaseErr = errors.Join(releaseErr, err)
		}
	}
	if runtime.controller != nil {
		releaseErr = errors.Join(releaseErr, runtime.controller.Close())
		runtime.controller = nil
		runtime.attempt = nil
	} else if runtime.attempt != nil {
		releaseErr = errors.Join(releaseErr, runtime.attempt.Close())
		runtime.attempt = nil
	}
	if runtime.peer != nil {
		releaseErr = errors.Join(releaseErr, runtime.peer.Close())
		runtime.peer = nil
	}
	if runtime.activeCancel != nil {
		runtime.activeCancel(context.Canceled)
	}
	if runtime.deadlineCancel != nil {
		runtime.deadlineCancel()
	}
	if runtime.carrierWatchDone != nil {
		<-runtime.carrierWatchDone
		runtime.carrierWatchDone = nil
	}
	return releaseErr
}
