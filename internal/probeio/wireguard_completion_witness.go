package probeio

import (
	"context"
	"errors"
	"time"
)

// CompletionContextWitness is a local snapshot, never an authorization input.
// It retains neither a context nor its arbitrary Cause/Error text.
type CompletionContextWitness struct {
	State           string
	Cause           string
	Bounded         bool
	RemainingMillis int64
}

// WireGuardCompletionFailure distinguishes cancellation at the failed operation
// from the cancellation subsequently performed by gate.fail/Close. All text is
// a fixed label; no peer, endpoint, secret, path, or process identity is stored.
type WireGuardCompletionFailure struct {
	Point     string
	Cause     string
	GateState WireGuardGateState
	Attempt   CompletionContextWitness
	Session   CompletionContextWitness
	Challenge CompletionContextWitness
}

func completionErrorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrTransportInactive):
		return "lease_inactive"
	case errors.Is(err, ErrLeaseClosed):
		return "lease_closed"
	case errors.Is(err, ErrWireGuardGateLimit):
		return "gate_limit"
	case errors.Is(err, ErrWireGuardGateState):
		return "gate_state"
	default:
		return "other"
	}
}

func completionContextSnapshot(ctx context.Context, now time.Time) CompletionContextWitness {
	if ctx == nil {
		return CompletionContextWitness{State: "missing", Cause: "none"}
	}
	w := CompletionContextWitness{State: "active", Cause: completionErrorClass(context.Cause(ctx))}
	if err := ctx.Err(); err != nil {
		w.State = completionErrorClass(err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		w.Bounded = true
		w.RemainingMillis = deadline.Sub(now).Milliseconds()
	}
	return w
}

func (gate *WireGuardSessionGate) recordCompletionFailure(point string, cause error, sessionCtx context.Context) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.completionFailure != nil {
		return
	}
	now := time.Now()
	w := WireGuardCompletionFailure{Point: point, Cause: completionErrorClass(cause), GateState: gate.state,
		Attempt: completionContextSnapshot(gate.attemptCtx, now), Session: completionContextSnapshot(sessionCtx, now),
		Challenge: completionContextSnapshot(gate.challengeCtx, now)}
	gate.completionFailure = &w
}
