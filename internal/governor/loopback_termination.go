package governor

import (
	"context"
	"errors"
	"time"
)

// LoopbackFinalizationTimeout bounds the accounting verdict, not probe I/O.
// The original network cancellation drain remains two seconds. A kernel fsync
// cannot be cancelled: timeout retains the owner until the actual writer exits.
const LoopbackFinalizationTimeout = 15 * time.Second

var (
	ErrTerminalFinalizing          = errors.New("terminal_finalizing")
	ErrTerminalFinalizationTimeout = errors.New("terminal_finalization_timeout")
	ErrTerminalFinalizationFailed  = errors.New("terminal_finalization_failed")
)

// All mutable fields belong to Governor.mu. Channels are single-authority
// witnesses; a timeout verdict never closes settled or the attempt's Done.
type loopbackTerminal struct {
	networkDrained       chan struct{}
	networkDone          chan struct{}
	accountingDone       chan struct{}
	verdict              chan struct{}
	settled              chan struct{}
	networkClosed        bool
	accountingClosed     bool
	stoppedAt            time.Time
	accountingRegistered bool
	networkErr           error
	finishErr            error
	result               error
}

func newLoopbackTerminal() *loopbackTerminal {
	return &loopbackTerminal{
		networkDrained: make(chan struct{}), networkDone: make(chan struct{}),
		accountingDone: make(chan struct{}),
		verdict:        make(chan struct{}), settled: make(chan struct{}),
	}
}

// AcquireLoopbackAttempt is the only opt-in to the reviewed two-phase terminal
// lifecycle. Its exact production consumer is architecture-gated. No context
// cancellation is detached, and all admission costs remain fully reserved.
func (p *PeerLease) AcquireLoopbackAttempt(ctx context.Context, request AttemptRequest) (*AttemptLease, error) {
	return p.acquireAttempt(ctx, request, true)
}

// ProbeRevocation separates permission revocation from final resource release
// only for the opt-in lifecycle. Ordinary leases preserve their original Done
// signal. probeio is the sole consumer; this is not a physical drain witness.
func (a *AttemptLease) ProbeRevocation() <-chan struct{} {
	if a != nil && a.terminal != nil {
		return a.Stopping()
	}
	return a.Done()
}

func (g *Governor) loopbackAdmissionBlockedLocked() error {
	if g.finalizationFault != nil {
		return g.finalizationFault
	}
	if g.loopbackFinalizing != 0 {
		return ErrTerminalFinalizing
	}
	return nil
}

func (g *Governor) loopbackWorkOutstandingLocked() bool {
	for _, attempt := range g.attempts {
		if attempt.terminal == nil {
			continue
		}
		select {
		case <-attempt.terminal.settled:
		default:
			return true
		}
	}
	return false
}

func (a *AttemptLease) registerPairingDrain() (DrainHandle, error) {
	return a.registerDrain(pairingAdmissionGateDrainName, a.terminal != nil)
}

func (g *Governor) maybeCloseLoopbackNetworkLocked(a *AttemptLease) {
	if a.terminal == nil || !a.stoppingStarted {
		return
	}
	network, accounting := false, false
	for _, drain := range a.drains {
		if drain.accounting {
			accounting = true
		} else {
			network = true
		}
	}
	if !network && !a.terminal.networkClosed {
		a.terminal.networkClosed = true
		close(a.terminal.networkDrained)
	}
	if !accounting && !a.terminal.accountingClosed {
		a.terminal.accountingClosed = true
		close(a.terminal.accountingDone)
	}
}

func (a *AttemptLease) closeLoopbackAttempt() error {
	g := a.governor
	g.mu.Lock()
	g.beginAttemptStoppingLocked(a)
	done := a.terminal.verdict
	g.mu.Unlock()
	<-done
	g.mu.Lock()
	defer g.mu.Unlock()
	return a.terminal.result
}

func (a *AttemptLease) awaitLoopbackNetwork() error {
	g := a.governor
	g.mu.Lock()
	g.beginAttemptStoppingLocked(a)
	g.mu.Unlock()
	<-a.terminal.networkDone
	g.mu.Lock()
	defer g.mu.Unlock()
	return a.terminal.networkErr
}

func (a *AttemptLease) recordLoopbackFinishError(err error) {
	if err == nil || a.terminal == nil {
		return
	}
	g := a.governor
	g.mu.Lock()
	defer g.mu.Unlock()
	a.terminal.finishErr = errors.Join(ErrTerminalFinalizationFailed, err)
	g.finalizationFault = errors.Join(g.finalizationFault, a.terminal.finishErr)
}

// One manager per lease. On failure it publishes a bounded verdict, then stays
// owned by the governor until every actual drain (including its sole writer)
// completes. It never launches another attempt or clears the fault on late I/O.
func (g *Governor) runLoopbackTermination(a *AttemptLease) {
	terminal := a.terminal
	networkTimer := time.NewTimer(time.Until(terminal.stoppedAt.Add(g.limits.CancellationDrainTimeout)))
	var networkErr error
	select {
	case <-terminal.networkDrained:
	case <-networkTimer.C:
		g.mu.Lock()
		if !terminal.networkClosed {
			_, tripErr := g.tripLocked(SafetyTripEvent{
				Reason: SafetyTripCancellation, Detail: "loopback network drain exceeded its deadline",
				PeerID: a.PeerID(), AttemptID: a.request.ID, BuildVersion: g.ownerInfo.BuildVersion,
			})
			networkErr = errors.Join(ErrCancellationDrainTimeout, tripErr)
		}
		g.mu.Unlock()
	}
	networkTimer.Stop()
	g.mu.Lock()
	terminal.networkErr = networkErr
	close(terminal.networkDone)
	g.mu.Unlock()

	finishTimer := time.NewTimer(LoopbackFinalizationTimeout)
	timedOut := false
	select {
	case <-terminal.accountingDone:
	case <-finishTimer.C:
		select {
		case <-terminal.accountingDone:
		default:
			timedOut = true
		}
	}
	finishTimer.Stop()
	g.mu.Lock()
	if timedOut {
		g.finalizationFault = errors.Join(g.finalizationFault, ErrTerminalFinalizationTimeout)
	}
	terminal.result = errors.Join(networkErr, terminal.finishErr)
	if timedOut {
		terminal.result = errors.Join(terminal.result, ErrTerminalFinalizationTimeout)
	}
	a.closeErr = terminal.result
	if terminal.result == nil {
		g.loopbackFinalizing--
		g.releaseAttemptLocked(a)
		close(terminal.settled)
		close(terminal.verdict)
		g.mu.Unlock()
		return
	}
	close(terminal.verdict)
	g.mu.Unlock()

	// This wait is explicitly owned, not a retry or a claim that the operating
	// system can interrupt fsync. Close refuses to release the owner meanwhile.
	<-a.drained
	g.mu.Lock()
	close(terminal.settled)
	g.mu.Unlock()
}

// RegisterLoopbackPreFinish installs one non-extensible revocation hook. It is
// unavailable on ordinary/Gate B/C authorizations, after first emission or once
// terminal selection has begun. The carrier must install before any controller.
func (authorization *CommittedCarrierAuthorization) RegisterLoopbackPreFinish(hook func() error) error {
	if authorization == nil || authorization.committed == nil || hook == nil {
		return ErrCommittedAttemptInvalid
	}
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	c := authorization.committed
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.attempt.terminal == nil || c.terminalChosen || c.preFinishHook != nil || authorization.first {
		return ErrCommittedAttemptInvalid
	}
	c.preFinishHook = hook
	return nil
}

func (c *CommittedAttempt) finishLoopback(reason PairingTerminalReason) error {
	// terminalChosen and the hook have already been sealed under c.mu. Only
	// this winning caller creates the writer; every other caller waits finished.
	go func() {
		var hookErr error
		if c.preFinishHook != nil {
			hookErr = c.preFinishHook()
		}
		// Preserve an already-known revocation error even if the subsequent
		// disk call outlives the bounded verdict. No late result can rewrite it.
		c.mu.Lock()
		c.writerErr = hookErr
		c.mu.Unlock()
		networkErr := c.attempt.awaitLoopbackNetwork()
		finishErr := c.ledger.Finish(c.receipt, reason)
		c.attempt.recordLoopbackFinishError(finishErr)
		c.mu.Lock()
		c.writerErr = errors.Join(hookErr, networkErr, finishErr)
		close(c.writerDone)
		c.mu.Unlock()
		// The private pairing drain always completes without error. Publish
		// the writer's result before this final physical-accounting witness.
		if c.drain != nil {
			_ = c.drain.Complete()
		}
	}()
	// Begin stopping even if the hook or the storage worker is blocked.
	result := c.attempt.closeLoopbackAttempt()
	if result == nil {
		<-c.writerDone
	}
	c.mu.Lock()
	result = errors.Join(result, c.writerErr)
	c.terminalErr = result
	close(c.finished)
	c.mu.Unlock()
	return result
}
