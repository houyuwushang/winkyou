package governor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrPairingAdmissionRejected       = errors.New("pairing admission gate rejected the attempt")
	ErrCommittedAttemptConsumed       = errors.New("committed pairing attempt was already consumed")
	ErrCommittedAttemptInvalid        = errors.New("committed pairing attempt is no longer valid")
	ErrFirstEmissionAlreadyAuthorized = errors.New("first emission was already authorized")
	ErrPairingCredentialExpired       = errors.New("pairing credential expired")
)

const pairingAdmissionGateDrainName = "pairing-admission-gate"

type pairingAdmissionGateHooks struct {
	afterPrecheck         func() error
	afterDurableAdmission func() error
	beforePostcheck       func() error
	afterPostcheck        func() error
	beforeReturn          func() error
}

// PairingAdmissionGate combines one live machine AttemptLease with the
// process-independent pairing journal. It owns no socket or emission sink.
type PairingAdmissionGate struct {
	hooks pairingAdmissionGateHooks
}

// NewPairingAdmissionGate constructs the zero-network admission gate. The
// returned value contains no authority until Commit receives a live lease.
func NewPairingAdmissionGate() *PairingAdmissionGate {
	return &PairingAdmissionGate{}
}

// Commit performs pre-check, durable burn-and-admit, and post-check in that
// order. Only a verified durable commit can construct CommittedAttempt.
func (gate *PairingAdmissionGate) Commit(ctx context.Context, attempt *AttemptLease, request PairingAdmissionRequest) (*CommittedAttempt, error) {
	if gate == nil {
		return nil, fmt.Errorf("%w: gate is nil", ErrPairingAdmissionRejected)
	}
	if err := validatePairingAdmissionRequest(request); err != nil {
		return nil, errors.Join(ErrPairingAdmissionRejected, err)
	}
	if attempt == nil || attempt.governor == nil || attempt.governor.owner == nil {
		return nil, errors.Join(ErrPairingAdmissionRejected, ErrLeaseClosed)
	}
	ledger, err := attempt.governor.owner.PairingLedger()
	if err != nil {
		return nil, errors.Join(ErrPairingAdmissionRejected, err)
	}
	// One owner-bound clock now governs both credential expiry and the durable
	// admission timestamp. Production uses time.Now; tests can freeze only this
	// existing journal clock without introducing a second authority.
	ownerID, err := precheckPairingAdmission(ctx, attempt, request, ledger.now)
	if err != nil {
		return nil, errors.Join(ErrPairingAdmissionRejected, err)
	}
	if err := runPairingGateHook(gate.hooks.afterPrecheck); err != nil {
		return nil, errors.Join(ErrPairingAdmissionRejected, err)
	}

	drain, err := attempt.RegisterDrain(pairingAdmissionGateDrainName)
	if err != nil {
		return nil, errors.Join(ErrPairingAdmissionRejected, err)
	}
	drainTransferred := false
	defer func() {
		if !drainTransferred {
			_ = drain.Complete()
		}
	}()

	receipt, err := ledger.Admit(request)
	if err != nil {
		return nil, errors.Join(ErrPairingAdmissionRejected, err)
	}
	failAfterCommit := func(primary error) (*CommittedAttempt, error) {
		reason := pairingTerminalReasonForGateError(primary)
		finishErr := ledger.Finish(receipt, reason)
		return nil, errors.Join(ErrPairingAdmissionRejected, primary, finishErr)
	}

	if err := runPairingGateHook(gate.hooks.afterDurableAdmission); err != nil {
		return failAfterCommit(err)
	}
	if err := runPairingGateHook(gate.hooks.beforePostcheck); err != nil {
		return failAfterCommit(err)
	}
	if err := postcheckPairingAdmission(ctx, attempt, request, ownerID, ledger.now); err != nil {
		return failAfterCommit(err)
	}
	if err := runPairingGateHook(gate.hooks.afterPostcheck); err != nil {
		return failAfterCommit(err)
	}
	if err := runPairingGateHook(gate.hooks.beforeReturn); err != nil {
		return failAfterCommit(err)
	}
	if err := postcheckPairingAdmission(ctx, attempt, request, ownerID, ledger.now); err != nil {
		return failAfterCommit(err)
	}

	committed := &CommittedAttempt{
		attempt:         attempt,
		ledger:          ledger,
		receipt:         receipt,
		request:         request,
		ownerInstanceID: ownerID,
		drain:           drain,
		context:         ctx,
		now:             ledger.now,
		finished:        make(chan struct{}),
	}
	drainTransferred = true
	go committed.watchInvalidation()
	return committed, nil
}

func runPairingGateHook(hook func() error) error {
	if hook == nil {
		return nil
	}
	return hook()
}

func precheckPairingAdmission(ctx context.Context, attempt *AttemptLease, request PairingAdmissionRequest, now func() time.Time) (string, error) {
	if attempt == nil || attempt.governor == nil {
		return "", ErrLeaseClosed
	}
	if request.AttemptID != attempt.request.ID {
		return "", fmt.Errorf("%w: journal attempt id does not match the live lease", ErrPairingLedgerInvalidRequest)
	}
	if request.Envelope != PairingEnvelopeFromAttemptCost(attempt.request.Cost) {
		return "", fmt.Errorf("%w: journal envelope does not match the reserved lease cost", ErrPairingLedgerInvalidRequest)
	}
	if !pairingOperationAllowed(attempt.governor.profile, attempt.request.Operation) {
		return "", fmt.Errorf("%w: pairing admission profile/operation mismatch", ErrNotAllowed)
	}
	return inspectPairingAttempt(ctx, attempt, "", request.ExpiresAt, now)
}

func postcheckPairingAdmission(ctx context.Context, attempt *AttemptLease, request PairingAdmissionRequest, ownerID string, now func() time.Time) error {
	_, err := inspectPairingAttempt(ctx, attempt, ownerID, request.ExpiresAt, now)
	return err
}

func inspectPairingAttempt(ctx context.Context, attempt *AttemptLease, expectedOwnerID string, expiresAt time.Time, now func() time.Time) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if attempt == nil || attempt.governor == nil {
		return "", ErrLeaseClosed
	}
	if now == nil {
		now = time.Now
	}
	if !now().UTC().Before(expiresAt) {
		return "", errors.Join(ErrCommittedAttemptInvalid, ErrPairingCredentialExpired)
	}

	g := attempt.governor
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.scope != ScopeMachine || !pairingOperationAllowed(g.profile, attempt.request.Operation) ||
		g.owner == nil || g.owner.Scope() != ScopeMachine {
		return "", ErrPairingMachineScopeRequired
	}
	if g.trip.BlocksActiveWork {
		return "", &SafetyTripError{Status: g.trip}
	}
	freshTrip := g.owner.SafetyTripStatus()
	if freshTrip.BlocksActiveWork {
		g.trip = freshTrip
		g.beginSafetyTripDrainLocked()
		return "", &SafetyTripError{Status: freshTrip}
	}
	if g.closed || g.closing || attempt.closed || attempt.stoppingStarted || g.attempts[attempt.request.ID] != attempt {
		return "", ErrLeaseClosed
	}
	owner := g.owner.Info()
	if owner.InstanceID == "" || owner.Scope != ScopeMachine {
		return "", ErrPairingMachineScopeRequired
	}
	if expectedOwnerID != "" && owner.InstanceID != expectedOwnerID {
		return "", fmt.Errorf("%w: machine owner instance changed", ErrCommittedAttemptInvalid)
	}
	return owner.InstanceID, nil
}

func pairingOperationAllowed(profile Profile, operation Operation) bool {
	return profile == ProfilePhase1Machine && operation == OperationConnectTest ||
		profile == ProfilePhase1ManualTraversal && (operation == OperationPrediction || operation == OperationBirthday) ||
		profile == ProfilePhase1HardNATCampaign && operation == OperationBirthday
}

func pairingTerminalReasonForGateError(err error) PairingTerminalReason {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrPairingCredentialExpired):
		return PairingTerminalExpired
	case errors.Is(err, context.Canceled), errors.Is(err, ErrLeaseClosed), errors.Is(err, ErrSafetyTripped):
		return PairingTerminalCancelled
	case errors.Is(err, ErrPairingMachineScopeRequired), errors.Is(err, ErrCommittedAttemptInvalid):
		return PairingTerminalScopeChanged
	default:
		return PairingTerminalProtocolError
	}
}

// CommittedAttempt is a one-time, process-private handoff. Its fields are
// deliberately unexported: zero values and caller-constructed values carry no
// authority. A future carrier constructor must consume it before first I/O.
type CommittedAttempt struct {
	mu sync.Mutex

	attempt         *AttemptLease
	ledger          *PairingAdmissionLedger
	receipt         *PairingAdmissionReceipt
	request         PairingAdmissionRequest
	ownerInstanceID string
	drain           DrainHandle
	context         context.Context
	now             func() time.Time

	consumed       bool
	terminalChosen bool
	terminalReason PairingTerminalReason
	terminalErr    error
	finished       chan struct{}
}

// ConsumeForCarrier consumes the token exactly once and returns another
// unforgeable, zero-network authorization. It rechecks cancellation, safety
// trip, expiry, scope, owner identity, and lease liveness before handoff.
func (committed *CommittedAttempt) ConsumeForCarrier(ctx context.Context) (*CommittedCarrierAuthorization, error) {
	if committed == nil || committed.attempt == nil || committed.ledger == nil || committed.receipt == nil {
		return nil, ErrCommittedAttemptInvalid
	}
	committed.mu.Lock()
	if committed.consumed {
		committed.mu.Unlock()
		return nil, ErrCommittedAttemptConsumed
	}
	if committed.terminalChosen {
		done := committed.finished
		committed.mu.Unlock()
		<-done
		return nil, errors.Join(ErrCommittedAttemptInvalid, committed.terminalErr)
	}
	committed.consumed = true
	committed.mu.Unlock()

	if err := committed.validate(ctx); err != nil {
		finishErr := committed.finish(pairingTerminalReasonForGateError(err))
		return nil, errors.Join(ErrCommittedAttemptInvalid, err, finishErr)
	}
	return &CommittedCarrierAuthorization{committed: committed}, nil
}

func (committed *CommittedAttempt) validate(ctx context.Context) error {
	committed.mu.Lock()
	if committed.terminalChosen {
		done := committed.finished
		committed.mu.Unlock()
		<-done
		return errors.Join(ErrCommittedAttemptInvalid, committed.terminalErr)
	}
	committed.mu.Unlock()
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if committed.context != nil {
		if err := committed.context.Err(); err != nil {
			return err
		}
	}
	_, err := inspectPairingAttempt(ctx, committed.attempt, committed.ownerInstanceID, committed.request.ExpiresAt, committed.now)
	return err
}

func (committed *CommittedAttempt) watchInvalidation() {
	if committed == nil || committed.attempt == nil {
		return
	}
	now := time.Now
	if committed.now != nil {
		now = committed.now
	}
	duration := committed.request.ExpiresAt.Sub(now().UTC())
	if duration < 0 {
		duration = 0
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	var contextDone <-chan struct{}
	if committed.context != nil {
		contextDone = committed.context.Done()
	}
	select {
	case <-committed.finished:
		return
	case <-committed.attempt.Stopping():
		_ = committed.finish(PairingTerminalCancelled)
	case <-contextDone:
		reason := PairingTerminalCancelled
		if errors.Is(committed.context.Err(), context.DeadlineExceeded) {
			reason = PairingTerminalExpired
		}
		_ = committed.finish(reason)
	case <-timer.C:
		_ = committed.finish(PairingTerminalExpired)
	}
}

func (committed *CommittedAttempt) finish(reason PairingTerminalReason) error {
	if committed == nil || committed.ledger == nil || committed.receipt == nil {
		return ErrCommittedAttemptInvalid
	}
	if !reason.valid() {
		return fmt.Errorf("%w: invalid terminal reason %q", ErrPairingLedgerInvalidRequest, reason)
	}
	committed.mu.Lock()
	if committed.terminalChosen {
		done := committed.finished
		chosen := committed.terminalReason
		committed.mu.Unlock()
		<-done
		if chosen != reason {
			return errors.Join(ErrCommittedAttemptInvalid, committed.terminalErr)
		}
		return committed.terminalErr
	}
	committed.terminalChosen = true
	committed.terminalReason = reason
	committed.mu.Unlock()

	err := committed.ledger.Finish(committed.receipt, reason)
	if committed.drain != nil {
		err = errors.Join(err, committed.drain.Complete())
	}
	committed.mu.Lock()
	committed.terminalErr = err
	close(committed.finished)
	committed.mu.Unlock()
	return err
}

// CommittedCarrierAuthorization is the zero-network state a future reviewed
// carrier constructor must retain. It cannot be constructed usefully by a
// caller and authorizes no raw socket by itself.
type CommittedCarrierAuthorization struct {
	mu        sync.Mutex
	committed *CommittedAttempt
	first     bool
}

// BeforeFirstEmission is the mandatory final fail-closed check immediately
// before a future carrier's first byte. It is one-shot and performs no I/O.
func (authorization *CommittedCarrierAuthorization) BeforeFirstEmission(ctx context.Context) error {
	if authorization == nil || authorization.committed == nil {
		return ErrCommittedAttemptInvalid
	}
	authorization.mu.Lock()
	defer authorization.mu.Unlock()
	if authorization.first {
		return ErrFirstEmissionAlreadyAuthorized
	}
	if err := authorization.committed.validate(ctx); err != nil {
		finishErr := authorization.committed.finish(pairingTerminalReasonForGateError(err))
		return errors.Join(ErrCommittedAttemptInvalid, err, finishErr)
	}
	authorization.first = true
	return nil
}

// CheckActive revalidates the attempt before each later emission. Future
// carrier review must place this check at its controlled I/O boundary.
func (authorization *CommittedCarrierAuthorization) CheckActive(ctx context.Context) error {
	if authorization == nil || authorization.committed == nil {
		return ErrCommittedAttemptInvalid
	}
	authorization.mu.Lock()
	first := authorization.first
	authorization.mu.Unlock()
	if !first {
		return ErrCommittedAttemptInvalid
	}
	if err := authorization.committed.validate(ctx); err != nil {
		finishErr := authorization.committed.finish(pairingTerminalReasonForGateError(err))
		return errors.Join(ErrCommittedAttemptInvalid, err, finishErr)
	}
	return nil
}

// Stopping exposes the already-governed cancellation signal; it does not
// create a second lifecycle or cancellation authority.
func (authorization *CommittedCarrierAuthorization) Stopping() <-chan struct{} {
	if authorization == nil || authorization.committed == nil || authorization.committed.attempt == nil {
		return closedChannel()
	}
	return authorization.committed.attempt.Stopping()
}

// Finish appends one terminal result and completes the gate's drain witness.
// It is idempotent only for the same terminal reason.
func (authorization *CommittedCarrierAuthorization) Finish(reason PairingTerminalReason) error {
	if authorization == nil || authorization.committed == nil {
		return ErrCommittedAttemptInvalid
	}
	authorization.mu.Lock()
	first := authorization.first
	authorization.mu.Unlock()
	if reason == PairingTerminalSuccess && !first {
		return fmt.Errorf("%w: success requires first-emission authorization", ErrCommittedAttemptInvalid)
	}
	return authorization.committed.finish(reason)
}
