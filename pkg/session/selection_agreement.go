package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	rproto "winkyou/pkg/rendezvous/proto"
	"winkyou/pkg/solver"
)

type selectionInbox struct {
	proposal *selectionProposal
	confirm  *selectionConfirmation
	received int
}
type selectionRound struct {
	ordinal     uint64
	local       selectionProposal
	remote      selectionInbox
	digest      string
	strategy    string
	confirmed   bool
	entered     bool
	deadline    time.Time
	budgetStart time.Time
}
type selectionAgreement struct {
	mu                   sync.Mutex
	changed              chan struct{}
	ctx                  context.Context
	cancel               context.CancelFunc
	local                selectionCapability
	remote               *selectionCapability
	current              *selectionRound
	future               selectionInbox
	err                  error
	passStart            time.Time
	capabilityDeadline   time.Time
	capabilityReceivedAt time.Time
	confirmDeadline      time.Time
	cleanupErr           error
	strategyClosed       bool
	previous             solver.Strategy
	activeExecutors      map[solver.PlanExecutor]struct{}
	budgetUsed           bool // executeMu owns use of the first plan/group allowance
}

// NewConverging is the only permitted product constructor. New retains the
// independent library strategy contract; production cannot select it via config.
func NewConverging(cfg Config) (*Session, error) {
	if !selectionIdentifier(cfg.LocalNodeID, 128) || !selectionIdentifier(cfg.PeerID, 128) || !selectionIdentifier(cfg.SessionID, 512) || cfg.LocalNodeID == cfg.PeerID || cfg.Initiator != (cfg.LocalNodeID < cfg.PeerID) || cfg.RunTimeout <= 0 {
		return nil, selectionFailure("selection_invalid")
	}
	s, err := New(cfg)
	if err != nil {
		return nil, err
	}
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return nil, selectionFailure("selection_invalid")
	}
	capability := s.localCapability()
	local := selectionCapability{Strategies: capability.Strategies, Features: capability.Features, Version: selectionVersion, Epoch: hex.EncodeToString(epoch[:])}
	if err := validateSelectionCapability(local); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.agreement = &selectionAgreement{changed: make(chan struct{}, 1), ctx: ctx, cancel: cancel, local: local, strategyClosed: true, activeExecutors: make(map[solver.PlanExecutor]struct{})}
	return s, nil
}

func (a *selectionAgreement) wake() {
	select {
	case a.changed <- struct{}{}:
	default:
	}
}
func (a *selectionAgreement) stopLocked(err error) error {
	if a.err == nil {
		if !IsSelectionError(err) {
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				err = selectionDeadline("selection_timeout")
			case errors.Is(err, context.Canceled):
				err = &selectionError{class: "selection_closed", cause: context.Canceled}
			default:
				err = selectionFailure("selection_closed")
			}
		}
		a.err = err
		a.future = selectionInbox{}
		if a.current != nil {
			a.current.remote = selectionInbox{}
		}
		a.cancel()
		a.wake()
	}
	return a.err
}
func (s *Session) stopSelection(err error) error {
	if s.agreement == nil {
		return err
	}
	a := s.agreement
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopLocked(err)
}
func (s *Session) beginSelectionPass() error {
	if s.agreement == nil {
		return nil
	}
	a := s.agreement
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.passStart = time.Now()
	window := min(s.capabilityWaitTimeout(), defaultCapabilityWaitTimeout)
	a.capabilityDeadline = a.passStart.Add(window)
	if a.current == nil && !a.capabilityReceivedAt.IsZero() {
		a.confirmDeadline = firstSelectionConfirmDeadline(a.passStart, a.capabilityReceivedAt, window, s.executionTimeout())
	}
	return nil
}

// Both first-round subwindows consume the existing first execution allowance.
// A nonpositive remainder intentionally yields an already-expired deadline.
func firstSelectionConfirmDeadline(passStart, receivedAt time.Time, window, runTimeout time.Duration) time.Time {
	// Control exchange cannot start before this pass, even if capability arrived early.
	anchor := receivedAt
	if anchor.Before(passStart) {
		anchor = passStart
	}
	remaining := passStart.Add(runTimeout).Sub(anchor)
	return anchor.Add(min(window, defaultCapabilityWaitTimeout, remaining))
}

func (s *Session) selectionCapabilityContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.agreement == nil {
		return s.operationContext(ctx)
	}
	a := s.agreement
	a.mu.Lock()
	deadline := a.capabilityDeadline
	a.mu.Unlock()
	return context.WithDeadline(ctx, deadline)
}

func (s *Session) waitForSelectionCapability(ctx context.Context) (rproto.Capability, error) {
	waitCtx, cancel := s.selectionCapabilityContext(ctx)
	defer cancel()
	a := s.agreement
	for {
		a.mu.Lock()
		err := a.err
		remote := a.remote
		waitErr := waitCtx.Err()
		firstRound := a.current == nil
		a.mu.Unlock()
		if err != nil {
			return rproto.Capability{}, err
		}
		if ctx.Err() != nil {
			return rproto.Capability{}, s.stopSelection(ctx.Err())
		}
		// An accepted first capability was validated against the immutable
		// capability deadline while holding a.mu. A delayed waiter must not
		// turn that timely receipt into capability_missing at the old deadline.
		if waitErr != nil && (remote == nil || !firstRound) {
			if ctx.Err() != nil {
				return rproto.Capability{}, s.stopSelection(ctx.Err())
			}
			return rproto.Capability{}, s.stopSelection(selectionDeadline("capability_missing"))
		}
		if remote != nil {
			return cloneCapability(remote.domainWire()), nil
		}
		select {
		case <-waitCtx.Done():
			// Re-read receipt and expiry in one critical section before deciding.
		case <-a.changed:
		}
	}
}

// The transport supplies the authenticated/associated peer separately; an
// envelope cannot choose its own sender. This does not create new authentication.
func (s *Session) HandleMessageFrom(ctx context.Context, peerID string, msg solver.Message) error {
	if s.agreement != nil && peerID != s.cfg.PeerID {
		return s.stopSelection(selectionFailure("selection_invalid"))
	}
	return s.HandleMessage(ctx, msg)
}

func (s *Session) receiveSelectionCapability(payload []byte, at time.Time) error {
	var capability selectionCapability
	if err := decodeSelectionJSON(payload, &capability); err != nil {
		return s.stopSelection(err)
	}
	if err := validateSelectionCapability(capability); err != nil {
		return s.stopSelection(err)
	}
	capability.Strategies = normalizeCapability(capability.domainWire()).Strategies
	capability.Features = normalizeCapability(capability.domainWire()).Features
	a := s.agreement
	a.mu.Lock()
	if a.err != nil {
		a.mu.Unlock()
		// Preserve the legacy read-only late-arrival diagnostic. The immutable
		// agreement input and terminal remain untouched; wait/execute read a.err.
		s.setRemoteCapability(capability.domainWire(), at)
		return nil
	}
	if a.remote != nil && (a.remote.Epoch != capability.Epoch || selectionCapabilityDigest(a.remote.domainWire()) != selectionCapabilityDigest(capability.domainWire())) {
		err := a.stopLocked(selectionFailure("selection_conflict"))
		a.mu.Unlock()
		return err
	}
	if a.remote == nil {
		// at belongs only to the existing diagnostic snapshot. Never trust a
		// sender/carrier timestamp to extend either local protocol window.
		receivedAt := time.Now()
		if !a.capabilityDeadline.IsZero() && !receivedAt.Before(a.capabilityDeadline) {
			err := a.stopLocked(selectionDeadline("capability_missing"))
			a.mu.Unlock()
			s.setRemoteCapability(capability.domainWire(), at)
			return err
		}
		a.capabilityReceivedAt = receivedAt
		if !a.passStart.IsZero() {
			window := min(s.capabilityWaitTimeout(), defaultCapabilityWaitTimeout)
			a.confirmDeadline = firstSelectionConfirmDeadline(a.passStart, receivedAt, window, s.executionTimeout())
		}
	}
	a.remote = &capability
	a.wake()
	a.mu.Unlock()
	s.setRemoteCapability(capability.domainWire(), at)
	return nil
}

func (s *Session) receiveSelectionControl(kind string, payload []byte) error {
	var binding selectionBinding
	var proposal *selectionProposal
	var confirmation *selectionConfirmation
	if kind == selectionProposalType {
		proposal = &selectionProposal{}
		if err := decodeSelectionJSON(payload, proposal); err != nil {
			return s.stopSelection(err)
		}
		if !selectionList(proposal.Strategies, selectionStrategyLimit, true) {
			return s.stopSelection(selectionFailure("selection_invalid"))
		}
		binding = proposal.selectionBinding
	} else {
		confirmation = &selectionConfirmation{}
		if err := decodeSelectionJSON(payload, confirmation); err != nil {
			return s.stopSelection(err)
		}
		if !selectionIdentifier(confirmation.Strategy, selectionTokenLimit) || !selectionHex(confirmation.Digest, 32) {
			return s.stopSelection(selectionFailure("selection_invalid"))
		}
		binding = confirmation.selectionBinding
	}
	if err := validateSelectionBinding(binding); err != nil {
		return s.stopSelection(err)
	}
	ordinal, _ := selectionOrdinal(binding.Ordinal)
	a := s.agreement
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil
	}
	if binding.ToEpoch != a.local.Epoch || binding.ReceiverCapability != selectionCapabilityDigest(a.local.domainWire()) || a.remote != nil && (binding.FromEpoch != a.remote.Epoch || binding.SenderCapability != selectionCapabilityDigest(a.remote.domainWire())) {
		return a.stopLocked(selectionFailure("selection_conflict"))
	}
	inbox := &a.future
	if a.current == nil {
		if ordinal != 0 {
			return a.stopLocked(selectionFailure("selection_conflict"))
		}
	} else {
		if ordinal < a.current.ordinal {
			return nil
		}
		if ordinal == a.current.ordinal {
			inbox = &a.current.remote
		} else if a.current.ordinal == ^uint64(0) || ordinal != a.current.ordinal+1 {
			return a.stopLocked(selectionFailure("selection_conflict"))
		}
	}
	inbox.received++
	if inbox.received > selectionReceiveLimit {
		return a.stopLocked(selectionFailure("selection_invalid"))
	}
	if proposal != nil {
		if inbox.proposal != nil && !equalProposal(inbox.proposal, proposal) {
			return a.stopLocked(selectionFailure("selection_conflict"))
		}
		inbox.proposal = proposal
	} else {
		if inbox.confirm != nil && *inbox.confirm != *confirmation {
			return a.stopLocked(selectionFailure("selection_conflict"))
		}
		inbox.confirm = confirmation
	}
	// Once committed, even a first delayed conflicting confirmation is terminal.
	if a.current != nil && ordinal == a.current.ordinal && a.current.confirmed && (inbox.confirm == nil || inbox.confirm.Digest != a.current.digest || inbox.confirm.Strategy != a.current.strategy) {
		return a.stopLocked(selectionFailure("selection_conflict"))
	}
	a.wake()
	return nil
}

func (s *Session) sendSelection(ctx context.Context, kind string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > selectionPayloadLimit {
		return selectionFailure("selection_invalid")
	}
	envelope, err := s.newEnvelope(kind, value)
	if err != nil {
		return err
	}
	payload, err := rproto.MarshalEnvelope(envelope)
	if err != nil || len(payload) > selectionEnvelopeLimit {
		return selectionFailure("selection_invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.io.Send(ctx, solver.Message{Kind: solver.MessageKindEnvelope, Namespace: envelopeNamespace, Type: kind, Payload: payload, ReceivedAt: time.Now()})
}

func (s *Session) agreeCandidates(ctx context.Context, candidates []StrategyCandidate, newPass bool) ([]StrategyCandidate, error) {
	if s.agreement == nil {
		return candidates, nil
	}
	a := s.agreement
	if err := s.requirePreviousSelectionClosed(); err != nil {
		return nil, s.stopSelection(err)
	}
	start := time.Now()
	a.mu.Lock()
	if a.err != nil {
		err := a.err
		a.mu.Unlock()
		return nil, err
	}
	if a.remote == nil {
		a.mu.Unlock()
		return nil, s.stopSelection(selectionFailure("capability_missing"))
	}
	ordinal, previous := uint64(0), ""
	if a.current != nil {
		if a.current.ordinal == ^uint64(0) {
			a.mu.Unlock()
			return nil, s.stopSelection(selectionFailure("selection_invalid"))
		}
		ordinal, previous = a.current.ordinal+1, a.current.digest
	}
	localCap, remoteCap := a.local.domainWire(), a.remote.domainWire()
	proposal := selectionProposal{selectionBinding: selectionBinding{Version: selectionVersion, FromEpoch: a.local.Epoch, ToEpoch: a.remote.Epoch, Ordinal: strconv.FormatUint(ordinal, 10), SenderCapability: selectionCapabilityDigest(localCap), ReceiverCapability: selectionCapabilityDigest(remoteCap), Previous: previous, PreviousClosed: true}}
	for _, candidate := range candidates {
		if !slices.Contains(localCap.Strategies, candidate.Name) || !slices.Contains(remoteCap.Strategies, candidate.Name) {
			a.mu.Unlock()
			return nil, s.stopSelection(selectionFailure("selection_conflict"))
		}
		proposal.Strategies = append(proposal.Strategies, candidate.Name)
	}
	if !selectionList(proposal.Strategies, selectionStrategyLimit, true) {
		a.mu.Unlock()
		return nil, s.stopSelection(selectionFailure("selection_invalid"))
	}
	deadline := start.Add(min(s.capabilityWaitTimeout(), defaultCapabilityWaitTimeout))
	if newPass {
		start, deadline = a.passStart, a.capabilityDeadline
	}
	if ordinal == 0 {
		start, deadline = a.passStart, a.confirmDeadline
	}
	budgetStart := start
	if ordinal != 0 {
		if timeout := s.executionTimeout(); timeout > 0 && start.Add(timeout).Before(deadline) {
			deadline = start.Add(timeout)
		}
	}
	round := &selectionRound{ordinal: ordinal, local: proposal, remote: a.future, deadline: deadline, budgetStart: budgetStart}
	a.current, a.future, a.budgetUsed = round, selectionInbox{}, false
	a.mu.Unlock()
	agreeCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	failed := func(err error) ([]StrategyCandidate, error) {
		if errors.Is(err, context.DeadlineExceeded) {
			err = selectionDeadline("selection_timeout")
		}
		return nil, s.stopSelection(err)
	}
	if err := s.sendSelection(agreeCtx, selectionProposalType, proposal); err != nil {
		return failed(err)
	}
	var remote selectionProposal
	for {
		a.mu.Lock()
		err := a.err
		p := round.remote.proposal
		if p != nil {
			remote = *p
			remote.Strategies = slices.Clone(p.Strategies)
		}
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if p != nil {
			break
		}
		select {
		case <-agreeCtx.Done():
			return failed(agreeCtx.Err())
		case <-a.changed:
		}
	}
	expected := proposal.selectionBinding
	expected.FromEpoch, expected.ToEpoch = expected.ToEpoch, expected.FromEpoch
	expected.SenderCapability, expected.ReceiverCapability = expected.ReceiverCapability, expected.SenderCapability
	if remote.selectionBinding != expected {
		return failed(selectionFailure("selection_conflict"))
	}
	for _, name := range remote.Strategies {
		if !slices.Contains(remoteCap.Strategies, name) || !slices.Contains(localCap.Strategies, name) {
			return failed(selectionFailure("selection_conflict"))
		}
	}
	joint, err := jointSelection(s.cfg, localCap, remoteCap, proposal, remote)
	if err != nil {
		return failed(err)
	}
	digest := selectionHash(joint)
	confirm := selectionConfirmation{selectionBinding: proposal.selectionBinding, Strategy: joint.Order[0], Digest: digest}
	if err := s.sendSelection(agreeCtx, selectionConfirmType, confirm); err != nil {
		return failed(err)
	}
	for {
		a.mu.Lock()
		err := a.err
		c := round.remote.confirm
		var received selectionConfirmation
		if c != nil {
			received = *c
		}
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if c != nil {
			if received.selectionBinding != expected || received.Digest != digest || received.Strategy != joint.Order[0] {
				return failed(selectionFailure("selection_conflict"))
			}
			break
		}
		select {
		case <-agreeCtx.Done():
			return failed(agreeCtx.Err())
		case <-a.changed:
		}
	}
	a.mu.Lock()
	if a.err != nil {
		err := a.err
		a.mu.Unlock()
		return nil, err
	}
	if agreeCtx.Err() != nil || !time.Now().Before(deadline) {
		a.mu.Unlock()
		return failed(selectionDeadline("selection_timeout"))
	}
	round.confirmed, round.digest, round.strategy = true, digest, joint.Order[0]
	a.mu.Unlock()
	s.metaMu.Lock()
	s.meta.SelectionDigest, s.meta.SelectionOrdinal = digest, ordinal
	s.metaMu.Unlock()
	ordered := make([]StrategyCandidate, 0, len(joint.Order))
	for _, name := range joint.Order {
		for _, candidate := range candidates {
			if candidate.Name == name {
				candidate.Selection.Negotiated = true
				ordered = append(ordered, candidate)
				break
			}
		}
	}
	return ordered, nil
}

func (s *Session) prepareCandidateAgreement(ctx context.Context, candidate StrategyCandidate) error {
	if s.agreement == nil {
		return nil
	}
	a := s.agreement
	a.mu.Lock()
	round := a.current
	ready := a.err == nil && round != nil && round.confirmed && !round.entered && round.strategy == candidate.Name
	a.mu.Unlock()
	if ready {
		return nil
	}
	_, err := s.agreeCandidates(ctx, []StrategyCandidate{candidate}, false)
	return err
}

func (s *Session) enterSelection(ctx context.Context, strategy solver.Strategy) (context.Context, context.CancelFunc, error) {
	if s.agreement == nil {
		return ctx, func() {}, nil
	}
	a := s.agreement
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return nil, nil, a.err
	}
	round := a.current
	if round == nil || !round.confirmed || round.entered || round.strategy != strategy.Name() {
		return nil, nil, a.stopLocked(selectionFailure("selection_conflict"))
	}
	if ctx.Err() != nil {
		return nil, nil, a.stopLocked(ctx.Err())
	}
	if !time.Now().Before(round.deadline) {
		return nil, nil, a.stopLocked(selectionDeadline("selection_timeout"))
	}
	round.entered = true
	a.previous, a.strategyClosed = strategy, false
	execCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.ctx, cancel)
	return execCtx, func() { stop(); cancel() }, nil
}

func (s *Session) selectionCleanup(fn func() error) error {
	err := s.runCleanup(fn)
	if s.agreement != nil && err != nil {
		a := s.agreement
		a.mu.Lock()
		a.cleanupErr = err
		a.stopLocked(selectionFailure("selection_previous_active"))
		a.mu.Unlock()
	}
	return err
}
func (s *Session) closeSelectionStrategy(strategy solver.Strategy) error {
	err := s.selectionCleanup(strategy.Close)
	if s.agreement != nil {
		a := s.agreement
		a.mu.Lock()
		if a.previous == strategy && err == nil {
			a.strategyClosed = true
		}
		a.mu.Unlock()
	}
	return err
}

func (s *Session) openSelectionExecutor(executor solver.PlanExecutor) {
	if s.agreement == nil {
		return
	}
	a := s.agreement
	a.mu.Lock()
	a.activeExecutors[executor] = struct{}{}
	a.mu.Unlock()
}
func (s *Session) closeSelectionExecutor(executor solver.PlanExecutor) error {
	err := s.selectionCleanup(executor.Close)
	if s.agreement != nil && err == nil {
		a := s.agreement
		a.mu.Lock()
		delete(a.activeExecutors, executor)
		a.mu.Unlock()
	}
	return err
}
func (s *Session) selectionTerminalError() error {
	if s.agreement == nil {
		return nil
	}
	a := s.agreement
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}
func (s *Session) requirePreviousSelectionClosed() error {
	if s.agreement == nil {
		return nil
	}
	a := s.agreement
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	if a.cleanupErr != nil || len(a.activeExecutors) != 0 {
		return selectionFailure("selection_previous_active")
	}
	if a.previous == nil || a.strategyClosed {
		return nil
	}
	// Factory executors are joined by executePlan/group before returning outcomes;
	// they may transfer a transport without closing the healthy data-plane owner.
	if _, ok := a.previous.(solver.ExecutorFactory); ok {
		return nil
	}
	return selectionFailure("selection_previous_active")
}

func (s *Session) selectionExecutionContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if s.agreement == nil {
		if timeout > 0 {
			return context.WithTimeout(ctx, timeout)
		}
		return ctx, func() {}
	}
	a := s.agreement
	a.mu.Lock()
	start := time.Time{}
	if !a.budgetUsed && a.current != nil {
		start = a.current.budgetStart
		a.budgetUsed = true
	}
	a.mu.Unlock()
	if timeout <= 0 {
		return ctx, func() {}
	}
	if !start.IsZero() {
		return context.WithDeadline(ctx, start.Add(timeout))
	}
	return context.WithTimeout(ctx, timeout)
}
func (s *Session) subtractSelectionTime(budget solver.ExecutionBudget) solver.ExecutionBudget {
	if s.agreement == nil {
		return budget
	}
	a := s.agreement
	a.mu.Lock()
	var start time.Time
	if a.current != nil {
		start = a.current.budgetStart
	}
	a.mu.Unlock()
	if !start.IsZero() {
		budget.TimeBudget -= time.Since(start)
		if budget.TimeBudget <= 0 {
			budget.TimeBudget = time.Nanosecond
		}
	}
	return budget
}
