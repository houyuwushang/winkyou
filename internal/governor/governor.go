package governor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrGovernorClosed           = errors.New("governor is closed")
	ErrLeaseClosed              = errors.New("governor lease is closed")
	ErrDuplicatePeer            = errors.New("peer already has an active lease")
	ErrDuplicateAttempt         = errors.New("attempt id is already active")
	ErrExclusiveClaimUsed       = errors.New("attempt exclusive claim is already used")
	ErrInvalidRequest           = errors.New("invalid governor request")
	ErrCancellationDrainTimeout = errors.New("attempt cancellation drain timed out")
	ErrRestrictedScopeRequired  = errors.New("user-acknowledged profile requires the restricted governor capability")
)

const maxAttemptDrainRegistrations = 8

// AttemptCost is the complete worst-case declaration reserved before an
// attempt can perform active work.
type AttemptCost struct {
	Resources   Resources
	Duration    time.Duration
	Heavyweight bool
}

// AttemptRequest identifies one bounded operation.
type AttemptRequest struct {
	ID        string
	Operation Operation
	Cost      AttemptCost
}

// Snapshot is a race-safe diagnostic view of the current authority.
type Snapshot struct {
	Owner               OwnerInfo
	Profile             Profile
	Scope               Scope
	Limits              Limits
	ActivePeers         int
	ActiveAttempts      int
	HeavyweightAttempts int
	Reserved            Resources
	SafetyTrip          SafetyTripStatus
	Closed              bool
}

// Governor is the only in-process source of peer and attempt leases beneath
// one OS-level namespace owner.
type Governor struct {
	mu sync.Mutex

	owner            *Owner
	profile          Profile
	scope            Scope
	limits           Limits
	trip             SafetyTripStatus
	closing          bool
	closed           bool
	closeDone        chan struct{}
	closeErr         error
	tripDrainStarted bool

	peers               map[string]*PeerLease
	attempts            map[string]*AttemptLease
	reserved            Resources
	heavyweightAttempts int
}

// New constructs a governor and takes lifecycle ownership of owner on success.
// requested may be nil to use the compiled profile ceiling. A non-nil value can
// only lower that ceiling.
func New(owner *Owner, profile Profile, requested *Limits) (*Governor, error) {
	if profile == ProfilePhase1UserAcknowledged {
		return nil, ErrRestrictedScopeRequired
	}
	return newGovernor(owner, profile, requested)
}

func newGovernor(owner *Owner, profile Profile, requested *Limits) (*Governor, error) {
	if owner == nil || !owner.usable() {
		return nil, fmt.Errorf("%w: namespace owner is missing or closed", ErrInvalidRequest)
	}
	scope, err := profile.Scope()
	if err != nil {
		return nil, err
	}
	if owner.Scope() != scope {
		return nil, fmt.Errorf(
			"%w: owner scope %q does not match profile scope %q",
			ErrInvalidRequest,
			owner.Scope(),
			scope,
		)
	}
	hard, err := HardLimits(profile)
	if err != nil {
		return nil, err
	}
	limits := hard
	if requested != nil {
		if err := validateNotRaised(*requested, hard); err != nil {
			return nil, err
		}
		limits = *requested
	}
	trip := owner.SafetyTripStatus()
	if trip.BlocksActiveWork {
		return nil, &SafetyTripError{Status: trip}
	}
	if err := owner.claim(); err != nil {
		return nil, err
	}

	return &Governor{
		owner:     owner,
		profile:   profile,
		scope:     scope,
		limits:    limits,
		trip:      trip,
		closeDone: make(chan struct{}),
		peers:     make(map[string]*PeerLease),
		attempts:  make(map[string]*AttemptLease),
	}, nil
}

// AcquirePeer creates the only active peer lease for peerID.
func (g *Governor) AcquirePeer(peerID string) (*PeerLease, error) {
	if g == nil {
		return nil, ErrGovernorClosed
	}
	if err := validateIdentifier("peer id", peerID); err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.closing {
		return nil, ErrGovernorClosed
	}
	if g.trip.BlocksActiveWork {
		return nil, &SafetyTripError{Status: g.trip}
	}
	if _, exists := g.peers[peerID]; exists {
		return nil, fmt.Errorf("%w: %s", ErrDuplicatePeer, peerID)
	}
	if len(g.peers) >= g.limits.MaxActivePeers {
		return nil, &LimitError{
			Field:     "active_peers",
			Requested: int64(len(g.peers) + 1),
			Maximum:   int64(g.limits.MaxActivePeers),
		}
	}
	lease := &PeerLease{
		governor: g,
		peerID:   peerID,
		attempts: make(map[string]*AttemptLease),
	}
	g.peers[peerID] = lease
	return lease, nil
}

// Snapshot returns current reservations without exposing mutable state.
func (g *Governor) Snapshot() Snapshot {
	if g == nil {
		return Snapshot{Closed: true}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return Snapshot{
		Owner:               g.owner.Info(),
		Profile:             g.profile,
		Scope:               g.scope,
		Limits:              g.limits,
		ActivePeers:         len(g.peers),
		ActiveAttempts:      len(g.attempts),
		HeavyweightAttempts: g.heavyweightAttempts,
		Reserved:            g.reserved,
		SafetyTrip:          g.trip,
		Closed:              g.closed || g.closing,
	}
}

// Close closes every child lease, releases all reservations, and finally
// releases the process-independent namespace owner. It is idempotent.
func (g *Governor) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed || g.closing {
		done := g.closeDone
		g.mu.Unlock()
		<-done
		g.mu.Lock()
		err := g.closeErr
		g.mu.Unlock()
		return err
	}
	g.closing = true
	attempts := g.activeAttemptsLocked()
	for _, attempt := range attempts {
		g.beginAttemptStoppingLocked(attempt)
	}
	g.mu.Unlock()

	drainErr := g.drainAttempts(attempts)

	g.mu.Lock()
	g.stopActiveLocked()
	g.closed = true
	owner := g.owner
	g.mu.Unlock()
	ownerErr := owner.closeClaimed()
	result := errors.Join(drainErr, ownerErr)

	g.mu.Lock()
	g.closeErr = result
	close(g.closeDone)
	g.mu.Unlock()
	return result
}

// PeerLease groups attempts for one peer and enforces per-peer single-flight.
type PeerLease struct {
	governor *Governor
	peerID   string
	attempts map[string]*AttemptLease
	closed   bool
}

func (p *PeerLease) PeerID() string {
	if p == nil {
		return ""
	}
	return p.peerID
}

// AcquireAttempt atomically reserves the complete declared cost. Cancellation
// releases the lease even when the caller forgets to close it.
func (p *PeerLease) AcquireAttempt(ctx context.Context, request AttemptRequest) (*AttemptLease, error) {
	if p == nil || p.governor == nil {
		return nil, ErrLeaseClosed
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	g := p.governor
	g.mu.Lock()
	if g.trip.BlocksActiveWork {
		g.mu.Unlock()
		return nil, &SafetyTripError{Status: g.trip}
	}
	if g.closed || g.closing || p.closed {
		g.mu.Unlock()
		return nil, ErrLeaseClosed
	}
	if err := g.validateAttemptLocked(p, request); err != nil {
		g.mu.Unlock()
		return nil, err
	}

	lease := &AttemptLease{
		governor:        g,
		peer:            p,
		request:         request,
		stopping:        make(chan struct{}),
		drained:         make(chan struct{}),
		done:            make(chan struct{}),
		drains:          make(map[uint64]*attemptDrain),
		exclusiveClaims: make(map[string]struct{}),
	}
	p.attempts[request.ID] = lease
	g.attempts[request.ID] = lease
	g.reserved = g.reserved.add(request.Cost.Resources)
	if request.Cost.Heavyweight {
		g.heavyweightAttempts++
	}
	g.mu.Unlock()

	if done := ctx.Done(); done != nil {
		go func() {
			select {
			case <-done:
				_ = lease.Close()
			case <-lease.done:
			}
		}()
	}
	if err := ctx.Err(); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}

// Trip commits the persistent blocking latch, signals every active attempt to
// stop at that commit point, and then persists the diagnostic record. Registered
// drains finish asynchronously under the governor's bounded timeout authority.
// A failed detail write leaves both the in-process governor and durable latch
// blocking work.
func (g *Governor) Trip(event SafetyTripEvent) (SafetyTripStatus, error) {
	if g == nil {
		status := indeterminateSafetyTripStatus("governor is unavailable")
		return status, ErrGovernorClosed
	}
	if err := validateSafetyTripEvent(event); err != nil {
		return SafetyTripStatus{}, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tripLocked(event)
}

func (g *Governor) tripLocked(event SafetyTripEvent) (SafetyTripStatus, error) {
	if g.closed {
		return g.trip, ErrGovernorClosed
	}
	if g.trip.BlocksActiveWork {
		g.beginSafetyTripDrainLocked()
		return g.trip, nil
	}
	status, err := g.owner.tripStore.tripThen(event, g.beginSafetyTripDrainLocked)
	g.trip = status
	if !g.trip.BlocksActiveWork {
		g.trip = indeterminateSafetyTripStatus("trip operation did not produce a blocking state")
		if err == nil {
			err = &SafetyTripError{Status: g.trip}
		}
	}
	g.beginSafetyTripDrainLocked()
	return g.trip, err
}

func (g *Governor) validateAttemptLocked(peer *PeerLease, request AttemptRequest) error {
	if err := validateIdentifier("attempt id", request.ID); err != nil {
		return err
	}
	if !g.profile.Allows(request.Operation) {
		return fmt.Errorf("%w: profile=%s operation=%s", ErrNotAllowed, g.profile, request.Operation)
	}
	if _, exists := g.attempts[request.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateAttempt, request.ID)
	}
	if len(g.attempts) >= g.limits.MaxActiveAttempts {
		return &LimitError{
			Field:     "active_attempts",
			Requested: int64(len(g.attempts) + 1),
			Maximum:   int64(g.limits.MaxActiveAttempts),
		}
	}
	if len(peer.attempts) >= g.limits.MaxAttemptsPerPeer {
		return &LimitError{
			Field:     "attempts_per_peer",
			Requested: int64(len(peer.attempts) + 1),
			Maximum:   int64(g.limits.MaxAttemptsPerPeer),
		}
	}
	if err := request.Cost.Resources.validateNonNegative(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if request.Cost.Resources == (Resources{}) {
		return fmt.Errorf("%w: attempt must reserve at least one resource", ErrInvalidRequest)
	}
	if request.Cost.Duration <= 0 {
		return fmt.Errorf("%w: attempt duration must be positive", ErrInvalidRequest)
	}
	if request.Cost.Duration > g.limits.MaxAttemptDuration {
		return &LimitError{
			Field:     "attempt_duration_ns",
			Requested: int64(request.Cost.Duration),
			Maximum:   int64(g.limits.MaxAttemptDuration),
		}
	}
	if field, current, maximum, exceeded := firstResourceExcess(request.Cost.Resources, g.limits.PerAttempt); exceeded {
		return &LimitError{
			Field:     "per_attempt_" + field,
			Requested: current,
			Maximum:   maximum,
		}
	}
	reserved := g.reserved.add(request.Cost.Resources)
	if field, current, maximum, exceeded := firstResourceExcess(reserved, g.limits.Aggregate); exceeded {
		return &LimitError{
			Field:     "aggregate_" + field,
			Requested: current,
			Maximum:   maximum,
		}
	}
	if request.Cost.Heavyweight && g.heavyweightAttempts >= g.limits.MaxHeavyweightAttempts {
		return &LimitError{
			Field:     "heavyweight_attempts",
			Requested: int64(g.heavyweightAttempts + 1),
			Maximum:   int64(g.limits.MaxHeavyweightAttempts),
		}
	}
	return nil
}

// Close cancels every active attempt for this peer and releases the peer slot.
func (p *PeerLease) Close() error {
	if p == nil || p.governor == nil {
		return nil
	}
	g := p.governor
	g.mu.Lock()
	if p.closed {
		g.mu.Unlock()
		return nil
	}
	p.closed = true
	attempts := make([]*AttemptLease, 0, len(p.attempts))
	for _, attempt := range p.attempts {
		attempts = append(attempts, attempt)
		g.beginAttemptStoppingLocked(attempt)
	}
	g.mu.Unlock()

	err := g.drainAttempts(attempts)
	g.mu.Lock()
	if g.peers[p.peerID] == p {
		delete(g.peers, p.peerID)
	}
	g.mu.Unlock()
	return err
}

// DrainHandle proves that one attempt-owned worker or I/O controller has
// registered for bounded cancellation. Complete is idempotent.
type DrainHandle interface {
	Complete() error
}

// AttemptLease is proof that a complete attempt cost has been reserved.
type AttemptLease struct {
	governor        *Governor
	peer            *PeerLease
	request         AttemptRequest
	stopping        chan struct{}
	drained         chan struct{}
	done            chan struct{}
	drains          map[uint64]*attemptDrain
	exclusiveClaims map[string]struct{}
	nextDrainID     uint64
	stoppingStarted bool
	drainedClosed   bool
	closed          bool
	closeErr        error
}

type attemptDrain struct {
	attempt *AttemptLease
	id      uint64
	name    string
	once    sync.Once
}

func (a *AttemptLease) Request() AttemptRequest {
	if a == nil {
		return AttemptRequest{}
	}
	return a.request
}

// PeerID returns the immutable peer identity bound to this attempt lease.
func (a *AttemptLease) PeerID() string {
	if a == nil || a.peer == nil {
		return ""
	}
	return a.peer.peerID
}

// ClaimExclusive consumes one named, attempt-lifetime capability before its
// adapter performs I/O. Claims never reset, including after an adapter drains,
// so a failed carrier cannot reconnect under the same reservation.
func (a *AttemptLease) ClaimExclusive(name string) error {
	if a == nil || a.governor == nil {
		return ErrLeaseClosed
	}
	if err := validateIdentifier("exclusive claim", name); err != nil {
		return err
	}
	g := a.governor
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.closing || a.closed || a.stoppingStarted {
		return ErrLeaseClosed
	}
	if _, used := a.exclusiveClaims[name]; used {
		return ErrExclusiveClaimUsed
	}
	a.exclusiveClaims[name] = struct{}{}
	return nil
}

// Trip asks the machine governor to enter its persistent fail-closed state.
// Peer and attempt identity are always taken from the lease so a downstream
// capability cannot attribute a trip to a different operation.
func (a *AttemptLease) Trip(event SafetyTripEvent) (SafetyTripStatus, error) {
	if a == nil || a.governor == nil {
		status := indeterminateSafetyTripStatus("attempt lease has no governor")
		return status, ErrLeaseClosed
	}
	event.PeerID = a.PeerID()
	event.AttemptID = a.request.ID
	if err := validateSafetyTripEvent(event); err != nil {
		return SafetyTripStatus{}, err
	}
	g := a.governor
	g.mu.Lock()
	defer g.mu.Unlock()
	if a.closed || a.stoppingStarted {
		return g.trip, ErrLeaseClosed
	}
	return g.tripLocked(event)
}

// RegisterDrain registers one attempt-owned worker or I/O controller that
// must finish after Stopping closes and before Done closes. Registration is
// rejected once cancellation begins.
func (a *AttemptLease) RegisterDrain(name string) (DrainHandle, error) {
	if a == nil || a.governor == nil {
		return nil, ErrLeaseClosed
	}
	if err := validateIdentifier("drain name", name); err != nil {
		return nil, err
	}
	g := a.governor
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.closing || a.closed || a.stoppingStarted {
		return nil, ErrLeaseClosed
	}
	if len(a.drains) >= maxAttemptDrainRegistrations {
		return nil, &LimitError{
			Field:     "attempt_drains",
			Requested: int64(len(a.drains) + 1),
			Maximum:   maxAttemptDrainRegistrations,
		}
	}
	a.nextDrainID++
	drain := &attemptDrain{attempt: a, id: a.nextDrainID, name: name}
	a.drains[drain.id] = drain
	return drain, nil
}

// Stopping closes at the start of cancellation while the governor still owns
// the machine namespace and retains authority to persist a timeout trip.
func (a *AttemptLease) Stopping() <-chan struct{} {
	if a == nil {
		return closedChannel()
	}
	return a.stopping
}

// Done closes only after registered drains complete or the governor has
// persisted a fail-closed timeout trip and forcibly revoked the attempt.
func (a *AttemptLease) Done() <-chan struct{} {
	if a == nil {
		return closedChannel()
	}
	return a.done
}

func (a *AttemptLease) Close() error {
	if a == nil || a.governor == nil {
		return nil
	}
	g := a.governor
	g.mu.Lock()
	if a.closed {
		err := a.closeErr
		g.mu.Unlock()
		return err
	}
	if a.stoppingStarted {
		done := a.done
		g.mu.Unlock()
		<-done
		g.mu.Lock()
		err := a.closeErr
		g.mu.Unlock()
		return err
	}
	g.beginAttemptStoppingLocked(a)
	g.mu.Unlock()
	return g.drainAttempts([]*AttemptLease{a})
}

func (drain *attemptDrain) Complete() error {
	if drain == nil || drain.attempt == nil || drain.attempt.governor == nil {
		return nil
	}
	drain.once.Do(func() {
		attempt := drain.attempt
		g := attempt.governor
		g.mu.Lock()
		if attempt.drains[drain.id] == drain {
			delete(attempt.drains, drain.id)
			if attempt.stoppingStarted && len(attempt.drains) == 0 {
				g.closeAttemptDrainedLocked(attempt)
			}
		}
		g.mu.Unlock()
	})
	return nil
}

func (g *Governor) drainAttempts(attempts []*AttemptLease) error {
	if len(attempts) == 0 {
		return nil
	}
	attempts = append([]*AttemptLease(nil), attempts...)
	sort.Slice(attempts, func(left, right int) bool {
		return attempts[left].request.ID < attempts[right].request.ID
	})

	g.mu.Lock()
	for _, attempt := range attempts {
		g.beginAttemptStoppingLocked(attempt)
	}
	timeout := g.limits.CancellationDrainTimeout
	g.mu.Unlock()

	timedOut := waitForAttemptDrains(attempts, timeout)
	var result error
	if timedOut != nil {
		g.mu.Lock()
		if !timedOut.closed && len(timedOut.drains) > 0 {
			pending := len(timedOut.drains)
			firstPending := g.firstPendingDrainNameLocked(timedOut)
			event := SafetyTripEvent{
				Reason:       SafetyTripCancellation,
				Detail:       fmt.Sprintf("attempt cancellation exceeded %s with %d pending drain(s); first=%s", timeout, pending, firstPending),
				PeerID:       timedOut.PeerID(),
				AttemptID:    timedOut.request.ID,
				BuildVersion: g.owner.Info().BuildVersion,
			}
			if err := validateSafetyTripEvent(event); err != nil {
				result = errors.Join(ErrCancellationDrainTimeout, err)
			} else {
				_, tripErr := g.tripLocked(event)
				result = errors.Join(ErrCancellationDrainTimeout, tripErr)
			}
		}
		g.mu.Unlock()
	}

	g.mu.Lock()
	for _, attempt := range attempts {
		if attempt.closeErr == nil {
			attempt.closeErr = result
		} else {
			result = errors.Join(result, attempt.closeErr)
		}
		g.releaseAttemptLocked(attempt)
	}
	g.mu.Unlock()
	return result
}

func (g *Governor) firstPendingDrainNameLocked(attempt *AttemptLease) string {
	if attempt == nil || len(attempt.drains) == 0 {
		return "unknown"
	}
	ids := make([]uint64, 0, len(attempt.drains))
	for id := range attempt.drains {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	return attempt.drains[ids[0]].name
}

func waitForAttemptDrains(attempts []*AttemptLease, timeout time.Duration) *AttemptLease {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for _, attempt := range attempts {
		select {
		case <-attempt.drained:
		case <-attempt.done:
		case <-timer.C:
			for _, candidate := range attempts {
				select {
				case <-candidate.drained:
					continue
				case <-candidate.done:
					continue
				default:
					return candidate
				}
			}
			return nil
		}
	}
	return nil
}

func (g *Governor) beginAttemptStoppingLocked(attempt *AttemptLease) {
	if attempt == nil || attempt.closed || attempt.stoppingStarted {
		return
	}
	attempt.stoppingStarted = true
	close(attempt.stopping)
	if len(attempt.drains) == 0 {
		g.closeAttemptDrainedLocked(attempt)
	}
}

func (g *Governor) closeAttemptDrainedLocked(attempt *AttemptLease) {
	if attempt == nil || attempt.drainedClosed {
		return
	}
	attempt.drainedClosed = true
	close(attempt.drained)
}

func (g *Governor) releaseAttemptLocked(attempt *AttemptLease) {
	if attempt == nil || attempt.closed {
		return
	}
	g.beginAttemptStoppingLocked(attempt)
	attempt.closed = true
	delete(g.attempts, attempt.request.ID)
	if attempt.peer != nil {
		delete(attempt.peer.attempts, attempt.request.ID)
	}
	g.reserved = g.reserved.subtract(attempt.request.Cost.Resources)
	if attempt.request.Cost.Heavyweight {
		g.heavyweightAttempts--
	}
	close(attempt.done)
}

func (g *Governor) activeAttemptsLocked() []*AttemptLease {
	attempts := make([]*AttemptLease, 0, len(g.attempts))
	for _, attempt := range g.attempts {
		attempts = append(attempts, attempt)
	}
	return attempts
}

// beginSafetyTripDrainLocked is invoked at the durable trip commit point. It
// synchronously revokes new capabilities, then lets registered controllers
// unwind outside the caller's I/O stack. The governor remains the timeout
// authority and retains the machine owner until Governor.Close completes.
func (g *Governor) beginSafetyTripDrainLocked() {
	attempts := g.activeAttemptsLocked()
	for _, attempt := range attempts {
		g.beginAttemptStoppingLocked(attempt)
	}
	if len(attempts) == 0 || g.tripDrainStarted {
		return
	}
	g.tripDrainStarted = true
	go g.finishSafetyTripDrain(attempts)
}

func (g *Governor) finishSafetyTripDrain(attempts []*AttemptLease) {
	_ = g.drainAttempts(attempts)
	g.mu.Lock()
	for peerID, peer := range g.peers {
		if len(peer.attempts) == 0 {
			peer.closed = true
			delete(g.peers, peerID)
		}
	}
	g.tripDrainStarted = false
	g.mu.Unlock()
}

func (g *Governor) stopActiveLocked() {
	for _, peer := range g.peers {
		for _, attempt := range peer.attempts {
			g.releaseAttemptLocked(attempt)
		}
		peer.closed = true
	}
	clear(g.peers)
	clear(g.attempts)
	g.reserved = Resources{}
	g.heavyweightAttempts = 0
}

func closedChannel() <-chan struct{} {
	closed := make(chan struct{})
	close(closed)
	return closed
}

func validateIdentifier(field, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidRequest, field)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidRequest, field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s has surrounding whitespace", ErrInvalidRequest, field)
	}
	if len(value) > 256 {
		return fmt.Errorf("%w: %s is too long", ErrInvalidRequest, field)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: %s contains a control character", ErrInvalidRequest, field)
	}
	return nil
}
