package governor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrGovernorClosed   = errors.New("governor is closed")
	ErrLeaseClosed      = errors.New("governor lease is closed")
	ErrDuplicatePeer    = errors.New("peer already has an active lease")
	ErrDuplicateAttempt = errors.New("attempt id is already active")
	ErrInvalidRequest   = errors.New("invalid governor request")
)

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

	owner   *Owner
	profile Profile
	scope   Scope
	limits  Limits
	trip    SafetyTripStatus
	closed  bool

	peers               map[string]*PeerLease
	attempts            map[string]*AttemptLease
	reserved            Resources
	heavyweightAttempts int
}

// New constructs a governor and takes lifecycle ownership of owner on success.
// requested may be nil to use the compiled profile ceiling. A non-nil value can
// only lower that ceiling.
func New(owner *Owner, profile Profile, requested *Limits) (*Governor, error) {
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
		owner:    owner,
		profile:  profile,
		scope:    scope,
		limits:   limits,
		trip:     trip,
		peers:    make(map[string]*PeerLease),
		attempts: make(map[string]*AttemptLease),
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
	if g.closed {
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
		Closed:              g.closed,
	}
}

// Close closes every child lease, releases all reservations, and finally
// releases the process-independent namespace owner. It is idempotent.
func (g *Governor) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.stopActiveLocked()
	owner := g.owner
	g.mu.Unlock()
	return owner.closeClaimed()
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
	if g.closed || p.closed {
		g.mu.Unlock()
		return nil, ErrLeaseClosed
	}
	if err := g.validateAttemptLocked(p, request); err != nil {
		g.mu.Unlock()
		return nil, err
	}

	lease := &AttemptLease{
		governor: g,
		peer:     p,
		request:  request,
		done:     make(chan struct{}),
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

// Trip commits the persistent blocking latch, closes every active attempt at
// that commit point, and then persists the diagnostic record. A failed detail
// write leaves both the in-process governor and durable latch blocking work.
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
	if g.closed {
		return g.trip, ErrGovernorClosed
	}
	if g.trip.BlocksActiveWork {
		g.stopActiveLocked()
		return g.trip, nil
	}
	status, err := g.owner.tripStore.tripThen(event, g.stopActiveLocked)
	g.trip = status
	if !g.trip.BlocksActiveWork {
		g.trip = indeterminateSafetyTripStatus("trip operation did not produce a blocking state")
		if err == nil {
			err = &SafetyTripError{Status: g.trip}
		}
	}
	g.stopActiveLocked()
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
	defer g.mu.Unlock()
	if p.closed {
		return nil
	}
	for _, attempt := range p.attempts {
		g.releaseAttemptLocked(attempt)
	}
	p.closed = true
	delete(g.peers, p.peerID)
	return nil
}

// AttemptLease is proof that a complete attempt cost has been reserved.
type AttemptLease struct {
	governor *Governor
	peer     *PeerLease
	request  AttemptRequest
	done     chan struct{}
	closed   bool
}

func (a *AttemptLease) Request() AttemptRequest {
	if a == nil {
		return AttemptRequest{}
	}
	return a.request
}

// Done is closed when the lease is released by Close, peer/governor shutdown,
// or context cancellation.
func (a *AttemptLease) Done() <-chan struct{} {
	if a == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return a.done
}

func (a *AttemptLease) Close() error {
	if a == nil || a.governor == nil {
		return nil
	}
	g := a.governor
	g.mu.Lock()
	defer g.mu.Unlock()
	g.releaseAttemptLocked(a)
	return nil
}

func (g *Governor) releaseAttemptLocked(attempt *AttemptLease) {
	if attempt == nil || attempt.closed {
		return
	}
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
