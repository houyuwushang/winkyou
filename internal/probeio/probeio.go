package probeio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"winkyou/internal/governor"
	"winkyou/pkg/transport"
)

const consecutiveWriteFailureLimit = 3

var (
	ErrInvalidConfig      = errors.New("probeio: invalid configuration")
	ErrLeaseClosed        = errors.New("probeio: attempt lease is closed")
	ErrSocketClosed       = errors.New("probeio: socket handle is closed")
	ErrUnregisteredTarget = errors.New("probeio: target is not registered")
	ErrInvalidTarget      = errors.New("probeio: invalid target")
	ErrReplyRejected      = errors.New("probeio: reply was rejected")
	ErrReplyNotVerified   = errors.New("probeio: no verified reply for target")
	ErrHardLimit          = errors.New("probeio: reserved hard limit exceeded")
	ErrResourceExhausted  = errors.New("probeio: operating system resource exhausted")
	ErrWriteFailures      = errors.New("probeio: consecutive write failure limit reached")
	ErrStaleGeneration    = errors.New("probeio: stale network generation")
	ErrInvalidGeneration  = errors.New("probeio: invalid network generation")
	ErrAlreadyPromoted    = errors.New("probeio: controller already promoted a socket")
	ErrDatagramContract   = errors.New("probeio: datagram implementation violated its contract")
)

// AttemptLease is the narrow governor capability required by probeio.
// *governor.AttemptLease implements this interface. Tests may provide a fake.
type AttemptLease interface {
	Request() governor.AttemptRequest
	PeerID() string
	Done() <-chan struct{}
	Close() error
	Trip(governor.SafetyTripEvent) (governor.SafetyTripStatus, error)
}

var _ AttemptLease = (*governor.AttemptLease)(nil)

// Datagram is an already-opened, context-aware datagram capability. It does
// not expose the underlying socket or descriptor. Implementations must allow
// Close to run concurrently with ReadFrom and WriteTo and unblock both calls.
type Datagram interface {
	ReadFrom(ctx context.Context, dst []byte) (n int, from netip.AddrPort, err error)
	WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (n int, err error)
	SetDeadline(deadline time.Time) error
	LocalAddr() net.Addr
	Close() error
}

// Factory creates exactly one Datagram for each successful OpenProbeSocket.
// No production implementation is included in this foundation slice.
type Factory interface {
	Open(ctx context.Context) (Datagram, error)
}

// GenerationSource lets every active operation reject handles created for an
// obsolete network observation generation.
type GenerationSource interface {
	CurrentGeneration() uint64
}

// Generation is a monotonic, race-safe GenerationSource.
type Generation struct {
	value atomic.Uint64
}

func NewGeneration(initial uint64) *Generation {
	generation := &Generation{}
	generation.value.Store(initial)
	return generation
}

func (g *Generation) CurrentGeneration() uint64 {
	if g == nil {
		return 0
	}
	return g.value.Load()
}

// Advance changes the current generation exactly once and never permits a
// rollback or reuse of an earlier generation number.
func (g *Generation) Advance(next uint64) error {
	if g == nil {
		return ErrInvalidGeneration
	}
	for {
		current := g.value.Load()
		if next <= current {
			return fmt.Errorf("%w: current=%d next=%d", ErrInvalidGeneration, current, next)
		}
		if g.value.CompareAndSwap(current, next) {
			return nil
		}
	}
}

// Timer is the minimum timer surface needed for the attempt-duration guard.
// It is injectable so tests never wait for wall-clock deadlines.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

type realTimer struct {
	timer *time.Timer
}

func (timer realTimer) C() <-chan time.Time { return timer.timer.C }
func (timer realTimer) Stop() bool          { return timer.timer.Stop() }

// Config binds one controller to one fully reserved attempt and one network
// generation. ResourceExhausted may add platform-specific classification such
// as Windows WSAENOBUFS; ErrResourceExhausted is always recognized.
type Config struct {
	Lease              AttemptLease
	Generation         GenerationSource
	ExpectedGeneration uint64
	Factory            Factory
	Now                func() time.Time
	NewTimer           func(time.Duration) Timer
	ResourceExhausted  func(error) bool
	BuildVersion       string
}

// Controller owns all probe sockets, target registrations, counters, and the
// single promotion decision for one attempt.
type Controller struct {
	mu sync.Mutex

	lease              AttemptLease
	generation         GenerationSource
	expectedGeneration uint64
	factory            Factory
	now                func() time.Time
	newTimer           func(time.Duration) Timer
	resourceExhausted  func(error) bool
	buildVersion       string
	request            governor.AttemptRequest
	startedAt          time.Time

	stopped     bool
	tripping    bool
	promoted    bool
	pending     int
	nextID      uint64
	sockets     map[uint64]*socketState
	targetRefs  map[netip.AddrPort]int
	fiveTuples  int
	packetsSent int
	sendTimes   []time.Time
	lastNow     time.Time

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	watchDone       chan struct{}
}

type socketLifecycle uint8

const (
	socketOpen socketLifecycle = iota
	socketPromoting
	socketPromoted
	socketClosed
)

type socketState struct {
	id         uint64
	datagram   Datagram
	state      socketLifecycle
	targets    map[netip.AddrPort]struct{}
	verified   map[netip.AddrPort]struct{}
	writeFails int
	ctx        context.Context
	cancel     context.CancelFunc
	ops        sync.WaitGroup
}

// ProbeSocket is a revocable handle. It never exposes its Datagram.
type ProbeSocket struct {
	controller *Controller
	state      *socketState
}

// ReplyVerifier authenticates and validates one reply before it can authorize
// promotion. The byte slice is only valid for the duration of the callback.
type ReplyVerifier func(packet []byte, from netip.AddrPort) error

// Promotion is the immutable result of a successful one-time handoff.
type Promotion struct {
	PeerID     string
	AttemptID  string
	Generation uint64
	Target     netip.AddrPort
	Transport  transport.PacketTransport
}

// New creates a controller and starts one lifecycle watcher. It never opens a
// socket; OpenProbeSocket is the only Factory call site.
func New(config Config) (*Controller, error) {
	if config.Lease == nil || config.Generation == nil || config.Factory == nil {
		return nil, fmt.Errorf("%w: lease, generation, and factory are required", ErrInvalidConfig)
	}
	request := config.Lease.Request()
	if request.Operation != governor.OperationDiagnose && request.Operation != governor.OperationConnectTest {
		return nil, fmt.Errorf("%w: operation %q cannot probe", ErrInvalidConfig, request.Operation)
	}
	if request.Cost.Duration <= 0 {
		return nil, fmt.Errorf("%w: attempt duration must be positive", ErrInvalidConfig)
	}
	if err := validateResources(request.Cost.Resources); err != nil {
		return nil, err
	}
	if config.Generation.CurrentGeneration() != config.ExpectedGeneration {
		return nil, fmt.Errorf("%w: expected=%d current=%d", ErrStaleGeneration, config.ExpectedGeneration, config.Generation.CurrentGeneration())
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	newTimer := config.NewTimer
	if newTimer == nil {
		newTimer = func(duration time.Duration) Timer {
			return realTimer{timer: time.NewTimer(duration)}
		}
	}
	classifier := config.ResourceExhausted
	if classifier == nil {
		classifier = func(err error) bool { return errors.Is(err, ErrResourceExhausted) }
	}
	buildVersion, err := normalizeBuildVersion(config.BuildVersion)
	if err != nil {
		return nil, err
	}
	startedAt := now()
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	controller := &Controller{
		lease:              config.Lease,
		generation:         config.Generation,
		expectedGeneration: config.ExpectedGeneration,
		factory:            config.Factory,
		now:                now,
		newTimer:           newTimer,
		resourceExhausted:  classifier,
		buildVersion:       buildVersion,
		request:            request,
		startedAt:          startedAt,
		sockets:            make(map[uint64]*socketState),
		targetRefs:         make(map[netip.AddrPort]int),
		lastNow:            startedAt,
		lifecycleCtx:       lifecycleCtx,
		lifecycleCancel:    lifecycleCancel,
		watchDone:          make(chan struct{}),
	}
	go controller.watchLifecycle()
	return controller, nil
}

func validateResources(resources governor.Resources) error {
	if resources.Sockets < 0 || resources.Targets < 0 || resources.PacketsPerSecond < 0 || resources.Packets < 0 || resources.FiveTuples < 0 {
		return fmt.Errorf("%w: resource reservation contains a negative value", ErrInvalidConfig)
	}
	if resources == (governor.Resources{}) {
		return fmt.Errorf("%w: resource reservation is empty", ErrInvalidConfig)
	}
	return nil
}

func (c *Controller) watchLifecycle() {
	timer := c.newTimer(c.request.Cost.Duration)
	if timer == nil || timer.C() == nil {
		_ = c.trip(governor.SafetyTripHardLimit, "attempt duration timer unavailable", ErrHardLimit)
		close(c.watchDone)
		return
	}
	defer func() {
		timer.Stop()
		close(c.watchDone)
	}()
	select {
	case <-c.lease.Done():
		c.stopLocal()
	case <-timer.C():
		_ = c.trip(governor.SafetyTripHardLimit, "attempt duration budget exhausted", ErrHardLimit)
	}
}

// OpenProbeSocket consumes one concurrently reserved socket slot. Factory is
// called only after all lease, generation, duration, and budget checks pass.
func (c *Controller) OpenProbeSocket(ctx context.Context) (*ProbeSocket, error) {
	if c == nil {
		return nil, ErrLeaseClosed
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	violation := c.guardViolationLocked(c.now())
	if violation == nil && len(c.sockets)+c.pending >= c.request.Cost.Resources.Sockets {
		violation = &safetyViolation{reason: governor.SafetyTripHardLimit, detail: "socket reservation exceeded", cause: ErrHardLimit}
	}
	if violation == nil {
		c.pending++
	}
	c.mu.Unlock()
	if violation != nil {
		return nil, c.handleViolation(violation)
	}

	openCtx, cancelOpen := mergeContext(ctx, c.lifecycleCtx)
	datagram, openErr := c.factory.Open(openCtx)
	cancelOpen()
	c.mu.Lock()
	c.pending--
	postViolation := c.guardViolationLocked(c.now())
	if openErr == nil && datagram == nil {
		openErr = fmt.Errorf("%w: factory returned a nil datagram", ErrInvalidConfig)
	}
	if openErr == nil && postViolation == nil {
		c.nextID++
		socketCtx, cancel := context.WithCancel(context.Background())
		state := &socketState{
			id:       c.nextID,
			datagram: datagram,
			state:    socketOpen,
			targets:  make(map[netip.AddrPort]struct{}),
			verified: make(map[netip.AddrPort]struct{}),
			ctx:      socketCtx,
			cancel:   cancel,
		}
		c.sockets[state.id] = state
		c.mu.Unlock()
		return &ProbeSocket{controller: c, state: state}, nil
	}
	c.mu.Unlock()
	if datagram != nil {
		_ = datagram.Close()
	}
	if postViolation != nil {
		return nil, c.handleViolation(postViolation)
	}
	if c.resourceExhausted(openErr) {
		return nil, c.trip(governor.SafetyTripResourceExhausted, "opening probe socket exhausted an operating-system resource", errors.Join(ErrResourceExhausted, openErr))
	}
	return nil, openErr
}

// RegisterTarget authorizes one canonical remote endpoint for this socket.
// Unique endpoints and socket/endpoint five-tuples are counted separately.
func (socket *ProbeSocket) RegisterTarget(target netip.AddrPort) error {
	canonical, err := canonicalTarget(target)
	if err != nil {
		return err
	}
	c, state, err := socket.parts()
	if err != nil {
		return err
	}
	c.mu.Lock()
	violation := c.guardViolationLocked(c.now())
	if violation == nil && state.state != socketOpen {
		c.mu.Unlock()
		return ErrSocketClosed
	}
	if violation == nil {
		if _, exists := state.targets[canonical]; exists {
			c.mu.Unlock()
			return nil
		}
		if c.targetRefs[canonical] == 0 && len(c.targetRefs) >= c.request.Cost.Resources.Targets {
			violation = &safetyViolation{reason: governor.SafetyTripHardLimit, detail: "target reservation exceeded", cause: ErrHardLimit}
		} else if c.fiveTuples >= c.request.Cost.Resources.FiveTuples {
			violation = &safetyViolation{reason: governor.SafetyTripHardLimit, detail: "five-tuple reservation exceeded", cause: ErrHardLimit}
		}
	}
	if violation == nil {
		state.targets[canonical] = struct{}{}
		c.targetRefs[canonical]++
		c.fiveTuples++
	}
	c.mu.Unlock()
	if violation != nil {
		return c.handleViolation(violation)
	}
	return nil
}

// SendProbe sends only to a registered target and accounts the attempt before
// entering the Datagram implementation. Failed writes still consume packet
// and PPS budget because they are real send attempts.
func (socket *ProbeSocket) SendProbe(ctx context.Context, target netip.AddrPort, packet []byte) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	canonical, err := canonicalTarget(target)
	if err != nil {
		return err
	}
	c, state, err := socket.parts()
	if err != nil {
		return err
	}

	c.mu.Lock()
	violation := c.guardViolationLocked(c.now())
	if violation == nil && state.state != socketOpen {
		c.mu.Unlock()
		return ErrSocketClosed
	}
	if violation == nil {
		if _, registered := state.targets[canonical]; !registered {
			c.mu.Unlock()
			return ErrUnregisteredTarget
		}
		violation = c.reserveSendLocked(c.now())
	}
	if violation == nil {
		state.ops.Add(1)
	}
	c.mu.Unlock()
	if violation != nil {
		return c.handleViolation(violation)
	}

	opCtx, cancel := mergeContext(ctx, state.ctx)
	n, writeErr := state.datagram.WriteTo(opCtx, packet, canonical)
	cancel()
	state.ops.Done()
	if writeErr == nil && n != len(packet) {
		writeErr = errors.Join(io.ErrShortWrite, ErrDatagramContract)
	}
	if writeErr == nil {
		c.mu.Lock()
		if state.state == socketOpen {
			state.writeFails = 0
		}
		c.mu.Unlock()
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if state.ctx.Err() != nil {
		return ErrLeaseClosed
	}
	if c.resourceExhausted(writeErr) {
		return c.trip(governor.SafetyTripResourceExhausted, "probe write exhausted an operating-system resource", errors.Join(ErrResourceExhausted, writeErr))
	}

	c.mu.Lock()
	if state.state == socketOpen {
		state.writeFails++
	}
	failures := state.writeFails
	c.mu.Unlock()
	if failures >= consecutiveWriteFailureLimit {
		return c.trip(governor.SafetyTripWriteFailures, fmt.Sprintf("probe socket reached %d consecutive write failures", failures), errors.Join(ErrWriteFailures, writeErr))
	}
	return writeErr
}

// ReceiveReply reads one datagram and runs the caller's authentication check.
// Only a registered, verifier-approved endpoint becomes eligible for Promote.
func (socket *ProbeSocket) ReceiveReply(ctx context.Context, dst []byte, verify ReplyVerifier) (int, netip.AddrPort, error) {
	if ctx == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if verify == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: reply verifier is required", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return 0, netip.AddrPort{}, err
	}
	c, state, err := socket.parts()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	c.mu.Lock()
	violation := c.guardViolationLocked(c.now())
	if violation == nil && state.state != socketOpen {
		c.mu.Unlock()
		return 0, netip.AddrPort{}, ErrSocketClosed
	}
	if violation == nil {
		state.ops.Add(1)
	}
	c.mu.Unlock()
	if violation != nil {
		return 0, netip.AddrPort{}, c.handleViolation(violation)
	}
	defer state.ops.Done()

	opCtx, cancel := mergeContext(ctx, state.ctx)
	defer cancel()
	n, from, readErr := state.datagram.ReadFrom(opCtx, dst)
	if readErr != nil {
		if ctx.Err() != nil {
			return 0, netip.AddrPort{}, ctx.Err()
		}
		if state.ctx.Err() != nil {
			return 0, netip.AddrPort{}, ErrLeaseClosed
		}
		return 0, netip.AddrPort{}, readErr
	}
	if n < 0 || n > len(dst) {
		return 0, netip.AddrPort{}, ErrDatagramContract
	}
	canonical, err := canonicalTarget(from)
	if err != nil {
		return n, from, err
	}
	c.mu.Lock()
	_, registered := state.targets[canonical]
	stillOpen := state.state == socketOpen && !c.stopped && !c.tripping
	c.mu.Unlock()
	if !registered {
		return n, canonical, ErrUnregisteredTarget
	}
	if !stillOpen {
		return n, canonical, ErrLeaseClosed
	}
	if err := verify(dst[:n], canonical); err != nil {
		return n, canonical, errors.Join(ErrReplyRejected, err)
	}
	c.mu.Lock()
	if state.state != socketOpen || c.stopped || c.tripping {
		c.mu.Unlock()
		return n, canonical, ErrLeaseClosed
	}
	state.verified[canonical] = struct{}{}
	c.mu.Unlock()
	return n, canonical, nil
}

// Promote transfers exactly one verified socket to a fixed-target
// PacketTransport, clears probe deadlines, revokes the old ProbeSocket, closes
// every sibling socket, and releases the attempt lease.
func (socket *ProbeSocket) Promote(target netip.AddrPort, pathID string) (Promotion, error) {
	canonical, err := canonicalTarget(target)
	if err != nil {
		return Promotion{}, err
	}
	if err := validateText("path id", pathID, 256, false); err != nil {
		return Promotion{}, err
	}
	c, state, err := socket.parts()
	if err != nil {
		return Promotion{}, err
	}

	c.mu.Lock()
	violation := c.guardViolationLocked(c.now())
	if violation == nil && c.promoted {
		c.mu.Unlock()
		return Promotion{}, ErrAlreadyPromoted
	}
	if violation == nil && state.state != socketOpen {
		c.mu.Unlock()
		return Promotion{}, ErrSocketClosed
	}
	if violation == nil {
		if _, registered := state.targets[canonical]; !registered {
			c.mu.Unlock()
			return Promotion{}, ErrUnregisteredTarget
		}
		if _, verified := state.verified[canonical]; !verified {
			c.mu.Unlock()
			return Promotion{}, ErrReplyNotVerified
		}
		state.state = socketPromoting
		state.cancel()
	}
	c.mu.Unlock()
	if violation != nil {
		return Promotion{}, c.handleViolation(violation)
	}

	state.ops.Wait()
	if err := state.datagram.SetDeadline(time.Time{}); err != nil {
		c.closeSocketState(state)
		return Promotion{}, fmt.Errorf("probeio: clear probe deadline: %w", err)
	}

	c.mu.Lock()
	violation = c.guardViolationLocked(c.now())
	if violation != nil || state.state != socketPromoting {
		c.mu.Unlock()
		c.closeSocketState(state)
		if violation != nil {
			return Promotion{}, c.handleViolation(violation)
		}
		return Promotion{}, ErrLeaseClosed
	}
	state.state = socketPromoted
	c.promoted = true
	c.stopped = true
	c.lifecycleCancel()
	delete(c.sockets, state.id)
	c.releaseTargetsLocked(state)
	siblings := c.detachOpenSocketsLocked()
	c.mu.Unlock()
	c.closeStates(siblings)

	if err := c.lease.Close(); err != nil {
		_ = state.datagram.Close()
		return Promotion{}, err
	}
	return Promotion{
		PeerID:     c.lease.PeerID(),
		AttemptID:  c.request.ID,
		Generation: c.expectedGeneration,
		Target:     canonical,
		Transport:  newPromotedTransport(state.datagram, canonical, pathID),
	}, nil
}

// Close revokes this socket without releasing sibling sockets or the attempt.
func (socket *ProbeSocket) Close() error {
	c, state, err := socket.parts()
	if err != nil {
		return err
	}
	c.mu.Lock()
	if state.state == socketPromoted {
		c.mu.Unlock()
		return ErrLeaseClosed
	}
	if state.state != socketOpen {
		c.mu.Unlock()
		return ErrSocketClosed
	}
	state.state = socketClosed
	delete(c.sockets, state.id)
	c.releaseTargetsLocked(state)
	state.cancel()
	c.mu.Unlock()
	_ = state.datagram.Close()
	state.ops.Wait()
	return nil
}

// Poison enters the persistent machine trip state for a reviewed reason.
func (c *Controller) Poison(reason governor.SafetyTripReason, detail string) error {
	if c == nil {
		return ErrLeaseClosed
	}
	if !validSafetyTripReason(reason) {
		return fmt.Errorf("%w: unsupported safety trip reason %q", ErrInvalidConfig, reason)
	}
	return c.trip(reason, detail, nil)
}

// Close stops all non-promoted sockets and releases the attempt. A promoted
// transport has independent ownership and is never closed by Controller.Close.
func (c *Controller) Close() error {
	if c == nil {
		return nil
	}
	c.stopLocal()
	err := c.lease.Close()
	<-c.watchDone
	return err
}

type safetyViolation struct {
	reason governor.SafetyTripReason
	detail string
	cause  error
}

func (violation *safetyViolation) Error() string { return violation.cause.Error() }

func (c *Controller) guardViolationLocked(now time.Time) *safetyViolation {
	if c.stopped || c.tripping {
		return &safetyViolation{cause: ErrLeaseClosed}
	}
	select {
	case <-c.lease.Done():
		return &safetyViolation{cause: ErrLeaseClosed}
	default:
	}
	current := c.generation.CurrentGeneration()
	if current != c.expectedGeneration {
		return &safetyViolation{
			reason: governor.SafetyTripStaleGeneration,
			detail: fmt.Sprintf("active probe generation=%d current=%d", c.expectedGeneration, current),
			cause:  ErrStaleGeneration,
		}
	}
	if now.Before(c.lastNow) {
		return &safetyViolation{reason: governor.SafetyTripHardLimit, detail: "probe budget clock moved backwards", cause: ErrHardLimit}
	}
	c.lastNow = now
	if !now.Before(c.startedAt.Add(c.request.Cost.Duration)) {
		return &safetyViolation{reason: governor.SafetyTripHardLimit, detail: "attempt duration budget exhausted", cause: ErrHardLimit}
	}
	return nil
}

func (c *Controller) reserveSendLocked(now time.Time) *safetyViolation {
	resources := c.request.Cost.Resources
	if c.packetsSent >= resources.Packets {
		return &safetyViolation{reason: governor.SafetyTripHardLimit, detail: "total outbound packet reservation exceeded", cause: ErrHardLimit}
	}
	cutoff := now.Add(-time.Second)
	first := 0
	for first < len(c.sendTimes) && !c.sendTimes[first].After(cutoff) {
		first++
	}
	if first > 0 {
		c.sendTimes = append(c.sendTimes[:0], c.sendTimes[first:]...)
	}
	if len(c.sendTimes) >= resources.PacketsPerSecond {
		return &safetyViolation{reason: governor.SafetyTripHardLimit, detail: "outbound packets-per-second reservation exceeded", cause: ErrHardLimit}
	}
	c.packetsSent++
	c.sendTimes = append(c.sendTimes, now)
	return nil
}

func (c *Controller) handleViolation(violation *safetyViolation) error {
	if violation == nil {
		return nil
	}
	if violation.reason == "" {
		return violation.cause
	}
	return c.trip(violation.reason, violation.detail, violation.cause)
}

func (c *Controller) trip(reason governor.SafetyTripReason, detail string, cause error) error {
	detail = boundedDetail(detail)
	c.mu.Lock()
	if c.stopped || c.tripping {
		c.mu.Unlock()
		if cause != nil {
			return errors.Join(cause, ErrLeaseClosed)
		}
		return ErrLeaseClosed
	}
	c.tripping = true
	c.mu.Unlock()

	_, tripErr := c.lease.Trip(governor.SafetyTripEvent{
		Reason:       reason,
		Detail:       detail,
		BuildVersion: c.buildVersion,
	})
	c.stopLocal()
	return errors.Join(cause, tripErr)
}

func boundedDetail(detail string) string {
	if !utf8.ValidString(detail) {
		detail = strings.ToValidUTF8(detail, "?")
	}
	detail = strings.Map(func(current rune) rune {
		if unicode.IsControl(current) {
			return ' '
		}
		return current
	}, detail)
	detail = strings.TrimSpace(detail)
	const maxBytes = 512
	if len(detail) <= maxBytes {
		return detail
	}
	for len(detail) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(detail)
		detail = detail[:len(detail)-size]
	}
	return detail
}

func (c *Controller) stopLocal() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.lifecycleCancel()
	states := c.detachOpenSocketsLocked()
	c.mu.Unlock()
	c.closeStates(states)
}

func (c *Controller) detachOpenSocketsLocked() []*socketState {
	states := make([]*socketState, 0, len(c.sockets))
	for id, state := range c.sockets {
		if state.state == socketPromoted {
			continue
		}
		state.state = socketClosed
		state.cancel()
		c.releaseTargetsLocked(state)
		delete(c.sockets, id)
		states = append(states, state)
	}
	return states
}

func (c *Controller) releaseTargetsLocked(state *socketState) {
	for target := range state.targets {
		if c.targetRefs[target] <= 1 {
			delete(c.targetRefs, target)
		} else {
			c.targetRefs[target]--
		}
		if c.fiveTuples > 0 {
			c.fiveTuples--
		}
	}
	clear(state.targets)
	clear(state.verified)
}

func (c *Controller) closeSocketState(state *socketState) {
	if state == nil {
		return
	}
	c.mu.Lock()
	if state.state != socketPromoted {
		state.state = socketClosed
		delete(c.sockets, state.id)
		c.releaseTargetsLocked(state)
		state.cancel()
	}
	c.mu.Unlock()
	_ = state.datagram.Close()
	state.ops.Wait()
}

func (c *Controller) closeStates(states []*socketState) {
	for _, state := range states {
		_ = state.datagram.Close()
	}
	for _, state := range states {
		state.ops.Wait()
	}
}

func (socket *ProbeSocket) parts() (*Controller, *socketState, error) {
	if socket == nil || socket.controller == nil || socket.state == nil {
		return nil, nil, ErrSocketClosed
	}
	return socket.controller, socket.state, nil
}

func canonicalTarget(target netip.AddrPort) (netip.AddrPort, error) {
	if !target.IsValid() || target.Port() == 0 || target.Addr().IsUnspecified() || target.Addr().IsMulticast() {
		return netip.AddrPort{}, ErrInvalidTarget
	}
	canonical := netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if canonical.Addr() == netip.IPv4Unspecified() || canonical.Addr() == netip.MustParseAddr("255.255.255.255") {
		return netip.AddrPort{}, ErrInvalidTarget
	}
	return canonical, nil
}

func normalizeBuildVersion(value string) (string, error) {
	if err := validateText("build version", value, 128, true); err != nil {
		return "", err
	}
	return value, nil
}

func validateText(field, value string, maxBytes int, allowEmpty bool) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidConfig, field)
	}
	if !allowEmpty && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidConfig, field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s has surrounding whitespace", ErrInvalidConfig, field)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("%w: %s is too long", ErrInvalidConfig, field)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: %s contains a control character", ErrInvalidConfig, field)
	}
	return nil
}

func validSafetyTripReason(reason governor.SafetyTripReason) bool {
	switch reason {
	case governor.SafetyTripResourceExhausted,
		governor.SafetyTripWriteFailures,
		governor.SafetyTripHardLimit,
		governor.SafetyTripCancellation,
		governor.SafetyTripStaleGeneration,
		governor.SafetyTripOperator:
		return true
	default:
		return false
	}
}

func mergeContext(parent, lifecycle context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(lifecycle, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

type promotedTransport struct {
	datagram  Datagram
	target    netip.AddrPort
	pathID    string
	closeOnce sync.Once
	closeErr  error
}

func newPromotedTransport(datagram Datagram, target netip.AddrPort, pathID string) transport.PacketTransport {
	return &promotedTransport{datagram: datagram, target: target, pathID: pathID}
}

func (promoted *promotedTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	if ctx == nil {
		return 0, transport.PacketMeta{}, fmt.Errorf("probeio: context is nil")
	}
	n, from, err := promoted.datagram.ReadFrom(ctx, dst)
	if err != nil {
		return 0, transport.PacketMeta{}, err
	}
	if n < 0 || n > len(dst) {
		return 0, transport.PacketMeta{}, ErrDatagramContract
	}
	canonical, canonicalErr := canonicalTarget(from)
	if canonicalErr != nil || canonical != promoted.target {
		return n, transport.PacketMeta{}, ErrUnregisteredTarget
	}
	return n, transport.PacketMeta{ReceivedAt: time.Now(), PathID: promoted.pathID}, nil
}

func (promoted *promotedTransport) WritePacket(ctx context.Context, packet []byte) error {
	if ctx == nil {
		return fmt.Errorf("probeio: context is nil")
	}
	n, err := promoted.datagram.WriteTo(ctx, packet, promoted.target)
	if err == nil && n != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func (promoted *promotedTransport) LocalAddr() net.Addr {
	return promoted.datagram.LocalAddr()
}

func (promoted *promotedTransport) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(promoted.target)
}

func (promoted *promotedTransport) Close() error {
	promoted.closeOnce.Do(func() {
		promoted.closeErr = promoted.datagram.Close()
	})
	return promoted.closeErr
}
