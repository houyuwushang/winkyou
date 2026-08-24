package rendezvouscarrier

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
)

type DeploymentTier string

const (
	DeploymentSelfHosted   DeploymentTier = "self_hosted"
	DeploymentMinimumTrust DeploymentTier = "minimum_trust"
)

func (tier DeploymentTier) valid() bool {
	return tier == DeploymentSelfHosted || tier == DeploymentMinimumTrust
}

type PresenceSlot string

const (
	PresenceSlotA PresenceSlot = "a"
	PresenceSlotB PresenceSlot = "b"
)

func (slot PresenceSlot) valid() bool { return slot == PresenceSlotA || slot == PresenceSlotB }
func (slot PresenceSlot) code() byte {
	if slot == PresenceSlotA {
		return 1
	}
	if slot == PresenceSlotB {
		return 2
	}
	return 0
}
func slotFromCode(code byte) PresenceSlot {
	if code == 1 {
		return PresenceSlotA
	}
	if code == 2 {
		return PresenceSlotB
	}
	return ""
}

var (
	ErrInvalidConfig      = errors.New("rendezvouscarrier: invalid configuration")
	ErrTargetForbidden    = errors.New("rendezvouscarrier: endpoint is not authorized")
	ErrPresenceTimeout    = errors.New("rendezvouscarrier: peer presence timed out")
	ErrBurnRequired       = errors.New("rendezvouscarrier: durable admission is required")
	ErrPreBurnSecureFrame = errors.New("rendezvouscarrier: secure frame arrived before durable admission")
	ErrCarrierDomain      = errors.New("rendezvouscarrier: authenticated frame arrived on the wrong carrier")
	ErrCarrierTerminal    = errors.New("rendezvouscarrier: terminal")
	ErrCarrierTransport   = errors.New("rendezvouscarrier: transport failure")
	ErrHandshakeOrder     = errors.New("rendezvouscarrier: handshake ordering violation")
)

// attemptLease is deliberately narrower than probeio.AttemptLease. It exists
// only so package tests can inject deterministic drain failures. The public
// Config boundary accepts only *governor.AttemptLease.
type attemptLease interface {
	Request() governor.AttemptRequest
	ClaimExclusive(string) error
	Stopping() <-chan struct{}
	RegisterDrain(string) (governor.DrainHandle, error)
}

var _ attemptLease = (*governor.AttemptLease)(nil)

const carrierClaimName = "n2-rendezvous-carrier"

// emissionAuthorization is retained only to let package tests exercise
// transport failures without constructing durable machine state. The public
// boundary accepts only governor.CommittedCarrierAuthorization.
type emissionAuthorization interface {
	BeforeFirstEmission(context.Context) error
	CheckActive(context.Context) error
}

var _ emissionAuthorization = (*governor.CommittedCarrierAuthorization)(nil)

// endpointResolver is injectable only from package tests. Production callers
// cannot replace the exact one-call resolver with an ungoverned implementation.
type endpointResolver interface {
	Resolve(context.Context, string, string) ([]netip.Addr, error)
}

// AllowedTargetScope is only an address-class check; it does not bypass the
// disconnected architecture gate or authorize a product/live-network caller.
// The zero value remains literal loopback. The unicast value is reserved for
// a separately reviewed N2d namespace harness.
type AllowedTargetScope uint8

const (
	AllowedTargetLoopback AllowedTargetScope = iota
	AllowedTargetIsolatedUnicast
)

func (scope AllowedTargetScope) valid() bool {
	return scope == AllowedTargetLoopback || scope == AllowedTargetIsolatedUnicast
}

func (scope AllowedTargetScope) allows(endpoint netip.AddrPort) bool {
	switch scope {
	case AllowedTargetLoopback:
		return endpoint.Addr().IsLoopback()
	case AllowedTargetIsolatedUnicast:
		return endpoint.Addr().IsGlobalUnicast() && !endpoint.Addr().IsLoopback()
	default:
		return false
	}
}

type Config struct {
	Lease              *governor.AttemptLease
	Endpoint           string
	Tier               DeploymentTier
	AssociationID      string
	Slot               PresenceSlot
	Role               directattempt.Role
	AllowedTargetScope AllowedTargetScope
	PresenceDeadline   time.Duration
	OperationDeadline  time.Duration

	testLease attemptLease
	resolver  endpointResolver
}

type Witness struct {
	Tier            DeploymentTier
	Connections     int
	DNSResolutions  int
	FramesRead      int
	FramesWritten   int
	BytesRead       int
	BytesWritten    int
	DrainRegistered bool
	Drained         bool
	Closed          bool
}

type carrierState uint8

const (
	statePreconnected carrierState = iota
	statePresent
	stateActive
	stateHandshakeComplete
	stateClosed
)

type Carrier struct {
	mu      sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex

	conn             net.Conn
	lease            attemptLease
	drain            governor.DrainHandle
	authorization    emissionAuthorization
	tier             DeploymentTier
	role             directattempt.Role
	state            carrierState
	presenceLimit    time.Duration
	operationLimit   time.Duration
	expiresAt        time.Time
	framesRead       int
	framesWritten    int
	bytesRead        int
	bytesWritten     int
	dnsLookups       int
	handshakeSent    bool
	handshakeRead    bool
	handshakeSending bool
	handshakeReading bool
	drainComplete    bool
	closeErr         error

	closed    chan struct{}
	drained   chan struct{}
	watchDone chan struct{}
	closeOnce sync.Once
	drainOnce sync.Once
	ops       sync.WaitGroup
}

// Dial performs exactly one preconnect and emits only the fixed, secret-free
// presence envelope. It never retries. Successful return does not authorize a
// secure-channel byte.
func Dial(ctx context.Context, config Config) (*Carrier, error) {
	var lease attemptLease
	if config.Lease != nil {
		lease = config.Lease
	} else {
		lease = config.testLease
	}
	if ctx == nil || lease == nil || !config.Tier.valid() || !config.Slot.valid() || !config.Role.Valid() || !config.AllowedTargetScope.valid() ||
		config.AssociationID == "" || !exactAttemptReservation(lease.Request().Cost) ||
		lease.Request().Operation != governor.OperationConnectTest {
		return nil, ErrInvalidConfig
	}
	presenceLimit := config.PresenceDeadline
	if presenceLimit == 0 {
		presenceLimit = PresenceTimeout
	}
	operationLimit := config.OperationDeadline
	if operationLimit == 0 {
		operationLimit = ActiveEnvelope
	}
	if presenceLimit <= 0 || presenceLimit > PresenceTimeout || operationLimit <= 0 || operationLimit > ActiveEnvelope {
		return nil, ErrInvalidConfig
	}
	payload, err := presencePayload(config.AssociationID, config.Slot)
	if err != nil {
		return nil, err
	}
	if err := lease.ClaimExclusive(carrierClaimName); err != nil {
		clear(payload)
		return nil, err
	}
	drain, err := lease.RegisterDrain(carrierClaimName)
	if err != nil {
		clear(payload)
		return nil, err
	}
	expiresAt := time.Now().Add(operationLimit)
	attemptCtx, cancel := context.WithDeadline(ctx, expiresAt)
	target, lookups, err := resolveTarget(attemptCtx, config)
	if err != nil {
		cancel()
		clear(payload)
		_ = drain.Complete()
		return nil, err
	}
	connection, err := openGovernedRendezvous(attemptCtx, target.String())
	if err != nil {
		err = contextIOError(attemptCtx, err)
	}
	cancel()
	if err != nil {
		clear(payload)
		_ = drain.Complete()
		return nil, err
	}
	carrier := &Carrier{
		conn: connection, lease: lease, drain: drain, tier: config.Tier,
		role: config.Role, state: statePreconnected, presenceLimit: presenceLimit,
		operationLimit: operationLimit, expiresAt: expiresAt, dnsLookups: lookups,
		closed: make(chan struct{}), drained: make(chan struct{}), watchDone: make(chan struct{}),
	}
	go carrier.watch()
	if err := carrier.writePreburn(ctx, wirePresence, payload); err != nil {
		clear(payload)
		_ = carrier.Close()
		return nil, err
	}
	clear(payload)
	return carrier, nil
}

func resolveTarget(ctx context.Context, config Config) (netip.AddrPort, int, error) {
	host, portText, err := net.SplitHostPort(config.Endpoint)
	if err != nil || host == "" {
		return netip.AddrPort{}, 0, ErrInvalidConfig
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, 0, ErrInvalidConfig
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		endpoint := netip.AddrPortFrom(address.Unmap(), uint16(port))
		if !validRendezvousEndpoint(address, endpoint) || !config.AllowedTargetScope.allows(endpoint) {
			return netip.AddrPort{}, 0, ErrTargetForbidden
		}
		return endpoint, 0, nil
	}
	resolver := config.resolver
	if resolver == nil {
		resolver = governedResolver{}
	}
	addresses, err := resolver.Resolve(ctx, "ip", host)
	if err != nil || len(addresses) != 1 {
		return netip.AddrPort{}, 1, ErrTargetForbidden
	}
	if !addresses[0].IsValid() {
		return netip.AddrPort{}, 1, ErrTargetForbidden
	}
	endpoint := netip.AddrPortFrom(addresses[0].Unmap(), uint16(port))
	if !validRendezvousEndpoint(addresses[0], endpoint) || !config.AllowedTargetScope.allows(endpoint) {
		return netip.AddrPort{}, 1, ErrTargetForbidden
	}
	return endpoint, 1, nil
}

func validRendezvousEndpoint(original netip.Addr, endpoint netip.AddrPort) bool {
	address := endpoint.Addr()
	return original.Zone() == "" && endpoint.IsValid() && endpoint.Port() != 0 && address.IsValid() &&
		!address.IsUnspecified() && !address.IsMulticast() && (address.IsLoopback() || address.IsGlobalUnicast())
}

// AwaitPresence accepts only the fixed ready marker. A secure frame observed
// here is terminal and cannot be buffered across the burn boundary.
func (carrier *Carrier) AwaitPresence(ctx context.Context) error {
	if carrier == nil || ctx == nil {
		return ErrCarrierTerminal
	}
	operationCtx, cancel := context.WithTimeout(ctx, carrier.presenceLimit)
	defer cancel()
	frame, err := carrier.read(operationCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			err = ErrPresenceTimeout
		}
		carrier.fail(err)
		return err
	}
	defer clear(frame.payload)
	if frame.kind == wireHandshake || frame.kind == wireControl {
		carrier.fail(ErrPreBurnSecureFrame)
		return ErrPreBurnSecureFrame
	}
	if frame.kind != wirePresenceReady {
		err = unexpectedFrame("presence", frame.kind)
		carrier.fail(err)
		return err
	}
	carrier.mu.Lock()
	if carrier.state != statePreconnected {
		carrier.mu.Unlock()
		carrier.fail(ErrCarrierTerminal)
		return ErrCarrierTerminal
	}
	carrier.state = statePresent
	carrier.mu.Unlock()
	return nil
}

// Activate crosses the durable burn boundary. BeforeFirstEmission runs
// immediately before the first post-burn marker; all later writes revalidate
// CheckActive.
func (carrier *Carrier) Activate(ctx context.Context, authorization *governor.CommittedCarrierAuthorization) error {
	return carrier.activate(ctx, authorization)
}

func (carrier *Carrier) activate(ctx context.Context, authorization emissionAuthorization) error {
	if carrier == nil || ctx == nil || authorization == nil {
		return ErrBurnRequired
	}
	carrier.mu.Lock()
	if carrier.state != statePresent || carrier.authorization != nil {
		carrier.mu.Unlock()
		return ErrBurnRequired
	}
	carrier.authorization = authorization
	carrier.mu.Unlock()
	if err := carrier.writeFirstPostburn(ctx, wireActivate, nil); err != nil {
		carrier.fail(err)
		return err
	}
	if err := authorization.CheckActive(ctx); err != nil {
		carrier.fail(err)
		return err
	}
	frame, err := carrier.read(ctx)
	if err != nil {
		carrier.fail(err)
		return err
	}
	defer clear(frame.payload)
	if frame.kind != wireActivateReady {
		err = unexpectedFrame("activation", frame.kind)
		carrier.fail(err)
		return err
	}
	carrier.mu.Lock()
	if carrier.state != statePresent {
		carrier.mu.Unlock()
		carrier.fail(ErrCarrierTerminal)
		return ErrCarrierTerminal
	}
	carrier.state = stateActive
	carrier.mu.Unlock()
	return nil
}

func (carrier *Carrier) SendHandshake(ctx context.Context, message []byte) error {
	if carrier == nil || ctx == nil || len(message) != noisecore.PublicKeySize+noisecore.TagSize {
		return ErrInvalidFrame
	}
	carrier.mu.Lock()
	active := carrier.state == stateActive && !carrier.handshakeSent && !carrier.handshakeSending
	if active {
		carrier.handshakeSending = true
	}
	carrier.mu.Unlock()
	if !active {
		return ErrHandshakeOrder
	}
	if err := carrier.writePostburn(ctx, wireHandshake, message); err != nil {
		carrier.fail(err)
		return err
	}
	carrier.mu.Lock()
	carrier.handshakeSending = false
	carrier.handshakeSent = true
	carrier.mu.Unlock()
	return nil
}

func (carrier *Carrier) ReceiveHandshake(ctx context.Context) ([]byte, error) {
	if carrier == nil || ctx == nil {
		return nil, ErrCarrierTerminal
	}
	carrier.mu.Lock()
	active := carrier.state == stateActive && !carrier.handshakeRead && !carrier.handshakeReading
	authorization := carrier.authorization
	if active {
		carrier.handshakeReading = true
	}
	carrier.mu.Unlock()
	if !active {
		return nil, ErrHandshakeOrder
	}
	if authorization == nil {
		return nil, ErrBurnRequired
	}
	if err := authorization.CheckActive(ctx); err != nil {
		carrier.fail(err)
		return nil, err
	}
	frame, err := carrier.read(ctx)
	if err != nil {
		carrier.fail(err)
		return nil, err
	}
	if frame.kind != wireHandshake {
		clear(frame.payload)
		err = unexpectedFrame("handshake", frame.kind)
		carrier.fail(err)
		return nil, err
	}
	carrier.mu.Lock()
	carrier.handshakeReading = false
	carrier.handshakeRead = true
	carrier.mu.Unlock()
	return frame.payload, nil
}

func (carrier *Carrier) MarkHandshakeComplete() error {
	if carrier == nil {
		return ErrCarrierTerminal
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if carrier.state != stateActive || !carrier.handshakeSent || !carrier.handshakeRead || carrier.handshakeSending || carrier.handshakeReading {
		return ErrHandshakeOrder
	}
	carrier.state = stateHandshakeComplete
	return nil
}

func (carrier *Carrier) SendControl(ctx context.Context, frame []byte) error {
	if carrier == nil || ctx == nil {
		return ErrCarrierTerminal
	}
	metadata, err := directattempt.InspectFrame(frame)
	if err != nil || metadata.Domain != directattempt.DomainRendezvousControl || metadata.Sender != carrier.role {
		if err == nil {
			err = ErrCarrierDomain
		}
		carrier.fail(err)
		return err
	}
	carrier.mu.Lock()
	ready := carrier.state == stateHandshakeComplete
	carrier.mu.Unlock()
	if !ready {
		return ErrHandshakeOrder
	}
	if err := carrier.writePostburn(ctx, wireControl, frame); err != nil {
		carrier.fail(err)
		return err
	}
	return nil
}

// ReceiveControl authenticates/decrypts before applying the arrival-carrier
// binding. A valid direct-punch frame received over TCP therefore still closes
// both protocol and carrier terminally.
func (carrier *Carrier) ReceiveControl(ctx context.Context, protocol *directattempt.Protocol) (directattempt.OpenedFrame, error) {
	if carrier == nil || ctx == nil || protocol == nil {
		return directattempt.OpenedFrame{}, ErrCarrierTerminal
	}
	carrier.mu.Lock()
	ready := carrier.state == stateHandshakeComplete
	carrier.mu.Unlock()
	if !ready {
		return directattempt.OpenedFrame{}, ErrHandshakeOrder
	}
	carrier.mu.Lock()
	authorization := carrier.authorization
	carrier.mu.Unlock()
	if authorization == nil {
		return directattempt.OpenedFrame{}, ErrBurnRequired
	}
	if err := authorization.CheckActive(ctx); err != nil {
		carrier.fail(err)
		return directattempt.OpenedFrame{}, err
	}
	frame, err := carrier.read(ctx)
	if err != nil {
		carrier.fail(err)
		return directattempt.OpenedFrame{}, err
	}
	defer clear(frame.payload)
	if frame.kind != wireControl {
		err = unexpectedFrame("control", frame.kind)
		carrier.fail(err)
		_ = protocol.Close()
		return directattempt.OpenedFrame{}, err
	}
	metadata, inspectErr := directattempt.InspectFrame(frame.payload)
	if inspectErr != nil {
		carrier.fail(inspectErr)
		_ = protocol.Close()
		return directattempt.OpenedFrame{}, inspectErr
	}
	opened, openErr := protocol.Open(frame.payload)
	if openErr != nil {
		carrier.fail(openErr)
		return directattempt.OpenedFrame{}, openErr
	}
	if metadata.Domain != directattempt.DomainRendezvousControl {
		_ = protocol.Close()
		carrier.fail(ErrCarrierDomain)
		return directattempt.OpenedFrame{}, ErrCarrierDomain
	}
	return opened, nil
}

func (carrier *Carrier) writePreburn(ctx context.Context, kind byte, payload []byte) error {
	return carrier.write(ctx, kind, payload, false, false)
}

func (carrier *Carrier) writePostburn(ctx context.Context, kind byte, payload []byte) error {
	return carrier.write(ctx, kind, payload, true, false)
}

func (carrier *Carrier) writeFirstPostburn(ctx context.Context, kind byte, payload []byte) error {
	return carrier.write(ctx, kind, payload, true, true)
}

func (carrier *Carrier) write(ctx context.Context, kind byte, payload []byte, postburn, firstEmission bool) error {
	if carrier == nil || ctx == nil {
		return ErrCarrierTerminal
	}
	frame, err := encodeFrame(kind, payload)
	if err != nil {
		return err
	}
	defer clear(frame)
	carrier.writeMu.Lock()
	defer carrier.writeMu.Unlock()
	if !carrier.beginOperation() {
		return ErrCarrierTerminal
	}
	defer carrier.ops.Done()
	if postburn {
		carrier.mu.Lock()
		authorization := carrier.authorization
		carrier.mu.Unlock()
		if authorization == nil {
			return ErrBurnRequired
		}
		var authorizationErr error
		if firstEmission {
			authorizationErr = authorization.BeforeFirstEmission(ctx)
		} else {
			authorizationErr = authorization.CheckActive(ctx)
		}
		if authorizationErr != nil {
			return authorizationErr
		}
	}
	carrier.mu.Lock()
	if carrier.framesWritten >= MaxFramesPerDirection || carrier.bytesWritten+len(frame) > MaxApplicationBytes {
		carrier.mu.Unlock()
		return ErrApplicationBudget
	}
	carrier.mu.Unlock()
	operationCtx, cancel := carrier.operationContext(ctx)
	defer cancel()
	if err := armWriteDeadline(operationCtx, carrier.conn); err != nil {
		if cause := carrier.terminalCause(); cause != nil {
			return cause
		}
		return err
	}
	written, err := carrier.conn.Write(frame)
	_ = carrier.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		if cause := carrier.terminalCause(); cause != nil {
			return cause
		}
		return contextIOError(operationCtx, err)
	}
	if written != len(frame) {
		return ioShortWrite()
	}
	carrier.mu.Lock()
	carrier.framesWritten++
	carrier.bytesWritten += written
	carrier.mu.Unlock()
	return nil
}

func (carrier *Carrier) read(ctx context.Context) (boundedFrame, error) {
	if carrier == nil || ctx == nil {
		return boundedFrame{}, ErrCarrierTerminal
	}
	carrier.readMu.Lock()
	defer carrier.readMu.Unlock()
	if !carrier.beginOperation() {
		return boundedFrame{}, ErrCarrierTerminal
	}
	defer carrier.ops.Done()
	operationCtx, cancel := carrier.operationContext(ctx)
	defer cancel()
	if err := armReadDeadline(operationCtx, carrier.conn); err != nil {
		if cause := carrier.terminalCause(); cause != nil {
			return boundedFrame{}, cause
		}
		return boundedFrame{}, err
	}
	frame, readBytes, err := decodeFrame(carrier.conn)
	_ = carrier.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if cause := carrier.terminalCause(); cause != nil {
			return boundedFrame{}, cause
		}
		return boundedFrame{}, contextIOError(operationCtx, err)
	}
	carrier.mu.Lock()
	if carrier.framesRead >= MaxFramesPerDirection || carrier.bytesRead+readBytes > MaxApplicationBytes {
		carrier.mu.Unlock()
		clear(frame.payload)
		return boundedFrame{}, ErrApplicationBudget
	}
	carrier.framesRead++
	carrier.bytesRead += readBytes
	carrier.mu.Unlock()
	return frame, nil
}

func (carrier *Carrier) beginOperation() bool {
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if carrier.state == stateClosed {
		return false
	}
	carrier.ops.Add(1)
	return true
}

func (carrier *Carrier) terminalCause() error {
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if carrier.state == stateClosed && carrier.closeErr != nil {
		return carrier.closeErr
	}
	return nil
}

func (carrier *Carrier) watch() {
	remaining := time.Until(carrier.expiresAt)
	if remaining < 0 {
		remaining = 0
	}
	timer := time.NewTimer(remaining)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		close(carrier.watchDone)
	}()
	select {
	case <-carrier.closed:
		return
	case <-carrier.lease.Stopping():
		carrier.fail(governor.ErrLeaseClosed)
	case <-timer.C:
		carrier.fail(context.DeadlineExceeded)
	}
}

func (carrier *Carrier) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := carrier.expiresAt
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	return context.WithDeadline(ctx, deadline)
}

func (carrier *Carrier) fail(cause error) {
	if carrier == nil {
		return
	}
	carrier.closeOnce.Do(func() {
		carrier.mu.Lock()
		carrier.state = stateClosed
		carrier.closeErr = cause
		connection := carrier.conn
		carrier.mu.Unlock()
		close(carrier.closed)
		if connection != nil {
			_ = connection.Close()
		}
		go carrier.completeDrain()
	})
}

func (carrier *Carrier) completeDrain() {
	carrier.ops.Wait()
	carrier.drainOnce.Do(func() {
		if carrier.drain != nil {
			_ = carrier.drain.Complete()
		}
		carrier.mu.Lock()
		carrier.drainComplete = true
		carrier.mu.Unlock()
		close(carrier.drained)
	})
}

func (carrier *Carrier) Close() error {
	if carrier == nil {
		return nil
	}
	carrier.fail(nil)
	<-carrier.watchDone
	<-carrier.drained
	carrier.mu.Lock()
	err := carrier.closeErr
	carrier.mu.Unlock()
	return err
}

func (carrier *Carrier) Witness() Witness {
	if carrier == nil {
		return Witness{Closed: true, Drained: true}
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	return Witness{
		Tier: carrier.tier, Connections: 1, DNSResolutions: carrier.dnsLookups,
		FramesRead: carrier.framesRead, FramesWritten: carrier.framesWritten,
		BytesRead: carrier.bytesRead, BytesWritten: carrier.bytesWritten,
		DrainRegistered: carrier.drain != nil, Drained: carrier.drainComplete,
		Closed: carrier.state == stateClosed,
	}
}

func armReadDeadline(ctx context.Context, connection net.Conn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrInvalidConfig
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return ErrCarrierTransport
	}
	return nil
}

func armWriteDeadline(ctx context.Context, connection net.Conn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrInvalidConfig
	}
	if err := connection.SetWriteDeadline(deadline); err != nil {
		return ErrCarrierTransport
	}
	return nil
}

func contextIOError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInvalidFrame) || errors.Is(err, ErrApplicationBudget) {
		return err
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return ErrCarrierTransport
}

func ioShortWrite() error { return fmt.Errorf("%w: short write", ErrInvalidFrame) }
