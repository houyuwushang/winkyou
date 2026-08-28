package oobcarrier

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatcontrol"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/oobattempt"
	"winkyou/internal/v2/rendezvouswire"
)

var (
	ErrInvalidConfig      = errors.New("oobcarrier: invalid configuration")
	ErrPresenceTimeout    = errors.New("oobcarrier: peer presence timed out")
	ErrBurnRequired       = errors.New("oobcarrier: durable admission is required")
	ErrPreBurnSecureFrame = errors.New("oobcarrier: secure frame arrived before durable admission")
	ErrCarrierDomain      = errors.New("oobcarrier: authenticated frame arrived on the wrong carrier")
	ErrCarrierTerminal    = errors.New("oobcarrier: terminal")
	ErrCarrierTransport   = errors.New("oobcarrier: bounded stream failure")
	ErrHandshakeOrder     = errors.New("oobcarrier: handshake ordering violation")
	ErrInvalidFrame       = errors.New("oobcarrier: invalid bounded frame")
	ErrApplicationBudget  = errors.New("oobcarrier: application byte ceiling exceeded")
)

// BoundedStream is already established and dedicated to one attempt. Close
// must unblock and wait for every in-flight Read and Write before returning.
type BoundedStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
}

type Config struct {
	Lease        *governor.AttemptLease
	Stream       BoundedStream
	OOBChannelID string
	Role         directattempt.Role

	testLease attemptLease
}

// HardNATConfig is the separate Gate B2 adoption surface. Its profile and
// resource class are checked against the exact manual-traversal reservation
// before ownership of the stream is taken.
type HardNATConfig struct {
	Lease          *governor.AttemptLease
	Stream         BoundedStream
	OOBChannelID   string
	Role           directattempt.Role
	PlannerProfile hardnatplan.Profile
	ResourceClass  hardnatplan.ResourceClass
	// ActiveDeadline may only lower the frozen Gate B2 active envelope. Gate B2
	// passes the same absolute deadline to its executor context so the carrier,
	// UDP schedule, handoff, and challenge share one lifetime.
	ActiveDeadline time.Time

	testLease attemptLease
}

// attemptLease is private so package tests can inject bounded lifecycle
// failures. The public Config continues to accept only a real governor lease.
type attemptLease interface {
	Request() governor.AttemptRequest
	ClaimExclusive(string) error
	Stopping() <-chan struct{}
	RegisterDrain(string) (governor.DrainHandle, error)
}

var _ attemptLease = (*governor.AttemptLease)(nil)

type emissionAuthorization interface {
	BeforeFirstEmission(context.Context) error
	CheckActive(context.Context) error
}

var _ emissionAuthorization = (*governor.CommittedCarrierAuthorization)(nil)

type Witness struct {
	FramesRead      int
	FramesWritten   int
	BytesRead       int
	BytesWritten    int
	Deadline        bool
	EOF             bool
	DrainRegistered bool
	Drained         bool
	Closed          bool
}

type carrierState uint8

const (
	stateAdopted carrierState = iota
	statePresent
	stateActive
	stateHandshakeComplete
	stateClosed
)

const carrierClaimName = "gate-a-oob-carrier"

type carrierMode uint8

const (
	carrierModeGateA carrierMode = iota + 1
	carrierModeGateB2
)

type Carrier struct {
	mu      sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex

	stream        BoundedStream
	lease         attemptLease
	drain         governor.DrainHandle
	authorization emissionAuthorization
	channelID     string
	role          directattempt.Role
	mode          carrierMode
	state         carrierState
	expiresAt     time.Time
	framesRead    int
	framesWritten int
	bytesRead     int
	bytesWritten  int
	handshakeSent bool
	handshakeRead bool
	deadlineSeen  bool
	eofSeen       bool
	drainComplete bool
	closeErr      error

	closed        chan struct{}
	drained       chan struct{}
	watchDone     chan struct{}
	incoming      chan carrierReadResult
	readerDone    chan struct{}
	readerStarted bool
	closeOnce     sync.Once
	drainOnce     sync.Once
	ops           sync.WaitGroup
}

// Adopt takes ownership of exactly one caller-provided child stream without
// reading or writing it. Cost and identity checks happen before that ownership
// boundary.
func Adopt(config Config) (*Carrier, error) {
	var lease attemptLease
	if config.Lease != nil {
		lease = config.Lease
	} else {
		lease = config.testLease
	}
	if lease == nil || config.Stream == nil || !config.Role.Valid() ||
		!exactAttemptReservation(lease.Request().Cost, config.Role) ||
		lease.Request().Operation != governor.OperationConnectTest ||
		!validIdentifier(config.OOBChannelID) {
		return nil, ErrInvalidConfig
	}
	if err := lease.ClaimExclusive(carrierClaimName); err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	drain, err := lease.RegisterDrain("gate-a-oob-carrier")
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	carrier := &Carrier{
		stream: config.Stream, lease: lease, drain: drain, channelID: config.OOBChannelID,
		role: config.Role, mode: carrierModeGateA, state: stateAdopted, expiresAt: time.Now().Add(ActiveEnvelope),
		closed: make(chan struct{}), drained: make(chan struct{}), watchDone: make(chan struct{}),
		incoming: make(chan carrierReadResult, MaxFramesPerDirection), readerDone: make(chan struct{}),
	}
	go carrier.watch()
	return carrier, nil
}

// AdoptHardNAT takes the same single bounded stream under Gate B2's distinct
// exact operation/profile authority. It neither opens nor discovers a stream.
func AdoptHardNAT(config HardNATConfig) (*Carrier, error) {
	var lease attemptLease
	if config.Lease != nil {
		lease = config.Lease
	} else {
		lease = config.testLease
	}
	if lease == nil || config.Stream == nil || !config.Role.Valid() || !validIdentifier(config.OOBChannelID) ||
		!hardnatbudget.Exact(config.PlannerProfile, config.ResourceClass, lease.Request().Operation, lease.Request().Cost) {
		return nil, ErrInvalidConfig
	}
	expiresAt := time.Now().Add(hardnatbudget.ActiveEnvelope)
	if !config.ActiveDeadline.IsZero() {
		remaining := time.Until(config.ActiveDeadline)
		if remaining <= 0 || remaining > hardnatbudget.ActiveEnvelope {
			return nil, ErrInvalidConfig
		}
		expiresAt = config.ActiveDeadline
	}
	if err := lease.ClaimExclusive("gate-b2-oob-carrier"); err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	drain, err := lease.RegisterDrain("gate-b2-oob-carrier")
	if err != nil {
		return nil, errors.Join(ErrInvalidConfig, err)
	}
	carrier := &Carrier{
		stream: config.Stream, lease: lease, drain: drain, channelID: config.OOBChannelID,
		role: config.Role, mode: carrierModeGateB2, state: stateAdopted, expiresAt: expiresAt,
		closed: make(chan struct{}), drained: make(chan struct{}), watchDone: make(chan struct{}),
		incoming: make(chan carrierReadResult, MaxFramesPerDirection), readerDone: make(chan struct{}),
	}
	go carrier.watch()
	return carrier, nil
}

// AwaitPresence exchanges only the secret-free channel identifier and fixed
// carrier slot. Role ordering avoids full-buffer duplex write deadlock.
func (carrier *Carrier) AwaitPresence(ctx context.Context) error {
	if carrier == nil || ctx == nil {
		return ErrCarrierTerminal
	}
	presenceCtx, cancel := context.WithTimeout(ctx, PresenceTimeout)
	defer cancel()
	payload, err := rendezvouswire.PresencePayloadForProfile(
		rendezvouswire.CallerProvidedStreamProfile, carrier.channelID, carrier.localSlot(),
	)
	if err != nil {
		return carrier.terminate(ErrInvalidConfig)
	}
	defer clear(payload)
	if carrier.role == directattempt.RoleInitiator {
		err = carrier.write(presenceCtx, rendezvouswire.KindPresence, payload, false, false)
		if err == nil {
			err = carrier.readAndValidatePresence(presenceCtx)
		}
	} else {
		err = carrier.readAndValidatePresence(presenceCtx)
		if err == nil {
			err = carrier.write(presenceCtx, rendezvouswire.KindPresence, payload, false, false)
		}
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			err = ErrPresenceTimeout
		}
		return carrier.terminate(err)
	}
	carrier.mu.Lock()
	if carrier.state != stateAdopted {
		carrier.mu.Unlock()
		return carrier.terminate(ErrCarrierTerminal)
	}
	carrier.state = statePresent
	carrier.mu.Unlock()
	return nil
}

func (carrier *Carrier) readAndValidatePresence(ctx context.Context) error {
	frame, err := carrier.read(ctx)
	if err != nil {
		return err
	}
	defer clear(frame.Payload)
	if frame.Kind == rendezvouswire.KindHandshake || frame.Kind == rendezvouswire.KindControl {
		return ErrPreBurnSecureFrame
	}
	if frame.Kind != rendezvouswire.KindPresence {
		return ErrInvalidFrame
	}
	channelID, slot, err := rendezvouswire.ParsePresencePayloadForProfile(rendezvouswire.CallerProvidedStreamProfile, frame.Payload)
	if err != nil || channelID != carrier.channelID || slot != carrier.peerSlot() {
		return ErrInvalidFrame
	}
	return nil
}

// Activate crosses the durable burn boundary. The initiator emits ACTIVATE;
// the responder emits ACTIVATE_READY. Each side authorizes its own first byte
// immediately before that byte is written.
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
	var err error
	if carrier.role == directattempt.RoleInitiator {
		err = carrier.write(ctx, rendezvouswire.KindActivate, nil, true, true)
		if err == nil {
			err = carrier.expect(ctx, rendezvouswire.KindActivateReady, true)
		}
	} else {
		err = carrier.expect(ctx, rendezvouswire.KindActivate, false)
		if err == nil {
			err = carrier.write(ctx, rendezvouswire.KindActivateReady, nil, true, true)
		}
	}
	if err != nil {
		return carrier.terminate(err)
	}
	carrier.mu.Lock()
	if carrier.state != statePresent {
		carrier.mu.Unlock()
		return carrier.terminate(ErrCarrierTerminal)
	}
	carrier.state = stateActive
	carrier.mu.Unlock()
	return nil
}

func (carrier *Carrier) expect(ctx context.Context, kind rendezvouswire.Kind, requireActive bool) error {
	if requireActive {
		if err := carrier.authorization.CheckActive(ctx); err != nil {
			return err
		}
	}
	frame, err := carrier.read(ctx)
	if err != nil {
		return err
	}
	defer clear(frame.Payload)
	if frame.Kind != kind {
		return ErrInvalidFrame
	}
	return nil
}

func (carrier *Carrier) SendHandshake(ctx context.Context, message []byte) error {
	if carrier == nil || ctx == nil || len(message) != noisecore.PublicKeySize+noisecore.TagSize {
		return ErrInvalidFrame
	}
	carrier.mu.Lock()
	state := carrier.state
	ready := state == stateActive && !carrier.handshakeSent
	carrier.mu.Unlock()
	if !ready {
		if state == stateClosed {
			return carrier.TerminalCause()
		}
		return ErrHandshakeOrder
	}
	if err := carrier.write(ctx, rendezvouswire.KindHandshake, message, true, false); err != nil {
		return carrier.terminate(err)
	}
	carrier.mu.Lock()
	carrier.handshakeSent = true
	carrier.mu.Unlock()
	return nil
}

func (carrier *Carrier) ReceiveHandshake(ctx context.Context) ([]byte, error) {
	if carrier == nil || ctx == nil {
		return nil, ErrCarrierTerminal
	}
	carrier.mu.Lock()
	state := carrier.state
	ready := state == stateActive && !carrier.handshakeRead
	carrier.mu.Unlock()
	if !ready {
		if state == stateClosed {
			return nil, carrier.TerminalCause()
		}
		return nil, ErrHandshakeOrder
	}
	if err := carrier.authorization.CheckActive(ctx); err != nil {
		return nil, carrier.terminate(err)
	}
	frame, err := carrier.read(ctx)
	if err != nil {
		return nil, carrier.terminate(err)
	}
	if frame.Kind != rendezvouswire.KindHandshake {
		clear(frame.Payload)
		return nil, carrier.terminate(ErrInvalidFrame)
	}
	carrier.mu.Lock()
	carrier.handshakeRead = true
	carrier.mu.Unlock()
	return frame.Payload, nil
}

func (carrier *Carrier) MarkHandshakeComplete() error {
	if carrier == nil {
		return ErrCarrierTerminal
	}
	carrier.mu.Lock()
	state := carrier.state
	if state != stateActive || !carrier.handshakeSent || !carrier.handshakeRead {
		carrier.mu.Unlock()
		if state == stateClosed {
			return carrier.TerminalCause()
		}
		return ErrHandshakeOrder
	}
	carrier.state = stateHandshakeComplete
	expiresAt := carrier.expiresAt
	stream := carrier.stream
	carrier.mu.Unlock()
	if stream.SetDeadline(expiresAt) != nil {
		return carrier.terminate(ErrCarrierTransport)
	}
	carrier.mu.Lock()
	if carrier.state == stateClosed {
		carrier.mu.Unlock()
		return carrier.TerminalCause()
	}
	carrier.readerStarted = true
	carrier.ops.Add(1)
	carrier.mu.Unlock()
	go carrier.readLoop()
	return nil
}

func (carrier *Carrier) SendControl(ctx context.Context, frame []byte) error {
	if carrier == nil || ctx == nil || carrier.mode != carrierModeGateA {
		return ErrCarrierTerminal
	}
	metadata, err := directattempt.InspectFrame(frame)
	if err != nil || metadata.Domain != directattempt.DomainRendezvousControl || metadata.Sender != carrier.role {
		if err == nil {
			err = ErrCarrierDomain
		}
		return carrier.terminate(err)
	}
	carrier.mu.Lock()
	state := carrier.state
	ready := state == stateHandshakeComplete
	carrier.mu.Unlock()
	if !ready {
		if state == stateClosed {
			return carrier.TerminalCause()
		}
		return ErrHandshakeOrder
	}
	if err := carrier.write(ctx, rendezvouswire.KindControl, frame, true, false); err != nil {
		return carrier.terminate(err)
	}
	return nil
}

func (carrier *Carrier) ReceiveControl(ctx context.Context, protocol *directattempt.Protocol) (directattempt.OpenedFrame, error) {
	if carrier == nil || ctx == nil || protocol == nil || carrier.mode != carrierModeGateA {
		return directattempt.OpenedFrame{}, ErrCarrierTerminal
	}
	carrier.mu.Lock()
	state := carrier.state
	ready := state == stateHandshakeComplete
	carrier.mu.Unlock()
	if !ready {
		if state == stateClosed {
			return directattempt.OpenedFrame{}, carrier.TerminalCause()
		}
		return directattempt.OpenedFrame{}, ErrHandshakeOrder
	}
	if err := carrier.authorization.CheckActive(ctx); err != nil {
		return directattempt.OpenedFrame{}, carrier.terminate(err)
	}
	frame, err := carrier.read(ctx)
	if err != nil {
		return directattempt.OpenedFrame{}, carrier.terminate(err)
	}
	defer clear(frame.Payload)
	if frame.Kind != rendezvouswire.KindControl {
		_ = protocol.Close()
		return directattempt.OpenedFrame{}, carrier.terminate(ErrInvalidFrame)
	}
	metadata, err := directattempt.InspectFrame(frame.Payload)
	if err != nil {
		_ = protocol.Close()
		return directattempt.OpenedFrame{}, carrier.terminate(err)
	}
	opened, err := protocol.Open(frame.Payload)
	if err != nil {
		return directattempt.OpenedFrame{}, carrier.terminate(err)
	}
	if metadata.Domain != directattempt.DomainRendezvousControl {
		_ = protocol.Close()
		return directattempt.OpenedFrame{}, carrier.terminate(ErrCarrierDomain)
	}
	return opened, nil
}

// SendHardNATControl accepts only the Gate B rendezvous-control domain and
// the carrier's authenticated sender role.
func (carrier *Carrier) SendHardNATControl(ctx context.Context, frame []byte) error {
	if carrier == nil || ctx == nil || carrier.mode != carrierModeGateB2 {
		return ErrCarrierTerminal
	}
	metadata, err := hardnatcontrol.InspectFrame(frame)
	if err != nil || metadata.Domain != hardnatcontrol.DomainRendezvousControl || metadata.Sender != carrier.role {
		if err == nil {
			err = ErrCarrierDomain
		}
		return carrier.terminate(err)
	}
	carrier.mu.Lock()
	state := carrier.state
	ready := state == stateHandshakeComplete
	carrier.mu.Unlock()
	if !ready {
		if state == stateClosed {
			return carrier.TerminalCause()
		}
		return ErrHandshakeOrder
	}
	if err := carrier.write(ctx, rendezvouswire.KindControl, frame, true, false); err != nil {
		return carrier.terminate(err)
	}
	return nil
}

// ReceiveHardNATControl decrypts exactly one Gate B rendezvous-control frame.
// Direct candidate/winner frames are permanently rejected on the OOB carrier.
func (carrier *Carrier) ReceiveHardNATControl(ctx context.Context, protocol *hardnatcontrol.Protocol) (hardnatcontrol.OpenedFrame, error) {
	if carrier == nil || ctx == nil || protocol == nil || carrier.mode != carrierModeGateB2 {
		return hardnatcontrol.OpenedFrame{}, ErrCarrierTerminal
	}
	carrier.mu.Lock()
	state := carrier.state
	ready := state == stateHandshakeComplete
	carrier.mu.Unlock()
	if !ready {
		if state == stateClosed {
			return hardnatcontrol.OpenedFrame{}, carrier.TerminalCause()
		}
		return hardnatcontrol.OpenedFrame{}, ErrHandshakeOrder
	}
	if err := carrier.authorization.CheckActive(ctx); err != nil {
		return hardnatcontrol.OpenedFrame{}, carrier.terminate(err)
	}
	frame, err := carrier.read(ctx)
	if err != nil {
		return hardnatcontrol.OpenedFrame{}, carrier.terminate(err)
	}
	defer clear(frame.Payload)
	if frame.Kind != rendezvouswire.KindControl {
		_ = protocol.Close()
		return hardnatcontrol.OpenedFrame{}, carrier.terminate(ErrInvalidFrame)
	}
	metadata, err := hardnatcontrol.InspectFrame(frame.Payload)
	if err != nil {
		_ = protocol.Close()
		return hardnatcontrol.OpenedFrame{}, carrier.terminate(err)
	}
	if metadata.Domain != hardnatcontrol.DomainRendezvousControl {
		_ = protocol.Close()
		return hardnatcontrol.OpenedFrame{}, carrier.terminate(ErrCarrierDomain)
	}
	opened, err := protocol.Open(frame.Payload)
	if err != nil {
		return hardnatcontrol.OpenedFrame{}, carrier.terminate(err)
	}
	return opened, nil
}

func (carrier *Carrier) write(ctx context.Context, kind rendezvouswire.Kind, payload []byte, postburn, first bool) error {
	if carrier == nil || ctx == nil {
		return ErrCarrierTerminal
	}
	frame, err := rendezvouswire.EncodeForProfile(rendezvouswire.CallerProvidedStreamProfile, kind, payload)
	if err != nil {
		return ErrInvalidFrame
	}
	defer clear(frame)
	carrier.writeMu.Lock()
	defer carrier.writeMu.Unlock()
	if !carrier.beginOperation() {
		return carrier.TerminalCause()
	}
	defer carrier.ops.Done()
	if postburn {
		if first {
			err = carrier.authorization.BeforeFirstEmission(ctx)
		} else {
			err = carrier.authorization.CheckActive(ctx)
		}
		if err != nil {
			return err
		}
	}
	carrier.mu.Lock()
	if carrier.framesWritten >= MaxFramesPerDirection || carrier.bytesWritten+len(frame) > MaxApplicationBytes {
		carrier.mu.Unlock()
		return ErrApplicationBudget
	}
	carrier.mu.Unlock()
	opCtx, cancel := carrier.operationContext(ctx)
	defer cancel()
	stopDeadline, err := carrier.armDeadline(opCtx)
	if err != nil {
		return err
	}
	defer stopDeadline()
	written, err := carrier.stream.Write(frame)
	if err != nil {
		return carrier.contextIOError(opCtx, err)
	}
	if written != len(frame) {
		return ErrInvalidFrame
	}
	carrier.mu.Lock()
	carrier.framesWritten++
	carrier.bytesWritten += written
	carrier.mu.Unlock()
	return nil
}

type carrierReadResult struct {
	frame rendezvouswire.Frame
	err   error
}

func (carrier *Carrier) read(ctx context.Context) (rendezvouswire.Frame, error) {
	carrier.readMu.Lock()
	defer carrier.readMu.Unlock()
	carrier.mu.Lock()
	async := carrier.readerStarted
	carrier.mu.Unlock()
	if async {
		select {
		case <-carrier.closed:
			return rendezvouswire.Frame{}, carrier.TerminalCause()
		default:
		}
		select {
		case result := <-carrier.incoming:
			return result.frame, result.err
		case <-carrier.closed:
			return rendezvouswire.Frame{}, carrier.TerminalCause()
		case <-ctx.Done():
			return rendezvouswire.Frame{}, ctx.Err()
		}
	}
	return carrier.decode(ctx)
}

func (carrier *Carrier) decode(ctx context.Context) (rendezvouswire.Frame, error) {
	if !carrier.beginOperation() {
		return rendezvouswire.Frame{}, carrier.TerminalCause()
	}
	defer carrier.ops.Done()
	return carrier.decodeFrame(ctx)
}

func (carrier *Carrier) decodeFrame(ctx context.Context) (rendezvouswire.Frame, error) {
	opCtx, cancel := carrier.operationContext(ctx)
	defer cancel()
	stopDeadline, err := carrier.armDeadline(opCtx)
	if err != nil {
		return rendezvouswire.Frame{}, err
	}
	defer stopDeadline()
	frame, count, err := rendezvouswire.DecodeForProfile(carrier.stream, rendezvouswire.CallerProvidedStreamProfile)
	if err != nil {
		return rendezvouswire.Frame{}, carrier.contextIOError(opCtx, err)
	}
	carrier.mu.Lock()
	if carrier.framesRead >= MaxFramesPerDirection || carrier.bytesRead+count > MaxApplicationBytes {
		carrier.mu.Unlock()
		clear(frame.Payload)
		return rendezvouswire.Frame{}, ErrApplicationBudget
	}
	carrier.framesRead++
	carrier.bytesRead += count
	carrier.mu.Unlock()
	return frame, nil
}

func (carrier *Carrier) readLoop() {
	var terminal error
	defer func() {
		carrier.ops.Done()
		if terminal != nil {
			carrier.fail(terminal)
		}
		close(carrier.readerDone)
	}()
	ctx, cancel := context.WithDeadline(context.Background(), carrier.expiresAt)
	defer cancel()
	for {
		frame, err := carrier.decodeFrame(ctx)
		if err == nil {
			err = carrier.validateQueuedFrame(frame)
		}
		if err != nil {
			clear(frame.Payload)
			terminal = err
			return
		}
		select {
		case carrier.incoming <- carrierReadResult{frame: frame}:
		case <-carrier.closed:
			clear(frame.Payload)
			return
		}
	}
}

func (carrier *Carrier) validateQueuedFrame(frame rendezvouswire.Frame) error {
	if frame.Kind != rendezvouswire.KindControl {
		return ErrInvalidFrame
	}
	if carrier.mode == carrierModeGateA {
		metadata, err := directattempt.InspectFrame(frame.Payload)
		if err != nil || metadata.Sender != carrier.role.Peer() {
			return ErrInvalidFrame
		}
		if metadata.Domain != directattempt.DomainRendezvousControl {
			return ErrCarrierDomain
		}
		return nil
	}
	metadata, err := hardnatcontrol.InspectFrame(frame.Payload)
	if err != nil || metadata.Sender != carrier.role.Peer() {
		return ErrInvalidFrame
	}
	if metadata.Domain != hardnatcontrol.DomainRendezvousControl {
		return ErrCarrierDomain
	}
	return nil
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

func (carrier *Carrier) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := carrier.expiresAt
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	return context.WithDeadline(ctx, deadline)
}

func (carrier *Carrier) armDeadline(ctx context.Context) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok || carrier.stream.SetDeadline(deadline) != nil {
		return nil, ErrCarrierTransport
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = carrier.stream.SetDeadline(time.Now())
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
		carrier.mu.Lock()
		active := carrier.state != stateClosed
		expiresAt := carrier.expiresAt
		carrier.mu.Unlock()
		if active {
			_ = carrier.stream.SetDeadline(expiresAt)
		}
	}, nil
}

func (carrier *Carrier) contextIOError(ctx context.Context, err error) error {
	type timeoutError interface{ Timeout() bool }
	deadlineExceeded := errors.Is(ctx.Err(), context.DeadlineExceeded)
	if !deadlineExceeded {
		var timeout timeoutError
		deadline, hasDeadline := ctx.Deadline()
		deadlineExceeded = hasDeadline && !time.Now().Before(deadline) && errors.As(err, &timeout) && timeout.Timeout()
	}
	carrier.mu.Lock()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		carrier.eofSeen = true
	}
	if deadlineExceeded {
		carrier.deadlineSeen = true
	}
	carrier.mu.Unlock()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if deadlineExceeded {
		return context.DeadlineExceeded
	}
	if errors.Is(err, rendezvouswire.ErrInvalidFrame) || errors.Is(err, rendezvouswire.ErrFrameTooLarge) {
		return ErrInvalidFrame
	}
	return ErrCarrierTransport
}

func (carrier *Carrier) terminate(cause error) error {
	carrier.fail(cause)
	return cause
}

func (carrier *Carrier) fail(cause error) {
	if carrier == nil {
		return
	}
	carrier.closeOnce.Do(func() {
		carrier.mu.Lock()
		carrier.state = stateClosed
		carrier.closeErr = cause
		stream := carrier.stream
		carrier.mu.Unlock()
		close(carrier.closed)
		if stream != nil {
			_ = stream.SetDeadline(time.Now())
			_ = stream.Close()
		}
		carrier.completeDrain()
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

func (carrier *Carrier) watch() {
	timer := time.NewTimer(time.Until(carrier.expiresAt))
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
	case <-carrier.lease.Stopping():
		carrier.fail(governor.ErrLeaseClosed)
	case <-timer.C:
		carrier.mu.Lock()
		carrier.deadlineSeen = true
		carrier.mu.Unlock()
		carrier.fail(context.DeadlineExceeded)
	}
}

func (carrier *Carrier) Close() error {
	if carrier == nil {
		return nil
	}
	carrier.fail(nil)
	<-carrier.watchDone
	<-carrier.drained
	carrier.mu.Lock()
	readerStarted := carrier.readerStarted
	carrier.mu.Unlock()
	if readerStarted {
		<-carrier.readerDone
	}
	carrier.clearIncoming()
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	return carrier.closeErr
}

// Done closes for EOF, stream error, active-envelope expiry, lease stopping,
// protocol termination, or explicit Close. It carries no transport metadata.
func (carrier *Carrier) Done() <-chan struct{} {
	if carrier == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return carrier.closed
}

// TerminalCause returns only the stable terminal cause observed by the
// carrier. A clean explicit Close maps to ErrCarrierTerminal.
func (carrier *Carrier) TerminalCause() error {
	if carrier == nil {
		return ErrCarrierTerminal
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	if carrier.closeErr != nil {
		return carrier.closeErr
	}
	return ErrCarrierTerminal
}

func (carrier *Carrier) clearIncoming() {
	for {
		select {
		case result := <-carrier.incoming:
			clear(result.frame.Payload)
		default:
			return
		}
	}
}

func (carrier *Carrier) Witness() Witness {
	if carrier == nil {
		return Witness{Closed: true, Drained: true}
	}
	carrier.mu.Lock()
	defer carrier.mu.Unlock()
	return Witness{
		FramesRead: carrier.framesRead, FramesWritten: carrier.framesWritten,
		BytesRead: carrier.bytesRead, BytesWritten: carrier.bytesWritten,
		Deadline: carrier.deadlineSeen, EOF: carrier.eofSeen,
		DrainRegistered: carrier.drain != nil, Drained: carrier.drainComplete, Closed: carrier.state == stateClosed,
	}
}

func (carrier *Carrier) localSlot() rendezvouswire.Slot {
	if carrier.role == directattempt.RoleInitiator {
		return rendezvouswire.SlotA
	}
	return rendezvouswire.SlotB
}

func (carrier *Carrier) peerSlot() rendezvouswire.Slot {
	if carrier.role == directattempt.RoleInitiator {
		return rendezvouswire.SlotB
	}
	return rendezvouswire.SlotA
}

func validIdentifier(value string) bool {
	payload, err := rendezvouswire.PresencePayloadForProfile(rendezvouswire.CallerProvidedStreamProfile, value, rendezvouswire.SlotA)
	clear(payload)
	return err == nil && oobattempt.OOBCarrierProfile == rendezvouswire.CallerProvidedStreamProfile
}
