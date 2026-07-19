package routed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/mesh"
)

const (
	defaultTCPDialTimeout = 5 * time.Second
	defaultFrameTimeout   = 5 * time.Second
	streamRetryInterval   = 250 * time.Millisecond
	initialAcceptRetry    = 5 * time.Millisecond
	maxAcceptRetry        = time.Second
	tcpReadBufferSize     = 32 << 10
	tcpInboundQueueSize   = 64
	maxStreamErrorLength  = 1024
)

var (
	ErrTCPForwarderClosed  = errors.New("routed dataplane: TCP forwarder closed")
	ErrTCPOpenRejected     = errors.New("routed dataplane: TCP open rejected")
	ErrTCPFlowProtocol     = errors.New("routed dataplane: TCP flow protocol error")
	errTCPInboundQueueFull = errors.New("routed dataplane: TCP inbound queue full")
)

type tcpFlowKey struct {
	peerID string
	flowID uint64
}

// TCPForwarder multiplexes fixed-target TCP flows over routed binary data
// frames. Target is intentionally local configuration: an OPEN frame never
// carries an arbitrary host or port selected by the remote peer.
type TCPForwarder struct {
	endpoint     *Endpoint
	target       string
	dialTimeout  time.Duration
	frameTimeout time.Duration
	openTimeout  time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	unregister   func()

	mu        sync.Mutex
	closed    bool
	flows     map[tcpFlowKey]*tcpFlow
	opening   map[tcpFlowKey]struct{}
	listeners map[*TCPListener]struct{}
	wg        sync.WaitGroup
}

type TCPForwarderConfig struct {
	Target       string
	DialTimeout  time.Duration
	FrameTimeout time.Duration
}

// NewTCPForwarder creates one stream protocol endpoint. target may be empty on
// a listener-only node. A node that accepts remote OPEN frames must configure a
// fixed TCP target such as 127.0.0.1:22.
func NewTCPForwarder(endpoint *Endpoint, target string) (*TCPForwarder, error) {
	return NewTCPForwarderWithConfig(endpoint, TCPForwarderConfig{Target: target})
}

// NewTCPForwarderWithConfig allows a long-running mesh runtime to align the
// reliable-frame deadline with its neighbor failure detector. The legacy
// constructor retains the compact five-second defaults used by small tests.
func NewTCPForwarderWithConfig(endpoint *Endpoint, config TCPForwarderConfig) (*TCPForwarder, error) {
	if endpoint == nil || endpoint.NodeID() == "" {
		return nil, fmt.Errorf("routed dataplane: endpoint is required")
	}
	target := strings.TrimSpace(config.Target)
	if target != "" {
		if err := validateLoopbackTCPAddress("target", target); err != nil {
			return nil, err
		}
	}
	dialTimeout := config.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultTCPDialTimeout
	}
	frameTimeout := config.FrameTimeout
	if frameTimeout <= 0 {
		frameTimeout = defaultFrameTimeout
	}
	openTimeout := saturatingDurationAdd(dialTimeout, frameTimeout)
	ctx, cancel := context.WithCancel(context.Background())
	forwarder := &TCPForwarder{
		endpoint:     endpoint,
		target:       target,
		dialTimeout:  dialTimeout,
		frameTimeout: frameTimeout,
		openTimeout:  openTimeout,
		ctx:          ctx,
		cancel:       cancel,
		flows:        make(map[tcpFlowKey]*tcpFlow),
		opening:      make(map[tcpFlowKey]struct{}),
		listeners:    make(map[*TCPListener]struct{}),
	}
	unregister, err := endpoint.RegisterHandler([]mesh.DataType{
		mesh.DataTypeStreamOpen,
		mesh.DataTypeStreamOpenOK,
		mesh.DataTypeStreamOpenError,
		mesh.DataTypeStreamData,
		mesh.DataTypeStreamFIN,
		mesh.DataTypeStreamReset,
		mesh.DataTypeStreamACK,
	}, forwarder.handleFrame)
	if err != nil {
		cancel()
		return nil, err
	}
	forwarder.unregister = unregister
	return forwarder, nil
}

// Target returns the fixed local TCP target used for new inbound OPEN frames.
// Existing flows keep their already-dialed connection when the target changes.
func (f *TCPForwarder) Target() string {
	if f == nil {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.target
}

// SetTarget changes the loopback TCP target used by subsequent inbound OPEN
// frames. The caller owns higher-level configured-versus-runtime policy; this
// layer only validates the target and makes the update atomic with OPEN.
func (f *TCPForwarder) SetTarget(target string) error {
	if f == nil {
		return ErrTCPForwarderClosed
	}
	target = strings.TrimSpace(target)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrTCPForwarderClosed
	}
	if err := validateLoopbackTCPAddress("target", target); err != nil {
		return err
	}
	f.target = target
	return nil
}

// ClearTarget rejects subsequent inbound OPEN frames without disturbing flows
// that have already connected to the previous target.
func (f *TCPForwarder) ClearTarget() error {
	if f == nil {
		return ErrTCPForwarderClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrTCPForwarderClosed
	}
	f.target = ""
	return nil
}

// TCPListener accepts ordinary local TCP connections and opens one routed flow
// to remoteID for each accepted connection.
type TCPListener struct {
	forwarder *TCPForwarder
	listener  net.Listener
	remoteID  string
	accept    func() error
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
}

func (f *TCPForwarder) StartListener(ctx context.Context, address, remoteID string) (*TCPListener, error) {
	return f.StartListenerWithPolicy(ctx, address, remoteID, nil)
}

// StartListenerWithPolicy applies acceptPolicy to every accepted local socket
// before it opens a routed flow. A rejected socket is closed without emitting
// an OPEN frame. This is used by system-visible facades to revalidate a
// virtual-address-to-node mapping against current membership at connection
// time; ordinary loopback listeners should use StartListener.
func (f *TCPForwarder) StartListenerWithPolicy(
	ctx context.Context,
	address, remoteID string,
	acceptPolicy func() error,
) (*TCPListener, error) {
	if f == nil {
		return nil, ErrTCPForwarderClosed
	}
	address = strings.TrimSpace(address)
	remoteID = strings.TrimSpace(remoteID)
	if err := validateTCPAddress("listen", address); err != nil {
		return nil, err
	}
	if remoteID == "" || remoteID == f.endpoint.NodeID() {
		return nil, fmt.Errorf("routed dataplane: valid remote node id is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("routed dataplane: listen TCP on %s: %w", address, err)
	}
	listenerCtx, cancel := context.WithCancel(f.ctx)
	result := &TCPListener{
		forwarder: f,
		listener:  listener,
		remoteID:  remoteID,
		accept:    acceptPolicy,
		ctx:       listenerCtx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		cancel()
		_ = listener.Close()
		return nil, ErrTCPForwarderClosed
	}
	f.listeners[result] = struct{}{}
	f.mu.Unlock()
	if !f.startTask(result.acceptLoop) {
		_ = result.Close()
		return nil, ErrTCPForwarderClosed
	}
	f.startTask(func() {
		select {
		case <-ctx.Done():
			_ = result.Close()
		case <-result.done:
		}
	})
	return result, nil
}

func (l *TCPListener) Addr() net.Addr {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Addr()
}

func (l *TCPListener) Done() <-chan struct{} {
	if l == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return l.done
}

func (l *TCPListener) Close() error {
	if l == nil {
		return nil
	}
	// Close intentionally does not wait for Done. acceptLoop uses this same
	// cleanup path when Accept fails permanently, so waiting here would make
	// the accept goroutine wait for itself.
	var closeErr error
	l.closeOnce.Do(func() {
		l.cancel()
		closeErr = l.listener.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
		if l.forwarder != nil {
			l.forwarder.mu.Lock()
			delete(l.forwarder.listeners, l)
			l.forwarder.mu.Unlock()
		}
	})
	return closeErr
}

func (l *TCPListener) acceptLoop() {
	defer func() {
		// Accept errors do not necessarily close the underlying socket. Always
		// release it and remove this listener from the forwarder registry before
		// reporting completion.
		_ = l.Close()
		close(l.done)
	}()
	var retryDelay time.Duration
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if l.ctx.Err() != nil || !isTemporaryAcceptError(err) {
				return
			}
			retryDelay = nextAcceptRetryDelay(retryDelay)
			if !waitAcceptRetry(l.ctx, retryDelay) {
				return
			}
			continue
		}
		retryDelay = 0
		if l.accept != nil {
			if err := l.accept(); err != nil {
				_ = conn.Close()
				continue
			}
		}
		if !l.forwarder.startTask(func() { l.forwarder.handleAccepted(l.ctx, l.remoteID, conn) }) {
			_ = conn.Close()
			return
		}
	}
}

func isTemporaryAcceptError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}

func nextAcceptRetryDelay(current time.Duration) time.Duration {
	if current <= 0 {
		return initialAcceptRetry
	}
	next := current * 2
	if next > maxAcceptRetry {
		return maxAcceptRetry
	}
	return next
}

func waitAcceptRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (f *TCPForwarder) handleAccepted(ctx context.Context, remoteID string, conn net.Conn) {
	flow := newTCPFlow(f, tcpFlowKey{peerID: remoteID, flowID: f.endpoint.nextFlowID()}, conn, true, 0)
	if !f.addFlow(flow) {
		_ = conn.Close()
		return
	}
	if err := flow.send(mesh.DataTypeStreamOpen, nil); err != nil {
		flow.shutdown()
		return
	}
	openDeadline := time.NewTimer(f.openTimeout)
	defer openDeadline.Stop()
	select {
	case err := <-flow.openResult:
		if err != nil {
			flow.shutdown()
			return
		}
		flow.start()
	case <-ctx.Done():
		flow.completeOpenLocally(ctx.Err())
		flow.fail(ctx.Err(), true)
	case <-f.ctx.Done():
		flow.shutdown()
	case <-flow.done:
	case <-openDeadline.C:
		// OPEN's transport ACK only proves that the responder received the
		// request. OPEN_OK/OPEN_ERROR is a separate result frame, so bound that
		// wait as well. Recheck the result channel because it can become ready at
		// the same instant as the timer.
		timeoutErr := fmt.Errorf("routed dataplane: flow %d OPEN result timeout", flow.key.flowID)
		if flow.completeOpenLocally(timeoutErr) {
			flow.shutdown()
			return
		}
		// Another terminal transition won while the timer was becoming ready.
		// Its buffered result was published under the same lock, so reading it
		// here cannot miss a committed OPEN_OK.
		if err := <-flow.openResult; err == nil {
			flow.start()
		} else {
			flow.shutdown()
		}
	}
}

func (f *TCPForwarder) handleFrame(_ context.Context, frame mesh.DataFrame) error {
	key := tcpFlowKey{peerID: frame.Source, flowID: frame.FlowID}
	if frame.Type == mesh.DataTypeStreamACK {
		if flow := f.lookupFlow(key); flow != nil {
			flow.acknowledge(frame.Sequence)
		}
		return nil
	}
	if frame.Type == mesh.DataTypeStreamOpen {
		if frame.Sequence != 1 {
			f.sendOpenFailure(frame, fmt.Errorf("%w: OPEN sequence is %d", ErrTCPFlowProtocol, frame.Sequence))
			return nil
		}
		if !f.claimOpening(key) {
			f.sendACK(frame)
			return nil
		}
		f.sendACK(frame)
		if !f.startTask(func() { f.handleOpen(frame) }) {
			f.releaseOpening(key)
			return ErrTCPForwarderClosed
		}
		return nil
	}

	flow := f.lookupFlow(key)
	if flow == nil {
		// A RESET sender retransmits until its ACK arrives. The receiver may
		// already have removed the flow after acknowledging an earlier copy, so
		// stale RESETs must still be acknowledged idempotently.
		if frame.Type == mesh.DataTypeStreamReset {
			f.sendACK(frame)
		}
		// The key may also still be in opening while a fixed-target dial is in
		// progress. We deliberately avoid a second cancellation registry here:
		// that dial and any subsequent OPEN_OK send are already bounded by
		// dialTimeout and frameTimeout respectively.
		// Ignore every other stale frame to avoid reset loops after simultaneous
		// close or a route change.
		return nil
	}
	if frame.Type == mesh.DataTypeStreamData || frame.Type == mesh.DataTypeStreamFIN {
		shouldACK, err := flow.enqueueSequenced(frame.Sequence, frame.Type, frame.Payload)
		if errors.Is(err, errTCPInboundQueueFull) {
			// Backpressure is expressed by withholding the ACK. recvSeq is still
			// unchanged, so the sender's retry can enqueue this exact payload once
			// writeLocal has drained capacity.
			return nil
		}
		if err != nil {
			if !f.startTask(func() { flow.fail(err, true) }) {
				flow.shutdown()
			}
			return nil
		}
		if shouldACK {
			f.sendACK(frame)
		}
		return nil
	}
	switch flow.observeSequence(frame.Sequence) {
	case sequenceDuplicate:
		if isOpenResultFrame(frame.Type) && !flow.shouldAcknowledgeOpenResult(frame.Type) {
			return nil
		}
		f.sendACK(frame)
		return nil
	case sequenceFuture:
		// Stop-and-wait permits only one unacknowledged frame. Do not ACK a
		// future sequence; its sender will retry after the missing frame lands.
		return nil
	}

	switch frame.Type {
	case mesh.DataTypeStreamOpenOK:
		if !flow.initiator {
			flow.fail(fmt.Errorf("%w: responder received OPEN_OK", ErrTCPFlowProtocol), true)
			return nil
		}
		if !flow.completeOpenFrame(mesh.DataTypeStreamOpenOK, nil) {
			return nil
		}
		f.sendACK(frame)
	case mesh.DataTypeStreamOpenError:
		if !flow.initiator || flow.isOpened() {
			flow.fail(fmt.Errorf("%w: unexpected OPEN_ERROR", ErrTCPFlowProtocol), true)
			return nil
		}
		reason := strings.TrimSpace(string(frame.Payload))
		if reason == "" {
			reason = "remote target unavailable"
		}
		if !flow.completeOpenFrame(mesh.DataTypeStreamOpenError, fmt.Errorf("%w: %s", ErrTCPOpenRejected, reason)) {
			return nil
		}
		f.sendACK(frame)
		flow.shutdown()
	case mesh.DataTypeStreamReset:
		f.sendACK(frame)
		flow.shutdown()
	default:
		return fmt.Errorf("%w: unsupported frame type %d", ErrTCPFlowProtocol, frame.Type)
	}
	return nil
}

func isOpenResultFrame(frameType mesh.DataType) bool {
	return frameType == mesh.DataTypeStreamOpenOK || frameType == mesh.DataTypeStreamOpenError
}

func (f *TCPForwarder) handleOpen(frame mesh.DataFrame) {
	key := tcpFlowKey{peerID: frame.Source, flowID: frame.FlowID}
	f.mu.Lock()
	target := f.target
	closed := f.closed
	f.mu.Unlock()
	if closed {
		f.releaseOpening(key)
		return
	}
	if target == "" {
		f.releaseOpening(key)
		f.sendOpenFailure(frame, fmt.Errorf("%w: this node has no fixed target", ErrTCPOpenRejected))
		return
	}
	dialCtx, cancel := context.WithTimeout(f.ctx, f.dialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
	if err != nil {
		f.releaseOpening(key)
		f.sendOpenFailure(frame, fmt.Errorf("dial fixed target: %w", err))
		return
	}
	flow := newTCPFlow(f, key, conn, false, frame.Sequence)
	flow.markOpened()
	if !f.promoteOpening(flow) {
		_ = conn.Close()
		return
	}
	if err := flow.send(mesh.DataTypeStreamOpenOK, nil); err != nil {
		flow.shutdown()
		return
	}
	flow.start()
}

func (f *TCPForwarder) sendOpenFailure(open mesh.DataFrame, cause error) {
	payload := []byte(compactStreamError(cause))
	frame := mesh.DataFrame{
		Version:     mesh.DataFrameVersion,
		Type:        mesh.DataTypeStreamOpenError,
		HopLimit:    16,
		Source:      f.endpoint.NodeID(),
		Destination: open.Source,
		FlowID:      open.FlowID,
		Sequence:    1,
		Payload:     payload,
	}
	// Rejected OPENs do not retain a responder flow. Send a short redundant
	// burst so a target-side failure is still likely to reach the initiator.
	for range 3 {
		ctx, cancel := context.WithTimeout(f.ctx, streamRetryInterval)
		_ = f.endpoint.Send(ctx, frame)
		cancel()
	}
}

func (f *TCPForwarder) sendACK(received mesh.DataFrame) {
	ctx, cancel := context.WithTimeout(f.ctx, streamRetryInterval)
	defer cancel()
	_ = f.endpoint.Send(ctx, mesh.DataFrame{
		Version: mesh.DataFrameVersion, Type: mesh.DataTypeStreamACK, HopLimit: 16,
		Source: f.endpoint.NodeID(), Destination: received.Source,
		FlowID: received.FlowID, Sequence: received.Sequence,
	})
}

func (f *TCPForwarder) claimOpening(key tcpFlowKey) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	if _, exists := f.flows[key]; exists {
		return false
	}
	if _, exists := f.opening[key]; exists {
		return false
	}
	f.opening[key] = struct{}{}
	return true
}

func (f *TCPForwarder) releaseOpening(key tcpFlowKey) {
	f.mu.Lock()
	delete(f.opening, key)
	f.mu.Unlock()
}

func (f *TCPForwarder) promoteOpening(flow *tcpFlow) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		delete(f.opening, flow.key)
		return false
	}
	if _, pending := f.opening[flow.key]; !pending {
		return false
	}
	if _, exists := f.flows[flow.key]; exists {
		delete(f.opening, flow.key)
		return false
	}
	delete(f.opening, flow.key)
	f.flows[flow.key] = flow
	return true
}

func (f *TCPForwarder) addFlow(flow *tcpFlow) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	if _, exists := f.flows[flow.key]; exists {
		return false
	}
	f.flows[flow.key] = flow
	return true
}

func (f *TCPForwarder) lookupFlow(key tcpFlowKey) *tcpFlow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flows[key]
}

func (f *TCPForwarder) removeFlow(flow *tcpFlow) {
	f.mu.Lock()
	if f.flows[flow.key] == flow {
		delete(f.flows, flow.key)
	}
	f.mu.Unlock()
}

func (f *TCPForwarder) startTask(task func()) bool {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return false
	}
	f.wg.Add(1)
	f.mu.Unlock()
	go func() {
		defer f.wg.Done()
		task()
	}()
	return true
}

func (f *TCPForwarder) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.cancel()
	listeners := make([]*TCPListener, 0, len(f.listeners))
	for listener := range f.listeners {
		listeners = append(listeners, listener)
	}
	flows := make([]*tcpFlow, 0, len(f.flows))
	for _, flow := range f.flows {
		flows = append(flows, flow)
	}
	unregister := f.unregister
	f.mu.Unlock()
	if unregister != nil {
		unregister()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	for _, flow := range flows {
		flow.shutdown()
	}
	f.wg.Wait()
	return nil
}

type tcpInbound struct {
	typeID  mesh.DataType
	payload []byte
}

type sequenceObservation uint8

const (
	sequenceExpected sequenceObservation = iota
	sequenceDuplicate
	sequenceFuture
)

type tcpFlow struct {
	forwarder *TCPForwarder
	key       tcpFlowKey
	conn      net.Conn
	initiator bool

	sendMu     sync.Mutex
	sendSeq    uint64
	ackMu      sync.Mutex
	pendingSeq uint64
	pendingACK bool
	recvMu     sync.Mutex
	recvSeq    uint64

	stateMu         sync.Mutex
	opened          bool
	openTerminal    bool
	openResultType  mesh.DataType
	localFIN        bool
	remoteFIN       bool
	remoteFINQueued bool

	inbound    chan tcpInbound
	ackNotify  chan struct{}
	openResult chan error
	done       chan struct{}
	startOnce  sync.Once
	closeOnce  sync.Once
}

func newTCPFlow(forwarder *TCPForwarder, key tcpFlowKey, conn net.Conn, initiator bool, recvSeq uint64) *tcpFlow {
	return &tcpFlow{
		forwarder:  forwarder,
		key:        key,
		conn:       conn,
		initiator:  initiator,
		recvSeq:    recvSeq,
		inbound:    make(chan tcpInbound, tcpInboundQueueSize),
		ackNotify:  make(chan struct{}, 1),
		openResult: make(chan error, 1),
		done:       make(chan struct{}),
	}
}

func (f *tcpFlow) start() {
	f.startOnce.Do(func() {
		if !f.forwarder.startTask(f.readLocal) {
			f.shutdown()
			return
		}
		if !f.forwarder.startTask(f.writeLocal) {
			f.shutdown()
		}
	})
}

func (f *tcpFlow) send(frameType mesh.DataType, payload []byte) error {
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	select {
	case <-f.done:
		return ErrTCPForwarderClosed
	default:
	}
	sequence := f.sendSeq + 1
	f.beginPending(sequence)
	defer f.clearPending(sequence)
	frame := mesh.DataFrame{
		Version:     mesh.DataFrameVersion,
		Type:        frameType,
		HopLimit:    16,
		Source:      f.forwarder.endpoint.NodeID(),
		Destination: f.key.peerID,
		FlowID:      f.key.flowID,
		Sequence:    sequence,
		Payload:     append([]byte(nil), payload...),
	}
	deadline := time.NewTimer(f.forwarder.frameTimeout)
	defer deadline.Stop()
	var lastErr error
	for {
		if f.finishAcknowledged(sequence) {
			return nil
		}
		attemptCtx, cancel := context.WithTimeout(f.forwarder.ctx, streamRetryInterval)
		lastErr = f.forwarder.endpoint.Send(attemptCtx, frame)
		cancel()
		if f.finishAcknowledged(sequence) {
			return nil
		}
		retry := time.NewTimer(streamRetryInterval)
		for {
			select {
			case <-f.ackNotify:
				if f.finishAcknowledged(sequence) {
					if !retry.Stop() {
						select {
						case <-retry.C:
						default:
						}
					}
					return nil
				}
			case <-retry.C:
				goto retransmit
			case <-deadline.C:
				if !retry.Stop() {
					select {
					case <-retry.C:
					default:
					}
				}
				// The ACK notification and deadline can become ready together. The
				// timer winning select must not turn an already-recorded ACK into a
				// false timeout.
				if f.finishAcknowledgedAtDeadline(sequence) {
					return nil
				}
				if lastErr != nil {
					return fmt.Errorf("routed dataplane: flow %d sequence %d ACK timeout after send error: %w", f.key.flowID, sequence, lastErr)
				}
				return fmt.Errorf("routed dataplane: flow %d sequence %d ACK timeout", f.key.flowID, sequence)
			case <-f.done:
				if !retry.Stop() {
					select {
					case <-retry.C:
					default:
					}
				}
				return ErrTCPForwarderClosed
			case <-f.forwarder.ctx.Done():
				if !retry.Stop() {
					select {
					case <-retry.C:
					default:
					}
				}
				return f.forwarder.ctx.Err()
			}
		}
	retransmit:
	}
}

func (f *tcpFlow) finishAcknowledged(sequence uint64) bool {
	f.ackMu.Lock()
	acknowledged := f.pendingSeq == sequence && f.pendingACK
	f.ackMu.Unlock()
	if !acknowledged {
		return false
	}
	f.sendSeq = sequence
	return true
}

// finishAcknowledgedAtDeadline linearizes the last ACK check with expiration
// of the exact pending sequence. If the deadline wins the lock, a later ACK is
// stale and cannot leak into another send attempt.
func (f *tcpFlow) finishAcknowledgedAtDeadline(sequence uint64) bool {
	f.ackMu.Lock()
	if f.pendingSeq != sequence {
		f.ackMu.Unlock()
		return false
	}
	if !f.pendingACK {
		f.pendingSeq = 0
		f.ackMu.Unlock()
		return false
	}
	f.ackMu.Unlock()
	f.sendSeq = sequence
	return true
}

func (f *tcpFlow) beginPending(sequence uint64) {
	f.ackMu.Lock()
	f.pendingSeq = sequence
	f.pendingACK = false
	f.ackMu.Unlock()
}

func (f *tcpFlow) clearPending(sequence uint64) {
	f.ackMu.Lock()
	if f.pendingSeq == sequence {
		f.pendingSeq = 0
		f.pendingACK = false
	}
	f.ackMu.Unlock()
}

func (f *tcpFlow) acknowledge(sequence uint64) {
	f.ackMu.Lock()
	if f.pendingSeq != sequence || f.pendingACK {
		f.ackMu.Unlock()
		return
	}
	f.pendingACK = true
	f.ackMu.Unlock()
	select {
	case f.ackNotify <- struct{}{}:
	default:
	}
}

func (f *tcpFlow) observeSequence(sequence uint64) sequenceObservation {
	f.recvMu.Lock()
	defer f.recvMu.Unlock()
	want := f.recvSeq + 1
	if sequence < want {
		return sequenceDuplicate
	}
	if sequence > want {
		return sequenceFuture
	}
	f.recvSeq = sequence
	return sequenceExpected
}

// enqueueSequenced atomically couples receive-sequence advancement and the ACK
// decision to inbound queue admission. A duplicate has already been admitted
// and is ACKed again, while a future or queue-blocked frame remains unacknowledged.
func (f *tcpFlow) enqueueSequenced(sequence uint64, frameType mesh.DataType, payload []byte) (bool, error) {
	f.recvMu.Lock()
	defer f.recvMu.Unlock()
	want := f.recvSeq + 1
	if sequence < want {
		return true, nil
	}
	if sequence > want {
		return false, nil
	}
	if err := f.enqueue(frameType, payload); err != nil {
		return false, err
	}
	f.recvSeq = sequence
	return true, nil
}

// completeOpenFrame commits a remotely received OPEN result. The result frame
// type is retained so only duplicates of the transition that actually won are
// ACKed. A timeout or local close uses completeOpenLocally and therefore cannot
// be mistaken for an accepted late OPEN_OK.
func (f *tcpFlow) completeOpenFrame(frameType mesh.DataType, err error) bool {
	return f.completeOpen(frameType, err)
}

func (f *tcpFlow) completeOpenLocally(err error) bool {
	return f.completeOpen(0, err)
}

func (f *tcpFlow) completeOpen(resultType mesh.DataType, err error) bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	if f.openTerminal {
		return false
	}
	f.openTerminal = true
	f.openResultType = resultType
	if resultType == mesh.DataTypeStreamOpenOK && err == nil {
		f.opened = true
	}
	// openResult has capacity one and this is the sole terminal publisher.
	// Publish before releasing stateMu so a losing timeout transition can read
	// the committed outcome immediately.
	f.openResult <- err
	return true
}

func (f *tcpFlow) shouldAcknowledgeOpenResult(frameType mesh.DataType) bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return f.openTerminal && f.openResultType == frameType
}

func (f *tcpFlow) enqueue(frameType mesh.DataType, payload []byte) error {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	if !f.opened {
		return fmt.Errorf("%w: frame %d before OPEN_OK", ErrTCPFlowProtocol, frameType)
	}
	remoteFIN := f.remoteFIN || f.remoteFINQueued
	if remoteFIN {
		return fmt.Errorf("%w: frame %d after FIN", ErrTCPFlowProtocol, frameType)
	}
	event := tcpInbound{typeID: frameType, payload: append([]byte(nil), payload...)}
	select {
	case <-f.done:
		return ErrTCPForwarderClosed
	case f.inbound <- event:
		if frameType == mesh.DataTypeStreamFIN {
			f.remoteFINQueued = true
		}
		return nil
	default:
		return fmt.Errorf("%w: flow %d", errTCPInboundQueueFull, f.key.flowID)
	}
}

func (f *tcpFlow) markOpened() bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	if f.opened {
		return false
	}
	f.opened = true
	return true
}

func (f *tcpFlow) isOpened() bool {
	f.stateMu.Lock()
	defer f.stateMu.Unlock()
	return f.opened
}

func (f *tcpFlow) readLocal() {
	buffer := make([]byte, tcpReadBufferSize)
	for {
		n, err := f.conn.Read(buffer)
		if n > 0 {
			if sendErr := f.send(mesh.DataTypeStreamData, buffer[:n]); sendErr != nil {
				f.shutdown()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if sendErr := f.send(mesh.DataTypeStreamFIN, nil); sendErr != nil {
					f.shutdown()
					return
				}
				f.markLocalFIN()
				return
			}
			select {
			case <-f.done:
				return
			default:
			}
			f.fail(err, true)
			return
		}
	}
}

func (f *tcpFlow) writeLocal() {
	for {
		select {
		case <-f.done:
			return
		case event := <-f.inbound:
			switch event.typeID {
			case mesh.DataTypeStreamData:
				if err := writeAll(f.conn, event.payload); err != nil {
					f.fail(err, true)
					return
				}
			case mesh.DataTypeStreamFIN:
				if closeWriter, ok := f.conn.(interface{ CloseWrite() error }); ok {
					if err := closeWriter.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
						f.fail(err, true)
						return
					}
				} else {
					f.fail(fmt.Errorf("TCP connection does not support half-close"), true)
					return
				}
				f.markRemoteFIN()
			}
		}
	}
}

func (f *tcpFlow) markLocalFIN() {
	f.stateMu.Lock()
	f.localFIN = true
	complete := f.remoteFIN
	f.stateMu.Unlock()
	if complete {
		f.shutdown()
	}
}

func (f *tcpFlow) markRemoteFIN() {
	f.stateMu.Lock()
	f.remoteFIN = true
	complete := f.localFIN
	f.stateMu.Unlock()
	if complete {
		f.shutdown()
	}
}

func (f *tcpFlow) fail(cause error, notify bool) {
	f.completeOpenLocally(cause)
	if notify {
		_ = f.send(mesh.DataTypeStreamReset, []byte(compactStreamError(cause)))
	}
	f.shutdown()
}

func (f *tcpFlow) shutdown() {
	f.closeOnce.Do(func() {
		f.completeOpenLocally(ErrTCPForwarderClosed)
		close(f.done)
		_ = f.conn.Close()
		f.forwarder.removeFlow(f)
	})
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func validateTCPAddress(label, address string) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("routed dataplane: %s TCP address is required", label)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return fmt.Errorf("routed dataplane: invalid %s TCP address %q: %w", label, address, err)
	}
	return nil
}

func validateLoopbackTCPAddress(label, address string) error {
	if err := validateTCPAddress(label, address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("routed dataplane: %s TCP address %q must use a loopback host", label, address)
	}
	return nil
}

func compactStreamError(err error) string {
	if err == nil {
		return "stream reset"
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		message = "stream reset"
	}
	if len(message) > maxStreamErrorLength {
		message = message[:maxStreamErrorLength]
	}
	return message
}

func saturatingDurationAdd(left, right time.Duration) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if left > maxDuration-right {
		return maxDuration
	}
	return left + right
}
