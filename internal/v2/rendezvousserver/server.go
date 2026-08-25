// Package rendezvousserver implements one bounded WYRC v1 association. It is
// an opaque TLS stream forwarder, not signaling, coordination, relay, mailbox,
// membership, or a pairing trust anchor.
package rendezvousserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"winkyou/internal/v2/rendezvouswire"
)

const (
	MaxAssociations        = 1
	MaxSlots               = 2
	MaxAcceptedConnections = 2
	MaxListeners           = 1
	PresenceTimeout        = 3 * time.Second
	AssociationLifetime    = 13 * time.Second
	MaxFramesPerDirection  = 8
	MaxApplicationBytes    = MaxFramesPerDirection * (rendezvouswire.HeaderBytes + rendezvouswire.MaxPayloadBytes)
)

type TerminalClass string

const (
	ClassCompleted           TerminalClass = "completed"
	ClassAssociationExpired  TerminalClass = "association_expired"
	ClassPresenceTimeout     TerminalClass = "presence_timeout"
	ClassAssociationRejected TerminalClass = "association_rejected"
	ClassProtocolViolation   TerminalClass = "protocol_violation"
	ClassBudgetExceeded      TerminalClass = "budget_exceeded"
	ClassTLSFailed           TerminalClass = "tls_failed"
	ClassPeerDisconnected    TerminalClass = "peer_disconnected"
	ClassDeadlineExceeded    TerminalClass = "deadline_exceeded"
	ClassShutdown            TerminalClass = "shutdown"
	ClassInternalError       TerminalClass = "internal_error"
)

type TerminalRecord struct {
	Event               string        `json:"event"`
	Class               TerminalClass `json:"class"`
	AcceptedConnections int           `json:"accepted_connections"`
	FramesRead          int           `json:"frames_read"`
	FramesWritten       int           `json:"frames_written"`
	BytesRead           int           `json:"bytes_read"`
	BytesWritten        int           `json:"bytes_written"`
}

type Config struct {
	ListenAddress   string
	TLSCertFile     string
	TLSKeyFile      string
	AssociationFile string
}

type side struct {
	slot rendezvouswire.Slot
	conn *tls.Conn

	writeMu                   sync.Mutex
	framesRead, framesWritten int
	bytesRead, bytesWritten   int
	handshakeRead             bool
	controlRead               int
}

type presenceResult struct {
	side        *side
	class       TerminalClass
	association string
}

type relayEvent struct {
	side  *side
	frame rendezvouswire.Frame
	bytes int
	err   error
}

type acceptResult struct {
	connection net.Conn
	class      TerminalClass
}

func Serve(ctx context.Context, config Config) TerminalRecord {
	record := TerminalRecord{Event: "terminal", Class: ClassInternalError}
	if ctx == nil || !validListenAddress(config.ListenAddress) || config.TLSCertFile == "" || config.TLSKeyFile == "" || config.AssociationFile == "" {
		return record
	}
	now := time.Now().UTC()
	admission, err := loadAdmission(config.AssociationFile, now)
	if err != nil {
		record.Class = ClassAssociationRejected
		return record
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		record.Class = ClassTLSFailed
		return record
	}
	listener, err := listenOneShot(config.ListenAddress)
	if err != nil {
		return record
	}
	server := &associationServer{
		listener: listener,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		},
		admission: admission,
	}
	return server.run(ctx, record)
}

type associationServer struct {
	listener      net.Listener
	tlsConfig     *tls.Config
	admission     validatedAdmission
	connectionsMu sync.Mutex
	connections   []net.Conn
	sides         []*side
}

func (server *associationServer) run(ctx context.Context, record TerminalRecord) TerminalRecord {
	defer func() {
		_ = server.listener.Close()
		server.closeConnections()
	}()

	first, class := server.accept(ctx, server.admission.expiresAt)
	if class != "" {
		record.Class = class
		return server.snapshot(record)
	}
	record.AcceptedConnections = 1
	started := time.Now()
	associationDeadline := started.Add(AssociationLifetime)
	presenceDeadline := started.Add(PresenceTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(associationDeadline) {
		associationDeadline = ctxDeadline
	}
	associationCtx, cancel := context.WithDeadline(ctx, associationDeadline)
	defer cancel()

	presenceResults := make(chan presenceResult, MaxSlots)
	server.readPresence(associationCtx, first, presenceDeadline, presenceResults)
	secondResult := make(chan acceptResult, 1)
	go func() {
		connection, terminal := server.accept(associationCtx, presenceDeadline)
		secondResult <- acceptResult{connection: connection, class: terminal}
	}()
	drainSecondAccept := func() {
		_ = server.listener.Close()
		pending := <-secondResult
		if pending.connection != nil {
			record.AcceptedConnections = 2
			_ = pending.connection.Close()
		}
	}

	var firstPresence *presenceResult
	var second net.Conn
	for second == nil {
		select {
		case result := <-presenceResults:
			if result.class != "" {
				drainSecondAccept()
				_ = first.Close()
				record.Class = result.class
				return server.snapshot(record)
			}
			firstPresence = &result
			server.sides = append(server.sides, result.side)
		case accepted := <-secondResult:
			if accepted.class != "" {
				_ = first.Close()
				record.Class = accepted.class
				return server.snapshot(record)
			}
			second = accepted.connection
			record.AcceptedConnections = 2
			_ = server.listener.Close()
		case <-associationCtx.Done():
			drainSecondAccept()
			_ = first.Close()
			record.Class = contextClass(ctx, ClassPresenceTimeout)
			return server.snapshot(record)
		}
	}
	server.readPresence(associationCtx, second, presenceDeadline, presenceResults)
	results := make([]presenceResult, 0, 2)
	if firstPresence != nil {
		results = append(results, *firstPresence)
	}
	for len(results) < 2 {
		select {
		case result := <-presenceResults:
			if result.class != "" {
				record.Class = result.class
				return server.snapshot(record)
			}
			results = append(results, result)
			server.sides = append(server.sides, result.side)
		case <-associationCtx.Done():
			record.Class = contextClass(ctx, ClassPresenceTimeout)
			return server.snapshot(record)
		}
	}
	bySlot := make(map[rendezvouswire.Slot]*side, 2)
	for _, result := range results {
		if result.association != server.admission.associationID || bySlot[result.side.slot] != nil {
			record.Class = ClassAssociationRejected
			return server.snapshot(record)
		}
		bySlot[result.side.slot] = result.side
	}
	if bySlot[rendezvouswire.SlotA] == nil || bySlot[rendezvouswire.SlotB] == nil {
		record.Class = ClassAssociationRejected
		return server.snapshot(record)
	}

	if !server.writeBoth(associationCtx, bySlot, rendezvouswire.KindPresenceReady) {
		record.Class = contextClass(ctx, ClassPeerDisconnected)
		return server.snapshot(record)
	}
	if class := server.awaitActivation(associationCtx, bySlot); class != "" {
		record.Class = class
		return server.snapshot(record)
	}
	if !server.writeBoth(associationCtx, bySlot, rendezvouswire.KindActivateReady) {
		record.Class = contextClass(ctx, ClassPeerDisconnected)
		return server.snapshot(record)
	}
	record.Class = server.relay(associationCtx, bySlot)
	return server.snapshot(record)
}

func (server *associationServer) accept(ctx context.Context, deadline time.Time) (net.Conn, TerminalClass) {
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 1)
	go func() {
		connection, err := server.listener.Accept()
		results <- result{conn: connection, err: err}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case accepted := <-results:
		if accepted.err != nil {
			if ctx.Err() != nil {
				return nil, contextClass(ctx, ClassDeadlineExceeded)
			}
			return nil, ClassInternalError
		}
		server.trackConnection(accepted.conn)
		return accepted.conn, ""
	case <-ctx.Done():
		_ = server.listener.Close()
		return nil, contextClass(ctx, ClassDeadlineExceeded)
	case <-timer.C:
		_ = server.listener.Close()
		if deadline.Equal(server.admission.expiresAt) {
			return nil, ClassAssociationExpired
		}
		return nil, ClassPresenceTimeout
	}
}

func (server *associationServer) trackConnection(connection net.Conn) {
	if connection == nil {
		return
	}
	server.connectionsMu.Lock()
	server.connections = append(server.connections, connection)
	server.connectionsMu.Unlock()
}

func (server *associationServer) closeConnections() {
	server.connectionsMu.Lock()
	connections := append([]net.Conn(nil), server.connections...)
	server.connections = nil
	server.connectionsMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (server *associationServer) acceptedConnections() int {
	server.connectionsMu.Lock()
	defer server.connectionsMu.Unlock()
	return len(server.connections)
}

func (server *associationServer) readPresence(ctx context.Context, raw net.Conn, deadline time.Time, output chan<- presenceResult) {
	go func() {
		connection := tls.Server(raw, server.tlsConfig.Clone())
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			output <- presenceResult{class: ClassTLSFailed}
			return
		}
		if err := connection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			output <- presenceResult{class: contextClass(ctx, ClassTLSFailed)}
			return
		}
		frame, count, err := rendezvouswire.Decode(connection)
		if err != nil || frame.Kind != rendezvouswire.KindPresence {
			clear(frame.Payload)
			_ = connection.Close()
			class := ClassProtocolViolation
			if err != nil {
				class = classifyReadError(ctx, err, ClassPresenceTimeout)
			}
			output <- presenceResult{class: class}
			return
		}
		association, slot, err := rendezvouswire.ParsePresencePayload(frame.Payload)
		clear(frame.Payload)
		if err != nil {
			_ = connection.Close()
			output <- presenceResult{class: ClassProtocolViolation}
			return
		}
		_ = connection.SetDeadline(time.Time{})
		current := &side{slot: slot, conn: connection, framesRead: 1, bytesRead: count}
		output <- presenceResult{side: current, association: association}
	}()
}

func (server *associationServer) awaitActivation(ctx context.Context, sides map[rendezvouswire.Slot]*side) TerminalClass {
	type result struct {
		side  *side
		frame rendezvouswire.Frame
		count int
		err   error
	}
	results := make(chan result, 2)
	for _, current := range sides {
		go func(current *side) {
			frame, count, err := readFrame(ctx, current.conn)
			results <- result{side: current, frame: frame, count: count, err: err}
		}(current)
	}
	for range 2 {
		select {
		case current := <-results:
			if current.err != nil {
				return classifyReadError(ctx, current.err, ClassDeadlineExceeded)
			}
			defer clear(current.frame.Payload)
			if current.frame.Kind != rendezvouswire.KindActivate || !current.side.chargeRead(current.count) {
				if current.side.framesRead > MaxFramesPerDirection || current.side.bytesRead > MaxApplicationBytes {
					return ClassBudgetExceeded
				}
				return ClassProtocolViolation
			}
		case <-ctx.Done():
			return contextClass(ctx, ClassDeadlineExceeded)
		}
	}
	return ""
}

func (server *associationServer) writeBoth(ctx context.Context, sides map[rendezvouswire.Slot]*side, kind rendezvouswire.Kind) bool {
	for _, slot := range []rendezvouswire.Slot{rendezvouswire.SlotA, rendezvouswire.SlotB} {
		if err := sides[slot].write(ctx, kind, nil); err != nil {
			return false
		}
	}
	return true
}

func (server *associationServer) relay(ctx context.Context, sides map[rendezvouswire.Slot]*side) TerminalClass {
	relayCtx, cancelRelay := context.WithCancel(ctx)
	events := make(chan relayEvent)
	var readers sync.WaitGroup
	for _, current := range sides {
		readers.Add(1)
		go func(current *side) {
			defer readers.Done()
			for {
				frame, count, err := readFrame(relayCtx, current.conn)
				select {
				case events <- relayEvent{side: current, frame: frame, bytes: count, err: err}:
				case <-relayCtx.Done():
					clear(frame.Payload)
					return
				}
				if err != nil {
					return
				}
			}
		}(current)
	}
	defer func() {
		cancelRelay()
		for _, current := range sides {
			_ = current.conn.Close()
		}
		readers.Wait()
	}()

	for {
		select {
		case event := <-events:
			if event.err != nil {
				return classifyReadError(ctx, event.err, ClassDeadlineExceeded)
			}
			if !event.side.chargeRead(event.bytes) {
				clear(event.frame.Payload)
				return ClassBudgetExceeded
			}
			if !event.side.validOpaqueOrder(event.frame.Kind) {
				clear(event.frame.Payload)
				return ClassProtocolViolation
			}
			peer := sides[rendezvouswire.SlotA]
			if event.side.slot == rendezvouswire.SlotA {
				peer = sides[rendezvouswire.SlotB]
			}
			err := peer.write(relayCtx, event.frame.Kind, event.frame.Payload)
			clear(event.frame.Payload)
			if err != nil {
				if errors.Is(err, errBudget) {
					return ClassBudgetExceeded
				}
				return contextClass(ctx, ClassPeerDisconnected)
			}
			if completedOpaqueEnvelope(sides) {
				return ClassCompleted
			}
		case <-relayCtx.Done():
			return contextClass(ctx, ClassDeadlineExceeded)
		}
	}
}

var errBudget = errors.New("rendezvousserver: application budget exceeded")

func (current *side) chargeRead(count int) bool {
	current.framesRead++
	current.bytesRead += count
	return current.framesRead <= MaxFramesPerDirection && current.bytesRead <= MaxApplicationBytes
}

func (current *side) write(ctx context.Context, kind rendezvouswire.Kind, payload []byte) error {
	frame, err := rendezvouswire.Encode(kind, payload)
	if err != nil {
		return err
	}
	defer clear(frame)
	current.writeMu.Lock()
	defer current.writeMu.Unlock()
	if current.framesWritten >= MaxFramesPerDirection || current.bytesWritten+len(frame) > MaxApplicationBytes {
		return errBudget
	}
	if err := setOperationDeadline(ctx, current.conn); err != nil {
		return err
	}
	written, err := current.conn.Write(frame)
	_ = current.conn.SetWriteDeadline(time.Time{})
	if err != nil || written != len(frame) {
		return io.ErrShortWrite
	}
	current.framesWritten++
	current.bytesWritten += written
	return nil
}

func (current *side) validOpaqueOrder(kind rendezvouswire.Kind) bool {
	switch kind {
	case rendezvouswire.KindHandshake:
		if current.handshakeRead || current.controlRead != 0 {
			return false
		}
		current.handshakeRead = true
		return true
	case rendezvouswire.KindControl:
		if !current.handshakeRead {
			return false
		}
		current.controlRead++
		maximum := 4
		if current.slot == rendezvouswire.SlotB {
			maximum = 3
		}
		return current.controlRead <= maximum
	default:
		return false
	}
}

func completedOpaqueEnvelope(sides map[rendezvouswire.Slot]*side) bool {
	a, b := sides[rendezvouswire.SlotA], sides[rendezvouswire.SlotB]
	return a.handshakeRead && b.handshakeRead && a.controlRead == 4 && b.controlRead == 3
}

func readFrame(ctx context.Context, connection net.Conn) (rendezvouswire.Frame, int, error) {
	if err := setOperationDeadline(ctx, connection); err != nil {
		return rendezvouswire.Frame{}, 0, err
	}
	frame, count, err := rendezvouswire.Decode(connection)
	_ = connection.SetReadDeadline(time.Time{})
	return frame, count, err
}

func setOperationDeadline(ctx context.Context, connection net.Conn) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.DeadlineExceeded
	}
	return connection.SetDeadline(deadline)
}

func (server *associationServer) snapshot(record TerminalRecord) TerminalRecord {
	record.AcceptedConnections = server.acceptedConnections()
	for _, current := range server.sides {
		if current == nil {
			continue
		}
		record.FramesRead += current.framesRead
		record.FramesWritten += current.framesWritten
		record.BytesRead += current.bytesRead
		record.BytesWritten += current.bytesWritten
	}
	return record
}

func validListenAddress(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.String() != host || address.Zone() != "" || address.Unmap() != address || address.IsMulticast() {
		return false
	}
	return address.IsUnspecified() || address.IsLoopback() || address.IsGlobalUnicast()
}

func contextClass(parent context.Context, fallback TerminalClass) TerminalClass {
	if errors.Is(parent.Err(), context.Canceled) {
		return ClassShutdown
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) {
		return ClassDeadlineExceeded
	}
	return fallback
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func classifyReadError(ctx context.Context, err error, timeoutClass TerminalClass) TerminalClass {
	if errors.Is(err, rendezvouswire.ErrFrameTooLarge) {
		return ClassBudgetExceeded
	}
	if errors.Is(err, rendezvouswire.ErrInvalidFrame) {
		return ClassProtocolViolation
	}
	if isTimeout(err) {
		return contextClass(ctx, timeoutClass)
	}
	return contextClass(ctx, ClassPeerDisconnected)
}

func MarshalTerminal(record TerminalRecord) []byte {
	payload, err := json.Marshal(record)
	if err != nil {
		return []byte(`{"event":"terminal","class":"internal_error","accepted_connections":0,"frames_read":0,"frames_written":0,"bytes_read":0,"bytes_written":0}`)
	}
	return payload
}
