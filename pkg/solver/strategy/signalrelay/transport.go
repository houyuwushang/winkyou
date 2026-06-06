package signalrelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/solver"
	"winkyou/pkg/transport"
)

const (
	defaultQueueSize   = 256
	closeSendTimeout   = 250 * time.Millisecond
	maxPacketSizeBytes = 64 * 1024
)

var errTransportClosed = errors.New("signalrelay: transport closed")

type packet struct {
	data       []byte
	receivedAt time.Time
}

type signalTransport struct {
	sessionID string
	planID    string
	localID   string
	remoteID  string
	pathID    string
	sess      solver.SessionIO

	recvCh  chan packet
	closeCh chan struct{}
	closed  atomic.Bool
	seq     atomic.Uint64
	once    sync.Once
}

func (t *signalTransport) AcceptsMessage(msg solver.Message) bool {
	if t == nil || !IsMessage(msg) {
		return false
	}
	switch msg.Type {
	case MessageTypePacket:
		payload, err := unmarshalPacketPayload(msg.Payload)
		if err != nil {
			return false
		}
		return acceptSignalMessage(payload.SessionID, payload.PlanID, t.sessionID)
	case MessageTypeClose:
		payload, err := unmarshalClosePayload(msg.Payload)
		if err != nil {
			return false
		}
		return acceptSignalMessage(payload.SessionID, payload.PlanID, t.sessionID)
	default:
		return false
	}
}

func (t *signalTransport) HandleMessage(ctx context.Context, sess solver.SessionIO, msg solver.Message) error {
	_ = ctx
	_ = sess
	if t == nil || !IsMessage(msg) {
		return nil
	}
	receivedAt := msg.ReceivedAt
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	switch msg.Type {
	case MessageTypePacket:
		payload, err := unmarshalPacketPayload(msg.Payload)
		if err != nil {
			return err
		}
		return t.handlePacket(payload, receivedAt)
	case MessageTypeClose:
		payload, err := unmarshalClosePayload(msg.Payload)
		if err != nil {
			return err
		}
		return t.handleClose(payload)
	default:
		return nil
	}
}

func newSignalTransport(input solver.SolveInput, plan solver.Plan, sess solver.SessionIO, queueSize int) *signalTransport {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	pathID := "signalrelay:coordinator_signal:" + input.SessionID
	return &signalTransport{
		sessionID: input.SessionID,
		planID:    plan.ID,
		localID:   input.LocalNodeID,
		remoteID:  input.RemoteNodeID,
		pathID:    pathID,
		sess:      sess,
		recvCh:    make(chan packet, queueSize),
		closeCh:   make(chan struct{}),
	}
}

func (t *signalTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case pkt := <-t.recvCh:
		n := copy(dst, pkt.data)
		if n < len(pkt.data) {
			return n, transport.PacketMeta{PathID: t.pathID, ReceivedAt: pkt.receivedAt}, fmt.Errorf("signalrelay: packet truncated from %d to %d bytes", len(pkt.data), n)
		}
		if pkt.receivedAt.IsZero() {
			pkt.receivedAt = time.Now()
		}
		return n, transport.PacketMeta{PathID: t.pathID, ReceivedAt: pkt.receivedAt}, nil
	case <-t.closeCh:
		return 0, transport.PacketMeta{}, errTransportClosed
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	}
}

func (t *signalTransport) WritePacket(ctx context.Context, pkt []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if t.closed.Load() {
		return errTransportClosed
	}
	if len(pkt) == 0 {
		return nil
	}
	if len(pkt) > maxPacketSizeBytes {
		return fmt.Errorf("signalrelay: packet too large: %d bytes", len(pkt))
	}
	payload, err := marshalPacketPayload(packetPayload{
		SessionID: t.sessionID,
		PlanID:    t.planID,
		Seq:       t.seq.Add(1),
		Data:      append([]byte(nil), pkt...),
		SentAt:    time.Now(),
	})
	if err != nil {
		return err
	}
	return t.sess.Send(ctx, NewMessage(MessageTypePacket, payload, time.Now()))
}

func (t *signalTransport) LocalAddr() net.Addr {
	return signalAddr{nodeID: t.localID}
}

func (t *signalTransport) RemoteAddr() net.Addr {
	return signalAddr{nodeID: t.remoteID}
}

func (t *signalTransport) Close() error {
	var err error
	t.once.Do(func() {
		t.closed.Store(true)
		if t.sess != nil {
			ctx, cancel := context.WithTimeout(context.Background(), closeSendTimeout)
			defer cancel()
			payload, marshalErr := marshalClosePayload(closePayload{
				SessionID: t.sessionID,
				PlanID:    t.planID,
				Reason:    "local_close",
				SentAt:    time.Now(),
			})
			if marshalErr != nil {
				err = marshalErr
			} else if sendErr := t.sess.Send(ctx, NewMessage(MessageTypeClose, payload, time.Now())); sendErr != nil {
				err = sendErr
			}
		}
		close(t.closeCh)
	})
	return err
}

func (t *signalTransport) deliver(payload packetPayload, receivedAt time.Time) {
	if t == nil || t.closed.Load() || len(payload.Data) == 0 {
		return
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	pkt := packet{data: append([]byte(nil), payload.Data...), receivedAt: receivedAt}
	select {
	case t.recvCh <- pkt:
	default:
		select {
		case <-t.recvCh:
		default:
		}
		t.recvCh <- pkt
	}
}

func (t *signalTransport) handlePacket(payload packetPayload, receivedAt time.Time) error {
	if t == nil {
		return nil
	}
	if !acceptSignalMessage(payload.SessionID, payload.PlanID, t.sessionID) {
		return nil
	}
	t.deliver(payload, receivedAt)
	return nil
}

func (t *signalTransport) handleClose(payload closePayload) error {
	if t == nil {
		return nil
	}
	if !acceptSignalMessage(payload.SessionID, payload.PlanID, t.sessionID) {
		return nil
	}
	t.remoteClose()
	return nil
}

func (t *signalTransport) remoteClose() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		t.closed.Store(true)
		close(t.closeCh)
	})
}

type signalAddr struct {
	nodeID string
}

func (a signalAddr) Network() string { return StrategyName }

func (a signalAddr) String() string {
	if a.nodeID == "" {
		return StrategyName + ":unknown"
	}
	return StrategyName + ":" + a.nodeID
}
