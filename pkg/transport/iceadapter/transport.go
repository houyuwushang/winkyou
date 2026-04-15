package iceadapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"winkyou/pkg/transport"
)

type deadlineConn interface {
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type packetConnAdapter struct {
	conn      net.Conn
	pathID    string
	closeOnce sync.Once
}

func New(conn net.Conn, pathID string) transport.PacketTransport {
	return &packetConnAdapter{conn: conn, pathID: pathID}
}

func (a *packetConnAdapter) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	if a.conn == nil {
		return 0, transport.PacketMeta{}, net.ErrClosed
	}
	if len(dst) == 0 {
		return 0, transport.PacketMeta{}, nil
	}

	if err := applyReadDeadline(ctx, a.conn); err != nil {
		return 0, transport.PacketMeta{}, err
	}
	n, err := a.conn.Read(dst)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, transport.PacketMeta{}, ctxErr
		}
		return 0, transport.PacketMeta{}, err
	}
	return n, transport.PacketMeta{
		ReceivedAt: time.Now(),
		PathID:     a.pathID,
	}, nil
}

func (a *packetConnAdapter) WritePacket(ctx context.Context, pkt []byte) error {
	if a.conn == nil {
		return net.ErrClosed
	}
	if len(pkt) == 0 {
		return nil
	}
	if err := applyWriteDeadline(ctx, a.conn); err != nil {
		return err
	}
	written, err := a.conn.Write(pkt)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	if written != len(pkt) {
		return fmt.Errorf("transport: short packet write %d/%d", written, len(pkt))
	}
	return nil
}

func (a *packetConnAdapter) LocalAddr() net.Addr {
	if a.conn == nil {
		return nil
	}
	return a.conn.LocalAddr()
}

func (a *packetConnAdapter) RemoteAddr() net.Addr {
	if a.conn == nil {
		return nil
	}
	return a.conn.RemoteAddr()
}

func (a *packetConnAdapter) Close() error {
	var err error
	a.closeOnce.Do(func() {
		if a.conn != nil {
			err = a.conn.Close()
		}
	})
	return err
}

func applyReadDeadline(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return net.ErrClosed
	}
	deadliner, ok := conn.(deadlineConn)
	if !ok {
		return nil
	}
	deadline := deadlineFromContext(ctx)
	if deadline.IsZero() {
		return deadliner.SetReadDeadline(time.Time{})
	}
	return deadliner.SetReadDeadline(deadline)
}

func applyWriteDeadline(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return net.ErrClosed
	}
	deadliner, ok := conn.(deadlineConn)
	if !ok {
		return nil
	}
	deadline := deadlineFromContext(ctx)
	if deadline.IsZero() {
		return deadliner.SetWriteDeadline(time.Time{})
	}
	return deadliner.SetWriteDeadline(deadline)
}

func deadlineFromContext(ctx context.Context) time.Time {
	if ctx == nil {
		return time.Time{}
	}
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	if err := ctx.Err(); err != nil && errors.Is(err, context.Canceled) {
		return time.Now()
	}
	return time.Time{}
}
