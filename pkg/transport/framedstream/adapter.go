package framedstream

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"winkyou/pkg/transport"
)

const DefaultMaxFrameSize = 64 * 1024

type deadlineConn interface {
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Adapter wraps a framed stream net.Conn as a PacketTransport.
// Frame format: 4-byte big-endian length prefix + payload.
type Adapter struct {
	conn         net.Conn
	reader       *bufio.Reader
	pathID       string
	maxFrameSize int
	readMu       sync.Mutex
	writeMu      sync.Mutex
	closeOnce    sync.Once
}

func New(conn net.Conn, pathID string) transport.PacketTransport {
	return NewWithMaxFrameSize(conn, pathID, DefaultMaxFrameSize)
}

func NewWithMaxFrameSize(conn net.Conn, pathID string, maxFrameSize int) transport.PacketTransport {
	if maxFrameSize <= 0 {
		maxFrameSize = DefaultMaxFrameSize
	}
	return &Adapter{
		conn:         conn,
		reader:       bufio.NewReader(conn),
		pathID:       pathID,
		maxFrameSize: maxFrameSize,
	}
}

func (a *Adapter) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	if a.conn == nil {
		return 0, transport.PacketMeta{}, net.ErrClosed
	}
	if len(dst) == 0 {
		return 0, transport.PacketMeta{}, nil
	}

	a.readMu.Lock()
	defer a.readMu.Unlock()

	if err := applyReadDeadline(ctx, a.conn); err != nil {
		return 0, transport.PacketMeta{}, err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(a.reader, lenBuf[:]); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, transport.PacketMeta{}, ctxErr
		}
		return 0, transport.PacketMeta{}, err
	}

	frameLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	if frameLen < 0 || frameLen > a.maxFrameSize {
		return 0, transport.PacketMeta{}, fmt.Errorf("framedstream: oversized frame %d > %d", frameLen, a.maxFrameSize)
	}
	if frameLen > len(dst) {
		return 0, transport.PacketMeta{}, fmt.Errorf("framedstream: destination buffer too small: need %d have %d", frameLen, len(dst))
	}

	if _, err := io.ReadFull(a.reader, dst[:frameLen]); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, transport.PacketMeta{}, ctxErr
		}
		return 0, transport.PacketMeta{}, err
	}

	return frameLen, transport.PacketMeta{ReceivedAt: time.Now(), PathID: a.pathID}, nil
}

func (a *Adapter) WritePacket(ctx context.Context, pkt []byte) error {
	if a.conn == nil {
		return net.ErrClosed
	}
	if len(pkt) == 0 {
		return nil
	}
	if len(pkt) > a.maxFrameSize {
		return fmt.Errorf("framedstream: frame too large %d > %d", len(pkt), a.maxFrameSize)
	}

	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	if err := applyWriteDeadline(ctx, a.conn); err != nil {
		return err
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(pkt)))

	if _, err := a.conn.Write(lenBuf[:]); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
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
		return fmt.Errorf("framedstream: short frame write %d/%d", written, len(pkt))
	}
	return nil
}

func (a *Adapter) LocalAddr() net.Addr {
	if a.conn == nil {
		return nil
	}
	return a.conn.LocalAddr()
}

func (a *Adapter) RemoteAddr() net.Addr {
	if a.conn == nil {
		return nil
	}
	return a.conn.RemoteAddr()
}

func (a *Adapter) Close() error {
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
