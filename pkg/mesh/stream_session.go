package mesh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/peercontrol"
)

const maxControlFrameSize = 1 << 20

// StreamNeighborSession carries control and routed data on independent reliable
// streams. Either stream may later be a QUIC stream; Slice 3 uses two TCP
// connections so user traffic cannot head-of-line block control framing.
type StreamNeighborSession struct {
	peerID        string
	controlConn   net.Conn
	dataConn      net.Conn
	handleControl func(context.Context, string, peercontrol.Message) error
	handleData    func(context.Context, string, DataFrame) error
	onClose       func()

	controlWriteMu sync.Mutex
	dataWriteMu    sync.Mutex
	startOnce      sync.Once
	closeOnce      sync.Once
	done           chan struct{}
}

// NewStreamNeighborSession creates a control-only session for Slice 1/2 and
// compatibility tests.
func NewStreamNeighborSession(
	peerID string,
	conn net.Conn,
	handle func(context.Context, string, peercontrol.Message) error,
) (*StreamNeighborSession, error) {
	return newStreamNeighborSession(peerID, conn, nil, handle, nil)
}

func NewDualStreamNeighborSession(
	peerID string,
	controlConn net.Conn,
	dataConn net.Conn,
	handleControl func(context.Context, string, peercontrol.Message) error,
	handleData func(context.Context, string, DataFrame) error,
) (*StreamNeighborSession, error) {
	return newStreamNeighborSession(peerID, controlConn, dataConn, handleControl, handleData)
}

func newStreamNeighborSession(
	peerID string,
	controlConn net.Conn,
	dataConn net.Conn,
	handleControl func(context.Context, string, peercontrol.Message) error,
	handleData func(context.Context, string, DataFrame) error,
) (*StreamNeighborSession, error) {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return nil, fmt.Errorf("mesh: stream neighbor peer id is required")
	}
	if controlConn == nil {
		return nil, fmt.Errorf("mesh: stream neighbor control connection is required")
	}
	if handleControl == nil {
		return nil, fmt.Errorf("mesh: stream neighbor control handler is required")
	}
	if (dataConn == nil) != (handleData == nil) {
		return nil, fmt.Errorf("mesh: data connection and handler must be configured together")
	}
	return &StreamNeighborSession{
		peerID:        peerID,
		controlConn:   controlConn,
		dataConn:      dataConn,
		handleControl: handleControl,
		handleData:    handleData,
		done:          make(chan struct{}),
	}, nil
}

func (s *StreamNeighborSession) PeerID() string {
	if s == nil {
		return ""
	}
	return s.peerID
}

func (*StreamNeighborSession) neighborKind() NeighborKind { return NeighborKindStream }

func (s *StreamNeighborSession) dataChannelAvailable() bool {
	return s != nil && s.dataConn != nil
}

func (s *StreamNeighborSession) Start(ctx context.Context) {
	if s == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.startOnce.Do(func() {
		go func() {
			select {
			case <-ctx.Done():
				_ = s.Close()
			case <-s.done:
			}
		}()
		go s.readControlLoop(ctx)
		if s.dataConn != nil {
			go s.readDataLoop(ctx)
		}
	})
}

func (s *StreamNeighborSession) Send(ctx context.Context, msg peercontrol.Message) error {
	if s == nil || s.controlConn == nil {
		return net.ErrClosed
	}
	raw, err := peercontrol.Marshal(msg)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > maxControlFrameSize {
		return fmt.Errorf("mesh: control frame size %d is outside 1..%d", len(raw), maxControlFrameSize)
	}
	return s.writeFrame(ctx, s.controlConn, &s.controlWriteMu, raw)
}

func (s *StreamNeighborSession) SendData(ctx context.Context, frame DataFrame) error {
	if s == nil || s.dataConn == nil {
		return ErrDataChannelUnavailable
	}
	raw, err := MarshalDataFrame(frame)
	if err != nil {
		return err
	}
	return s.writeFrame(ctx, s.dataConn, &s.dataWriteMu, raw)
}

func (s *StreamNeighborSession) writeFrame(ctx context.Context, conn net.Conn, mu *sync.Mutex, raw []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	mu.Lock()
	defer mu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		defer conn.SetWriteDeadline(time.Time{})
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(raw)))
	if err := writeFull(conn, header); err != nil {
		return err
	}
	return writeFull(conn, raw)
}

func (s *StreamNeighborSession) readControlLoop(ctx context.Context) {
	defer s.Close()
	for {
		raw, err := readFrame(s.controlConn, maxControlFrameSize)
		if err != nil {
			return
		}
		msg, err := peercontrol.Unmarshal(raw)
		if err != nil {
			// Frame boundaries are intact, so a malformed trusted-lab message can
			// be discarded without losing the stream. Security policy comes later.
			continue
		}
		_ = s.handleControl(ctx, s.peerID, msg)
	}
}

func (s *StreamNeighborSession) readDataLoop(ctx context.Context) {
	defer s.Close()
	for {
		raw, err := readFrame(s.dataConn, MaxEncodedDataFrame)
		if err != nil {
			return
		}
		frame, err := UnmarshalDataFrame(raw)
		if err != nil {
			continue
		}
		_ = s.handleData(ctx, s.peerID, frame)
	}
}

func (s *StreamNeighborSession) Done() <-chan struct{} {
	if s == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.done
}

func (s *StreamNeighborSession) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		close(s.done)
		if s.controlConn != nil {
			err := s.controlConn.Close()
			if !errors.Is(err, net.ErrClosed) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		if s.dataConn != nil {
			err := s.dataConn.Close()
			if !errors.Is(err, net.ErrClosed) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		if s.onClose != nil {
			s.onClose()
		}
	})
	return closeErr
}

func (r *Router) AttachStream(peerID string, conn net.Conn) error {
	if r == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return ErrClosed
	}
	session, err := NewStreamNeighborSession(peerID, conn, r.HandleInbound)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return err
	}
	return r.attachStreamSession(peerID, session)
}

func (r *Router) AttachStreams(peerID string, controlConn, dataConn net.Conn) error {
	if r == nil {
		closeConns(controlConn, dataConn)
		return ErrClosed
	}
	session, err := NewDualStreamNeighborSession(
		peerID,
		controlConn,
		dataConn,
		r.HandleInbound,
		r.HandleInboundData,
	)
	if err != nil {
		closeConns(controlConn, dataConn)
		return err
	}
	return r.attachStreamSession(peerID, session)
}

func (r *Router) attachStreamSession(peerID string, session *StreamNeighborSession) error {
	handle, err := r.addNeighbor(session)
	if err != nil {
		_ = session.Close()
		return err
	}
	session.onClose = func() {
		r.withdrawNeighborHandle(handle)
	}
	session.Start(r.ctx)
	return nil
}

func readFrame(reader io.Reader, maximum int) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header))
	if length <= 0 || length > maximum {
		return nil, fmt.Errorf("mesh: framed stream length %d is outside 1..%d", length, maximum)
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func closeConns(conns ...net.Conn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}
