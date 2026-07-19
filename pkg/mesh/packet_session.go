package mesh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/peercontrol"
	"winkyou/pkg/transport"
)

var ErrPacketNeighborTimeout = errors.New("mesh: packet neighbor liveness timeout")

const (
	packetNeighborVersion     = 1
	packetNeighborHeaderSize  = 10
	MaxPacketNeighborPayload  = 60 << 10
	MaxPacketNeighborDatagram = packetNeighborHeaderSize + MaxPacketNeighborPayload
)

var packetNeighborMagic = [4]byte{'W', 'K', 'P', 'N'}

type packetNeighborKind uint8

const (
	packetNeighborControl packetNeighborKind = iota + 1
	packetNeighborData
	packetNeighborPing
	packetNeighborPong
)

type PacketNeighborConfig struct {
	KeepAliveInterval time.Duration
	PeerTimeout       time.Duration
	ReadPollInterval  time.Duration
	WriteTimeout      time.Duration
	OnClose           func(peerID string, cause error)
	// DeferAdvertisement attaches the packet session for liveness and direct
	// control traffic without publishing it as a routable graph edge. The
	// owner must promote the exact returned NeighborHandle after its own
	// probation or authentication succeeds.
	DeferAdvertisement bool
}

func (c PacketNeighborConfig) Normalized() PacketNeighborConfig {
	return c.withDefaults()
}

func (c PacketNeighborConfig) withDefaults() PacketNeighborConfig {
	if c.KeepAliveInterval <= 0 {
		c.KeepAliveInterval = 2 * time.Second
	}
	if c.PeerTimeout <= 0 {
		c.PeerTimeout = 8 * time.Second
	}
	if c.PeerTimeout <= c.KeepAliveInterval {
		c.PeerTimeout = 4 * c.KeepAliveInterval
	}
	if c.ReadPollInterval <= 0 || c.ReadPollInterval > c.KeepAliveInterval {
		c.ReadPollInterval = c.KeepAliveInterval
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 2 * time.Second
	}
	return c
}

// PacketNeighborSession upgrades a solver-produced PacketTransport into one
// graph edge. The small outer header keeps peer control, routed data, and
// liveness separate while preserving the transport's datagram boundaries.
// Control reliability currently comes from periodic topology refresh; a QUIC
// neighbor can implement the same NeighborSession contract later.
type PacketNeighborSession struct {
	peerID        string
	transport     transport.PacketTransport
	handleControl func(context.Context, string, peercontrol.Message) error
	handleData    func(context.Context, string, DataFrame) error
	config        PacketNeighborConfig
	onClose       func()

	writeMu   sync.Mutex
	startOnce sync.Once
	closeOnce sync.Once
	done      chan struct{}
	cancelMu  sync.Mutex
	cancel    context.CancelFunc
	lastRx    atomic.Int64
}

func NewPacketNeighborSession(
	peerID string,
	packetTransport transport.PacketTransport,
	config PacketNeighborConfig,
	handleControl func(context.Context, string, peercontrol.Message) error,
	handleData func(context.Context, string, DataFrame) error,
) (*PacketNeighborSession, error) {
	peerID = strings.TrimSpace(peerID)
	if peerID == "" {
		return nil, fmt.Errorf("mesh: packet neighbor peer id is required")
	}
	if packetTransport == nil {
		return nil, fmt.Errorf("mesh: packet neighbor transport is required")
	}
	if handleControl == nil || handleData == nil {
		return nil, fmt.Errorf("mesh: packet neighbor control and data handlers are required")
	}
	now := time.Now()
	session := &PacketNeighborSession{
		peerID:        peerID,
		transport:     packetTransport,
		handleControl: handleControl,
		handleData:    handleData,
		config:        config.withDefaults(),
		done:          make(chan struct{}),
	}
	session.lastRx.Store(now.UnixNano())
	return session, nil
}

func (s *PacketNeighborSession) PeerID() string {
	if s == nil {
		return ""
	}
	return s.peerID
}

func (*PacketNeighborSession) neighborKind() NeighborKind { return NeighborKindPacket }

func (s *PacketNeighborSession) Start(parent context.Context) {
	if s == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	s.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		s.cancelMu.Lock()
		s.cancel = cancel
		s.cancelMu.Unlock()
		go s.readLoop(ctx)
		go s.keepAliveLoop(ctx)
		go func() {
			select {
			case <-ctx.Done():
				_ = s.Close()
			case <-s.done:
			}
		}()
	})
}

func (s *PacketNeighborSession) Send(ctx context.Context, msg peercontrol.Message) error {
	if s == nil {
		return ErrClosed
	}
	raw, err := peercontrol.Marshal(msg)
	if err != nil {
		return err
	}
	return s.sendPacket(ctx, packetNeighborControl, raw)
}

func (s *PacketNeighborSession) SendData(ctx context.Context, frame DataFrame) error {
	if s == nil {
		return ErrClosed
	}
	raw, err := MarshalDataFrame(frame)
	if err != nil {
		return err
	}
	return s.sendPacket(ctx, packetNeighborData, raw)
}

func (s *PacketNeighborSession) sendPacket(ctx context.Context, kind packetNeighborKind, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := marshalPacketNeighbor(kind, payload)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.done:
		return ErrClosed
	default:
	}
	writeCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && s.config.WriteTimeout > 0 {
		writeCtx, cancel = context.WithTimeout(ctx, s.config.WriteTimeout)
		defer cancel()
	}
	return s.transport.WritePacket(writeCtx, raw)
}

func (s *PacketNeighborSession) readLoop(ctx context.Context) {
	var closeCause error
	defer func() { s.closeWithError(closeCause) }()
	buffer := make([]byte, MaxPacketNeighborDatagram)
	for {
		readCtx, cancel := context.WithTimeout(ctx, s.config.ReadPollInterval)
		n, _, err := s.transport.ReadPacket(readCtx, buffer)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var networkError net.Error
			if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
				if s.peerExpired(time.Now()) {
					closeCause = ErrPacketNeighborTimeout
					return
				}
				continue
			}
			closeCause = err
			return
		}
		kind, payload, err := unmarshalPacketNeighbor(buffer[:n])
		if err != nil {
			continue
		}
		s.lastRx.Store(time.Now().UnixNano())
		switch kind {
		case packetNeighborControl:
			msg, decodeErr := peercontrol.Unmarshal(payload)
			if decodeErr == nil {
				_ = s.handleControl(ctx, s.peerID, msg)
			}
		case packetNeighborData:
			frame, decodeErr := UnmarshalDataFrame(payload)
			if decodeErr == nil {
				_ = s.handleData(ctx, s.peerID, frame)
			}
		case packetNeighborPing:
			if err := s.sendPacket(ctx, packetNeighborPong, nil); err != nil {
				closeCause = err
				return
			}
		case packetNeighborPong:
		}
	}
}

func (s *PacketNeighborSession) keepAliveLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case now := <-ticker.C:
			if s.peerExpired(now) {
				s.closeWithError(ErrPacketNeighborTimeout)
				return
			}
			if err := s.sendPacket(ctx, packetNeighborPing, nil); err != nil {
				s.closeWithError(err)
				return
			}
		}
	}
}

func (s *PacketNeighborSession) peerExpired(now time.Time) bool {
	last := time.Unix(0, s.lastRx.Load())
	return now.Sub(last) >= s.config.PeerTimeout
}

func (s *PacketNeighborSession) Done() <-chan struct{} {
	if s == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return s.done
}

func (s *PacketNeighborSession) Close() error {
	return s.closeWithError(nil)
}

func (s *PacketNeighborSession) closeWithError(cause error) error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		close(s.done)
		s.cancelMu.Lock()
		cancel := s.cancel
		s.cancelMu.Unlock()
		if cancel != nil {
			cancel()
		}
		closeErr = s.transport.Close()
		if s.onClose != nil {
			s.onClose()
		}
		if s.config.OnClose != nil {
			s.config.OnClose(s.peerID, cause)
		}
	})
	return closeErr
}

func marshalPacketNeighbor(kind packetNeighborKind, payload []byte) ([]byte, error) {
	switch kind {
	case packetNeighborControl, packetNeighborData:
		if len(payload) == 0 {
			return nil, fmt.Errorf("mesh: packet neighbor kind %d requires payload", kind)
		}
	case packetNeighborPing, packetNeighborPong:
		if len(payload) != 0 {
			return nil, fmt.Errorf("mesh: packet neighbor liveness frame does not accept payload")
		}
	default:
		return nil, fmt.Errorf("mesh: unsupported packet neighbor kind %d", kind)
	}
	if len(payload) > MaxPacketNeighborPayload {
		return nil, fmt.Errorf("mesh: packet neighbor payload %d exceeds maximum %d", len(payload), MaxPacketNeighborPayload)
	}
	raw := make([]byte, packetNeighborHeaderSize+len(payload))
	copy(raw[:4], packetNeighborMagic[:])
	raw[4] = packetNeighborVersion
	raw[5] = byte(kind)
	binary.BigEndian.PutUint32(raw[6:10], uint32(len(payload)))
	copy(raw[packetNeighborHeaderSize:], payload)
	return raw, nil
}

func unmarshalPacketNeighbor(raw []byte) (packetNeighborKind, []byte, error) {
	if len(raw) < packetNeighborHeaderSize {
		return 0, nil, fmt.Errorf("mesh: packet neighbor frame is too short")
	}
	if string(raw[:4]) != string(packetNeighborMagic[:]) || raw[4] != packetNeighborVersion {
		return 0, nil, fmt.Errorf("mesh: invalid packet neighbor header")
	}
	length := int(binary.BigEndian.Uint32(raw[6:10]))
	if length > MaxPacketNeighborPayload || packetNeighborHeaderSize+length != len(raw) {
		return 0, nil, fmt.Errorf("mesh: invalid packet neighbor length %d", length)
	}
	kind := packetNeighborKind(raw[5])
	payload := append([]byte(nil), raw[packetNeighborHeaderSize:]...)
	if _, err := marshalPacketNeighbor(kind, payload); err != nil {
		return 0, nil, err
	}
	return kind, payload, nil
}

func (r *Router) AttachPacketTransport(peerID string, packetTransport transport.PacketTransport, config PacketNeighborConfig) error {
	_, err := r.AttachPacketTransportWithHandle(peerID, packetTransport, config)
	return err
}

func (r *Router) AttachPacketTransportWithHandle(
	peerID string,
	packetTransport transport.PacketTransport,
	config PacketNeighborConfig,
) (NeighborHandle, error) {
	if r == nil {
		if packetTransport != nil {
			_ = packetTransport.Close()
		}
		return NeighborHandle{}, ErrClosed
	}
	session, err := NewPacketNeighborSession(peerID, packetTransport, config, r.HandleInbound, r.HandleInboundData)
	if err != nil {
		if packetTransport != nil {
			_ = packetTransport.Close()
		}
		return NeighborHandle{}, err
	}
	handle, err := r.addNeighborWithAdvertisement(session, !config.DeferAdvertisement)
	if err != nil {
		_ = session.Close()
		return NeighborHandle{}, err
	}
	session.onClose = func() {
		r.withdrawNeighborHandle(handle)
	}
	session.Start(r.ctx)
	return handle, nil
}
