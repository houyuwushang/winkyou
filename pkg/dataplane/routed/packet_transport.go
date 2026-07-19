package routed

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/transport"
)

const defaultPacketQueue = 256

type receivedPacket struct {
	payload    []byte
	receivedAt time.Time
}

// PacketTransport adapts one remote mesh node to the repository's existing
// packet transport boundary.
type PacketTransport struct {
	endpoint *Endpoint
	remoteID string
	pathID   string
	flowID   uint64
	seq      atomic.Uint64

	recv      chan receivedPacket
	done      chan struct{}
	closeOnce sync.Once
}

func (e *Endpoint) NewPacketTransport(remoteID, pathID string) (*PacketTransport, error) {
	if e == nil {
		return nil, ErrClosed
	}
	remoteID = strings.TrimSpace(remoteID)
	if remoteID == "" || remoteID == e.NodeID() {
		return nil, fmt.Errorf("routed dataplane: valid remote node id is required")
	}
	if strings.TrimSpace(pathID) == "" {
		pathID = "mesh/" + e.NodeID() + "/" + remoteID
	}
	packetTransport := &PacketTransport{
		endpoint: e,
		remoteID: remoteID,
		pathID:   pathID,
		flowID:   e.nextFlowID(),
		recv:     make(chan receivedPacket, defaultPacketQueue),
		done:     make(chan struct{}),
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrClosed
	}
	if _, exists := e.packets[remoteID]; exists {
		return nil, fmt.Errorf("%w: remote %s", ErrHandlerExists, remoteID)
	}
	e.packets[remoteID] = packetTransport
	return packetTransport, nil
}

func (p *PacketTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	if p == nil {
		return 0, transport.PacketMeta{}, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	case <-p.done:
		return 0, transport.PacketMeta{}, ErrClosed
	case packet := <-p.recv:
		meta := transport.PacketMeta{ReceivedAt: packet.receivedAt, PathID: p.pathID}
		if len(dst) < len(packet.payload) {
			return 0, meta, io.ErrShortBuffer
		}
		return copy(dst, packet.payload), meta, nil
	}
}

func (p *PacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	if p == nil || p.endpoint == nil {
		return ErrClosed
	}
	if len(packet) == 0 {
		return fmt.Errorf("routed dataplane: empty packet")
	}
	select {
	case <-p.done:
		return ErrClosed
	default:
	}
	return p.endpoint.Send(ctx, mesh.DataFrame{
		Version:     mesh.DataFrameVersion,
		Type:        mesh.DataTypePacket,
		HopLimit:    16,
		Source:      p.endpoint.NodeID(),
		Destination: p.remoteID,
		FlowID:      p.flowID,
		Sequence:    p.seq.Add(1),
		Payload:     append([]byte(nil), packet...),
	})
}

func (p *PacketTransport) deliver(frame mesh.DataFrame) error {
	packet := receivedPacket{payload: append([]byte(nil), frame.Payload...), receivedAt: time.Now().UTC()}
	select {
	case <-p.done:
		return ErrClosed
	case p.recv <- packet:
		return nil
	default:
		return fmt.Errorf("routed dataplane: packet queue full for %s", p.remoteID)
	}
}

func (p *PacketTransport) LocalAddr() net.Addr {
	if p == nil || p.endpoint == nil {
		return nodeAddr("")
	}
	return nodeAddr(p.endpoint.NodeID())
}

func (p *PacketTransport) RemoteAddr() net.Addr {
	if p == nil {
		return nodeAddr("")
	}
	return nodeAddr(p.remoteID)
}

func (p *PacketTransport) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		close(p.done)
		if p.endpoint != nil {
			p.endpoint.mu.Lock()
			if p.endpoint.packets[p.remoteID] == p {
				delete(p.endpoint.packets, p.remoteID)
			}
			p.endpoint.mu.Unlock()
		}
	})
	return nil
}

func (p *PacketTransport) closeFromEndpoint() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() { close(p.done) })
}

type nodeAddr string

func (a nodeAddr) Network() string { return "wink-mesh" }
func (a nodeAddr) String() string  { return string(a) }

var _ transport.PacketTransport = (*PacketTransport)(nil)
