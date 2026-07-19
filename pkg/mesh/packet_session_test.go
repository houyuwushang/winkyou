package mesh

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/transport"
)

func TestPacketNeighborFrameRoundTrip(t *testing.T) {
	for _, test := range []struct {
		kind    packetNeighborKind
		payload []byte
	}{
		{kind: packetNeighborControl, payload: []byte("control")},
		{kind: packetNeighborData, payload: []byte("data")},
		{kind: packetNeighborPing},
		{kind: packetNeighborPong},
	} {
		raw, err := marshalPacketNeighbor(test.kind, test.payload)
		if err != nil {
			t.Fatal(err)
		}
		kind, payload, err := unmarshalPacketNeighbor(raw)
		if err != nil {
			t.Fatal(err)
		}
		if kind != test.kind || string(payload) != string(test.payload) {
			t.Fatalf("round trip = %d/%q, want %d/%q", kind, payload, test.kind, test.payload)
		}
	}
	if _, err := marshalPacketNeighbor(packetNeighborData, make([]byte, MaxPacketNeighborPayload+1)); err == nil {
		t.Fatal("oversized packet neighbor payload accepted")
	}
}

func TestPacketNeighborRoutesDataAndDetectsPeerLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	delivered := make(chan DataFrame, 1)
	routerA, err := NewRouter(Config{NodeID: "A"})
	if err != nil {
		t.Fatal(err)
	}
	defer routerA.Close()
	routerC, err := NewRouter(Config{
		NodeID: "C",
		OnData: func(_ context.Context, frame DataFrame) error {
			delivered <- frame
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer routerC.Close()

	transportA, transportC := newMemoryPacketPair()
	config := PacketNeighborConfig{
		KeepAliveInterval: 20 * time.Millisecond,
		PeerTimeout:       120 * time.Millisecond,
		ReadPollInterval:  20 * time.Millisecond,
		WriteTimeout:      100 * time.Millisecond,
	}
	if err := routerA.AttachPacketTransport("C", transportA, config); err != nil {
		t.Fatal(err)
	}
	if err := routerC.AttachPacketTransport("A", transportC, config); err != nil {
		t.Fatal(err)
	}
	frame := DataFrame{
		Version: DataFrameVersion, Type: DataTypePacket, HopLimit: 8,
		Source: "A", Destination: "C", FlowID: 1, Sequence: 1, Payload: []byte("direct"),
	}
	if err := routerA.SendData(ctx, frame); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-delivered:
		if string(got.Payload) != "direct" {
			t.Fatalf("payload = %q", got.Payload)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := routerA.RemoveNeighbor("C"); err != nil {
		t.Fatal(err)
	}
	eventually(t, ctx, func() bool { return !routerC.hasNeighbor("A") }, "C did not expire the silent packet neighbor")
}

type memoryPacketTransport struct {
	recv      chan []byte
	done      chan struct{}
	peer      *memoryPacketTransport
	closeOnce sync.Once
}

func newMemoryPacketPair() (*memoryPacketTransport, *memoryPacketTransport) {
	left := &memoryPacketTransport{recv: make(chan []byte, 128), done: make(chan struct{})}
	right := &memoryPacketTransport{recv: make(chan []byte, 128), done: make(chan struct{})}
	left.peer = right
	right.peer = left
	return left, right
}

func (m *memoryPacketTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	select {
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	case <-m.done:
		return 0, transport.PacketMeta{}, net.ErrClosed
	case packet := <-m.recv:
		if len(dst) < len(packet) {
			return 0, transport.PacketMeta{}, errors.New("short buffer")
		}
		return copy(dst, packet), transport.PacketMeta{ReceivedAt: time.Now()}, nil
	}
}

func (m *memoryPacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return net.ErrClosed
	case <-m.peer.done:
		return net.ErrClosed
	case m.peer.recv <- append([]byte(nil), packet...):
		return nil
	}
}

func (m *memoryPacketTransport) LocalAddr() net.Addr  { return memoryPacketAddr("local") }
func (m *memoryPacketTransport) RemoteAddr() net.Addr { return memoryPacketAddr("remote") }
func (m *memoryPacketTransport) Close() error {
	m.closeOnce.Do(func() { close(m.done) })
	return nil
}

type memoryPacketAddr string

func (a memoryPacketAddr) Network() string { return "memory-packet" }
func (a memoryPacketAddr) String() string  { return string(a) }

var _ transport.PacketTransport = (*memoryPacketTransport)(nil)
