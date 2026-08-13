package mesh

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
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

func TestPacketNeighborUsesSeparateReadinessAndLivenessDeadlines(t *testing.T) {
	t.Run("delayed peer attachment", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		leftTransport, rightTransport := newMemoryPacketPair()
		observedLeft := &writeObservedPacketTransport{
			PacketTransport: leftTransport,
			writes:          make(chan struct{}, 32),
		}
		config := PacketNeighborConfig{
			KeepAliveInterval: 5 * time.Millisecond,
			ReadinessTimeout:  250 * time.Millisecond,
			PeerTimeout:       25 * time.Millisecond,
			ReadPollInterval:  5 * time.Millisecond,
			WriteTimeout:      100 * time.Millisecond,
		}
		noopControl := func(context.Context, string, peercontrol.Message) error { return nil }
		noopData := func(context.Context, string, DataFrame) error { return nil }
		left, err := NewPacketNeighborSession("right", observedLeft, config, noopControl, noopData)
		if err != nil {
			t.Fatal(err)
		}
		defer left.Close()
		left.Start(ctx)

		// Eight successful keepalives prove that the first session remained in
		// bounded readiness for longer than the established peer timeout. The old
		// lifecycle closed it before the sixth write.
		for writes := 0; writes < 8; writes++ {
			select {
			case <-observedLeft.writes:
			case <-left.Done():
				t.Fatalf("session closed before peer attachment after %d writes", writes)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}

		right, err := NewPacketNeighborSession("left", rightTransport, config, noopControl, noopData)
		if err != nil {
			t.Fatal(err)
		}
		defer right.Close()
		right.Start(ctx)
		if err := left.waitReady(ctx); err != nil {
			t.Fatalf("left readiness: %v", err)
		}
		if err := right.waitReady(ctx); err != nil {
			t.Fatalf("right readiness: %v", err)
		}
	})

	t.Run("never-ready timeout cause", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		leftTransport, rightTransport := newMemoryPacketPair()
		defer rightTransport.Close()
		closed := make(chan error, 1)
		session, err := NewPacketNeighborSession("silent", leftTransport, PacketNeighborConfig{
			KeepAliveInterval: 5 * time.Millisecond,
			ReadinessTimeout:  35 * time.Millisecond,
			PeerTimeout:       20 * time.Millisecond,
			ReadPollInterval:  5 * time.Millisecond,
			WriteTimeout:      50 * time.Millisecond,
			OnClose: func(_ string, cause error) {
				closed <- cause
			},
		}, func(context.Context, string, peercontrol.Message) error { return nil }, func(context.Context, string, DataFrame) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		session.Start(ctx)
		if err := session.waitReady(ctx); !errors.Is(err, ErrPacketNeighborReadinessTimeout) {
			t.Fatalf("waitReady error = %v, want %v", err, ErrPacketNeighborReadinessTimeout)
		}
		select {
		case cause := <-closed:
			if !errors.Is(cause, ErrPacketNeighborReadinessTimeout) {
				t.Fatalf("close cause = %v, want %v", cause, ErrPacketNeighborReadinessTimeout)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	})

	t.Run("established peer loss cause", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		leftTransport, rightTransport := newMemoryPacketPair()
		droppingRight := &dropWritesPacketTransport{PacketTransport: rightTransport}
		closed := make(chan error, 1)
		config := PacketNeighborConfig{
			KeepAliveInterval: 5 * time.Millisecond,
			ReadinessTimeout:  100 * time.Millisecond,
			PeerTimeout:       35 * time.Millisecond,
			ReadPollInterval:  5 * time.Millisecond,
			WriteTimeout:      50 * time.Millisecond,
		}
		leftConfig := config
		leftConfig.OnClose = func(_ string, cause error) { closed <- cause }
		noopControl := func(context.Context, string, peercontrol.Message) error { return nil }
		noopData := func(context.Context, string, DataFrame) error { return nil }
		left, err := NewPacketNeighborSession("right", leftTransport, leftConfig, noopControl, noopData)
		if err != nil {
			t.Fatal(err)
		}
		defer left.Close()
		right, err := NewPacketNeighborSession("left", droppingRight, config, noopControl, noopData)
		if err != nil {
			t.Fatal(err)
		}
		defer right.Close()
		left.Start(ctx)
		right.Start(ctx)
		if err := left.waitReady(ctx); err != nil {
			t.Fatal(err)
		}
		if err := right.waitReady(ctx); err != nil {
			t.Fatal(err)
		}
		droppingRight.drop.Store(true)
		select {
		case cause := <-closed:
			if !errors.Is(cause, ErrPacketNeighborTimeout) {
				t.Fatalf("close cause = %v, want %v", cause, ErrPacketNeighborTimeout)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	})
}

type memoryPacketTransport struct {
	recv      chan []byte
	done      chan struct{}
	peer      *memoryPacketTransport
	closeOnce sync.Once
}

type writeObservedPacketTransport struct {
	transport.PacketTransport
	writes chan struct{}
}

type dropWritesPacketTransport struct {
	transport.PacketTransport
	drop atomic.Bool
}

func (t *dropWritesPacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	if t.drop.Load() {
		return nil
	}
	return t.PacketTransport.WritePacket(ctx, packet)
}

func (t *writeObservedPacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	if err := t.PacketTransport.WritePacket(ctx, packet); err != nil {
		return err
	}
	select {
	case t.writes <- struct{}{}:
	default:
	}
	return nil
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
