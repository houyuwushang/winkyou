package routed

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/mesh"
	"winkyou/pkg/transport"
)

func TestTCPForwarderCarriesHalfClosedFlowAcrossThreeNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var eventMu sync.Mutex
	forwarded := make(map[mesh.DataType]int)
	nodeA := newMeshNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond})
	nodeB := newMeshNode(t, mesh.NodeConfig{
		NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond,
		OnDataEvent: func(event mesh.DataEvent) {
			if event.Kind != mesh.EventForwarded || event.Frame.Type == mesh.DataTypePacket {
				return
			}
			eventMu.Lock()
			forwarded[event.Frame.Type]++
			eventMu.Unlock()
		},
	})
	nodeC := newMeshNode(t, mesh.NodeConfig{NodeID: "C", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond})
	attachDualTCPPair(t, nodeA, "B", nodeB, "A")
	attachDualTCPPair(t, nodeB, "C", nodeC, "B")
	for _, node := range []*mesh.Node{nodeA, nodeB, nodeC} {
		if err := node.Start(ctx); err != nil {
			t.Fatalf("%s.Start() error = %v", node.NodeID(), err)
		}
	}
	waitForCondition(t, ctx, func() bool {
		forward, forwardOK := nodeA.Route("C")
		reverse, reverseOK := nodeC.Route("A")
		return forwardOK && reverseOK &&
			slices.Equal(forward.Path, []string{"A", "B", "C"}) &&
			slices.Equal(reverse.Path, []string{"C", "B", "A"})
	}, "A and C did not learn reciprocal routes")

	targetAddress, targetReceived := startHalfCloseEchoTarget(t)
	endpointA := newEndpoint(t, nodeA)
	endpointC := newEndpoint(t, nodeC)
	forwarderA, err := NewTCPForwarder(endpointA, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderA.Close() })
	forwarderC, err := NewTCPForwarder(endpointC, targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderC.Close() })
	listener, err := forwarderA.StartListener(ctx, "127.0.0.1:0", "C")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local forward listener: %v", err)
	}
	tcpConn := conn.(*net.TCPConn)
	defer tcpConn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tcpConn.SetDeadline(deadline)
	}
	payload := bytes.Repeat([]byte("winkyou-routed-tcp-"), 5000)
	if err := writeAll(tcpConn, payload); err != nil {
		t.Fatalf("write local payload: %v", err)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatalf("half-close local connection: %v", err)
	}
	reply, err := io.ReadAll(tcpConn)
	if err != nil {
		t.Fatalf("read forwarded reply: %v", err)
	}
	wantReply := append([]byte("echo:"), payload...)
	if !bytes.Equal(reply, wantReply) {
		t.Fatalf("reply length/content = %d/%t, want %d/true", len(reply), bytes.Equal(reply, wantReply), len(wantReply))
	}

	select {
	case received := <-targetReceived:
		if !bytes.Equal(received, payload) {
			t.Fatalf("target received %d bytes, want %d exact bytes", len(received), len(payload))
		}
	case <-ctx.Done():
		t.Fatalf("target did not finish: %v", ctx.Err())
	}
	waitForCondition(t, ctx, func() bool {
		forwarderA.mu.Lock()
		flowsA := len(forwarderA.flows)
		forwarderA.mu.Unlock()
		forwarderC.mu.Lock()
		flowsC := len(forwarderC.flows)
		forwarderC.mu.Unlock()
		return flowsA == 0 && flowsC == 0
	}, "TCP flows did not finish after bidirectional FIN")

	eventMu.Lock()
	got := make(map[mesh.DataType]int, len(forwarded))
	for frameType, count := range forwarded {
		got[frameType] = count
	}
	eventMu.Unlock()
	if got[mesh.DataTypeStreamOpen] != 1 || got[mesh.DataTypeStreamOpenOK] != 1 {
		t.Fatalf("B forwarded OPEN/OPEN_OK = %d/%d, want 1/1", got[mesh.DataTypeStreamOpen], got[mesh.DataTypeStreamOpenOK])
	}
	if got[mesh.DataTypeStreamData] < 2 || got[mesh.DataTypeStreamFIN] != 2 {
		t.Fatalf("B forwarded DATA/FIN = %d/%d, want at least 2/2", got[mesh.DataTypeStreamData], got[mesh.DataTypeStreamFIN])
	}
	if got[mesh.DataTypeStreamReset] != 0 || got[mesh.DataTypeStreamOpenError] != 0 {
		t.Fatalf("B forwarded RESET/OPEN_ERROR = %d/%d, want 0/0", got[mesh.DataTypeStreamReset], got[mesh.DataTypeStreamOpenError])
	}
}

func TestTCPForwarderRetransmitsDroppedPacketNeighborFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	nodeA := newMeshNode(t, mesh.NodeConfig{NodeID: "A", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond})
	nodeB := newMeshNode(t, mesh.NodeConfig{NodeID: "B", Lease: 5 * time.Second, RefreshInterval: 100 * time.Millisecond})
	if err := nodeA.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Start(ctx); err != nil {
		t.Fatal(err)
	}
	packetA, packetB := newLossyTCPPacketPair()
	packetA.drop = map[mesh.DataType]int{
		mesh.DataTypeStreamOpen: 1,
		mesh.DataTypeStreamData: 1,
		mesh.DataTypeStreamFIN:  1,
	}
	packetB.drop = map[mesh.DataType]int{
		mesh.DataTypeStreamACK:  3,
		mesh.DataTypeStreamData: 1,
	}
	neighborConfig := mesh.PacketNeighborConfig{
		KeepAliveInterval: 50 * time.Millisecond,
		PeerTimeout:       3 * time.Second,
		ReadPollInterval:  25 * time.Millisecond,
		WriteTimeout:      time.Second,
	}
	if err := nodeA.AttachPacketTransport("B", packetA, neighborConfig); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.AttachPacketTransport("A", packetB, neighborConfig); err != nil {
		t.Fatal(err)
	}
	waitForCondition(t, ctx, func() bool {
		forward, forwardOK := nodeA.Route("B")
		reverse, reverseOK := nodeB.Route("A")
		return forwardOK && reverseOK &&
			slices.Equal(forward.Path, []string{"A", "B"}) &&
			slices.Equal(reverse.Path, []string{"B", "A"})
	}, "lossy packet neighbors did not advertise reciprocal routes")

	targetAddress, targetReceived := startHalfCloseEchoTarget(t)
	endpointA := newEndpoint(t, nodeA)
	endpointB := newEndpoint(t, nodeB)
	forwarderA, err := NewTCPForwarder(endpointA, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderA.Close() })
	forwarderB, err := NewTCPForwarder(endpointB, targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarderB.Close() })
	listener, err := forwarderA.StartListener(ctx, "127.0.0.1:0", "B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tcpConn := conn.(*net.TCPConn)
	defer tcpConn.Close()
	_ = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("lossy-packet-neighbor-"), 3000)
	if err := writeAll(tcpConn, payload); err != nil {
		t.Fatal(err)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(tcpConn)
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte("echo:"), payload...); !bytes.Equal(reply, want) {
		t.Fatalf("lossy reply length/content = %d/%t, want %d/true", len(reply), bytes.Equal(reply, want), len(want))
	}
	select {
	case received := <-targetReceived:
		if !bytes.Equal(received, payload) {
			t.Fatalf("lossy target received %d bytes, want %d", len(received), len(payload))
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if packetA.totalDropped() != 3 || packetB.totalDropped() != 4 {
		t.Fatalf("dropped packet data frames A/B = %d/%d, want 3/4", packetA.totalDropped(), packetB.totalDropped())
	}
}

func startHalfCloseEchoTarget(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		payload, readErr := io.ReadAll(conn)
		if readErr != nil {
			return
		}
		received <- append([]byte(nil), payload...)
		_ = writeAll(conn, append([]byte("echo:"), payload...))
		if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	}()
	return listener.Addr().String(), received
}

type lossyTCPPacketTransport struct {
	recv      chan []byte
	done      chan struct{}
	peer      *lossyTCPPacketTransport
	closeOnce sync.Once

	mu      sync.Mutex
	drop    map[mesh.DataType]int
	dropped int
}

func newLossyTCPPacketPair() (*lossyTCPPacketTransport, *lossyTCPPacketTransport) {
	left := &lossyTCPPacketTransport{recv: make(chan []byte, 256), done: make(chan struct{})}
	right := &lossyTCPPacketTransport{recv: make(chan []byte, 256), done: make(chan struct{})}
	left.peer = right
	right.peer = left
	return left, right
}

func (p *lossyTCPPacketTransport) ReadPacket(ctx context.Context, dst []byte) (int, transport.PacketMeta, error) {
	select {
	case <-ctx.Done():
		return 0, transport.PacketMeta{}, ctx.Err()
	case <-p.done:
		return 0, transport.PacketMeta{}, net.ErrClosed
	case packet := <-p.recv:
		if len(dst) < len(packet) {
			return 0, transport.PacketMeta{}, io.ErrShortBuffer
		}
		return copy(dst, packet), transport.PacketMeta{ReceivedAt: time.Now()}, nil
	}
}

func (p *lossyTCPPacketTransport) WritePacket(ctx context.Context, packet []byte) error {
	if p.shouldDrop(packet) {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return net.ErrClosed
	case <-p.peer.done:
		return net.ErrClosed
	case p.peer.recv <- append([]byte(nil), packet...):
		return nil
	}
}

func (p *lossyTCPPacketTransport) shouldDrop(packet []byte) bool {
	const packetNeighborHeaderSize = 10
	if len(packet) <= packetNeighborHeaderSize || string(packet[:4]) != "WKPN" || packet[5] != 2 {
		return false
	}
	length := int(binary.BigEndian.Uint32(packet[6:10]))
	if length != len(packet)-packetNeighborHeaderSize {
		return false
	}
	frame, err := mesh.UnmarshalDataFrame(packet[packetNeighborHeaderSize:])
	if err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.drop[frame.Type] <= 0 {
		return false
	}
	p.drop[frame.Type]--
	p.dropped++
	return true
}

func (p *lossyTCPPacketTransport) totalDropped() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropped
}

func (p *lossyTCPPacketTransport) LocalAddr() net.Addr  { return lossyTCPPacketAddr("local") }
func (p *lossyTCPPacketTransport) RemoteAddr() net.Addr { return lossyTCPPacketAddr("remote") }
func (p *lossyTCPPacketTransport) Close() error {
	p.closeOnce.Do(func() { close(p.done) })
	return nil
}

type lossyTCPPacketAddr string

func (a lossyTCPPacketAddr) Network() string { return "lossy-memory-packet" }
func (a lossyTCPPacketAddr) String() string  { return string(a) }

var _ transport.PacketTransport = (*lossyTCPPacketTransport)(nil)
