package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/pkg/peercontrol"
)

func TestNodeNeighborReportsStreamPacketAndUnknownKinds(t *testing.T) {
	node := mustNode(t, NodeConfig{NodeID: "A"})

	streamLocal, streamRemote := net.Pipe()
	t.Cleanup(func() { _ = streamRemote.Close() })
	if err := node.AttachStream("stream-peer", streamLocal); err != nil {
		t.Fatal(err)
	}
	streamInfo, ok := node.Neighbor("stream-peer")
	if !ok || streamInfo.PeerID != "stream-peer" || streamInfo.Kind != NeighborKindStream {
		t.Fatalf("stream neighbor info = %+v, ok=%t", streamInfo, ok)
	}
	if err := node.RemoveNeighborHandle(streamInfo.Handle); err != nil {
		t.Fatal(err)
	}
	if _, ok := node.Neighbor("stream-peer"); ok {
		t.Fatal("stream neighbor survived handle removal")
	}

	packet, packetPeer := newMemoryPacketPair()
	t.Cleanup(func() { _ = packetPeer.Close() })
	handle, err := node.AttachPacketTransportWithHandle("packet-peer", packet, PacketNeighborConfig{
		KeepAliveInterval: 100 * time.Millisecond,
		PeerTimeout:       time.Second,
		ReadPollInterval:  20 * time.Millisecond,
		WriteTimeout:      100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	packetInfo, ok := node.Neighbor("packet-peer")
	if !ok || packetInfo.Kind != NeighborKindPacket || packetInfo.Handle.entry != handle.entry {
		t.Fatalf("packet neighbor info = %+v, ok=%t", packetInfo, ok)
	}

	unknown := &recordingSession{peerID: "unknown-peer"}
	if err := node.router.AddNeighbor(unknown); err != nil {
		t.Fatal(err)
	}
	unknownInfo, ok := node.Neighbor("unknown-peer")
	if !ok || unknownInfo.Kind != NeighborKindUnknown {
		t.Fatalf("unknown neighbor info = %+v, ok=%t", unknownInfo, ok)
	}
	raw, err := json.Marshal(unknownInfo)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Handle")) || bytes.Contains(raw, []byte("handle")) {
		t.Fatalf("opaque neighbor handle leaked into JSON: %s", raw)
	}
}

func TestNeighborHandleRemovalIsIdempotentAndCannotDeleteReplacement(t *testing.T) {
	node := mustNode(t, NodeConfig{NodeID: "A"})
	if err := node.RemoveNeighborHandle(NeighborHandle{}); err != nil {
		t.Fatalf("remove zero handle: %v", err)
	}

	first, firstPeer := newMemoryPacketPair()
	t.Cleanup(func() { _ = firstPeer.Close() })
	firstHandle, err := node.AttachPacketTransportWithHandle("B", first, PacketNeighborConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.RemoveNeighborHandle(firstHandle); err != nil {
		t.Fatal(err)
	}
	if err := node.RemoveNeighborHandle(firstHandle); err != nil {
		t.Fatalf("remove stale first handle: %v", err)
	}

	second, secondPeer := newMemoryPacketPair()
	t.Cleanup(func() { _ = secondPeer.Close() })
	secondHandle, err := node.AttachPacketTransportWithHandle("B", second, PacketNeighborConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.RemoveNeighborHandle(firstHandle); err != nil {
		t.Fatalf("remove stale handle after replacement: %v", err)
	}
	info, ok := node.Neighbor("B")
	if !ok || info.Handle.entry != secondHandle.entry {
		t.Fatalf("stale handle removed replacement: info=%+v ok=%t", info, ok)
	}

	other := mustNode(t, NodeConfig{NodeID: "other"})
	otherPacket, otherPeer := newMemoryPacketPair()
	t.Cleanup(func() { _ = otherPeer.Close() })
	if _, err := other.AttachPacketTransportWithHandle("B", otherPacket, PacketNeighborConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := other.RemoveNeighborHandle(secondHandle); err != nil {
		t.Fatalf("remove foreign handle: %v", err)
	}
	if !other.HasNeighbor("B") {
		t.Fatal("foreign handle removed neighbor from another node")
	}

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if removeErr := node.RemoveNeighborHandle(secondHandle); removeErr != nil {
				errorsSeen <- removeErr
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for removeErr := range errorsSeen {
		t.Errorf("concurrent handle removal: %v", removeErr)
	}
	if node.HasNeighbor("B") {
		t.Fatal("current handle did not remove neighbor")
	}
}

func TestDeferredPacketNeighborRequiresExactHandlePromotion(t *testing.T) {
	node := mustNode(t, NodeConfig{NodeID: "A"})
	var notifications atomic.Int32
	if _, err := node.RegisterTopologyHandler(func() { notifications.Add(1) }); err != nil {
		t.Fatal(err)
	}

	first, firstPeer := newMemoryPacketPair()
	t.Cleanup(func() { _ = firstPeer.Close() })
	firstHandle, err := node.AttachPacketTransportWithHandle("B", first, PacketNeighborConfig{
		DeferAdvertisement: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, ok := node.Neighbor("B")
	if !ok || info.Advertised {
		t.Fatalf("deferred neighbor info = %+v, ok=%t", info, ok)
	}
	if links := node.localLinkState().Links; len(links) != 0 {
		t.Fatalf("deferred neighbor leaked into local LSA: %+v", links)
	}
	if got := notifications.Load(); got != 0 {
		t.Fatalf("deferred attachment published %d topology notifications", got)
	}

	if !node.PromoteNeighborHandle(firstHandle) {
		t.Fatal("current deferred handle was not promoted")
	}
	info, ok = node.Neighbor("B")
	if !ok || !info.Advertised {
		t.Fatalf("promoted neighbor info = %+v, ok=%t", info, ok)
	}
	links := node.localLinkState().Links
	if len(links) != 1 || links[0].PeerID != "B" {
		t.Fatalf("promoted local LSA links = %+v", links)
	}
	if !node.PromoteNeighborHandle(firstHandle) {
		t.Fatal("idempotent promotion rejected current handle")
	}
	if got := notifications.Load(); got != 1 {
		t.Fatalf("idempotent promotion published %d topology notifications, want 1", got)
	}
	if err := node.RemoveNeighborHandle(firstHandle); err != nil {
		t.Fatal(err)
	}

	second, secondPeer := newMemoryPacketPair()
	t.Cleanup(func() { _ = secondPeer.Close() })
	secondHandle, err := node.AttachPacketTransportWithHandle("B", second, PacketNeighborConfig{
		DeferAdvertisement: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.PromoteNeighborHandle(firstHandle) {
		t.Fatal("stale handle promoted its replacement")
	}
	if links := node.localLinkState().Links; len(links) != 0 {
		t.Fatalf("stale promotion leaked replacement into local LSA: %+v", links)
	}
	if !node.PromoteNeighborHandle(secondHandle) {
		t.Fatal("replacement handle was not promoted")
	}
	if err := node.RemoveNeighborHandle(secondHandle); err != nil {
		t.Fatal(err)
	}
}

func TestStaleDownCannotWithdrawReplacementNeighbor(t *testing.T) {
	node := mustNode(t, NodeConfig{NodeID: "A"})
	var notifications atomic.Int32
	if _, err := node.RegisterTopologyHandler(func() { notifications.Add(1) }); err != nil {
		t.Fatal(err)
	}

	old := &blockingNeighborSession{
		peerID: "B", closeStarted: make(chan struct{}), releaseClose: make(chan struct{}),
	}
	oldHandle, err := node.router.addNeighbor(old)
	if err != nil {
		t.Fatal(err)
	}
	removeDone := make(chan error, 1)
	go func() { removeDone <- node.RemoveNeighborHandle(oldHandle) }()
	select {
	case <-old.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("old neighbor close did not start")
	}

	replacement := &recordingSession{peerID: "B"}
	replacementHandle, err := node.router.addNeighbor(replacement)
	if err != nil {
		close(old.releaseClose)
		t.Fatal(err)
	}
	close(old.releaseClose)
	if err := <-removeDone; err != nil {
		t.Fatal(err)
	}
	info, ok := node.Neighbor("B")
	if !ok || info.Handle.entry != replacementHandle.entry {
		t.Fatalf("late Down withdrew replacement: info=%+v ok=%t", info, ok)
	}
	node.mu.Lock()
	_, linked := node.links["B"]
	node.mu.Unlock()
	if !linked {
		t.Fatal("late Down removed replacement from local link state")
	}
	if got := notifications.Load(); got != 2 {
		t.Fatalf("replacement session topology notifications = %d, want initial Up plus replacement identity", got)
	}
	if err := node.RemoveNeighborHandle(replacementHandle); err != nil {
		t.Fatal(err)
	}
	if got := notifications.Load(); got != 3 {
		t.Fatalf("final replacement Down notifications = %d, want 3", got)
	}
}

type blockingNeighborSession struct {
	peerID       string
	closeStarted chan struct{}
	releaseClose chan struct{}
	closeOnce    sync.Once
}

func (s *blockingNeighborSession) PeerID() string { return s.peerID }
func (*blockingNeighborSession) Send(context.Context, peercontrol.Message) error {
	return nil
}
func (s *blockingNeighborSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeStarted)
		<-s.releaseClose
	})
	return nil
}
