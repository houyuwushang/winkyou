//go:build linux && natlab

package natlab

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"testing"
)

// The recorder observes the real caller-owned stream. It neither decrypts
// frames nor sees the PSK, never changes return values, and has a fixed 8,256
// byte storage bound per direction. Only hashes/lengths enter the private
// child witness file; neither ciphertext nor identifiers are logged.
type gateB3WireRecorder struct {
	net.Conn
	mu    sync.Mutex
	read  []byte
	write []byte
	bad   bool
}

type gateB3WireFrame struct {
	Bytes  int
	Digest [32]byte
}

type gateB3WireWitness struct {
	Read  []gateB3WireFrame
	Write []gateB3WireFrame
	Bad   bool
}

func (stream *gateB3WireRecorder) record(write bool, payload []byte) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	target := &stream.read
	if write {
		target = &stream.write
	}
	if len(payload) > 8256-len(*target) {
		stream.bad = true
		return
	}
	*target = append(*target, payload...)
}

func (stream *gateB3WireRecorder) Read(payload []byte) (int, error) {
	n, err := stream.Conn.Read(payload)
	stream.record(false, payload[:n])
	return n, err
}

func (stream *gateB3WireRecorder) Write(payload []byte) (int, error) {
	n, err := stream.Conn.Write(payload)
	stream.record(true, payload[:n])
	return n, err
}

func (stream *gateB3WireRecorder) witness() gateB3WireWitness {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	read, readOK := gateB3WireFrames(stream.read)
	write, writeOK := gateB3WireFrames(stream.write)
	clear(stream.read)
	clear(stream.write)
	return gateB3WireWitness{Read: read, Write: write, Bad: stream.bad || !readOK || !writeOK}
}

func gateB3WireFrames(data []byte) ([]gateB3WireFrame, bool) {
	var frames []gateB3WireFrame
	for len(data) != 0 {
		if len(data) < 8 || string(data[:4]) != "WYRC" || data[4] != 1 || len(frames) >= 8 {
			return nil, false
		}
		length := 8 + int(binary.BigEndian.Uint16(data[6:8]))
		if length > 1032 || length > len(data) {
			return nil, false
		}
		frames = append(frames, gateB3WireFrame{Bytes: length, Digest: sha256.Sum256(data[:length])})
		data = data[length:]
	}
	return frames, true
}

func assertGateB3WirePair(t *testing.T, initiator, responder *gateB2EndpointProcess, left, right gateB3EndpointResult) {
	t.Helper()
	var a, b gateB3WireWitness
	if !readN1JSON(initiator.resultPath+".wire", &a) || !readN1JSON(responder.resultPath+".wire", &b) || a.Bad || b.Bad {
		t.Fatal("mapping lifetime bounded wire recorder failed")
	}
	for index, witness := range []gateB3WireWitness{a, b} {
		result := []gateB3EndpointResult{left, right}[index]
		read, write := 0, 0
		for _, frame := range witness.Read {
			read += frame.Bytes
		}
		for _, frame := range witness.Write {
			write += frame.Bytes
		}
		if len(witness.Read) != result.CarrierFramesRead || len(witness.Write) != result.CarrierFramesWrite ||
			read != result.CarrierBytesRead || write != result.CarrierBytesWrite {
			t.Fatal("mapping lifetime carrier counters differ from independently parsed wire bytes")
		}
	}
	for _, direction := range [][2][]gateB3WireFrame{{a.Read, b.Write}, {b.Read, a.Write}} {
		if len(direction[0]) > len(direction[1]) {
			t.Fatal("mapping lifetime read a frame not emitted by its peer")
		}
		for index, frame := range direction[0] {
			if frame != direction[1][index] {
				t.Fatal("mapping lifetime corresponding frame length/digest differed")
			}
		}
	}
	// The unmodified protocol authenticates READY/FIRE's joint/execution AD
	// and the seventh frame's role-ordered selection before issuing a winner
	// or waiting for that unique winner. Both consumed seven identical-to-peer
	// frames plus the frozen terminal stage prove this ordering; the passive
	// recorder cannot and does not claim to independently decrypt selection.
	if left.CarrierFramesRead < 7 || right.CarrierFramesRead < 7 {
		t.Fatal("mapping lifetime did not reach bilateral authenticated selection")
	}
	t.Log("mapping lifetime wire witness: exact_frames_and_bytes=true peer_frame_digests_equal=true selection_delivery_bilateral=true")
}
