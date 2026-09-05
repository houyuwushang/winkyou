package hardnatcontrol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"winkyou/internal/v2/hardnatplan"
)

// These fixtures isolate the post-VERIFY codec; the governed product tests
// separately execute real VERIFY before taking it. All material is synthetic.
func readyProtocols(t *testing.T) (*Protocol, *Protocol) {
	t.Helper()
	left, right := completeNoise(t)
	var result [2]*Protocol
	leftPackets, err := left.TakePacketCipher(MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	rightPackets, err := right.TakePacketCipher(MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{AttemptID: "AAECAwQFBgcICQoLDA0ODw", ContextDigest: [32]byte{1},
		HandshakeHash: [32]byte{2}, EnvelopeDigest: [32]byte{3}, Generation: 1,
		Profile: hardnatplan.ProfilePredictiveEdm, ResourceClass: hardnatplan.ResourcePredictive}
	result[0], err = NewProductProtocol(RoleInitiator, hardnatplan.RoleInitiator, binding, leftPackets)
	if err != nil {
		t.Fatal(err)
	}
	result[1], err = NewProductProtocol(RoleResponder, hardnatplan.RoleResponder, binding, rightPackets)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range result {
		p.state.sentVerify, p.state.receivedVerify, p.state.hasWinner = true, true, true
		p.state.winner.Digest = [32]byte{6}
		p.joint.JointDigest = [32]byte{4}
		p.executionDigest = [32]byte{5}
		p.completeLocked()
		t.Cleanup(func() { _ = p.Close() })
	}
	return result[0], result[1]
}

func readyCodecs(t *testing.T) (*ConsumerReadiness, *ConsumerReadiness) {
	t.Helper()
	left, right := readyProtocols(t)
	first, err := left.TakeConsumerReadiness()
	if err != nil {
		t.Fatal(err)
	}
	second, err := right.TakeConsumerReadiness()
	if err != nil {
		t.Fatal(err)
	}
	if left.packets != nil || right.packets != nil {
		t.Fatal("cipher ownership was copied")
	}
	if _, err := left.TakeConsumerReadiness(); err == nil {
		t.Fatal("second transfer accepted")
	}
	_ = left.Close()
	_ = right.Close()
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })
	return first, second
}

func TestConsumerReadyByteGoldenAndOwnership(t *testing.T) {
	left, right := readyCodecs(t)
	ready, err := left.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := right.Open(ready); err != nil {
		t.Fatal(err)
	}
	ack, err := right.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Open(ack); err != nil {
		t.Fatal(err)
	}
	for _, frame := range [][]byte{ready, ack} {
		if len(frame) != ConsumerReadyFrameBytes {
			t.Fatal("frame size changed")
		}
		if _, err := InspectFrame(frame); err == nil {
			t.Fatal("legacy WYHB parser accepted WYCR")
		}
	}
	vector := struct{ Schema, Ready, Ack, ReadyAD, AckAD string }{
		"winkyou-gate-c-consumer-ready-vectors/1", hex.EncodeToString(ready), hex.EncodeToString(ack),
		hex.EncodeToString(left.ad(ready[:24])), hex.EncodeToString(right.ad(ack[:24])),
	}
	got, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("testdata/consumer_ready.golden.json")
	if err != nil {
		t.Fatalf("missing golden: %v\n%s", err, got)
	}
	want = []byte(strings.ReplaceAll(string(want), "\r\n", "\n"))
	if !bytes.Equal(want, got) {
		t.Fatalf("consumer readiness golden mismatch\n%s", got)
	}
}

func TestConsumerReadyRejectsInvalidAndReplayTerminally(t *testing.T) {
	for _, mutation := range []string{"magic", "version", "type", "role", "reserved", "nonce", "generation", "short", "long", "tag", "context", "winner", "replay", "cross-domain"} {
		t.Run(mutation, func(t *testing.T) {
			left, right := readyCodecs(t)
			frame, err := left.Seal()
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "magic":
				frame[0] ^= 1
			case "version":
				frame[4]++
			case "type":
				frame[5]++
			case "role":
				frame[6]++
			case "reserved":
				frame[7]++
			case "nonce":
				frame[15]++
			case "generation":
				frame[23]++
			case "short":
				frame = frame[:39]
			case "long":
				frame = append(frame, 0)
			case "tag":
				frame[39] ^= 1
			case "context":
				right.binding[16] ^= 1
			case "winner":
				right.binding[len(right.binding)-1] ^= 1
			case "replay":
				if err := right.Open(frame); err != nil {
					t.Fatal(err)
				}
			case "cross-domain":
				copy(frame, "WYHB")
			}
			if err := right.Open(frame); err == nil {
				t.Fatal("invalid frame accepted")
			}
			if right.packets.Ready() || !right.closed {
				t.Fatal("keys remained usable after rejection")
			}
			if _, err := right.Seal(); err == nil {
				t.Fatal("terminal codec emitted")
			}
		})
	}
	left, right := readyCodecs(t)
	if _, err := right.Seal(); err == nil {
		t.Fatal("ACK before READY")
	}
	if err := left.Open(make([]byte, 40)); err == nil {
		t.Fatal("receive before READY")
	}
}

func TestConsumerReadyCannotBeTakenBeforeVerifyOrFromLegacy(t *testing.T) {
	for _, mutation := range []string{"legacy", "sent", "received", "winner", "success"} {
		left, _ := readyProtocols(t)
		switch mutation {
		case "legacy":
			left.retainForConsumer = false
			left.completeLocked()
		case "sent":
			left.state.sentVerify = false
		case "received":
			left.state.receivedVerify = false
		case "winner":
			left.state.hasWinner = false
		case "success":
			left.state.success = false
		}
		if _, err := left.TakeConsumerReadiness(); err == nil {
			t.Fatalf("%s transfer accepted", mutation)
		}
	}
}
