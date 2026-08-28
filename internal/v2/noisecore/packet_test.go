package noisecore_test

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"winkyou/internal/v2/noisecore"
)

func TestPacketCipherAuthenticatesOutOfOrderSequences(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("packet-order"), []byte("packet-order"), repeatedKey(0x51), repeatedKey(0x51))
	initiatorPackets := takePackets(t, initiator, 2)
	responderPackets := takePackets(t, responder, 2)
	defer initiatorPackets.Close()
	defer responderPackets.Close()

	second, err := initiatorPackets.Seal(1, []byte("header-1"), []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiatorPackets.Seal(0, []byte("header-0"), []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	openedSecond, err := responderPackets.Open(1, []byte("header-1"), second)
	if err != nil {
		t.Fatal(err)
	}
	openedFirst, err := responderPackets.Open(0, []byte("header-0"), first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(openedSecond, []byte("second")) || !bytes.Equal(openedFirst, []byte("first")) {
		t.Fatalf("opened out of order = %q then %q", openedSecond, openedFirst)
	}

	returnPacket, err := responderPackets.Seal(2, []byte("return-header"), []byte("return"))
	if err != nil {
		t.Fatal(err)
	}
	openedReturn, err := initiatorPackets.Open(2, []byte("return-header"), returnPacket)
	if err != nil || !bytes.Equal(openedReturn, []byte("return")) {
		t.Fatalf("open reverse direction = %q, %v", openedReturn, err)
	}
}

func TestPacketCipherMatchesNoiseSection11Point4TransportNonces(t *testing.T) {
	prologue := []byte("packet-noise-nonce")
	psk := repeatedKey(0x58)
	packetInitiator, packetResponder := completeHandshake(t, prologue, prologue, psk, psk)
	orderedInitiator, orderedResponder := completeHandshake(t, prologue, prologue, psk, psk)
	defer packetResponder.Close()
	defer orderedInitiator.Close()
	defer orderedResponder.Close()
	packets := takePackets(t, packetInitiator, 2)
	defer packets.Close()

	for sequence, plaintext := range [][]byte{[]byte("zero"), []byte("one"), []byte("two")} {
		additionalData := []byte{byte(sequence), 0xa5}
		packetCiphertext, err := packets.Seal(uint64(sequence), additionalData, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		orderedCiphertext, err := orderedInitiator.Encrypt(additionalData, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(packetCiphertext, orderedCiphertext) {
			t.Fatalf("sequence %d ciphertext differs from ordered Noise transport", sequence)
		}
	}
}

func TestPacketCipherReplayClosesReceiveDirection(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("packet-replay"), []byte("packet-replay"), repeatedKey(0x52), repeatedKey(0x52))
	initiatorPackets := takePackets(t, initiator, 2)
	responderPackets := takePackets(t, responder, 2)
	defer initiatorPackets.Close()
	defer responderPackets.Close()

	packet, err := initiatorPackets.Seal(0, nil, []byte("once"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responderPackets.Open(0, nil, packet); err != nil {
		t.Fatal(err)
	}
	if _, err := responderPackets.Open(0, nil, packet); !errors.Is(err, noisecore.ErrSequenceReuse) {
		t.Fatalf("replay error = %v", err)
	}
	if _, err := responderPackets.Open(1, nil, packet); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("receive after replay error = %v", err)
	}
}

func TestPacketCipherSequenceReuseClosesSendDirection(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("packet-send-reuse"), []byte("packet-send-reuse"), repeatedKey(0x53), repeatedKey(0x53))
	initiatorPackets := takePackets(t, initiator, 2)
	responderPackets := takePackets(t, responder, 2)
	defer initiatorPackets.Close()
	defer responderPackets.Close()

	if _, err := initiatorPackets.Seal(0, nil, []byte("once")); err != nil {
		t.Fatal(err)
	}
	if _, err := initiatorPackets.Seal(0, nil, []byte("twice")); !errors.Is(err, noisecore.ErrSequenceReuse) {
		t.Fatalf("sequence reuse error = %v", err)
	}
	if _, err := initiatorPackets.Seal(1, nil, []byte("after-reuse")); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("send after reuse error = %v", err)
	}
}

func TestPacketCipherTamperClosesReceiveDirection(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("packet-tamper"), []byte("packet-tamper"), repeatedKey(0x54), repeatedKey(0x54))
	initiatorPackets := takePackets(t, initiator, 2)
	responderPackets := takePackets(t, responder, 2)
	defer initiatorPackets.Close()
	defer responderPackets.Close()

	packet, err := initiatorPackets.Seal(0, []byte("header"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	if _, err := responderPackets.Open(0, []byte("header"), tampered); !errors.Is(err, noisecore.ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}
	if _, err := responderPackets.Open(0, []byte("header"), packet); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("receive after tamper error = %v", err)
	}
}

func TestPacketCipherRejectsOutOfRangeSequence(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("packet-range"), []byte("packet-range"), repeatedKey(0x55), repeatedKey(0x55))
	initiatorPackets := takePackets(t, initiator, 3)
	responderPackets := takePackets(t, responder, 2)
	defer initiatorPackets.Close()
	defer responderPackets.Close()

	packet, err := initiatorPackets.Seal(3, nil, []byte("outside peer range"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responderPackets.Open(3, nil, packet); !errors.Is(err, noisecore.ErrSequenceOutOfRange) {
		t.Fatalf("receive range error = %v", err)
	}
	if _, err := responderPackets.Open(0, nil, packet); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("receive after range error = %v", err)
	}
}

func TestTakePacketCipherIsMutuallyExclusiveWithOrderedTransport(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("packet-transfer"), []byte("packet-transfer"), repeatedKey(0x56), repeatedKey(0x56))
	defer responder.Close()
	if _, err := initiator.Encrypt(nil, []byte("ordered")); err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.TakePacketCipher(2); !errors.Is(err, noisecore.ErrTransportAlreadyUsed) {
		t.Fatalf("take after ordered transport error = %v", err)
	}
	if _, err := initiator.Encrypt(nil, nil); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("session after rejected transfer error = %v", err)
	}
}

func TestTakePacketCipherRejectsUnboundedSequenceWithoutConsumingSession(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("packet-bound"), []byte("packet-bound"), repeatedKey(0x57), repeatedKey(0x57))
	defer responder.Close()
	if _, err := initiator.TakePacketCipher(math.MaxUint64); !errors.Is(err, noisecore.ErrSequenceOutOfRange) {
		t.Fatalf("unbounded transfer error = %v", err)
	}
	packets := takePackets(t, initiator, 2)
	if !packets.Ready() {
		t.Fatal("bounded packet cipher is not ready")
	}
	if err := packets.Close(); err != nil {
		t.Fatal(err)
	}
	if packets.Ready() {
		t.Fatal("closed packet cipher still reports ready")
	}
}

func TestPlannerKeySourceMatchesRolesAndSeparatesContext(t *testing.T) {
	initiator, responder := completeHandshake(t, []byte("planner-export"), []byte("planner-export"), repeatedKey(0x59), repeatedKey(0x59))
	initiatorPackets, initiatorPlanner, err := initiator.TakePacketCipherAndPlannerKeySource(530)
	if err != nil {
		t.Fatal(err)
	}
	responderPackets, responderPlanner, err := responder.TakePacketCipherAndPlannerKeySource(530)
	if err != nil {
		t.Fatal(err)
	}
	defer initiatorPackets.Close()
	defer responderPackets.Close()
	defer initiatorPlanner.Close()
	defer responderPlanner.Close()
	left, err := initiatorPlanner.Derive([]byte("canonical-context"))
	if err != nil {
		t.Fatal(err)
	}
	right, err := responderPlanner.Derive([]byte("canonical-context"))
	if err != nil {
		t.Fatal(err)
	}
	separated, err := responderPlanner.Derive([]byte("other-context"))
	if err != nil {
		t.Fatal(err)
	}
	if left != right || left == separated || left == ([32]byte{}) {
		t.Fatalf("planner keys role/context = %x/%x/%x", left, right, separated)
	}
	initiatorPlanner.Close()
	if _, err := initiatorPlanner.Derive([]byte("canonical-context")); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("derive after close = %v", err)
	}
}

func takePackets(t testingTB, session *noisecore.Session, maxSequence uint64) *noisecore.PacketCipher {
	t.Helper()
	packets, err := session.TakePacketCipher(maxSequence)
	if err != nil {
		t.Fatalf("take packet cipher: %v", err)
	}
	return packets
}
