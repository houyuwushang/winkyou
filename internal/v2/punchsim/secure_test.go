package punchsim

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"winkyou/internal/v2/noisecore"
)

type fixedSecureTestPSK [noisecore.PSKSize]byte

func (source fixedSecureTestPSK) LoadPSK() ([noisecore.PSKSize]byte, error) {
	return [noisecore.PSKSize]byte(source), nil
}

func TestSecureSimulationPacketReplayFails(t *testing.T) {
	initiatorSession, responderSession := completeSecureTestSessions(t)
	initiator, err := initiatorSession.TakePacketCipher(MaxSecurePacketSequence)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	responder, err := responderSession.TakePacketCipher(MaxSecurePacketSequence)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()

	attemptID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16))
	packet, err := secureSimulationPacket(initiator, attemptID, 1, RoleInitiator, packetSYN)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	if _, err := openSecureSimulationPacket(responder, packet, attemptID, 1, RoleInitiator); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecureSimulationPacket(responder, packet, attemptID, 1, RoleInitiator); !errors.Is(err, ErrSecurePacket) || !errors.Is(err, noisecore.ErrSequenceReuse) {
		t.Fatalf("replay error = %v", err)
	}
}

func TestSecureSimulationPacketRoundTrip(t *testing.T) {
	initiatorSession, responderSession := completeSecureTestSessions(t)
	initiator, err := initiatorSession.TakePacketCipher(MaxSecurePacketSequence)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	responder, err := responderSession.TakePacketCipher(MaxSecurePacketSequence)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	attemptID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	packet, err := secureSimulationPacket(initiator, attemptID, 1, RoleInitiator, packetSYN)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(packet)
	kind, err := openSecureSimulationPacket(responder, packet, attemptID, 1, RoleInitiator)
	if err != nil {
		t.Fatal(err)
	}
	if kind != packetSYN {
		t.Fatalf("kind = %q", kind)
	}
	returnPacket, err := secureSimulationPacket(responder, attemptID, 1, RoleResponder, packetSYN)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(returnPacket)
	if _, err := openSecureSimulationPacket(initiator, returnPacket, attemptID, 1, RoleResponder); err != nil {
		t.Fatal(err)
	}
}

func completeSecureTestSessions(t *testing.T) (*noisecore.Session, *noisecore.Session) {
	t.Helper()
	var psk fixedSecureTestPSK
	for index := range psk {
		psk[index] = 0x41
	}
	initiator, err := noisecore.NewInitiator(noisecore.Config{
		Prologue: []byte("punchsim secure test"),
		PSK:      psk,
		Random:   bytes.NewReader(bytes.Repeat([]byte{0x11}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	responder, err := noisecore.NewResponder(noisecore.Config{
		Prologue: []byte("punchsim secure test"),
		PSK:      psk,
		Random:   bytes.NewReader(bytes.Repeat([]byte{0x22}, 32)),
	})
	if err != nil {
		_ = initiator.Close()
		t.Fatal(err)
	}
	first, err := initiator.WriteMessage(nil)
	if err == nil {
		_, err = responder.ReadMessage(first)
	}
	clear(first)
	if err != nil {
		_ = initiator.Close()
		_ = responder.Close()
		t.Fatal(err)
	}
	second, err := responder.WriteMessage(nil)
	if err == nil {
		_, err = initiator.ReadMessage(second)
	}
	clear(second)
	if err != nil {
		_ = initiator.Close()
		_ = responder.Close()
		t.Fatal(err)
	}
	return initiator, responder
}
