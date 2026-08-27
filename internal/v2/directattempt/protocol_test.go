package directattempt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/v2/noisecore"
)

func TestProtocolFreezesBlindSimultaneousOpenAndBidirectionalVerify(t *testing.T) {
	initiator, responder, binding := testProtocolPair(t)
	defer initiator.Close()
	defer responder.Close()

	iPrepare := mustSeal(t, initiator, FramePrepare, nil)
	rPrepare := mustSeal(t, responder, FramePrepare, nil)
	mustOpen(t, responder, iPrepare, FramePrepare)
	mustOpen(t, initiator, rPrepare, FramePrepare)

	iReady, err := NewReadyPayload(binding, RoleInitiator, netip.MustParseAddrPort("192.0.2.10:41000"))
	if err != nil {
		t.Fatal(err)
	}
	rReady, err := NewReadyPayload(binding, RoleResponder, netip.MustParseAddrPort("198.51.100.20:42000"))
	if err != nil {
		t.Fatal(err)
	}
	iReadyFrame := mustSeal(t, initiator, FrameReady, &iReady)
	rReadyFrame := mustSeal(t, responder, FrameReady, &rReady)
	opened := mustOpen(t, responder, iReadyFrame, FrameReady)
	if opened.Ready == nil || opened.Ready.Endpoint != iReady.Endpoint {
		t.Fatal("responder did not receive the authenticated initiator endpoint")
	}
	opened = mustOpen(t, initiator, rReadyFrame, FrameReady)
	if opened.Ready == nil || opened.Ready.Endpoint != rReady.Endpoint {
		t.Fatal("initiator did not receive the authenticated responder endpoint")
	}

	fire := mustSeal(t, initiator, FrameFire, nil)
	mustOpen(t, responder, fire, FrameFire)
	syn := mustSeal(t, initiator, FrameSYN, nil)
	// This is the N2 semantic difference from loopback /1: the responder emits
	// SYN_ACK immediately after FIRE and before seeing SYN.
	synACK := mustSeal(t, responder, FrameSYNACK, nil)
	mustOpen(t, initiator, synACK, FrameSYNACK)
	ack := mustSeal(t, initiator, FrameACK, nil)
	mustOpen(t, responder, ack, FrameACK)
	// A delayed, unique SYN remains admissible; it is not a prerequisite for
	// responder completion and triggers no second SYN_ACK.
	mustOpen(t, responder, syn, FrameSYN)

	iVerify := mustSeal(t, initiator, FrameVerify, nil)
	rVerify := mustSeal(t, responder, FrameVerify, nil)
	mustOpen(t, initiator, rVerify, FrameVerify)
	mustOpen(t, responder, iVerify, FrameVerify)
	if status := initiator.Status(); !status.Terminal || !status.Success || status.Sent != 6 || status.Received != 4 {
		t.Fatalf("initiator status = %+v", status)
	}
	if status := responder.Status(); !status.Terminal || !status.Success || status.Sent != 4 || status.Received != 6 {
		t.Fatalf("responder status = %+v", status)
	}
}

func TestRoleSequenceSetsHaveIntentionalHoles(t *testing.T) {
	tests := []struct {
		role Role
		want map[uint64]FrameType
	}{
		{RoleInitiator, map[uint64]FrameType{0: FramePrepare, 1: FrameReady, 2: FrameFire, 3: FrameSYN, 5: FrameACK, 6: FrameVerify, 7: FrameCancel}},
		{RoleResponder, map[uint64]FrameType{0: FramePrepare, 1: FrameReady, 4: FrameSYNACK, 6: FrameVerify, 7: FrameCancel}},
	}
	for _, test := range tests {
		for sequence := uint64(0); sequence <= MaxSequence; sequence++ {
			frameType := FrameType(sequence)
			wantType, want := test.want[sequence]
			if got := frameTypeAllowedForRole(frameType, test.role); got != want || want && wantType != frameType {
				t.Errorf("role=%s sequence=%d allowed=%t, want %t", test.role, sequence, got, want)
			}
		}
	}
}

func TestProtocolRejectsDuplicateWrongTypeRoleDomainContextAndAuthenticationTerminally(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{"type sequence mismatch", func(frame []byte) { frame[6] = byte(FrameReady) }},
		{"wrong role", func(frame []byte) { frame[7] = roleCode(RoleResponder) }},
		{"cross AD domain", func(frame []byte) { frame[5] = domainCode(DomainDirectPunch) }},
		{"authentication", func(frame []byte) { frame[len(frame)-1] ^= 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initiator, responder, _ := testProtocolPair(t)
			defer initiator.Close()
			defer responder.Close()
			frame := mustSeal(t, initiator, FramePrepare, nil)
			test.mutate(frame)
			if _, err := responder.Open(frame); err == nil {
				t.Fatal("mutated frame was accepted")
			}
			if status := responder.Status(); !status.Terminal || status.Success {
				t.Fatalf("responder status = %+v", status)
			}
			if _, err := responder.Seal(FramePrepare, nil); !errors.Is(err, ErrTerminal) {
				t.Fatalf("post-failure Seal error = %v", err)
			}
		})
	}

	t.Run("wrong context AD", func(t *testing.T) {
		initiator, responder, _ := testProtocolPair(t)
		defer initiator.Close()
		defer responder.Close()
		frame := mustSeal(t, initiator, FramePrepare, nil)
		responder.binding.ContextDigest[0] ^= 1
		if _, err := responder.Open(frame); err == nil {
			t.Fatal("cross-context frame was accepted")
		}
		if status := responder.Status(); !status.Terminal || status.Success {
			t.Fatalf("responder status = %+v", status)
		}
	})

	t.Run("local duplicate", func(t *testing.T) {
		initiator, responder, _ := testProtocolPair(t)
		defer initiator.Close()
		defer responder.Close()
		_ = mustSeal(t, initiator, FramePrepare, nil)
		if _, err := initiator.Seal(FramePrepare, nil); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("duplicate error = %v", err)
		}
		if !initiator.Status().Terminal {
			t.Fatal("duplicate did not terminate protocol")
		}
	})

	t.Run("role forbidden", func(t *testing.T) {
		initiator, responder, _ := testProtocolPair(t)
		defer initiator.Close()
		defer responder.Close()
		if _, err := initiator.Seal(FrameSYNACK, nil); !errors.Is(err, ErrInvalidSequence) {
			t.Fatalf("role error = %v", err)
		}
		if !initiator.Status().Terminal {
			t.Fatal("forbidden role sequence did not terminate")
		}
	})
}

func TestOOBProtocolProfileRejectsRoleGenerationContextDomainReplayAndDowngrade(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func([]byte, *Protocol)
	}{
		{"wrong role", func(frame []byte, _ *Protocol) { frame[7] = roleCode(RoleResponder) }},
		{"wrong generation", func(_ []byte, receiver *Protocol) { receiver.binding.Generation++ }},
		{"wrong context", func(_ []byte, receiver *Protocol) { receiver.binding.ContextDigest[0] ^= 1 }},
		{"cross carrier domain", func(frame []byte, _ *Protocol) { frame[5] = domainCode(DomainDirectPunch) }},
		{"profile downgrade", func(_ []byte, receiver *Protocol) { receiver.profile = DirectAttemptProfile }},
	}
	for _, testCase := range mutations {
		t.Run(testCase.name, func(t *testing.T) {
			initiator, responder, _ := testProtocolPairForProfile(t, OOBDirectAttemptProfile)
			defer initiator.Close()
			defer responder.Close()
			frame := mustSeal(t, initiator, FramePrepare, nil)
			testCase.mutate(frame, responder)
			if _, err := responder.Open(frame); err == nil || !responder.Status().Terminal {
				t.Fatalf("OOB mutation accepted or remained active: %v / %+v", err, responder.Status())
			}
		})
	}

	initiator, responder, _ := testProtocolPairForProfile(t, OOBDirectAttemptProfile)
	defer initiator.Close()
	defer responder.Close()
	frame := mustSeal(t, initiator, FramePrepare, nil)
	mustOpen(t, responder, frame, FramePrepare)
	if _, err := responder.Open(frame); err == nil || !responder.Status().Terminal {
		t.Fatalf("OOB replay accepted or remained active: %v / %+v", err, responder.Status())
	}
}

func TestReadyPayloadCanonicalEncodingAndNegativeBoundaries(t *testing.T) {
	_, _, binding := testProtocolPair(t)
	ready4, err := NewReadyPayload(binding, RoleInitiator, netip.MustParseAddrPort("192.0.2.9:4660"))
	if err != nil {
		t.Fatal(err)
	}
	payload4, err := ready4.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	opened4, err := ParseReadyPayload(payload4)
	if err != nil || opened4 != ready4 {
		t.Fatalf("IPv4 round trip = %+v, %v", opened4, err)
	}
	ready6, err := NewReadyPayload(binding, RoleResponder, netip.MustParseAddrPort("[2001:db8::9]:22136"))
	if err != nil {
		t.Fatal(err)
	}
	payload6, err := ready6.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	opened6, err := ParseReadyPayload(payload6)
	if err != nil || opened6 != ready6 {
		t.Fatalf("IPv6 round trip = %+v, %v", opened6, err)
	}

	if got := binary.BigEndian.Uint64(payload4[len(readyPayloadMagic)+32+1+32:]); got != Generation {
		t.Fatalf("generation byte order = %d", got)
	}
	if payload4[len(readyPayloadMagic)+32+1+32+8] != 4 {
		t.Fatal("IPv4 family marker is not canonical")
	}
	if payload6[len(readyPayloadMagic)+32+1+32+8] != 6 {
		t.Fatal("IPv6 family marker is not canonical")
	}

	for name, endpoint := range map[string]string{
		"loopback": "127.0.0.1:1", "unspecified": "0.0.0.0:1",
		"multicast": "224.0.0.1:1", "mapped": "[::ffff:192.0.2.1]:1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReadyPayload(binding, RoleInitiator, netip.MustParseAddrPort(endpoint)); !errors.Is(err, ErrInvalidReady) {
				t.Fatalf("endpoint %s error = %v", endpoint, err)
			}
		})
	}
	for name, payload := range map[string][]byte{
		"truncated":     payload4[:len(payload4)-1],
		"trailing":      append(append([]byte(nil), payload4...), 0),
		"wrong profile": bytes.Replace(payload4, []byte(DirectAttemptProfile), []byte("winkyou-test-direct-attempt-control/2"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReadyPayload(payload); !errors.Is(err, ErrInvalidReady) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestExplicitOOBProfileDoesNotWidenLegacyReadyParser(t *testing.T) {
	_, _, binding := testProtocolPair(t)
	endpoint := netip.MustParseAddrPort("192.0.2.10:4242")
	ready, err := NewReadyPayloadForProfile(binding, RoleInitiator, endpoint, OOBDirectAttemptProfile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ready.MarshalBinaryForProfile(OOBDirectAttemptProfile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReadyPayload(payload); !errors.Is(err, ErrInvalidReady) {
		t.Fatalf("legacy parser error = %v", err)
	}
	parsed, err := ParseReadyPayloadForProfile(payload, OOBDirectAttemptProfile)
	if err != nil || parsed.Profile != OOBDirectAttemptProfile {
		t.Fatalf("explicit parser = %+v, %v", parsed, err)
	}
}

func TestOOBProfileAllowsOnlyItsReviewedLoopbackTestSlice(t *testing.T) {
	initiator, responder, binding := testProtocolPair(t)
	defer initiator.Close()
	defer responder.Close()
	loopback := netip.MustParseAddrPort("127.0.0.1:41000")
	if _, err := NewReadyPayload(binding, RoleInitiator, loopback); !errors.Is(err, ErrInvalidReady) {
		t.Fatalf("legacy READY loopback = %v, want rejection", err)
	}
	ready, err := NewReadyPayloadForProfile(binding, RoleInitiator, loopback, OOBDirectAttemptProfile)
	if err != nil {
		t.Fatalf("Gate A loopback READY = %v", err)
	}
	payload, err := ready.MarshalBinaryForProfile(OOBDirectAttemptProfile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseReadyPayload(payload); !errors.Is(err, ErrInvalidReady) {
		t.Fatalf("legacy parser accepted Gate A loopback READY: %v", err)
	}
}

func TestAuthenticatedREADYFieldMismatchTerminatesReceiver(t *testing.T) {
	initiator, responder, binding := testProtocolPair(t)
	defer initiator.Close()
	defer responder.Close()
	iPrepare := mustSeal(t, initiator, FramePrepare, nil)
	rPrepare := mustSeal(t, responder, FramePrepare, nil)
	mustOpen(t, responder, iPrepare, FramePrepare)
	mustOpen(t, initiator, rPrepare, FramePrepare)
	ready, err := NewReadyPayload(binding, RoleInitiator, netip.MustParseAddrPort("192.0.2.10:41000"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ready.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Preserve valid AEAD while authenticating a reflected sender_role inside
	// READY. The receiver must reject after decryption and close the attempt.
	payload[len(readyPayloadMagic)+32] = roleCode(RoleResponder)
	header, err := BuildFrameHeader(RoleInitiator, FrameReady, len(payload)+noisecore.TagSize)
	if err != nil {
		t.Fatal(err)
	}
	additionalData, err := BuildAdditionalData(binding, header)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := initiator.packets.Seal(1, additionalData, payload)
	clear(additionalData)
	clear(payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := append(append([]byte(nil), header...), ciphertext...)
	clear(header)
	clear(ciphertext)
	if _, err := responder.Open(frame); !errors.Is(err, ErrInvalidReady) {
		t.Fatalf("Open error = %v", err)
	}
	if status := responder.Status(); !status.Terminal || status.Success {
		t.Fatalf("responder status = %+v", status)
	}
}

func TestFrameHeaderADLengthAndBigEndianAreFrozen(t *testing.T) {
	_, _, binding := testProtocolPair(t)
	for frameType := FramePrepare; frameType <= FrameCancel; frameType++ {
		role := RoleInitiator
		if frameType == FrameSYNACK {
			role = RoleResponder
		}
		if !frameTypeAllowedForRole(frameType, role) {
			continue
		}
		header, err := BuildFrameHeader(role, frameType, noisecore.TagSize)
		if err != nil {
			t.Fatal(err)
		}
		sequence, _ := frameType.Sequence()
		if len(header) != FrameHeaderBytes || binary.BigEndian.Uint64(header[8:16]) != sequence || binary.BigEndian.Uint16(header[16:18]) != noisecore.TagSize {
			t.Fatalf("header for %s = %x", frameType, header)
		}
		additionalData, err := BuildAdditionalData(binding, header)
		if err != nil {
			t.Fatal(err)
		}
		domain, _ := frameType.Domain()
		if !bytes.Contains(additionalData, []byte(DirectAttemptProfile)) || !bytes.Contains(additionalData, []byte(domain)) || !bytes.HasSuffix(additionalData, header) {
			t.Fatalf("AD for %s = %x", frameType, additionalData)
		}
		clear(additionalData)
	}
	if _, err := BuildFrameHeader(RoleInitiator, FramePrepare, MaxFrameBytes-FrameHeaderBytes+1); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("oversize header error = %v", err)
	}
}

func TestInspectFrameReturnsValidatedNonSecretMetadata(t *testing.T) {
	initiator, responder, _ := testProtocolPair(t)
	defer initiator.Close()
	defer responder.Close()
	frame := mustSeal(t, initiator, FramePrepare, nil)
	metadata, err := InspectFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Domain != DomainRendezvousControl || metadata.Type != FramePrepare ||
		metadata.Sender != RoleInitiator || metadata.Sequence != 0 || metadata.CiphertextBytes != noisecore.TagSize {
		t.Fatalf("metadata = %+v", metadata)
	}
	mutated := append([]byte(nil), frame...)
	mutated[16] = 0
	mutated[17] = 0
	if _, err := InspectFrame(mutated); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("mutated metadata error = %v", err)
	}
}

func TestAuthenticatedCancelIsSingleUseAndTerminal(t *testing.T) {
	initiator, responder, _ := testProtocolPair(t)
	defer initiator.Close()
	defer responder.Close()
	cancel := mustSeal(t, initiator, FrameCancel, nil)
	if status := initiator.Status(); !status.Terminal || !status.Cancelled || status.Success {
		t.Fatalf("sender cancel status = %+v", status)
	}
	mustOpen(t, responder, cancel, FrameCancel)
	if status := responder.Status(); !status.Terminal || !status.Cancelled || status.Success {
		t.Fatalf("receiver cancel status = %+v", status)
	}
	if _, err := responder.Open(cancel); !errors.Is(err, ErrTerminal) {
		t.Fatalf("post-cancel replay error = %v", err)
	}
}

type fixedPSK [noisecore.PSKSize]byte

func (source fixedPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

func testProtocolPair(t testing.TB) (*Protocol, *Protocol, Binding) {
	return testProtocolPairForProfile(t, DirectAttemptProfile)
}

func testProtocolPairForProfile(t testing.TB, profile string) (*Protocol, *Protocol, Binding) {
	t.Helper()
	now := time.Date(2026, 8, 24, 9, 10, 11, 0, time.UTC)
	iArtifact, err := ParseArtifact(testArtifactPayload(t, RoleInitiator, now), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	rArtifact, err := ParseArtifact(testArtifactPayload(t, RoleResponder, now), now.Add(time.Second))
	if err != nil {
		iArtifact.Close()
		t.Fatal(err)
	}
	defer iArtifact.Close()
	defer rArtifact.Close()
	context, _ := iArtifact.PairingContext()
	prologue, err := BuildNoisePrologue(context)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prologue)
	iPSK, _ := iArtifact.TakePSK()
	rPSK, _ := rArtifact.TakePSK()
	initiatorSession, err := noisecore.NewInitiator(noisecore.Config{
		Prologue: prologue, PSK: fixedPSK(iPSK), Random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 32)),
	})
	clear(iPSK[:])
	if err != nil {
		clear(rPSK[:])
		t.Fatal(err)
	}
	responderSession, err := noisecore.NewResponder(noisecore.Config{
		Prologue: prologue, PSK: fixedPSK(rPSK), Random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 32)),
	})
	clear(rPSK[:])
	if err != nil {
		_ = initiatorSession.Close()
		t.Fatal(err)
	}
	first, err := initiatorSession.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := responderSession.ReadMessage(first); err != nil || len(payload) != 0 {
		t.Fatalf("read first handshake = %x, %v", payload, err)
	}
	clear(first)
	second, err := responderSession.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := initiatorSession.ReadMessage(second); err != nil || len(payload) != 0 {
		t.Fatalf("read second handshake = %x, %v", payload, err)
	}
	clear(second)
	iHash, err := initiatorSession.HandshakeHash()
	if err != nil {
		t.Fatal(err)
	}
	rHash, err := responderSession.HandshakeHash()
	if err != nil || iHash != rHash {
		t.Fatalf("handshake hashes differ: %x/%x, %v", iHash, rHash, err)
	}
	iPackets, err := initiatorSession.TakePacketCipher(MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	rPackets, err := responderSession.TakePacketCipher(MaxSequence)
	if err != nil {
		_ = iPackets.Close()
		t.Fatal(err)
	}
	digest, _ := iArtifact.ContextDigest()
	binding := Binding{AttemptID: iArtifact.AttemptID, ContextDigest: digest, HandshakeHash: iHash, Generation: Generation}
	initiator, err := NewProtocolForProfile(RoleInitiator, binding, iPackets, profile)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewProtocolForProfile(RoleResponder, binding, rPackets, profile)
	if err != nil {
		initiator.Close()
		t.Fatal(err)
	}
	return initiator, responder, binding
}

func mustSeal(t testing.TB, protocol *Protocol, frameType FrameType, ready *ReadyPayload) []byte {
	t.Helper()
	frame, err := protocol.Seal(frameType, ready)
	if err != nil {
		t.Fatalf("seal %s: %v", frameType, err)
	}
	return frame
}

func mustOpen(t testing.TB, protocol *Protocol, frame []byte, want FrameType) OpenedFrame {
	t.Helper()
	opened, err := protocol.Open(frame)
	if err != nil {
		t.Fatalf("open %s: %v", want, err)
	}
	if opened.Type != want {
		t.Fatalf("opened type = %s, want %s", opened.Type, want)
	}
	return opened
}
