package rendezvouswire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestDecodeDistinguishesFixedPayloadCeiling(t *testing.T) {
	header := make([]byte, HeaderBytes)
	copy(header, Magic)
	header[4] = Version
	header[5] = byte(KindControl)
	binary.BigEndian.PutUint16(header[6:], MaxPayloadBytes+1)
	_, count, err := Decode(bytes.NewReader(header))
	if count != HeaderBytes || !errors.Is(err, ErrFrameTooLarge) || !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("oversized decode = count:%d error:%v", count, err)
	}
}

func TestCodecRoundTripAtControlCeilings(t *testing.T) {
	for _, size := range []int{MinControlPayloadBytes, MaxPayloadBytes} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		encoded, err := Encode(KindControl, payload)
		if err != nil {
			t.Fatal(err)
		}
		decoded, count, err := Decode(bytes.NewReader(encoded))
		if err != nil || count != len(encoded) || decoded.Kind != KindControl || !bytes.Equal(decoded.Payload, payload) {
			t.Fatalf("round trip size %d = %+v/%d/%v", size, decoded, count, err)
		}
		clear(decoded.Payload)
		clear(encoded)
		clear(payload)
	}
}

func TestCallerProvidedPresenceProfileIsExplicitAndMutuallyRejected(t *testing.T) {
	associationID := "QEFCQ0RFRkdISUpLTE1OTw"
	payload, err := PresencePayloadForProfile(CallerProvidedStreamProfile, associationID, SlotA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParsePresencePayload(payload); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("legacy parser accepted Gate A presence: %v", err)
	}
	legacy, err := PresencePayload(associationID, SlotA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParsePresencePayloadForProfile(CallerProvidedStreamProfile, legacy); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("Gate A parser accepted N3b presence: %v", err)
	}
	frame, err := EncodeForProfile(CallerProvidedStreamProfile, KindPresence, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, count, err := DecodeForProfile(bytes.NewReader(frame), CallerProvidedStreamProfile)
	if err != nil || count != len(frame) || decoded.Kind != KindPresence || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("Gate A decode = %+v/%d/%v", decoded, count, err)
	}
}

func TestCallerProvidedFramingHandlesHalfAndStickyFrames(t *testing.T) {
	presence, err := PresencePayloadForProfile(CallerProvidedStreamProfile, "QEFCQ0RFRkdISUpLTE1OTw", SlotA)
	if err != nil {
		t.Fatal(err)
	}
	first, err := EncodeForProfile(CallerProvidedStreamProfile, KindPresence, presence)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncodeForProfile(CallerProvidedStreamProfile, KindActivate, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, truncated := range map[string][]byte{
		"half header":  first[:HeaderBytes-1],
		"half payload": first[:len(first)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := DecodeForProfile(bytes.NewReader(truncated), CallerProvidedStreamProfile); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated decode = %v", err)
			}
		})
	}
	sticky := bytes.NewReader(append(append([]byte(nil), first...), second...))
	decodedFirst, firstCount, err := DecodeForProfile(sticky, CallerProvidedStreamProfile)
	if err != nil || firstCount != len(first) || decodedFirst.Kind != KindPresence {
		t.Fatalf("first sticky frame = %+v/%d/%v", decodedFirst, firstCount, err)
	}
	decodedSecond, secondCount, err := DecodeForProfile(sticky, CallerProvidedStreamProfile)
	if err != nil || secondCount != len(second) || decodedSecond.Kind != KindActivate || sticky.Len() != 0 {
		t.Fatalf("second sticky frame = %+v/%d/%v remaining=%d", decodedSecond, secondCount, err, sticky.Len())
	}
}
