package rendezvouswire

import (
	"bytes"
	"encoding/binary"
	"errors"
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
