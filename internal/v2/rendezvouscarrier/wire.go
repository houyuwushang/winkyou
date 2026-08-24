package rendezvouscarrier

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
)

const (
	streamMagic   = "WYRC"
	streamVersion = 1
)

const (
	wirePresence byte = iota + 1
	wirePresenceReady
	wireActivate
	wireActivateReady
	wireHandshake
	wireControl
)

var (
	ErrInvalidFrame      = errors.New("rendezvouscarrier: invalid bounded frame")
	ErrApplicationBudget = errors.New("rendezvouscarrier: application byte ceiling exceeded")
)

type boundedFrame struct {
	kind    byte
	payload []byte
}

func presencePayload(associationID string, slot PresenceSlot) ([]byte, error) {
	association, err := base64.RawURLEncoding.DecodeString(associationID)
	if err != nil || len(association) != 16 || base64.RawURLEncoding.EncodeToString(association) != associationID || !slot.valid() {
		clear(association)
		return nil, ErrInvalidConfig
	}
	profile := []byte(directattempt.RendezvousPresenceProfile)
	payload := make([]byte, 1+len(profile)+16+1)
	payload[0] = byte(len(profile))
	copy(payload[1:], profile)
	copy(payload[1+len(profile):], association)
	payload[len(payload)-1] = slot.code()
	clear(association)
	return payload, nil
}

func parsePresencePayload(payload []byte) (string, PresenceSlot, error) {
	if len(payload) < 19 {
		return "", "", ErrInvalidFrame
	}
	profileLength := int(payload[0])
	if profileLength == 0 || len(payload) != 1+profileLength+16+1 ||
		!bytes.Equal(payload[1:1+profileLength], []byte(directattempt.RendezvousPresenceProfile)) {
		return "", "", ErrInvalidFrame
	}
	association := base64.RawURLEncoding.EncodeToString(payload[1+profileLength : 1+profileLength+16])
	slot := slotFromCode(payload[len(payload)-1])
	if !slot.valid() {
		return "", "", ErrInvalidFrame
	}
	return association, slot, nil
}

func validateWirePayload(kind byte, payload []byte) error {
	switch kind {
	case wirePresence:
		_, _, err := parsePresencePayload(payload)
		return err
	case wirePresenceReady, wireActivate, wireActivateReady:
		if len(payload) != 0 {
			return ErrInvalidFrame
		}
	case wireHandshake:
		if len(payload) != noisecore.PublicKeySize+noisecore.TagSize {
			return ErrInvalidFrame
		}
	case wireControl:
		if len(payload) < directattempt.FrameHeaderBytes+noisecore.TagSize || len(payload) > directattempt.MaxFrameBytes {
			return ErrInvalidFrame
		}
	default:
		return ErrInvalidFrame
	}
	return nil
}

func encodeFrame(kind byte, payload []byte) ([]byte, error) {
	if err := validateWirePayload(kind, payload); err != nil {
		return nil, err
	}
	frame := make([]byte, streamHeaderBytes+len(payload))
	copy(frame[:4], streamMagic)
	frame[4] = streamVersion
	frame[5] = kind
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[streamHeaderBytes:], payload)
	return frame, nil
}

func decodeFrame(reader io.Reader) (boundedFrame, int, error) {
	header := make([]byte, streamHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return boundedFrame{}, 0, err
	}
	if !bytes.Equal(header[:4], []byte(streamMagic)) || header[4] != streamVersion {
		return boundedFrame{}, len(header), ErrInvalidFrame
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	if length > directattempt.MaxFrameBytes {
		return boundedFrame{}, len(header), ErrInvalidFrame
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return boundedFrame{}, len(header), err
	}
	if err := validateWirePayload(header[5], payload); err != nil {
		clear(payload)
		return boundedFrame{}, len(header) + len(payload), err
	}
	return boundedFrame{kind: header[5], payload: payload}, len(header) + len(payload), nil
}

func unexpectedFrame(stage string, kind byte) error {
	return fmt.Errorf("%w: %s received frame kind %d", ErrInvalidFrame, stage, kind)
}
