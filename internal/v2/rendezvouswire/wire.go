// Package rendezvouswire owns the bounded WYRC v1 stream codec shared by the
// governed client carrier and the one-shot rendezvous server. It deliberately
// has no network, governor, probe, Noise, or signaling dependency.
package rendezvouswire

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Magic                = "WYRC"
	Version         byte = 1
	HeaderBytes          = 8
	MaxPayloadBytes      = 1024

	PresenceProfile = "winkyou-test-direct-presence/1"
	// CallerProvidedStreamProfile is the Gate A presence profile used only on
	// an already-established, attempt-dedicated bounded child stream.
	CallerProvidedStreamProfile = "caller-provided-bounded-stream/1"

	// The WYRC v1 handshake carries one NNpsk0 public key plus its AEAD tag.
	HandshakePayloadBytes = 48
	// The smallest control frame is the fixed direct-attempt header plus tag.
	MinControlPayloadBytes = 34
)

type Kind byte

const (
	KindPresence Kind = iota + 1
	KindPresenceReady
	KindActivate
	KindActivateReady
	KindHandshake
	KindControl
)

type Slot byte

const (
	SlotA Slot = 1
	SlotB Slot = 2
)

func (slot Slot) Valid() bool { return slot == SlotA || slot == SlotB }

var ErrInvalidFrame = errors.New("rendezvouswire: invalid bounded frame")

var ErrFrameTooLarge = fmt.Errorf("%w: payload exceeds the fixed ceiling", ErrInvalidFrame)

type Frame struct {
	Kind    Kind
	Payload []byte
}

func PresencePayload(associationID string, slot Slot) ([]byte, error) {
	return PresencePayloadForProfile(PresenceProfile, associationID, slot)
}

func PresencePayloadForProfile(profile, associationID string, slot Slot) ([]byte, error) {
	if !validPresenceProfile(profile) {
		return nil, ErrInvalidFrame
	}
	association, err := base64.RawURLEncoding.DecodeString(associationID)
	if err != nil || len(association) != 16 || base64.RawURLEncoding.EncodeToString(association) != associationID || !slot.Valid() {
		clear(association)
		return nil, ErrInvalidFrame
	}
	profileBytes := []byte(profile)
	payload := make([]byte, 1+len(profileBytes)+len(association)+1)
	payload[0] = byte(len(profileBytes))
	copy(payload[1:], profileBytes)
	copy(payload[1+len(profileBytes):], association)
	payload[len(payload)-1] = byte(slot)
	clear(association)
	return payload, nil
}

func ParsePresencePayload(payload []byte) (string, Slot, error) {
	return ParsePresencePayloadForProfile(PresenceProfile, payload)
}

func ParsePresencePayloadForProfile(profile string, payload []byte) (string, Slot, error) {
	if !validPresenceProfile(profile) {
		return "", 0, ErrInvalidFrame
	}
	if len(payload) < 19 {
		return "", 0, ErrInvalidFrame
	}
	profileLength := int(payload[0])
	if profileLength == 0 || len(payload) != 1+profileLength+16+1 ||
		!bytes.Equal(payload[1:1+profileLength], []byte(profile)) {
		return "", 0, ErrInvalidFrame
	}
	association := base64.RawURLEncoding.EncodeToString(payload[1+profileLength : 1+profileLength+16])
	slot := Slot(payload[len(payload)-1])
	if !slot.Valid() {
		return "", 0, ErrInvalidFrame
	}
	return association, slot, nil
}

func ValidatePayload(kind Kind, payload []byte) error {
	return ValidatePayloadForProfile(PresenceProfile, kind, payload)
}

func ValidatePayloadForProfile(profile string, kind Kind, payload []byte) error {
	switch kind {
	case KindPresence:
		_, _, err := ParsePresencePayloadForProfile(profile, payload)
		return err
	case KindPresenceReady, KindActivate, KindActivateReady:
		if len(payload) != 0 {
			return ErrInvalidFrame
		}
	case KindHandshake:
		if len(payload) != HandshakePayloadBytes {
			return ErrInvalidFrame
		}
	case KindControl:
		if len(payload) > MaxPayloadBytes {
			return ErrFrameTooLarge
		}
		if len(payload) < MinControlPayloadBytes {
			return ErrInvalidFrame
		}
	default:
		return ErrInvalidFrame
	}
	return nil
}

func Encode(kind Kind, payload []byte) ([]byte, error) {
	return EncodeForProfile(PresenceProfile, kind, payload)
}

func EncodeForProfile(profile string, kind Kind, payload []byte) ([]byte, error) {
	if err := ValidatePayloadForProfile(profile, kind, payload); err != nil {
		return nil, err
	}
	frame := make([]byte, HeaderBytes+len(payload))
	copy(frame[:4], Magic)
	frame[4] = Version
	frame[5] = byte(kind)
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[HeaderBytes:], payload)
	return frame, nil
}

func Decode(reader io.Reader) (Frame, int, error) {
	return DecodeForProfile(reader, PresenceProfile)
}

func DecodeForProfile(reader io.Reader, profile string) (Frame, int, error) {
	if !validPresenceProfile(profile) {
		return Frame{}, 0, ErrInvalidFrame
	}
	header := make([]byte, HeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil {
		return Frame{}, 0, err
	}
	if !bytes.Equal(header[:4], []byte(Magic)) || header[4] != Version {
		return Frame{}, len(header), ErrInvalidFrame
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	if length > MaxPayloadBytes {
		return Frame{}, len(header), ErrFrameTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return Frame{}, len(header), err
	}
	kind := Kind(header[5])
	if err := ValidatePayloadForProfile(profile, kind, payload); err != nil {
		clear(payload)
		return Frame{}, len(header) + len(payload), err
	}
	return Frame{Kind: kind, Payload: payload}, len(header) + len(payload), nil
}

func validPresenceProfile(profile string) bool {
	return profile == PresenceProfile || profile == CallerProvidedStreamProfile
}
