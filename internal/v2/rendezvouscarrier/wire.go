package rendezvouscarrier

import (
	"errors"
	"fmt"
	"io"

	"winkyou/internal/v2/rendezvouswire"
)

const (
	streamMagic   = rendezvouswire.Magic
	streamVersion = rendezvouswire.Version

	wirePresence      = byte(rendezvouswire.KindPresence)
	wirePresenceReady = byte(rendezvouswire.KindPresenceReady)
	wireActivate      = byte(rendezvouswire.KindActivate)
	wireActivateReady = byte(rendezvouswire.KindActivateReady)
	wireHandshake     = byte(rendezvouswire.KindHandshake)
	wireControl       = byte(rendezvouswire.KindControl)
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
	payload, err := rendezvouswire.PresencePayload(associationID, rendezvouswire.Slot(slot.code()))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return payload, nil
}

func parsePresencePayload(payload []byte) (string, PresenceSlot, error) {
	association, slot, err := rendezvouswire.ParsePresencePayload(payload)
	if err != nil {
		return "", "", ErrInvalidFrame
	}
	return association, slotFromCode(byte(slot)), nil
}

func validateWirePayload(kind byte, payload []byte) error {
	if err := rendezvouswire.ValidatePayload(rendezvouswire.Kind(kind), payload); err != nil {
		return ErrInvalidFrame
	}
	return nil
}

func encodeFrame(kind byte, payload []byte) ([]byte, error) {
	frame, err := rendezvouswire.Encode(rendezvouswire.Kind(kind), payload)
	if err != nil {
		return nil, ErrInvalidFrame
	}
	return frame, nil
}

func decodeFrame(reader io.Reader) (boundedFrame, int, error) {
	frame, count, err := rendezvouswire.Decode(reader)
	if err != nil {
		if errors.Is(err, rendezvouswire.ErrInvalidFrame) {
			err = ErrInvalidFrame
		}
		return boundedFrame{}, count, err
	}
	return boundedFrame{kind: byte(frame.Kind), payload: frame.Payload}, count, nil
}

func unexpectedFrame(stage string, kind byte) error {
	return fmt.Errorf("%w: %s received frame kind %d", ErrInvalidFrame, stage, kind)
}
