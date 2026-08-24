package punchproto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"winkyou/internal/v2/noisecore"
)

const (
	PlainPacketProtocol  = "winkyou-test-punch/1"
	SecurePacketProtocol = "winkyou-test-punch-noise/1"
	SecurePacketPrefix   = "WYNP\x01"

	MaxSecurePacketSequence = 2
	MaxPacketBytes          = 256
)

var (
	ErrInvalidContext    = errors.New("punchproto: invalid attempt context")
	ErrInvalidMessage    = errors.New("punchproto: invalid punch message")
	ErrInvalidTransition = errors.New("punchproto: invalid punch transition")
	ErrSecurePacket      = errors.New("punchproto: invalid secure punch packet")
)

type Role string

const (
	RoleInitiator Role = "initiator"
	RoleResponder Role = "responder"
)

func (role Role) Valid() bool {
	return role == RoleInitiator || role == RoleResponder
}

func (role Role) Peer() (Role, bool) {
	switch role {
	case RoleInitiator:
		return RoleResponder, true
	case RoleResponder:
		return RoleInitiator, true
	default:
		return "", false
	}
}

type MessageType string

const (
	MessageSYN    MessageType = "syn"
	MessageSYNACK MessageType = "syn_ack"
	MessageACK    MessageType = "ack"
)

func (message MessageType) Valid() bool {
	return message == MessageSYN || message == MessageSYNACK || message == MessageACK
}

type machineState uint8

const (
	machineNew machineState = iota
	machineAwaitFirst
	machineAwaitFinal
	machineComplete
)

// Machine validates only the SYN/SYN_ACK/ACK ordering. Transport, deadlines,
// packet budgets, and admission remain the caller's responsibility.
type Machine struct {
	state machineState
}

type Transition struct {
	Reply    MessageType
	Complete bool
}

func NewMachine() *Machine {
	return &Machine{state: machineNew}
}

func (machine *Machine) Start() (MessageType, error) {
	if machine == nil || machine.state != machineNew {
		return "", ErrInvalidTransition
	}
	machine.state = machineAwaitFirst
	return MessageSYN, nil
}

// Await arms a passive responder to accept the peer's SYN without emitting a
// competing SYN. It is mutually exclusive with Start and performs no I/O.
func (machine *Machine) Await() error {
	if machine == nil || machine.state != machineNew {
		return ErrInvalidTransition
	}
	machine.state = machineAwaitFirst
	return nil
}

func (machine *Machine) Receive(message MessageType) (Transition, error) {
	if machine == nil || !message.Valid() {
		return Transition{}, ErrInvalidMessage
	}
	switch machine.state {
	case machineAwaitFirst:
		switch message {
		case MessageSYN:
			machine.state = machineAwaitFinal
			return Transition{Reply: MessageSYNACK}, nil
		case MessageSYNACK:
			machine.state = machineComplete
			return Transition{Reply: MessageACK, Complete: true}, nil
		default:
			return Transition{}, ErrInvalidTransition
		}
	case machineAwaitFinal:
		if message != MessageSYNACK && message != MessageACK {
			return Transition{}, ErrInvalidTransition
		}
		machine.state = machineComplete
		return Transition{Complete: true}, nil
	default:
		return Transition{}, ErrInvalidTransition
	}
}

func EncodePlainPacket(attemptID string, generation uint64, role Role, message MessageType) ([]byte, error) {
	if !ValidAttemptContext(attemptID, generation, role) || !message.Valid() {
		return nil, ErrInvalidContext
	}
	return []byte(strings.Join([]string{
		PlainPacketProtocol,
		attemptID,
		strconv.FormatUint(generation, 10),
		string(role),
		string(message),
	}, "|")), nil
}

func OpenPlainPacket(packet []byte, attemptID string, generation uint64, peerRole Role) (MessageType, error) {
	if !ValidAttemptContext(attemptID, generation, peerRole) {
		return "", ErrInvalidContext
	}
	for _, candidate := range []MessageType{MessageSYN, MessageSYNACK, MessageACK} {
		expected, err := EncodePlainPacket(attemptID, generation, peerRole, candidate)
		if err != nil {
			return "", err
		}
		matches := bytes.Equal(packet, expected)
		clear(expected)
		if matches {
			return candidate, nil
		}
	}
	return "", ErrInvalidMessage
}

func ValidAttemptContext(attemptID string, generation uint64, role Role) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(attemptID)
	valid := err == nil && len(decoded) == 16 &&
		base64.RawURLEncoding.EncodeToString(decoded) == attemptID &&
		generation == 1 && role.Valid()
	clear(decoded)
	return valid
}

type secureFrameType byte

const (
	secureFramePunchSYN    secureFrameType = 0x11
	secureFramePunchSYNACK secureFrameType = 0x12
	secureFramePunchACK    secureFrameType = 0x13
)

const securePunchBodySize = 16 + 8 + 1 + 1

func SealSecurePacket(packets *noisecore.PacketCipher, attemptID string, generation uint64, role Role, message MessageType) ([]byte, error) {
	if packets == nil || !packets.Ready() || !ValidAttemptContext(attemptID, generation, role) {
		return nil, ErrInvalidContext
	}
	frameType, ok := secureFrameTypeForMessage(message)
	if !ok {
		return nil, ErrSecurePacket
	}
	sequence, ok := secureSequenceForMessage(message)
	if !ok {
		return nil, ErrSecurePacket
	}
	attemptBytes, err := base64.RawURLEncoding.DecodeString(attemptID)
	if err != nil || len(attemptBytes) != 16 {
		clear(attemptBytes)
		return nil, ErrSecurePacket
	}
	body := make([]byte, securePunchBodySize)
	copy(body[:16], attemptBytes)
	clear(attemptBytes)
	binary.BigEndian.PutUint64(body[16:24], generation)
	body[24] = roleCode(role)
	body[25] = byte(frameType)
	header := secureFrame(frameType, sequence)
	additionalData := secureAdditionalData(header)
	ciphertext, err := packets.Seal(sequence, additionalData, body)
	clear(body)
	clear(additionalData)
	if err != nil {
		clear(header)
		return nil, err
	}
	packet := make([]byte, 0, len(header)+len(ciphertext))
	packet = append(packet, header...)
	packet = append(packet, ciphertext...)
	clear(header)
	clear(ciphertext)
	return packet, nil
}

func OpenSecurePacket(packets *noisecore.PacketCipher, packet []byte, attemptID string, generation uint64, peerRole Role) (MessageType, error) {
	if packets == nil || !packets.Ready() || !ValidAttemptContext(attemptID, generation, peerRole) {
		return "", ErrInvalidContext
	}
	headerSize := len(SecurePacketPrefix) + 1 + 8
	if len(packet) != headerSize+securePunchBodySize+noisecore.TagSize || !bytes.HasPrefix(packet, []byte(SecurePacketPrefix)) {
		return "", ErrSecurePacket
	}
	frameType := secureFrameType(packet[len(SecurePacketPrefix)])
	message, ok := messageForSecureFrameType(frameType)
	if !ok {
		return "", ErrSecurePacket
	}
	sequence := binary.BigEndian.Uint64(packet[len(SecurePacketPrefix)+1 : headerSize])
	expectedSequence, ok := secureSequenceForMessage(message)
	if !ok || sequence != expectedSequence || sequence > MaxSecurePacketSequence {
		return "", ErrSecurePacket
	}
	additionalData := secureAdditionalData(packet[:headerSize])
	plaintext, err := packets.Open(sequence, additionalData, packet[headerSize:])
	clear(additionalData)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSecurePacket, err)
	}
	defer clear(plaintext)
	attemptBytes, err := base64.RawURLEncoding.DecodeString(attemptID)
	if err != nil || len(attemptBytes) != 16 {
		clear(attemptBytes)
		return "", ErrSecurePacket
	}
	defer clear(attemptBytes)
	if len(plaintext) != securePunchBodySize ||
		!bytes.Equal(plaintext[:16], attemptBytes) ||
		binary.BigEndian.Uint64(plaintext[16:24]) != generation ||
		plaintext[24] != roleCode(peerRole) ||
		plaintext[25] != byte(frameType) {
		return "", ErrSecurePacket
	}
	return message, nil
}

func secureFrame(frameType secureFrameType, sequence uint64) []byte {
	packet := make([]byte, 0, len(SecurePacketPrefix)+1+8)
	packet = append(packet, SecurePacketPrefix...)
	packet = append(packet, byte(frameType))
	var sequenceBytes [8]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	packet = append(packet, sequenceBytes[:]...)
	clear(sequenceBytes[:])
	return packet
}

func secureSequenceForMessage(message MessageType) (uint64, bool) {
	switch message {
	case MessageSYN:
		return 0, true
	case MessageSYNACK:
		return 1, true
	case MessageACK:
		return 2, true
	default:
		return 0, false
	}
}

func secureAdditionalData(header []byte) []byte {
	additionalData := make([]byte, 0, len(SecurePacketProtocol)+1+len(header))
	additionalData = append(additionalData, SecurePacketProtocol...)
	additionalData = append(additionalData, 0)
	additionalData = append(additionalData, header...)
	return additionalData
}

func secureFrameTypeForMessage(message MessageType) (secureFrameType, bool) {
	switch message {
	case MessageSYN:
		return secureFramePunchSYN, true
	case MessageSYNACK:
		return secureFramePunchSYNACK, true
	case MessageACK:
		return secureFramePunchACK, true
	default:
		return 0, false
	}
}

func messageForSecureFrameType(frameType secureFrameType) (MessageType, bool) {
	switch frameType {
	case secureFramePunchSYN:
		return MessageSYN, true
	case secureFramePunchSYNACK:
		return MessageSYNACK, true
	case secureFramePunchACK:
		return MessageACK, true
	default:
		return "", false
	}
}

func roleCode(role Role) byte {
	switch role {
	case RoleInitiator:
		return 1
	case RoleResponder:
		return 2
	default:
		return 0
	}
}
