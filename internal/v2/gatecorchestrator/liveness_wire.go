package gatecorchestrator

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	livenessPort          = 32113
	livenessPayloadSize   = 64
	livenessPacketSize    = 20 + 8 + livenessPayloadSize
	livenessWireGuardSize = 128
)

type livenessKind byte

const (
	livenessPing livenessKind = 1
	livenessPong livenessKind = 2
)

type livenessMessage struct {
	kind     livenessKind
	sequence uint64
	nonce    [16]byte
}

var (
	errLivenessProtocol    = errors.New("session_liveness_protocol_invalid")
	errLivenessTimeout     = errors.New("session_liveness_timeout")
	errLivenessClock       = errors.New("session_liveness_clock_invalid")
	errLivenessBudget      = errors.New("session_liveness_budget_exceeded")
	errLivenessUnavailable = errors.New("session_liveness_unavailable")
)

func buildLivenessPacket(binding echoBinding, message livenessMessage) ([]byte, error) {
	if !validEchoBinding(binding) || message.sequence == 0 || (message.kind != livenessPing && message.kind != livenessPong) {
		return nil, errLivenessProtocol
	}
	b := make([]byte, livenessPacketSize)
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:4], livenessPacketSize)
	src, dst := binding.Local.As4(), binding.Remote.As4()
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	binary.BigEndian.PutUint16(b[20:22], livenessPort)
	binary.BigEndian.PutUint16(b[22:24], livenessPort)
	binary.BigEndian.PutUint16(b[24:26], 8+livenessPayloadSize)
	p := b[28:]
	copy(p, "WYCL")
	p[4], p[5], p[6] = 1, byte(message.kind), encodeEchoRole(binding.Role)
	digest := sha256.Sum256([]byte("winkyou-gate-c-liveness-attempt/1\x00" + binding.AttemptID))
	copy(p[8:24], digest[:16])
	copy(p[24:40], binding.ContextDigest[:16])
	binary.BigEndian.PutUint64(p[40:48], message.sequence)
	copy(p[48:64], message.nonce[:])
	checksum := livenessUDPChecksum(b)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(b[26:28], checksum)
	return b, nil
}

func parseLivenessPacket(b []byte, binding echoBinding) (livenessMessage, error) {
	if !validEchoBinding(binding) || len(b) != livenessPacketSize || b[0] != 0x45 || b[9] != 17 ||
		binary.BigEndian.Uint16(b[2:4]) != livenessPacketSize || binary.BigEndian.Uint16(b[6:8])&0xbfff != 0 ||
		ipv4Checksum(b[:20]) != 0 || binary.BigEndian.Uint16(b[20:22]) != livenessPort || binary.BigEndian.Uint16(b[22:24]) != livenessPort ||
		binary.BigEndian.Uint16(b[24:26]) != 8+livenessPayloadSize || binary.BigEndian.Uint16(b[26:28]) == 0 || livenessUDPChecksum(b) != 0 {
		return livenessMessage{}, errLivenessProtocol
	}
	src, dst := binding.Remote.As4(), binding.Local.As4()
	p := b[28:]
	digest := sha256.Sum256([]byte("winkyou-gate-c-liveness-attempt/1\x00" + binding.AttemptID))
	if !equalBytes(b[12:16], src[:]) || !equalBytes(b[16:20], dst[:]) || string(p[:4]) != "WYCL" || p[4] != 1 ||
		(p[5] != byte(livenessPing) && p[5] != byte(livenessPong)) || p[6] != encodeEchoRole(binding.Role.Peer()) || p[7] != 0 ||
		!equalBytes(p[8:24], digest[:16]) || !equalBytes(p[24:40], binding.ContextDigest[:16]) {
		return livenessMessage{}, errLivenessProtocol
	}
	m := livenessMessage{kind: livenessKind(p[5]), sequence: binary.BigEndian.Uint64(p[40:48])}
	copy(m.nonce[:], p[48:64])
	if m.sequence == 0 {
		return livenessMessage{}, errLivenessProtocol
	}
	return m, nil
}

func livenessUDPChecksum(b []byte) uint16 {
	// IPv4 pseudo-header + UDP, all fixed even lengths. No allocation or raw I/O.
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	sum += 17 + uint32(len(b)-20)
	for i := 20; i < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
