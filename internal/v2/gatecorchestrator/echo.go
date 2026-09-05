package gatecorchestrator

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"

	"winkyou/internal/v2/directattempt"
)

const (
	echoMagic       = "WYCE"
	echoVersion     = 1
	echoPayloadSize = 48
	echoPacketSize  = 20 + 8 + echoPayloadSize
	echoPort        = 32112
)

type echoKind byte

const (
	echoRequest  echoKind = 1
	echoResponse echoKind = 2
	echoClose    echoKind = 3
)

var ErrEchoInvalid = errors.New("gatecorchestrator: invalid in-tunnel control datagram")

type echoBinding struct {
	Role          directattempt.Role
	Local         netip.Addr
	Remote        netip.Addr
	AttemptID     string
	ContextDigest [32]byte
}

type echoMessage struct {
	Kind  echoKind
	Role  directattempt.Role
	Nonce [8]byte
}

func buildEchoPacket(binding echoBinding, kind echoKind, nonce [8]byte) ([]byte, error) {
	if !validEchoBinding(binding) || !validEchoKind(kind) {
		return nil, ErrEchoInvalid
	}
	payload := make([]byte, echoPayloadSize)
	copy(payload[0:4], echoMagic)
	payload[4] = echoVersion
	payload[5] = byte(kind)
	payload[6] = encodeEchoRole(binding.Role)
	payload[7] = 0
	attemptDigest := sha256.Sum256(append([]byte("winkyou-gate-c-attempt/1\x00"), []byte(binding.AttemptID)...))
	copy(payload[8:24], attemptDigest[:16])
	copy(payload[24:40], binding.ContextDigest[:16])
	copy(payload[40:48], nonce[:])
	clear(attemptDigest[:])

	packet := make([]byte, echoPacketSize)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	source, destination := binding.Local.As4(), binding.Remote.As4()
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], echoPort)
	binary.BigEndian.PutUint16(packet[22:24], echoPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	clear(payload)
	return packet, nil
}

func parseEchoPacket(packet []byte, binding echoBinding, wantKind echoKind, wantNonce *[8]byte) (echoMessage, error) {
	if !validEchoBinding(binding) || !validEchoKind(wantKind) || len(packet) != echoPacketSize ||
		packet[0] != 0x45 || binary.BigEndian.Uint16(packet[2:4]) != echoPacketSize || packet[9] != 17 ||
		ipv4Checksum(packet[:20]) != 0 || binary.BigEndian.Uint16(packet[20:22]) != echoPort ||
		binary.BigEndian.Uint16(packet[22:24]) != echoPort || binary.BigEndian.Uint16(packet[24:26]) != 8+echoPayloadSize {
		return echoMessage{}, ErrEchoInvalid
	}
	source := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	destination := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	if source != binding.Remote || destination != binding.Local {
		return echoMessage{}, ErrEchoInvalid
	}
	payload := packet[28:]
	peerRole := binding.Role.Peer()
	if string(payload[0:4]) != echoMagic || payload[4] != echoVersion || echoKind(payload[5]) != wantKind ||
		payload[6] != encodeEchoRole(peerRole) || payload[7] != 0 {
		return echoMessage{}, ErrEchoInvalid
	}
	attemptDigest := sha256.Sum256(append([]byte("winkyou-gate-c-attempt/1\x00"), []byte(binding.AttemptID)...))
	validDigest := equalBytes(payload[8:24], attemptDigest[:16]) && equalBytes(payload[24:40], binding.ContextDigest[:16])
	clear(attemptDigest[:])
	if !validDigest {
		return echoMessage{}, ErrEchoInvalid
	}
	message := echoMessage{Kind: wantKind, Role: peerRole}
	copy(message.Nonce[:], payload[40:48])
	if wantNonce != nil && message.Nonce != *wantNonce {
		return echoMessage{}, ErrEchoInvalid
	}
	return message, nil
}

func validEchoBinding(binding echoBinding) bool {
	return binding.Role.Valid() && binding.Local.Is4() && binding.Remote.Is4() && binding.Local != binding.Remote &&
		binding.Local.IsGlobalUnicast() && binding.Remote.IsGlobalUnicast() && binding.AttemptID != ""
}

func validEchoKind(kind echoKind) bool {
	return kind == echoRequest || kind == echoResponse || kind == echoClose
}

func encodeEchoRole(role directattempt.Role) byte {
	if role == directattempt.RoleInitiator {
		return 1
	}
	if role == directattempt.RoleResponder {
		return 2
	}
	return 0
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
