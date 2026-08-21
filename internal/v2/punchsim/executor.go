package punchsim

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/noisecore"
	"winkyou/pkg/transport"
)

const (
	SimulationPacketProtocol = "winkyou-test-punch/1"
	SecurePacketProtocol     = "winkyou-test-punch-noise/1"
	SecurePacketPrefix       = "WYNP\x01"
	PathID                   = "direct/test-punch"

	MaxPunchWindow          = time.Second
	DefaultPunchWindow      = 500 * time.Millisecond
	MaxOutboundPackets      = 2
	MaxInboundPackets       = 2
	MaxSimulationPacket     = 256
	MaxSecurePacketSequence = 2
)

var (
	ErrInvalidConfig    = errors.New("punchsim: invalid configuration")
	ErrPunchTimeout     = errors.New("punchsim: punch window expired")
	ErrProbeRejected    = errors.New("punchsim: simulated probe rejected")
	ErrProbeSend        = errors.New("punchsim: simulated probe send failed")
	ErrProbeReceive     = errors.New("punchsim: simulated probe receive failed")
	ErrProbeSequence    = errors.New("punchsim: invalid simulated probe sequence")
	ErrSecurePacket     = errors.New("punchsim: invalid secure simulation packet")
	ErrPromotion        = errors.New("punchsim: promotion failed")
	errUnexpectedPacket = errors.New("punchsim: unexpected simulated packet")
)

type Role string

const (
	RoleInitiator Role = "initiator"
	RoleResponder Role = "responder"
)

type ReplyVerifier func(packet []byte, from netip.AddrPort) error

// Socket is a capability-shaped simulation seam. The package never constructs
// an implementation. The only current adapter exists in a pure-memory _test.go
// file and delegates to probeio without exposing its Datagram.
type Socket interface {
	RegisterTarget(netip.AddrPort) error
	SendProbe(context.Context, netip.AddrPort, []byte) error
	ReceiveReply(context.Context, []byte, ReplyVerifier) (int, netip.AddrPort, error)
	Promote(netip.AddrPort, string) (Promotion, error)
	Close() error
}

type Promotion struct {
	AttemptID  string
	Generation uint64
	Target     netip.AddrPort
	Transport  transport.PacketTransport
}

type Config struct {
	Socket                Socket
	PeerEndpoint          netip.AddrPort
	Role                  Role
	AttemptID             string
	ObservationGeneration uint64
	PunchWindow           time.Duration
	Secure                *SecureConfig
}

// SecureConfig explicitly enables the simulation-only Noise mode. The caller
// must finish the reviewed-profile handshake over its control carrier before
// FIRE and transfers ownership of the bounded packet cipher to Run.
type SecureConfig struct {
	Packets *noisecore.PacketCipher
}

type Result struct {
	Role            Role
	PeerEndpoint    netip.AddrPort
	OutboundPackets int
	InboundPackets  int
	Secure          bool
	Promotion       Promotion
}

// PunchWorstCaseCost describes only the synchronized punch portion. Candidate
// gathering and control costs must be combined before a real attempt lease is
// acquired. Candidate gathering must reuse the one declared socket.
func PunchWorstCaseCost() governor.AttemptCost {
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets:          1,
			Targets:          1,
			PacketsPerSecond: MaxOutboundPackets,
			Packets:          MaxOutboundPackets,
			FiveTuples:       1,
		},
		Duration: MaxPunchWindow,
	}
}

type normalizedConfig struct {
	Config
	window time.Duration
}

type packetKind string

const (
	packetSYN    packetKind = "syn"
	packetSYNACK packetKind = "syn_ack"
	packetACK    packetKind = "ack"
)

type punchResult struct {
	outbound int
	inbound  int
}

type secureFrameType byte

const (
	secureFramePunchSYN    secureFrameType = 0x11
	secureFramePunchSYNACK secureFrameType = 0x12
	secureFramePunchACK    secureFrameType = 0x13
)

const securePunchBodySize = 16 + 8 + 1 + 1

// Run starts only after an injected simulation gate has released FIRE. It
// neither owns nor implements that gate. Run owns Socket on entry, closes it on
// every failure, and returns Promotion.Transport only after promotion.
func Run(ctx context.Context, input Config) (result Result, err error) {
	socket := input.Socket
	var securePackets *noisecore.PacketCipher
	if input.Secure != nil {
		securePackets = input.Secure.Packets
		if securePackets != nil {
			defer securePackets.Close()
		}
	}
	promoted := false
	if socket != nil {
		defer func() {
			if !promoted {
				err = errors.Join(err, socket.Close())
			}
		}()
	}

	config, err := normalizeConfig(ctx, input)
	if err != nil {
		return Result{}, err
	}
	if err := config.Socket.RegisterTarget(config.PeerEndpoint); err != nil {
		return Result{}, fmt.Errorf("%w: register peer target: %w", ErrInvalidConfig, err)
	}
	punch, err := runPunch(ctx, config, securePackets)
	if err != nil {
		return Result{}, err
	}
	promotion, err := config.Socket.Promote(config.PeerEndpoint, PathID)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrPromotion, err)
	}
	promoted = true
	if promotion.AttemptID != config.AttemptID ||
		promotion.Generation != config.ObservationGeneration ||
		promotion.Target != config.PeerEndpoint ||
		promotion.Transport == nil {
		if promotion.Transport != nil {
			_ = promotion.Transport.Close()
		}
		return Result{}, ErrPromotion
	}
	return Result{
		Role:            config.Role,
		PeerEndpoint:    config.PeerEndpoint,
		OutboundPackets: punch.outbound,
		InboundPackets:  punch.inbound,
		Secure:          config.Secure != nil,
		Promotion:       promotion,
	}, nil
}

func normalizeConfig(ctx context.Context, input Config) (normalizedConfig, error) {
	if ctx == nil || input.Socket == nil || !validEndpoint(input.PeerEndpoint) {
		return normalizedConfig{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return normalizedConfig{}, err
	}
	if input.Role != RoleInitiator && input.Role != RoleResponder {
		return normalizedConfig{}, ErrInvalidConfig
	}
	if !validAttemptID(input.AttemptID) || input.ObservationGeneration != 1 {
		return normalizedConfig{}, ErrInvalidConfig
	}
	window := input.PunchWindow
	if window == 0 {
		window = DefaultPunchWindow
	}
	if window <= 0 || window > MaxPunchWindow {
		return normalizedConfig{}, ErrInvalidConfig
	}
	if input.Secure != nil && (input.Secure.Packets == nil || !input.Secure.Packets.Ready()) {
		return normalizedConfig{}, ErrInvalidConfig
	}
	input.PeerEndpoint = netip.AddrPortFrom(input.PeerEndpoint.Addr().Unmap(), input.PeerEndpoint.Port())
	input.PunchWindow = window
	return normalizedConfig{Config: input, window: window}, nil
}

func validEndpoint(endpoint netip.AddrPort) bool {
	return endpoint.IsValid() && endpoint.Port() != 0 && endpoint.Addr().Zone() == "" &&
		!endpoint.Addr().IsUnspecified() && !endpoint.Addr().IsMulticast()
}

func validAttemptID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func runPunch(ctx context.Context, config normalizedConfig, packets *noisecore.PacketCipher) (punchResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, config.window)
	defer cancel()
	return runPunchWithin(runCtx, config, packets, punchResult{})
}

func runPunchWithin(ctx context.Context, config normalizedConfig, packets *noisecore.PacketCipher, result punchResult) (punchResult, error) {
	if err := sendSimulationPacket(ctx, config, packets, packetSYN); err != nil {
		return result, err
	}
	result.outbound++

	first, err := receiveSimulationPacket(ctx, config, packets)
	if err != nil {
		return result, err
	}
	result.inbound++
	switch first {
	case packetSYN:
		if err := sendSimulationPacket(ctx, config, packets, packetSYNACK); err != nil {
			return result, err
		}
		result.outbound++
		second, err := receiveSimulationPacket(ctx, config, packets)
		if err != nil {
			return result, err
		}
		result.inbound++
		if second != packetSYNACK && second != packetACK {
			return result, ErrProbeSequence
		}
		return result, nil
	case packetSYNACK:
		if err := sendSimulationPacket(ctx, config, packets, packetACK); err != nil {
			return result, err
		}
		result.outbound++
		return result, nil
	default:
		return result, ErrProbeSequence
	}
}

func sendSimulationPacket(ctx context.Context, config normalizedConfig, packets *noisecore.PacketCipher, kind packetKind) error {
	var packet []byte
	if packets != nil {
		var err error
		packet, err = secureSimulationPacket(packets, config.AttemptID, config.ObservationGeneration, config.Role, kind)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSecurePacket, err)
		}
	} else {
		packet = simulationPacket(config.AttemptID, config.ObservationGeneration, config.Role, kind)
	}
	defer clear(packet)
	if len(packet) == 0 || len(packet) > MaxSimulationPacket {
		return ErrInvalidConfig
	}
	if err := config.Socket.SendProbe(ctx, config.PeerEndpoint, packet); err != nil {
		if contextError := ctx.Err(); contextError != nil {
			if errors.Is(contextError, context.DeadlineExceeded) {
				return ErrPunchTimeout
			}
			return contextError
		}
		return fmt.Errorf("%w: %w", ErrProbeSend, err)
	}
	return nil
}

func receiveSimulationPacket(ctx context.Context, config normalizedConfig, packets *noisecore.PacketCipher) (packetKind, error) {
	buffer := make([]byte, MaxSimulationPacket+1)
	defer clear(buffer)
	var received packetKind
	_, from, err := config.Socket.ReceiveReply(ctx, buffer, func(packet []byte, source netip.AddrPort) error {
		if source != config.PeerEndpoint {
			return errUnexpectedPacket
		}
		peerRole := RoleInitiator
		if config.Role == RoleInitiator {
			peerRole = RoleResponder
		}
		if packets != nil {
			candidate, err := openSecureSimulationPacket(packets, packet, config.AttemptID, config.ObservationGeneration, peerRole)
			if err != nil {
				return err
			}
			received = candidate
			return nil
		}
		for _, candidate := range []packetKind{packetSYN, packetSYNACK, packetACK} {
			if string(packet) == string(simulationPacket(config.AttemptID, config.ObservationGeneration, peerRole, candidate)) {
				received = candidate
				return nil
			}
		}
		return errUnexpectedPacket
	})
	if err == nil && from != config.PeerEndpoint {
		return "", ErrProbeRejected
	}
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			if errors.Is(contextError, context.DeadlineExceeded) {
				return "", ErrPunchTimeout
			}
			return "", contextError
		}
		if errors.Is(err, errUnexpectedPacket) {
			return "", fmt.Errorf("%w: %w", ErrProbeRejected, err)
		}
		if errors.Is(err, ErrSecurePacket) || errors.Is(err, noisecore.ErrAuthentication) || errors.Is(err, noisecore.ErrClosed) {
			return "", fmt.Errorf("%w: %w", ErrProbeRejected, err)
		}
		return "", fmt.Errorf("%w: %w", ErrProbeReceive, err)
	}
	if received == "" {
		return "", ErrProbeRejected
	}
	return received, nil
}

func secureFrame(frameType secureFrameType, sequence uint64, body []byte) []byte {
	packet := make([]byte, 0, len(SecurePacketPrefix)+1+8+len(body))
	packet = append(packet, SecurePacketPrefix...)
	packet = append(packet, byte(frameType))
	var sequenceBytes [8]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	packet = append(packet, sequenceBytes[:]...)
	clear(sequenceBytes[:])
	packet = append(packet, body...)
	return packet
}

func secureSimulationPacket(packets *noisecore.PacketCipher, attemptID string, generation uint64, role Role, kind packetKind) ([]byte, error) {
	frameType, ok := secureFrameTypeForKind(kind)
	if !ok {
		return nil, ErrSecurePacket
	}
	sequence, ok := secureSequenceForKind(kind)
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
	body[24] = byte(roleCode(role))
	body[25] = byte(frameType)
	header := secureFrame(frameType, sequence, nil)
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

func openSecureSimulationPacket(packets *noisecore.PacketCipher, packet []byte, attemptID string, generation uint64, peerRole Role) (packetKind, error) {
	headerSize := len(SecurePacketPrefix) + 1 + 8
	if len(packet) != headerSize+securePunchBodySize+noisecore.TagSize || !bytes.HasPrefix(packet, []byte(SecurePacketPrefix)) {
		return "", ErrSecurePacket
	}
	frameType := secureFrameType(packet[len(SecurePacketPrefix)])
	kind, ok := packetKindForSecureFrame(frameType)
	if !ok {
		return "", ErrSecurePacket
	}
	sequence := binary.BigEndian.Uint64(packet[len(SecurePacketPrefix)+1 : headerSize])
	expectedSequence, ok := secureSequenceForKind(kind)
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
		plaintext[24] != byte(roleCode(peerRole)) ||
		plaintext[25] != byte(frameType) {
		return "", ErrSecurePacket
	}
	return kind, nil
}

func secureSequenceForKind(kind packetKind) (uint64, bool) {
	switch kind {
	case packetSYN:
		return 0, true
	case packetSYNACK:
		return 1, true
	case packetACK:
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

func secureFrameTypeForKind(kind packetKind) (secureFrameType, bool) {
	switch kind {
	case packetSYN:
		return secureFramePunchSYN, true
	case packetSYNACK:
		return secureFramePunchSYNACK, true
	case packetACK:
		return secureFramePunchACK, true
	default:
		return 0, false
	}
}

func packetKindForSecureFrame(frameType secureFrameType) (packetKind, bool) {
	switch frameType {
	case secureFramePunchSYN:
		return packetSYN, true
	case secureFramePunchSYNACK:
		return packetSYNACK, true
	case secureFramePunchACK:
		return packetACK, true
	default:
		return "", false
	}
}

func roleCode(role Role) byte {
	if role == RoleInitiator {
		return 1
	}
	if role == RoleResponder {
		return 2
	}
	return 0
}

func simulationPacket(attemptID string, generation uint64, role Role, kind packetKind) []byte {
	return []byte(strings.Join([]string{
		SimulationPacketProtocol,
		attemptID,
		strconv.FormatUint(generation, 10),
		string(role),
		string(kind),
	}, "|"))
}
