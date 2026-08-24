package punchsim

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/punchproto"
	"winkyou/pkg/transport"
)

const (
	SimulationPacketProtocol = punchproto.PlainPacketProtocol
	SecurePacketProtocol     = punchproto.SecurePacketProtocol
	SecurePacketPrefix       = punchproto.SecurePacketPrefix
	PathID                   = "direct/test-punch"

	MaxPunchWindow          = time.Second
	DefaultPunchWindow      = 500 * time.Millisecond
	MaxOutboundPackets      = 2
	MaxInboundPackets       = 2
	MaxSimulationPacket     = punchproto.MaxPacketBytes
	MaxSecurePacketSequence = punchproto.MaxSecurePacketSequence
)

var (
	ErrInvalidConfig    = errors.New("punchsim: invalid configuration")
	ErrPunchTimeout     = errors.New("punchsim: punch window expired")
	ErrProbeRejected    = errors.New("punchsim: simulated probe rejected")
	ErrProbeSend        = errors.New("punchsim: simulated probe send failed")
	ErrProbeReceive     = errors.New("punchsim: simulated probe receive failed")
	ErrProbeSequence    = errors.New("punchsim: invalid simulated probe sequence")
	ErrSecurePacket     = punchproto.ErrSecurePacket
	ErrPromotion        = errors.New("punchsim: promotion failed")
	errUnexpectedPacket = errors.New("punchsim: unexpected simulated packet")
)

type Role = punchproto.Role

const (
	RoleInitiator = punchproto.RoleInitiator
	RoleResponder = punchproto.RoleResponder
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

type packetKind = punchproto.MessageType

const (
	packetSYN    = punchproto.MessageSYN
	packetSYNACK = punchproto.MessageSYNACK
	packetACK    = punchproto.MessageACK
)

type punchResult struct {
	outbound int
	inbound  int
}

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
	machine := punchproto.NewMachine()
	first, err := machine.Start()
	if err != nil {
		return result, ErrProbeSequence
	}
	if err := sendSimulationPacket(ctx, config, packets, first); err != nil {
		return result, err
	}
	result.outbound++
	for result.inbound < MaxInboundPackets {
		received, err := receiveSimulationPacket(ctx, config, packets)
		if err != nil {
			return result, err
		}
		result.inbound++
		transition, err := machine.Receive(received)
		if err != nil {
			return result, ErrProbeSequence
		}
		if transition.Reply.Valid() {
			if err := sendSimulationPacket(ctx, config, packets, transition.Reply); err != nil {
				return result, err
			}
			result.outbound++
		}
		if transition.Complete {
			return result, nil
		}
	}
	return result, ErrProbeSequence
}

func sendSimulationPacket(ctx context.Context, config normalizedConfig, packets *noisecore.PacketCipher, kind packetKind) error {
	var packet []byte
	if packets != nil {
		var err error
		packet, err = punchproto.SealSecurePacket(packets, config.AttemptID, config.ObservationGeneration, config.Role, kind)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSecurePacket, err)
		}
	} else {
		var err error
		packet, err = punchproto.EncodePlainPacket(config.AttemptID, config.ObservationGeneration, config.Role, kind)
		if err != nil {
			return fmt.Errorf("%w: encode packet: %w", ErrInvalidConfig, err)
		}
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
		peerRole, ok := config.Role.Peer()
		if !ok {
			return errUnexpectedPacket
		}
		if packets != nil {
			candidate, err := punchproto.OpenSecurePacket(packets, packet, config.AttemptID, config.ObservationGeneration, peerRole)
			if err != nil {
				return err
			}
			received = candidate
			return nil
		}
		candidate, err := punchproto.OpenPlainPacket(packet, config.AttemptID, config.ObservationGeneration, peerRole)
		if err == nil {
			received = candidate
			return nil
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

func secureSimulationPacket(packets *noisecore.PacketCipher, attemptID string, generation uint64, role Role, kind packetKind) ([]byte, error) {
	return punchproto.SealSecurePacket(packets, attemptID, generation, role, kind)
}

func openSecureSimulationPacket(packets *noisecore.PacketCipher, packet []byte, attemptID string, generation uint64, peerRole Role) (packetKind, error) {
	return punchproto.OpenSecurePacket(packets, packet, attemptID, generation, peerRole)
}

func simulationPacket(attemptID string, generation uint64, role Role, kind packetKind) []byte {
	packet, _ := punchproto.EncodePlainPacket(attemptID, generation, role, kind)
	return packet
}
