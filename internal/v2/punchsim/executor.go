package punchsim

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"winkyou/internal/governor"
	"winkyou/pkg/transport"
)

const (
	SimulationPacketProtocol = "winkyou-test-punch/1"
	PathID                   = "direct/test-punch"

	MaxPunchWindow      = time.Second
	DefaultPunchWindow  = 500 * time.Millisecond
	MaxOutboundPackets  = 2
	MaxInboundPackets   = 2
	MaxSimulationPacket = 256
)

var (
	ErrInvalidConfig    = errors.New("punchsim: invalid configuration")
	ErrPunchTimeout     = errors.New("punchsim: punch window expired")
	ErrProbeRejected    = errors.New("punchsim: simulated probe rejected")
	ErrProbeSend        = errors.New("punchsim: simulated probe send failed")
	ErrProbeReceive     = errors.New("punchsim: simulated probe receive failed")
	ErrProbeSequence    = errors.New("punchsim: invalid simulated probe sequence")
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
}

type Result struct {
	Role            Role
	PeerEndpoint    netip.AddrPort
	OutboundPackets int
	InboundPackets  int
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

// Run starts only after an injected simulation gate has released FIRE. It
// neither owns nor implements that gate. Run owns Socket on entry, closes it on
// every failure, and returns Promotion.Transport only after promotion.
func Run(ctx context.Context, input Config) (result Result, err error) {
	socket := input.Socket
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
	punch, err := runPunch(ctx, config)
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

func runPunch(ctx context.Context, config normalizedConfig) (punchResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, config.window)
	defer cancel()

	result := punchResult{}
	if err := sendSimulationPacket(runCtx, config, packetSYN); err != nil {
		return result, err
	}
	result.outbound++

	first, err := receiveSimulationPacket(runCtx, config)
	if err != nil {
		return result, err
	}
	result.inbound++
	switch first {
	case packetSYN:
		if err := sendSimulationPacket(runCtx, config, packetSYNACK); err != nil {
			return result, err
		}
		result.outbound++
		second, err := receiveSimulationPacket(runCtx, config)
		if err != nil {
			return result, err
		}
		result.inbound++
		if second != packetSYNACK && second != packetACK {
			return result, ErrProbeSequence
		}
		return result, nil
	case packetSYNACK:
		if err := sendSimulationPacket(runCtx, config, packetACK); err != nil {
			return result, err
		}
		result.outbound++
		return result, nil
	default:
		return result, ErrProbeSequence
	}
}

func sendSimulationPacket(ctx context.Context, config normalizedConfig, kind packetKind) error {
	packet := simulationPacket(config.AttemptID, config.ObservationGeneration, config.Role, kind)
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

func receiveSimulationPacket(ctx context.Context, config normalizedConfig) (packetKind, error) {
	buffer := make([]byte, MaxSimulationPacket+1)
	var received packetKind
	_, from, err := config.Socket.ReceiveReply(ctx, buffer, func(packet []byte, source netip.AddrPort) error {
		if source != config.PeerEndpoint {
			return errUnexpectedPacket
		}
		peerRole := RoleInitiator
		if config.Role == RoleInitiator {
			peerRole = RoleResponder
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
		return "", fmt.Errorf("%w: %w", ErrProbeReceive, err)
	}
	if received == "" {
		return "", ErrProbeRejected
	}
	return received, nil
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
