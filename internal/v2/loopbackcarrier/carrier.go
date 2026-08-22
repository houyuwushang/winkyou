package loopbackcarrier

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/punchproto"
)

const (
	AttemptDuration      = 15 * time.Second
	MaxOutboundPackets   = 3
	MaxPacketsPerSecond  = 3
	handshakePacketBytes = noisecore.PublicKeySize + noisecore.TagSize
)

// ProgressStage identifies a redacted, non-authoritative lifecycle witness.
// It never carries an endpoint, identifier, secret, transcript, or handle.
type ProgressStage string

const ProgressStageSocketReady ProgressStage = "loopback_socket_ready"

// ProgressReporter observes reviewed carrier stages. A reporting failure
// aborts before the next emission and is recorded as a terminal carrier error.
type ProgressReporter func(ProgressStage) error

var (
	ErrCarrierUnavailable = errors.New("loopbackcarrier: carrier unavailable")
	ErrCarrierProtocol    = errors.New("loopbackcarrier: secure protocol failed")
	ErrCarrierTerminal    = errors.New("loopbackcarrier: terminal recording failed")
)

// Result contains no endpoint, identifier, secret, transcript, or reusable
// transport. A successful result proves only this one terminal loopback test.
type Result struct {
	Established       bool                              `json:"established"`
	Bidirectional     bool                              `json:"bidirectional"`
	Promoted          bool                              `json:"promoted"`
	Terminal          string                            `json:"terminal"`
	NetworkScope      string                            `json:"network_scope"`
	OutboundPackets   int                               `json:"outbound_packets"`
	WorstCaseEnvelope governor.PairingAdmissionEnvelope `json:"worst_case_envelope"`
}

func AttemptCost() governor.AttemptCost {
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets:          1,
			Targets:          1,
			PacketsPerSecond: MaxPacketsPerSecond,
			Packets:          MaxOutboundPackets,
			FiveTuples:       1,
		},
		Duration:    AttemptDuration,
		Heavyweight: true,
	}
}

// Connect validates a complete bundle before obtaining network authority,
// then executes exactly one terminal loopback attempt. Non-loopback and
// user-scoped bundles fail before acquiring a peer, attempt, or admission.
func Connect(ctx context.Context, machine *governor.Governor, payload []byte, buildVersion string, progress ProgressReporter) (result Result, err error) {
	if ctx == nil || machine == nil {
		return Result{}, ErrCarrierUnavailable
	}
	bundle, err := parseCompleteBundle(payload, time.Now())
	if err != nil {
		return Result{}, err
	}
	defer bundle.zeroize()
	if err := bundle.requireLoopbackMachine(); err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	peer, err := machine.AcquirePeer(bundle.peerID)
	if err != nil {
		return Result{}, errors.Join(ErrCarrierUnavailable, err)
	}
	defer func() { err = errors.Join(err, peer.Close()) }()
	cost := AttemptCost()
	attempt, err := peer.AcquireAttempt(ctx, governor.AttemptRequest{
		ID:        bundle.attemptID,
		Operation: governor.OperationConnectTest,
		Cost:      cost,
	})
	if err != nil {
		return Result{}, errors.Join(ErrCarrierUnavailable, err)
	}
	defer func() { err = errors.Join(err, attempt.Close()) }()

	committed, err := governor.NewPairingAdmissionGate().Commit(ctx, attempt, governor.PairingAdmissionRequest{
		CredentialID:  bundle.credentialID,
		AttemptID:     bundle.attemptID,
		ContextDigest: bundle.contextDigest,
		Scope:         governor.ScopeMachine,
		ExpiresAt:     bundle.expiresAt,
		Envelope:      governor.PairingEnvelopeFromAttemptCost(cost),
	})
	if err != nil {
		return Result{}, err
	}
	authorization, err := committed.ConsumeForCarrier(ctx)
	if err != nil {
		return Result{}, err
	}
	admitted := &admittedCarrier{
		authorization: authorization,
		attempt:       attempt,
		bundle:        bundle,
		buildVersion:  buildVersion,
		progress:      progress,
	}
	return admitted.run(ctx)
}

type admittedCarrier struct {
	authorization emissionAuthorization
	attempt       probeio.AttemptLease
	bundle        *preparedBundle
	buildVersion  string
	progress      ProgressReporter
}

type emissionAuthorization interface {
	BeforeFirstEmission(context.Context) error
	CheckActive(context.Context) error
	Finish(governor.PairingTerminalReason) error
}

var _ emissionAuthorization = (*governor.CommittedCarrierAuthorization)(nil)

func (carrier *admittedCarrier) run(ctx context.Context) (result Result, err error) {
	if carrier == nil || carrier.authorization == nil || carrier.attempt == nil || carrier.bundle == nil {
		return Result{}, ErrCarrierUnavailable
	}
	reason := governor.PairingTerminalCarrierError
	var controller *probeio.Controller
	defer func() {
		finishErr := carrier.authorization.Finish(reason)
		if finishErr != nil {
			err = errors.Join(err, ErrCarrierTerminal, finishErr)
		}
		if controller != nil {
			err = errors.Join(err, controller.Close())
		}
	}()

	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr:          carrier.bundle.local,
		AllowedTargetScope: probeio.AllowedTargetScopeLoopback,
	})
	if err != nil {
		return Result{}, errors.Join(ErrCarrierUnavailable, err)
	}
	generation := probeio.NewGeneration(1)
	controller, err = probeio.New(probeio.Config{
		Lease:              carrier.attempt,
		Generation:         generation,
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       carrier.buildVersion,
	})
	if err != nil {
		return Result{}, errors.Join(ErrCarrierUnavailable, err)
	}
	socket, err := controller.OpenProbeSocket(ctx)
	if err != nil {
		return Result{}, errors.Join(ErrCarrierUnavailable, err)
	}
	if err := socket.RegisterTarget(carrier.bundle.peer); err != nil {
		return Result{}, errors.Join(ErrCarrierUnavailable, err)
	}
	if carrier.progress != nil {
		if err := carrier.progress(ProgressStageSocketReady); err != nil {
			return Result{}, errors.Join(ErrCarrierUnavailable, err)
		}
	}

	prologue, err := pairingcontext.BuildNoisePrologue(carrier.bundle.context)
	if err != nil {
		return Result{}, errors.Join(ErrCarrierProtocol, err)
	}
	psk := carrier.bundle.psk
	clear(carrier.bundle.psk[:])
	source := &oneShotPSK{key: psk, available: true}
	clear(psk[:])
	var session *noisecore.Session
	if carrier.bundle.role == punchproto.RoleInitiator {
		session, err = noisecore.NewInitiator(noisecore.Config{Prologue: prologue, PSK: source})
	} else {
		session, err = noisecore.NewResponder(noisecore.Config{Prologue: prologue, PSK: source})
	}
	clear(prologue)
	source.zeroize()
	if err != nil {
		return Result{}, errors.Join(ErrCarrierProtocol, err)
	}
	defer session.Close()

	if err := carrier.authorization.BeforeFirstEmission(ctx); err != nil {
		reason = terminalReason(err)
		return Result{}, err
	}
	outbound, packetCipher, err := carrier.handshake(ctx, socket, session)
	if err != nil {
		reason = terminalReason(err)
		return Result{}, errors.Join(ErrCarrierProtocol, err)
	}
	defer packetCipher.Close()
	punchOutbound, err := carrier.punch(ctx, socket, packetCipher)
	outbound += punchOutbound
	if err != nil {
		reason = terminalReason(err)
		return Result{}, errors.Join(ErrCarrierProtocol, err)
	}

	if err := carrier.authorization.CheckActive(ctx); err != nil {
		reason = terminalReason(err)
		return Result{}, err
	}
	promotion, err := socket.PromoteTerminal(carrier.bundle.peer, "loopback/connect-test")
	if err != nil {
		reason = terminalReason(err)
		return Result{}, errors.Join(ErrCarrierUnavailable, err)
	}
	if closeErr := promotion.Transport.Close(); closeErr != nil {
		reason = governor.PairingTerminalCarrierError
		return Result{}, errors.Join(ErrCarrierUnavailable, closeErr)
	}
	reason = governor.PairingTerminalSuccess
	return Result{
		Established:       true,
		Bidirectional:     true,
		Promoted:          true,
		Terminal:          string(governor.PairingTerminalSuccess),
		NetworkScope:      "loopback",
		OutboundPackets:   outbound,
		WorstCaseEnvelope: governor.PairingEnvelopeFromAttemptCost(AttemptCost()),
	}, nil
}

func (carrier *admittedCarrier) handshake(ctx context.Context, socket *probeio.ProbeSocket, session *noisecore.Session) (int, *noisecore.PacketCipher, error) {
	outbound := 0
	if carrier.bundle.role == punchproto.RoleInitiator {
		message, err := session.WriteMessage(nil)
		if err != nil {
			return outbound, nil, err
		}
		if len(message) != handshakePacketBytes {
			clear(message)
			return outbound, nil, noisecore.ErrInvalidMessage
		}
		if err := socket.SendProbe(ctx, carrier.bundle.peer, message); err != nil {
			clear(message)
			return outbound, nil, err
		}
		outbound++
		clear(message)
		if err := carrier.authorization.CheckActive(ctx); err != nil {
			return outbound, nil, err
		}
		if err := receiveExact(ctx, socket, handshakePacketBytes+1, func(packet []byte) error {
			if len(packet) != handshakePacketBytes {
				return noisecore.ErrInvalidMessage
			}
			payload, err := session.ReadMessage(packet)
			defer clear(payload)
			if err != nil || len(payload) != 0 {
				if err != nil {
					return err
				}
				return noisecore.ErrInvalidMessage
			}
			return nil
		}); err != nil {
			return outbound, nil, err
		}
	} else {
		if err := receiveExact(ctx, socket, handshakePacketBytes+1, func(packet []byte) error {
			if len(packet) != handshakePacketBytes {
				return noisecore.ErrInvalidMessage
			}
			payload, err := session.ReadMessage(packet)
			defer clear(payload)
			if err != nil || len(payload) != 0 {
				if err != nil {
					return err
				}
				return noisecore.ErrInvalidMessage
			}
			return nil
		}); err != nil {
			return outbound, nil, err
		}
		if err := carrier.authorization.CheckActive(ctx); err != nil {
			return outbound, nil, err
		}
		message, err := session.WriteMessage(nil)
		if err != nil {
			return outbound, nil, err
		}
		if len(message) != handshakePacketBytes {
			clear(message)
			return outbound, nil, noisecore.ErrInvalidMessage
		}
		if err := socket.SendProbe(ctx, carrier.bundle.peer, message); err != nil {
			clear(message)
			return outbound, nil, err
		}
		outbound++
		clear(message)
	}
	packetCipher, err := session.TakePacketCipher(punchproto.MaxSecurePacketSequence)
	return outbound, packetCipher, err
}

func (carrier *admittedCarrier) punch(ctx context.Context, socket *probeio.ProbeSocket, cipher *noisecore.PacketCipher) (int, error) {
	machine := punchproto.NewMachine()
	outbound := 0
	if carrier.bundle.role == punchproto.RoleInitiator {
		first, err := machine.Start()
		if err != nil {
			return outbound, err
		}
		if err := carrier.sendPunch(ctx, socket, cipher, first); err != nil {
			return outbound, err
		}
		outbound++
		transition, err := carrier.receivePunch(ctx, socket, cipher, machine)
		if err != nil || !transition.Complete || transition.Reply != punchproto.MessageACK {
			if err != nil {
				return outbound, err
			}
			return outbound, punchproto.ErrInvalidTransition
		}
		if err := carrier.sendPunch(ctx, socket, cipher, transition.Reply); err != nil {
			return outbound, err
		}
		outbound++
		return outbound, nil
	}

	if err := machine.Await(); err != nil {
		return outbound, err
	}
	transition, err := carrier.receivePunch(ctx, socket, cipher, machine)
	if err != nil || transition.Reply != punchproto.MessageSYNACK || transition.Complete {
		if err != nil {
			return outbound, err
		}
		return outbound, punchproto.ErrInvalidTransition
	}
	if err := carrier.sendPunch(ctx, socket, cipher, transition.Reply); err != nil {
		return outbound, err
	}
	outbound++
	transition, err = carrier.receivePunch(ctx, socket, cipher, machine)
	if err != nil || !transition.Complete || transition.Reply != "" {
		if err != nil {
			return outbound, err
		}
		return outbound, punchproto.ErrInvalidTransition
	}
	return outbound, nil
}

func (carrier *admittedCarrier) sendPunch(ctx context.Context, socket *probeio.ProbeSocket, cipher *noisecore.PacketCipher, message punchproto.MessageType) error {
	if err := carrier.authorization.CheckActive(ctx); err != nil {
		return err
	}
	packet, err := punchproto.SealSecurePacket(cipher, carrier.bundle.attemptID, 1, carrier.bundle.role, message)
	if err != nil {
		return err
	}
	defer clear(packet)
	return socket.SendProbe(ctx, carrier.bundle.peer, packet)
}

func (carrier *admittedCarrier) receivePunch(ctx context.Context, socket *probeio.ProbeSocket, cipher *noisecore.PacketCipher, machine *punchproto.Machine) (punchproto.Transition, error) {
	if err := carrier.authorization.CheckActive(ctx); err != nil {
		return punchproto.Transition{}, err
	}
	peerRole, ok := carrier.bundle.role.Peer()
	if !ok {
		return punchproto.Transition{}, punchproto.ErrInvalidContext
	}
	var transition punchproto.Transition
	err := receiveExact(ctx, socket, punchproto.MaxPacketBytes, func(packet []byte) error {
		message, err := punchproto.OpenSecurePacket(cipher, packet, carrier.bundle.attemptID, 1, peerRole)
		if err != nil {
			return err
		}
		transition, err = machine.Receive(message)
		return err
	})
	return transition, err
}

func receiveExact(ctx context.Context, socket *probeio.ProbeSocket, maximum int, verify func([]byte) error) error {
	buffer := make([]byte, maximum)
	defer clear(buffer)
	_, _, err := socket.ReceiveReply(ctx, buffer, func(packet []byte, _ netip.AddrPort) error {
		return verify(packet)
	})
	return err
}

type oneShotPSK struct {
	key       [noisecore.PSKSize]byte
	available bool
}

func (source *oneShotPSK) LoadPSK() ([noisecore.PSKSize]byte, error) {
	if source == nil || !source.available {
		return [noisecore.PSKSize]byte{}, noisecore.ErrPSKUnavailable
	}
	key := source.key
	source.zeroize()
	return key, nil
}

func (source *oneShotPSK) zeroize() {
	if source == nil {
		return
	}
	clear(source.key[:])
	source.available = false
}

func terminalReason(err error) governor.PairingTerminalReason {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrCredentialExpired):
		return governor.PairingTerminalExpired
	case errors.Is(err, context.Canceled), errors.Is(err, governor.ErrLeaseClosed):
		return governor.PairingTerminalCancelled
	case errors.Is(err, governor.ErrPairingMachineScopeRequired), errors.Is(err, governor.ErrCommittedAttemptInvalid):
		return governor.PairingTerminalScopeChanged
	case errors.Is(err, noisecore.ErrAuthentication), errors.Is(err, noisecore.ErrInvalidMessage), errors.Is(err, punchproto.ErrSecurePacket), errors.Is(err, punchproto.ErrInvalidTransition), errors.Is(err, probeio.ErrReplyRejected):
		return governor.PairingTerminalProtocolError
	default:
		return governor.PairingTerminalCarrierError
	}
}

func (result Result) validate() error {
	if !result.Established || !result.Bidirectional || !result.Promoted || result.Terminal != string(governor.PairingTerminalSuccess) || result.NetworkScope != "loopback" {
		return fmt.Errorf("%w: incomplete result", ErrCarrierTerminal)
	}
	if result.OutboundPackets < 1 || result.OutboundPackets > MaxOutboundPackets {
		return fmt.Errorf("%w: outbound packet witness", ErrCarrierTerminal)
	}
	return nil
}
