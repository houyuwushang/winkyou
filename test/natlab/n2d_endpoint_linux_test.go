//go:build linux && natlab

package natlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/rendezvouscarrier"
)

const (
	n2dRequiredEnv       = "WINKYOU_N2D_REQUIRED"
	n2dEndpointHelperEnv = "WINKYOU_N2D_ENDPOINT_HELPER"
	n2dHelperConfigEnv   = "WINKYOU_N2D_HELPER_CONFIG"

	n2dActionAttempt      = "attempt"
	n2dActionRestartCheck = "restart_check"
	n2dActionSecondSocket = "violate_second_socket"
	n2dActionThirdTarget  = "violate_third_target"
	n2dActionSixthPacket  = "violate_sixth_packet"

	n2dStagePresent   = "present"
	n2dStageBurned    = "burned"
	n2dStageActivated = "activated"
	n2dStageHandshake = "handshake"
	n2dStagePrepare   = "prepare"
	n2dStageSocket    = "socket"
	n2dStageSTUN      = "stun"
	n2dStageReady     = "ready"
	n2dStageFire      = "fire"
	n2dStagePunchSent = "punch_sent"
	n2dStagePunch     = "punch"
	n2dStageVerify    = "verify"
	n2dStageTerminal  = "terminal"

	n2dTerminalSuccess         = "success"
	n2dTerminalExpired         = "expired"
	n2dTerminalPresenceTimeout = "presence_timeout"
	n2dTerminalReplayRejected  = "replay_rejected"
	n2dTerminalHardViolation   = "hard_violation"

	n2dAttemptLimit = 13 * time.Second
	n2dPunchLimit   = 1500 * time.Millisecond
)

type n2dEndpointConfig struct {
	Role               string `json:"role"`
	Action             string `json:"action"`
	GovernorDir        string `json:"governor_dir"`
	ArtifactPath       string `json:"artifact_path,omitempty"`
	ResultPath         string `json:"result_path"`
	EventDir           string `json:"event_dir"`
	PauseStage         string `json:"pause_stage,omitempty"`
	ReleasePath        string `json:"release_path,omitempty"`
	RendezvousEndpoint string `json:"rendezvous_endpoint,omitempty"`
	STUNEndpoint       string `json:"stun_endpoint,omitempty"`
	PeerProbeEndpoint  string `json:"peer_probe_endpoint,omitempty"`
}

type n2dEndpointResult struct {
	OK                   bool   `json:"ok"`
	Role                 string `json:"role"`
	Terminal             string `json:"terminal"`
	ErrorClass           string `json:"error_class,omitempty"`
	Burned               bool   `json:"burned"`
	SameSocket           bool   `json:"same_socket"`
	STUNPackets          int    `json:"stun_packets"`
	DirectPackets        int    `json:"direct_packets"`
	UDPPackets           int    `json:"udp_packets"`
	ControlFrames        int    `json:"control_frames"`
	HandshakeFrames      int    `json:"handshake_frames"`
	CarrierFramesRead    int    `json:"carrier_frames_read"`
	CarrierFramesWritten int    `json:"carrier_frames_written"`
	CarrierBytesRead     int    `json:"carrier_bytes_read"`
	CarrierBytesWritten  int    `json:"carrier_bytes_written"`
	DNSResolutions       int    `json:"dns_resolutions"`
	SafetyState          string `json:"safety_state"`
	SafetyBlocksWork     bool   `json:"safety_blocks_work"`
	LedgerState          string `json:"ledger_state"`
	LedgerSequence       uint64 `json:"ledger_sequence"`
	LedgerRecords        int    `json:"ledger_records"`
	LedgerAdmissions     int    `json:"ledger_admissions"`
	LedgerFailures       int    `json:"ledger_failures"`
	ActivePeers          int    `json:"active_peers"`
	ActiveAttempts       int    `json:"active_attempts"`
	ReservedSockets      int    `json:"reserved_sockets"`
	ReservedTargets      int    `json:"reserved_targets"`
	ReservedFiveTuples   int    `json:"reserved_five_tuples"`
	ReservedPackets      int    `json:"reserved_packets"`
	ElapsedMilliseconds  int64  `json:"elapsed_milliseconds"`
}

type n2dEvent struct {
	Stage string `json:"stage"`
	Port  uint16 `json:"port,omitempty"`
}

type n2dArtifactPair struct {
	Initiator    []byte
	Responder    []byte
	Association  string
	CredentialID string
	AttemptID    string
}

type n2dEndpointRuntime struct {
	result        n2dEndpointResult
	machine       *governor.Governor
	peer          *governor.PeerLease
	attempt       *governor.AttemptLease
	authorization *governor.CommittedCarrierAuthorization
	carrier       *rendezvouscarrier.Carrier
	controller    *probeio.Controller
	protocol      *directattempt.Protocol
	promotion     *probeio.Promotion
}

type n2dStaticPSK [noisecore.PSKSize]byte

func (source n2dStaticPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

func TestN2DEndpointProcess(t *testing.T) {
	if os.Getenv(n2dEndpointHelperEnv) != "1" {
		return
	}
	var config n2dEndpointConfig
	if !readN1JSON(os.Getenv(n2dHelperConfigEnv), &config) || !validN2DEndpointConfig(config) {
		t.Fatal("N2d endpoint helper configuration rejected")
	}
	started := time.Now()
	result, err := runN2DEndpoint(config)
	result.ElapsedMilliseconds = time.Since(started).Milliseconds()
	if err != nil {
		result.OK = false
		if result.ErrorClass == "" {
			result.ErrorClass = "internal_error"
		}
	}
	if writeErr := writeN1JSON(config.ResultPath, result); writeErr != nil {
		t.Fatal("N2d endpoint result write failed")
	}
	if err != nil {
		t.Error("N2d endpoint helper failed")
	}
}

func validN2DEndpointConfig(config n2dEndpointConfig) bool {
	role := directattempt.Role(config.Role)
	if !role.Valid() || config.GovernorDir == "" || config.ResultPath == "" || config.EventDir == "" {
		return false
	}
	switch config.Action {
	case n2dActionAttempt:
		return config.ArtifactPath != "" && config.RendezvousEndpoint != "" && config.STUNEndpoint != ""
	case n2dActionRestartCheck:
		return config.ArtifactPath != ""
	case n2dActionSecondSocket, n2dActionThirdTarget:
		return config.STUNEndpoint != "" && config.PeerProbeEndpoint != ""
	case n2dActionSixthPacket:
		return config.STUNEndpoint != ""
	default:
		return false
	}
}

func runN2DEndpoint(config n2dEndpointConfig) (n2dEndpointResult, error) {
	switch config.Action {
	case n2dActionAttempt:
		return runN2DAttempt(config)
	case n2dActionRestartCheck:
		return runN2DRestartCheck(config)
	case n2dActionSecondSocket, n2dActionThirdTarget, n2dActionSixthPacket:
		return runN2DHardViolation(config)
	default:
		return n2dEndpointResult{Role: config.Role}, errors.New("unsupported action")
	}
}

func runN2DAttempt(config n2dEndpointConfig) (result n2dEndpointResult, resultErr error) {
	result = n2dEndpointResult{Role: config.Role, SafetyState: string(governor.SafetyTripClear)}
	payload, err := os.ReadFile(config.ArtifactPath)
	if err != nil {
		result.ErrorClass = "artifact_read"
		return result, err
	}
	artifact, err := directattempt.ParseArtifact(payload, time.Now().UTC())
	clear(payload)
	if err != nil || artifact.LocalRole != directattempt.Role(config.Role) {
		result.ErrorClass = "artifact_rejected"
		return result, errors.Join(err, directattempt.ErrInvalidArtifact)
	}
	defer artifact.Close()

	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalContext, n2dAttemptLimit)
	defer cancel()

	runtime, err := acquireN2DRuntime(ctx, config, artifact.AttemptID)
	if err != nil {
		result.ErrorClass = "governor_acquire"
		return result, err
	}
	runtime.result = result
	defer func() {
		if runtime.machine != nil {
			resultErr = errors.Join(resultErr, runtime.finish(governor.PairingTerminalCarrierError))
		}
		result = runtime.result
	}()

	runtime.carrier, err = rendezvouscarrier.Dial(ctx, rendezvouscarrier.Config{
		Lease: runtime.attempt, Endpoint: config.RendezvousEndpoint,
		Tier:          rendezvouscarrier.DeploymentSelfHosted,
		AssociationID: artifact.RendezvousAssociationID,
		Slot:          n2dPresenceSlot(artifact.LocalRole), Role: artifact.LocalRole,
		AllowedTargetScope: rendezvouscarrier.AllowedTargetIsolatedUnicast,
		PresenceDeadline:   rendezvouscarrier.PresenceTimeout,
		OperationDeadline:  rendezvouscarrier.ActiveEnvelope,
	})
	if err != nil {
		runtime.result.ErrorClass = "carrier_preconnect"
		return runtime.result, err
	}
	if err := runtime.carrier.AwaitPresence(ctx); err != nil {
		if errors.Is(err, rendezvouscarrier.ErrPresenceTimeout) {
			runtime.result.OK = true
			runtime.result.Terminal = n2dTerminalPresenceTimeout
			runtime.result.ErrorClass = "presence_timeout"
			_ = n2dEmit(config, n2dStageTerminal, 0)
			resultErr = runtime.finish("")
			result = runtime.result
			return result, resultErr
		}
		runtime.result.ErrorClass = "presence_failed"
		return runtime.result, err
	}
	if err := n2dEmit(config, n2dStagePresent, 0); err != nil {
		runtime.result.ErrorClass = "event_write"
		return runtime.result, err
	}

	digest, err := artifact.ContextDigest()
	if err != nil {
		runtime.result.ErrorClass = "context_digest"
		return runtime.result, err
	}
	committed, err := governor.NewPairingAdmissionGate().Commit(ctx, runtime.attempt, governor.PairingAdmissionRequest{
		CredentialID: artifact.CredentialID, AttemptID: artifact.AttemptID,
		ContextDigest: hex.EncodeToString(digest[:]), Scope: governor.ScopeMachine,
		ExpiresAt: artifact.ExpiresAt, Envelope: governor.PairingEnvelopeFromAttemptCost(runtime.attempt.Request().Cost),
	})
	if err != nil {
		runtime.result.ErrorClass = "durable_burn"
		return runtime.result, err
	}
	runtime.result.Burned = true
	runtime.authorization, err = committed.ConsumeForCarrier(ctx)
	if err != nil {
		runtime.result.ErrorClass = "authorization_consume"
		return runtime.result, err
	}
	if err := n2dEmit(config, n2dStageBurned, 0); err != nil {
		runtime.result.ErrorClass = "event_write"
		return runtime.result, err
	}
	if err := runtime.carrier.Activate(ctx, runtime.authorization); err != nil {
		return runtime.expire(config, "activation", err)
	}
	if err := n2dEmit(config, n2dStageActivated, 0); err != nil {
		return runtime.result, err
	}
	if err := n2dPause(ctx, config, n2dStageActivated); err != nil {
		return runtime.expire(config, "activation_pause", err)
	}

	binding, err := runtime.handshake(ctx, artifact)
	if err != nil {
		return runtime.expire(config, "handshake", err)
	}
	if err := n2dEmit(config, n2dStageHandshake, 0); err != nil {
		return runtime.result, err
	}
	if err := runtime.exchangeControl(ctx, directattempt.FramePrepare); err != nil {
		return runtime.protocolFailure(config, "prepare", err)
	}
	if err := n2dEmit(config, n2dStagePrepare, 0); err != nil {
		return runtime.result, err
	}

	generation := probeio.NewGeneration(directattempt.Generation)
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.MustParseAddrPort("0.0.0.0:0"), AllowedTargetScope: probeio.AllowedTargetScopeUnicast,
	})
	if err != nil {
		return runtime.protocolFailure(config, "factory", err)
	}
	udpCost := stunobserve.N2SameSocketCost()
	runtime.controller, err = probeio.New(probeio.Config{
		Lease: runtime.attempt, Generation: generation, ExpectedGeneration: directattempt.Generation,
		Factory: factory, EnforcedCost: &udpCost, BuildVersion: "n2d-netns-test",
	})
	if err != nil {
		return runtime.protocolFailure(config, "probeio", err)
	}
	socket, err := runtime.controller.OpenProbeSocket(ctx)
	if err != nil {
		return runtime.protocolFailure(config, "socket", err)
	}
	local, err := socket.LocalAddr()
	if err != nil || !local.Addr().IsUnspecified() || local.Port() == 0 {
		return runtime.protocolFailure(config, "socket_metadata", errors.Join(err, probeio.ErrDatagramContract))
	}
	if err := n2dEmit(config, n2dStageSocket, local.Port()); err != nil {
		return runtime.result, err
	}
	observer, err := stunobserve.NewSameSocket(stunobserve.SameSocketConfig{
		Socket: socket, Generation: generation, ExpectedGeneration: directattempt.Generation, AllowNonLoopback: true,
	})
	if err != nil {
		return runtime.protocolFailure(config, "stun_adapter", err)
	}
	stunTarget, err := netip.ParseAddrPort(config.STUNEndpoint)
	if err != nil {
		return runtime.protocolFailure(config, "stun_target", err)
	}
	observation, err := observer.Observe(ctx, stunTarget)
	runtime.result.STUNPackets = observation.Transmissions
	runtime.result.UDPPackets += observation.Transmissions
	if err != nil {
		return runtime.expire(config, "stun", err)
	}
	if observation.LocalEndpoint.Port() != local.Port() {
		return runtime.protocolFailure(config, "same_socket", errors.New("local port changed"))
	}
	runtime.result.SameSocket = true
	if err := n2dEmit(config, n2dStageSTUN, local.Port()); err != nil {
		return runtime.result, err
	}

	peerReady, err := runtime.exchangeReady(ctx, binding, observation.MappedEndpoint)
	if err != nil || peerReady == nil {
		return runtime.protocolFailure(config, "ready", errors.Join(err, directattempt.ErrInvalidReady))
	}
	if err := observer.RegisterPeerTarget(peerReady.Endpoint, peerReady.Generation); err != nil {
		return runtime.protocolFailure(config, "peer_target", err)
	}
	if err := n2dEmit(config, n2dStageReady, local.Port()); err != nil {
		return runtime.result, err
	}

	if artifact.LocalRole == directattempt.RoleInitiator {
		if err := runtime.sendControl(ctx, directattempt.FrameFire); err != nil {
			return runtime.protocolFailure(config, "fire_send", err)
		}
	} else {
		opened, err := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
		if err != nil || opened.Type != directattempt.FrameFire {
			return runtime.expire(config, "fire_receive", errors.Join(err, directattempt.ErrInvalidTransition))
		}
	}
	if err := n2dEmit(config, n2dStageFire, local.Port()); err != nil {
		return runtime.result, err
	}
	if err := runtime.punch(ctx, config, socket, peerReady.Endpoint); err != nil {
		return runtime.expire(config, "punch_timeout", err)
	}
	if err := n2dEmit(config, n2dStagePunch, local.Port()); err != nil {
		return runtime.result, err
	}
	if err := runtime.exchangeControl(ctx, directattempt.FrameVerify); err != nil {
		return runtime.expire(config, "verify", err)
	}
	if status := runtime.protocol.Status(); !status.Terminal || !status.Success {
		return runtime.protocolFailure(config, "verify_state", directattempt.ErrInvalidTransition)
	}
	if err := n2dEmit(config, n2dStageVerify, local.Port()); err != nil {
		return runtime.result, err
	}
	promotion, err := socket.PromoteTerminal(peerReady.Endpoint, "n2d-isolated-direct")
	if err != nil {
		return runtime.protocolFailure(config, "promote", err)
	}
	runtime.promotion = &promotion
	runtime.result.OK = true
	runtime.result.Terminal = n2dTerminalSuccess
	runtime.result.ErrorClass = ""
	_ = n2dEmit(config, n2dStageTerminal, local.Port())
	resultErr = runtime.finish(governor.PairingTerminalSuccess)
	result = runtime.result
	return result, resultErr
}

func acquireN2DRuntime(ctx context.Context, config n2dEndpointConfig, attemptID string) (*n2dEndpointRuntime, error) {
	owner, err := governor.AcquirePreparedNamespace(config.GovernorDir, governor.ScopeMachine, "n2d-netns-test")
	if err != nil {
		return nil, err
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	peer, err := machine.AcquirePeer("n2d-peer")
	if err != nil {
		_ = machine.Close()
		return nil, err
	}
	attempt, err := peer.AcquireAttempt(ctx, governor.AttemptRequest{
		ID: attemptID, Operation: governor.OperationConnectTest, Cost: rendezvouscarrier.N2AttemptCost(),
	})
	if err != nil {
		_ = peer.Close()
		_ = machine.Close()
		return nil, err
	}
	return &n2dEndpointRuntime{machine: machine, peer: peer, attempt: attempt}, nil
}

func (runtime *n2dEndpointRuntime) handshake(ctx context.Context, artifact *directattempt.Artifact) (directattempt.Binding, error) {
	pairingContext, err := artifact.PairingContext()
	if err != nil {
		return directattempt.Binding{}, err
	}
	digest, err := artifact.ContextDigest()
	if err != nil {
		return directattempt.Binding{}, err
	}
	prologue, err := directattempt.BuildNoisePrologue(pairingContext)
	if err != nil {
		return directattempt.Binding{}, err
	}
	defer clear(prologue)
	psk, err := artifact.TakePSK()
	if err != nil {
		return directattempt.Binding{}, err
	}
	defer clear(psk[:])
	config := noisecore.Config{Prologue: prologue, PSK: n2dStaticPSK(psk)}
	var session *noisecore.Session
	if artifact.LocalRole == directattempt.RoleInitiator {
		session, err = noisecore.NewInitiator(config)
	} else {
		session, err = noisecore.NewResponder(config)
	}
	if err != nil {
		return directattempt.Binding{}, err
	}
	defer session.Close()
	if artifact.LocalRole == directattempt.RoleInitiator {
		first, err := session.WriteMessage(nil)
		if err != nil {
			return directattempt.Binding{}, err
		}
		if err := runtime.carrier.SendHandshake(ctx, first); err != nil {
			clear(first)
			return directattempt.Binding{}, err
		}
		clear(first)
		runtime.result.HandshakeFrames++
		second, err := runtime.carrier.ReceiveHandshake(ctx)
		if err != nil {
			return directattempt.Binding{}, err
		}
		payload, err := session.ReadMessage(second)
		clear(second)
		clear(payload)
		if err != nil || len(payload) != 0 {
			return directattempt.Binding{}, errors.Join(err, noisecore.ErrInvalidMessage)
		}
	} else {
		first, err := runtime.carrier.ReceiveHandshake(ctx)
		if err != nil {
			return directattempt.Binding{}, err
		}
		payload, err := session.ReadMessage(first)
		clear(first)
		clear(payload)
		if err != nil || len(payload) != 0 {
			return directattempt.Binding{}, errors.Join(err, noisecore.ErrInvalidMessage)
		}
		second, err := session.WriteMessage(nil)
		if err != nil {
			return directattempt.Binding{}, err
		}
		if err := runtime.carrier.SendHandshake(ctx, second); err != nil {
			clear(second)
			return directattempt.Binding{}, err
		}
		clear(second)
		runtime.result.HandshakeFrames++
	}
	hash, err := session.HandshakeHash()
	if err != nil {
		return directattempt.Binding{}, err
	}
	packets, err := session.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		return directattempt.Binding{}, err
	}
	if err := runtime.carrier.MarkHandshakeComplete(); err != nil {
		_ = packets.Close()
		return directattempt.Binding{}, err
	}
	binding := directattempt.Binding{
		AttemptID: artifact.AttemptID, ContextDigest: digest, HandshakeHash: hash, Generation: directattempt.Generation,
	}
	runtime.protocol, err = directattempt.NewProtocol(artifact.LocalRole, binding, packets)
	if err != nil {
		_ = packets.Close()
		return directattempt.Binding{}, err
	}
	return binding, nil
}

func (runtime *n2dEndpointRuntime) sendControl(ctx context.Context, frameType directattempt.FrameType) error {
	frame, err := runtime.protocol.Seal(frameType, nil)
	if err != nil {
		return err
	}
	defer clear(frame)
	if err := runtime.carrier.SendControl(ctx, frame); err != nil {
		return err
	}
	runtime.result.ControlFrames++
	return nil
}

func (runtime *n2dEndpointRuntime) exchangeControl(ctx context.Context, frameType directattempt.FrameType) error {
	if err := runtime.sendControl(ctx, frameType); err != nil {
		return err
	}
	opened, err := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
	if err != nil || opened.Type != frameType {
		return errors.Join(err, directattempt.ErrInvalidTransition)
	}
	return nil
}

func (runtime *n2dEndpointRuntime) exchangeReady(ctx context.Context, binding directattempt.Binding, endpoint netip.AddrPort) (*directattempt.ReadyPayload, error) {
	ready, err := directattempt.NewReadyPayload(binding, directattempt.Role(runtime.result.Role), endpoint)
	if err != nil {
		return nil, err
	}
	frame, err := runtime.protocol.Seal(directattempt.FrameReady, &ready)
	if err != nil {
		return nil, err
	}
	defer clear(frame)
	if err := runtime.carrier.SendControl(ctx, frame); err != nil {
		return nil, err
	}
	runtime.result.ControlFrames++
	opened, err := runtime.carrier.ReceiveControl(ctx, runtime.protocol)
	if err != nil || opened.Type != directattempt.FrameReady || opened.Ready == nil {
		return nil, errors.Join(err, directattempt.ErrInvalidReady)
	}
	copy := *opened.Ready
	return &copy, nil
}

func (runtime *n2dEndpointRuntime) punch(ctx context.Context, config n2dEndpointConfig, socket *probeio.ProbeSocket, peer netip.AddrPort) error {
	punchContext, cancel := context.WithTimeout(ctx, n2dPunchLimit)
	defer cancel()
	role := directattempt.Role(runtime.result.Role)
	firstType := directattempt.FrameSYN
	if role == directattempt.RoleResponder {
		firstType = directattempt.FrameSYNACK
	}
	first, err := runtime.protocol.Seal(firstType, nil)
	if err != nil {
		return err
	}
	if err := socket.SendProbe(punchContext, peer, first); err != nil {
		clear(first)
		return err
	}
	clear(first)
	runtime.result.DirectPackets++
	runtime.result.UDPPackets++
	if err := n2dEmit(config, n2dStagePunchSent, 0); err != nil {
		return err
	}
	if err := n2dPause(punchContext, config, n2dStagePunchSent); err != nil {
		return err
	}

	buffer := make([]byte, directattempt.MaxFrameBytes)
	defer clear(buffer)
	if role == directattempt.RoleInitiator {
		_, _, err := socket.ReceiveReply(punchContext, buffer, func(packet []byte, from netip.AddrPort) error {
			if from != peer {
				return directattempt.ErrInvalidFrame
			}
			opened, err := runtime.protocol.Open(packet)
			if err != nil || opened.Type != directattempt.FrameSYNACK {
				return errors.Join(err, directattempt.ErrInvalidTransition)
			}
			return nil
		})
		if err != nil {
			return err
		}
		ack, err := runtime.protocol.Seal(directattempt.FrameACK, nil)
		if err != nil {
			return err
		}
		defer clear(ack)
		if err := socket.SendProbe(punchContext, peer, ack); err != nil {
			return err
		}
		runtime.result.DirectPackets++
		runtime.result.UDPPackets++
		return nil
	}

	for received := 0; received < 2; received++ {
		complete := false
		_, _, err := socket.ReceiveReply(punchContext, buffer, func(packet []byte, from netip.AddrPort) error {
			if from != peer {
				return directattempt.ErrInvalidFrame
			}
			opened, err := runtime.protocol.Open(packet)
			if err != nil {
				return err
			}
			switch opened.Type {
			case directattempt.FrameSYN:
			case directattempt.FrameACK:
				complete = true
			default:
				return directattempt.ErrInvalidTransition
			}
			return nil
		})
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
	}
	return directattempt.ErrInvalidTransition
}

func (runtime *n2dEndpointRuntime) expire(config n2dEndpointConfig, class string, cause error) (n2dEndpointResult, error) {
	runtime.result.OK = true
	runtime.result.Terminal = n2dTerminalExpired
	runtime.result.ErrorClass = class
	_ = n2dEmit(config, n2dStageTerminal, 0)
	_ = cause
	return runtime.result, runtime.finish(governor.PairingTerminalExpired)
}

func (runtime *n2dEndpointRuntime) protocolFailure(config n2dEndpointConfig, class string, cause error) (n2dEndpointResult, error) {
	runtime.result.OK = true
	runtime.result.Terminal = n2dTerminalExpired
	runtime.result.ErrorClass = class
	_ = n2dEmit(config, n2dStageTerminal, 0)
	_ = cause
	return runtime.result, runtime.finish(governor.PairingTerminalProtocolError)
}

func (runtime *n2dEndpointRuntime) finish(reason governor.PairingTerminalReason) error {
	if runtime == nil || runtime.machine == nil {
		return nil
	}
	var result error
	if runtime.promotion != nil && runtime.promotion.Transport != nil {
		result = errors.Join(result, runtime.promotion.Transport.Close())
		runtime.promotion = nil
	}
	if runtime.protocol != nil {
		_ = runtime.protocol.Close()
		runtime.protocol = nil
	}
	if runtime.carrier != nil {
		_ = runtime.carrier.Close()
		witness := runtime.carrier.Witness()
		runtime.result.CarrierFramesRead = witness.FramesRead
		runtime.result.CarrierFramesWritten = witness.FramesWritten
		runtime.result.CarrierBytesRead = witness.BytesRead
		runtime.result.CarrierBytesWritten = witness.BytesWritten
		runtime.result.DNSResolutions = witness.DNSResolutions
		runtime.carrier = nil
	}
	if runtime.authorization != nil && reason != "" {
		result = errors.Join(result, runtime.authorization.Finish(reason))
		runtime.authorization = nil
	}
	if runtime.controller != nil {
		result = errors.Join(result, runtime.controller.Close())
		runtime.controller = nil
	} else if runtime.attempt != nil {
		result = errors.Join(result, runtime.attempt.Close())
	}
	runtime.attempt = nil
	if runtime.peer != nil {
		result = errors.Join(result, runtime.peer.Close())
		runtime.peer = nil
	}
	snapshot := runtime.machine.Snapshot()
	runtime.result.SafetyState = string(snapshot.SafetyTrip.State)
	runtime.result.SafetyBlocksWork = snapshot.SafetyTrip.BlocksActiveWork
	runtime.result.ActivePeers = snapshot.ActivePeers
	runtime.result.ActiveAttempts = snapshot.ActiveAttempts
	runtime.result.ReservedSockets = snapshot.Reserved.Sockets
	runtime.result.ReservedTargets = snapshot.Reserved.Targets
	runtime.result.ReservedFiveTuples = snapshot.Reserved.FiveTuples
	runtime.result.ReservedPackets = snapshot.Reserved.Packets
	if ledger, err := runtime.machineOwnerLedger(); err == nil {
		status := ledger.Status()
		runtime.result.LedgerState = string(status.State)
		runtime.result.LedgerSequence = status.Sequence
		runtime.result.LedgerRecords = status.Records
		runtime.result.LedgerAdmissions = status.TwentyFourHourAdmissions
		runtime.result.LedgerFailures = status.ConsecutiveFailures
	} else {
		result = errors.Join(result, err)
	}
	result = errors.Join(result, runtime.machine.Close())
	runtime.machine = nil
	return result
}

func (runtime *n2dEndpointRuntime) machineOwnerLedger() (*governor.PairingAdmissionLedger, error) {
	if runtime == nil || runtime.machine == nil {
		return nil, governor.ErrPairingMachineScopeRequired
	}
	// PairingAdmissionGate has already installed the owner-bound singleton.
	// A read-only status call is reached through the same owner by acquiring no
	// new path or lock; Snapshot alone deliberately omits ledger state.
	return n2dLedgerFromMachine(runtime.machine)
}

func n2dLedgerFromMachine(machine *governor.Governor) (*governor.PairingAdmissionLedger, error) {
	return governor.N2DTestPairingLedger(machine)
}

func n2dPresenceSlot(role directattempt.Role) rendezvouscarrier.PresenceSlot {
	if role == directattempt.RoleInitiator {
		return rendezvouscarrier.PresenceSlotA
	}
	return rendezvouscarrier.PresenceSlotB
}

func runN2DRestartCheck(config n2dEndpointConfig) (result n2dEndpointResult, resultErr error) {
	result = n2dEndpointResult{Role: config.Role, SafetyState: string(governor.SafetyTripClear)}
	payload, err := os.ReadFile(config.ArtifactPath)
	if err != nil {
		result.ErrorClass = "artifact_read"
		return result, err
	}
	artifact, err := directattempt.ParseArtifact(payload, time.Now().UTC())
	clear(payload)
	if err != nil {
		result.ErrorClass = "artifact_rejected"
		return result, err
	}
	defer artifact.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runtime, err := acquireN2DRuntime(ctx, config, artifact.AttemptID)
	if err != nil {
		result.ErrorClass = "governor_acquire"
		return result, err
	}
	runtime.result = result
	defer func() {
		resultErr = errors.Join(resultErr, runtime.finish(""))
		result = runtime.result
	}()
	digest, err := artifact.ContextDigest()
	if err != nil {
		return result, err
	}
	committed, err := governor.NewPairingAdmissionGate().Commit(ctx, runtime.attempt, governor.PairingAdmissionRequest{
		CredentialID: artifact.CredentialID, AttemptID: artifact.AttemptID,
		ContextDigest: hex.EncodeToString(digest[:]), Scope: governor.ScopeMachine,
		ExpiresAt: artifact.ExpiresAt, Envelope: governor.PairingEnvelopeFromAttemptCost(runtime.attempt.Request().Cost),
	})
	if committed != nil || !errors.Is(err, governor.ErrPairingCredentialUsed) {
		result.ErrorClass = "replay_not_rejected"
		return result, errors.Join(err, errors.New("credential replay accepted"))
	}
	runtime.result.OK = true
	runtime.result.Terminal = n2dTerminalReplayRejected
	runtime.result.ErrorClass = "credential_used"
	_ = n2dEmit(config, n2dStageTerminal, 0)
	return runtime.result, nil
}

func runN2DHardViolation(config n2dEndpointConfig) (result n2dEndpointResult, resultErr error) {
	result = n2dEndpointResult{Role: config.Role, SafetyState: string(governor.SafetyTripClear)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	attemptID := n2dOpaqueID("violation-attempt-" + config.Action + "-" + config.Role)
	runtime, err := acquireN2DRuntime(ctx, config, attemptID)
	if err != nil {
		result.ErrorClass = "governor_acquire"
		return result, err
	}
	runtime.result = result
	defer func() {
		resultErr = errors.Join(resultErr, runtime.finish(""))
		result = runtime.result
	}()
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.MustParseAddrPort("0.0.0.0:0"), AllowedTargetScope: probeio.AllowedTargetScopeUnicast,
	})
	if err != nil {
		return result, err
	}
	cost := stunobserve.N2SameSocketCost()
	runtime.controller, err = probeio.New(probeio.Config{
		Lease: runtime.attempt, Generation: probeio.NewGeneration(1), ExpectedGeneration: 1,
		Factory: factory, EnforcedCost: &cost, BuildVersion: "n2d-hard-violation-test",
	})
	if err != nil {
		return result, err
	}
	socket, err := runtime.controller.OpenProbeSocket(ctx)
	if err != nil {
		return result, err
	}
	local, err := socket.LocalAddr()
	if err != nil {
		return result, err
	}
	if err := n2dEmit(config, n2dStageSocket, local.Port()); err != nil {
		return result, err
	}
	stunTarget, err := netip.ParseAddrPort(config.STUNEndpoint)
	if err != nil {
		return result, err
	}
	var violation error
	switch config.Action {
	case n2dActionSecondSocket:
		_, violation = runtime.controller.OpenProbeSocket(ctx)
		runtime.result.ErrorClass = "second_socket"
	case n2dActionThirdTarget:
		peerTarget, parseErr := netip.ParseAddrPort(config.PeerProbeEndpoint)
		if parseErr != nil {
			return result, parseErr
		}
		if err := socket.RegisterTarget(stunTarget); err != nil {
			return result, err
		}
		if err := socket.RegisterTarget(peerTarget); err != nil {
			return result, err
		}
		violation = socket.RegisterTarget(netip.MustParseAddrPort("203.0.113.254:9"))
		runtime.result.ErrorClass = "third_target"
	case n2dActionSixthPacket:
		if err := socket.RegisterTarget(stunTarget); err != nil {
			return result, err
		}
		for index := 0; index < 5; index++ {
			if err := socket.SendProbe(ctx, stunTarget, []byte("N2D-BOUND")); err != nil {
				return result, err
			}
			runtime.result.UDPPackets++
		}
		violation = socket.SendProbe(ctx, stunTarget, []byte("N2D-BLOCKED"))
		runtime.result.ErrorClass = "sixth_packet"
	}
	if !errors.Is(violation, probeio.ErrHardLimit) {
		return result, errors.Join(violation, errors.New("hard violation was not blocked"))
	}
	runtime.result.OK = true
	runtime.result.Terminal = n2dTerminalHardViolation
	_ = n2dEmit(config, n2dStageTerminal, local.Port())
	return runtime.result, nil
}

func n2dEmit(config n2dEndpointConfig, stage string, port uint16) error {
	if !validN2DStage(stage) {
		return errors.New("invalid stage")
	}
	return writeN1JSON(filepath.Join(config.EventDir, stage+".json"), n2dEvent{Stage: stage, Port: port})
}

func validN2DStage(stage string) bool {
	switch stage {
	case n2dStagePresent, n2dStageBurned, n2dStageActivated, n2dStageHandshake, n2dStagePrepare,
		n2dStageSocket, n2dStageSTUN, n2dStageReady, n2dStageFire, n2dStagePunchSent,
		n2dStagePunch, n2dStageVerify, n2dStageTerminal:
		return true
	default:
		return false
	}
}

func n2dPause(ctx context.Context, config n2dEndpointConfig, stage string) error {
	if config.PauseStage != stage {
		return nil
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var released struct {
			Release bool `json:"release"`
		}
		if readN1JSON(config.ReleasePath, &released) && released.Release {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func buildN2DArtifacts(t testing.TB, label string, now time.Time) n2dArtifactPair {
	t.Helper()
	now = now.UTC().Truncate(time.Second)
	identifiers := map[string]string{}
	for _, name := range []string{"credential", "attempt", "initiator", "responder", "association"} {
		identifiers[name] = n2dOpaqueID(label + "-" + name)
	}
	secret := sha256.Sum256([]byte(label + "-synthetic-pairing-secret"))
	base := map[string]string{
		"artifact":                  directattempt.ArtifactProfile,
		"direct_attempt_profile":    directattempt.DirectAttemptProfile,
		"rendezvous_profile":        directattempt.RendezvousPresenceProfile,
		"rendezvous_association_id": identifiers["association"],
		"protocol":                  pairingcontext.ProtocolVersion,
		"auth_scope":                pairingcontext.AuthScope,
		"credential_id":             identifiers["credential"],
		"attempt_id":                identifiers["attempt"],
		"observation_generation":    "1",
		"initiator_participant_id":  identifiers["initiator"],
		"responder_participant_id":  identifiers["responder"],
		"initiator_governor_scope":  pairingcontext.GovernorScopeMachine,
		"responder_governor_scope":  pairingcontext.GovernorScopeMachine,
		"secure_channel_profile":    pairingcontext.SelectedSecureChannelProfile,
		"issued_at":                 now.Add(-time.Second).Format(time.RFC3339),
		"expires_at":                now.Add(9 * time.Minute).Format(time.RFC3339),
	}
	canonicalObject := make(map[string]any, len(base))
	for key, value := range base {
		canonicalObject[key] = value
	}
	canonical, err := pairingcontext.CanonicalizeFlatStringObject(canonicalObject)
	if err != nil {
		t.Fatal("N2d synthetic artifact canonicalization failed")
	}
	fingerprintDigest := sha256.Sum256(canonical)
	clear(canonical)
	fingerprint := base64.RawURLEncoding.EncodeToString(fingerprintDigest[:])
	clear(fingerprintDigest[:])
	build := func(role directattempt.Role) []byte {
		wire := make(map[string]string, len(base)+4)
		for key, value := range base {
			wire[key] = value
		}
		wire["local_role"] = string(role)
		wire["pairing_secret"] = base64.RawURLEncoding.EncodeToString(secret[:])
		wire["artifact_fingerprint"] = fingerprint
		payload, err := json.Marshal(wire)
		if err != nil {
			t.Fatal("N2d synthetic artifact encoding failed")
		}
		artifact, err := directattempt.ParseArtifact(payload, now)
		if err != nil {
			t.Fatal("N2d synthetic artifact self-check failed")
		}
		artifact.Close()
		return payload
	}
	pair := n2dArtifactPair{
		Initiator: build(directattempt.RoleInitiator), Responder: build(directattempt.RoleResponder),
		Association: identifiers["association"], CredentialID: identifiers["credential"], AttemptID: identifiers["attempt"],
	}
	clear(secret[:])
	return pair
}

func n2dOpaqueID(label string) string {
	digest := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

type n2dEndpointProcess struct {
	command      *exec.Cmd
	done         chan struct{}
	waitMu       sync.Mutex
	waitErr      error
	config       n2dEndpointConfig
	configPath   string
	artifactPath string
	resultPath   string
	governorDir  string
	eventDir     string
	namespace    string
	started      bool
	stopOnce     sync.Once
}

func newN2DEndpointProcess(t testing.TB, topology *n2dTopology, servers *n2dServers, artifacts n2dArtifactPair, role directattempt.Role, action, pauseStage, existingGovernorDir, existingArtifactPath string) *n2dEndpointProcess {
	t.Helper()
	directory := t.TempDir()
	governorDir := existingGovernorDir
	if governorDir == "" {
		governorDir = filepath.Join(directory, "governor")
		if err := os.Mkdir(governorDir, 0o700); err != nil {
			t.Fatal("N2d governor namespace setup failed")
		}
		if err := governor.PrepareN2DTestNamespace(governorDir, time.Now().UTC()); err != nil {
			t.Fatal("N2d durable namespace preparation failed")
		}
	}
	artifactPath := existingArtifactPath
	if artifactPath == "" && (action == n2dActionAttempt || action == n2dActionRestartCheck) {
		artifactPath = filepath.Join(directory, "artifact.json")
		payload := artifacts.Initiator
		if role == directattempt.RoleResponder {
			payload = artifacts.Responder
		}
		if err := os.WriteFile(artifactPath, payload, 0o600); err != nil {
			t.Fatal("N2d artifact staging failed")
		}
	}
	eventDir := filepath.Join(directory, "events")
	if err := os.Mkdir(eventDir, 0o700); err != nil {
		t.Fatal("N2d event directory setup failed")
	}
	process := &n2dEndpointProcess{
		done: make(chan struct{}), governorDir: governorDir, artifactPath: artifactPath,
		resultPath: filepath.Join(directory, "result.json"), eventDir: eventDir,
		configPath: filepath.Join(directory, "config.json"),
	}
	if role == directattempt.RoleInitiator {
		process.namespace = topology.clientA
	} else {
		process.namespace = topology.clientB
	}
	peerProbe := netip.AddrPortFrom(netip.MustParseAddr(n2dNATBWAN), 9)
	if role == directattempt.RoleResponder {
		peerProbe = netip.AddrPortFrom(netip.MustParseAddr(n2dNATAWAN), 9)
	}
	process.config = n2dEndpointConfig{
		Role: string(role), Action: action, GovernorDir: governorDir, ArtifactPath: artifactPath,
		ResultPath: process.resultPath, EventDir: eventDir, PauseStage: pauseStage,
		ReleasePath: filepath.Join(directory, "release.json"), PeerProbeEndpoint: peerProbe.String(),
	}
	if servers != nil {
		process.config.RendezvousEndpoint = servers.rendezvousEndpoint
		process.config.STUNEndpoint = servers.stunEndpoint()
	}
	if process.config.STUNEndpoint == "" {
		process.config.STUNEndpoint = netip.AddrPortFrom(netip.MustParseAddr(n2dPublicA), 9).String()
	}
	if err := writeN1JSON(process.configPath, process.config); err != nil {
		t.Fatal("N2d endpoint configuration write failed")
	}
	process.command = exec.Command(
		"ip", "netns", "exec", process.namespace, os.Args[0],
		"-test.run=^TestN2DEndpointProcess$", "-test.count=1", "-test.timeout=16s",
	)
	process.command.Env = append(os.Environ(), n2dEndpointHelperEnv+"=1", n2dHelperConfigEnv+"="+process.configPath)
	process.command.Stdout = io.Discard
	process.command.Stderr = io.Discard
	process.command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	t.Cleanup(process.stop)
	return process
}

func (process *n2dEndpointProcess) start(t testing.TB) {
	t.Helper()
	if process == nil || process.command == nil || process.started {
		t.Fatal("N2d endpoint start contract failed")
	}
	if err := process.command.Start(); err != nil {
		t.Fatal("N2d endpoint process start failed")
	}
	process.started = true
	go func() {
		err := process.command.Wait()
		process.waitMu.Lock()
		process.waitErr = err
		process.waitMu.Unlock()
		close(process.done)
	}()
}

func (process *n2dEndpointProcess) waitStage(t testing.TB, stage string, timeout time.Duration) n2dEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	path := filepath.Join(process.eventDir, stage+".json")
	for time.Now().Before(deadline) {
		var event n2dEvent
		if readN1JSON(path, &event) && event.Stage == stage {
			return event
		}
		select {
		case <-process.done:
			t.Fatal("N2d endpoint exited before expected stage")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("N2d endpoint stage deadline exceeded")
	return n2dEvent{}
}

func (process *n2dEndpointProcess) release(t testing.TB) {
	t.Helper()
	if err := writeN1JSON(process.config.ReleasePath, struct {
		Release bool `json:"release"`
	}{Release: true}); err != nil {
		t.Fatal("N2d endpoint release failed")
	}
}

func (process *n2dEndpointProcess) waitResult(t testing.TB) n2dEndpointResult {
	t.Helper()
	deadline := time.Now().Add(16 * time.Second)
	for time.Now().Before(deadline) {
		var result n2dEndpointResult
		if readN1JSON(process.resultPath, &result) {
			select {
			case <-process.done:
			case <-time.After(n2dTerminalMargin):
				t.Fatal("N2d endpoint did not exit after result")
			}
			process.waitMu.Lock()
			waitErr := process.waitErr
			process.waitMu.Unlock()
			if waitErr != nil || !result.OK {
				t.Fatal("N2d endpoint returned a harness failure")
			}
			return result
		}
		select {
		case <-process.done:
			t.Fatal("N2d endpoint exited without a result")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	process.stop()
	t.Fatal("N2d endpoint result deadline exceeded")
	return n2dEndpointResult{}
}

func (process *n2dEndpointProcess) kill(t testing.TB) {
	t.Helper()
	if process == nil || process.command == nil || process.command.Process == nil {
		t.Fatal("N2d endpoint kill contract failed")
	}
	if err := process.command.Process.Kill(); err != nil {
		t.Fatal("N2d endpoint kill failed")
	}
	select {
	case <-process.done:
	case <-time.After(n2dTerminalMargin):
		t.Fatal("N2d endpoint kill did not terminate in time")
	}
}

func (process *n2dEndpointProcess) stop() {
	if process == nil {
		return
	}
	process.stopOnce.Do(func() {
		if !process.started {
			return
		}
		select {
		case <-process.done:
			return
		default:
		}
		if process.command != nil && process.command.Process != nil {
			_ = process.command.Process.Kill()
		}
		select {
		case <-process.done:
		case <-time.After(n2dTerminalMargin):
		}
	})
}

func assertN2DResultRedacted(t testing.TB, result n2dEndpointResult) {
	t.Helper()
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal("N2d result encoding failed")
	}
	forbidden := []string{
		n2dClientAAddress, n2dNATALAN, n2dNATAWAN, n2dPublicA,
		n2dPublicB, n2dNATBWAN, n2dNATBLAN, n2dClientBAddress,
	}
	if hostname, err := os.Hostname(); err == nil && len(hostname) >= 3 {
		forbidden = append(forbidden, hostname)
	}
	for _, key := range []string{"USER", "USERNAME"} {
		if value := os.Getenv(key); len(value) >= 3 {
			forbidden = append(forbidden, value)
		}
	}
	if working, err := os.Getwd(); err == nil {
		forbidden = append(forbidden, working)
	}
	if home, err := os.UserHomeDir(); err == nil {
		forbidden = append(forbidden, home)
	}
	for _, value := range forbidden {
		if value != "" && bytes.Contains(payload, []byte(value)) {
			t.Fatal("N2d result contained forbidden environment metadata")
		}
	}
}

func n2dResultHasNoResidue(result n2dEndpointResult) bool {
	return result.ActivePeers == 0 && result.ActiveAttempts == 0 && result.ReservedSockets == 0 &&
		result.ReservedTargets == 0 && result.ReservedFiveTuples == 0 && result.ReservedPackets == 0
}

func n2dResultString(result n2dEndpointResult) string {
	return strings.Join([]string{result.Role, result.Terminal, result.ErrorClass}, "/")
}
