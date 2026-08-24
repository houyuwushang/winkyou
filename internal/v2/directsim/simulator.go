package directsim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"winkyou/internal/natsim"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/pairingcontext"
)

var (
	ErrInvalidConfig  = errors.New("directsim: invalid configuration")
	ErrAttemptFailed  = errors.New("directsim: direct attempt failed")
	ErrBudgetExceeded = errors.New("directsim: frozen cost exceeded")
)

type Stage string

const (
	StagePresence           Stage = "presence"
	StageDurableBurn        Stage = "durable_burn"
	StageFirstHandshakeByte Stage = "first_handshake_byte"
	StagePrepare            Stage = "prepare"
	StageSameSocketSTUN     Stage = "same_socket_stun"
	StageReady              Stage = "ready"
	StageFire               Stage = "fire"
	StageSimultaneousPunch  Stage = "simultaneous_punch"
	StageVerify             Stage = "verify"
	StageTerminal           Stage = "terminal"
)

var successfulStageOrder = []Stage{
	StagePresence,
	StageDurableBurn,
	StageFirstHandshakeByte,
	StagePrepare,
	StageSameSocketSTUN,
	StageReady,
	StageFire,
	StageSimultaneousPunch,
	StageVerify,
	StageTerminal,
}

// SuccessfulStages returns the only permitted successful stage order. The
// returned slice is caller-owned so tests and future adapters cannot mutate the
// simulator's protocol proof.
func SuccessfulStages() []Stage {
	return append([]Stage(nil), successfulStageOrder...)
}

type Fault string

const (
	FaultNone                 Fault = ""
	FaultDropSYN              Fault = "drop_syn"
	FaultDropSYNACK           Fault = "drop_syn_ack"
	FaultDropACK              Fault = "drop_ack"
	FaultReorderDirect        Fault = "reorder_direct"
	FaultDuplicateSYN         Fault = "duplicate_syn"
	FaultDuplicateSYNACK      Fault = "duplicate_syn_ack"
	FaultDuplicateACK         Fault = "duplicate_ack"
	FaultDuplicateControl     Fault = "duplicate_control"
	FaultReplayControl        Fault = "replay_control"
	FaultWrongRole            Fault = "wrong_role"
	FaultWrongGeneration      Fault = "wrong_generation"
	FaultWrongContext         Fault = "wrong_context"
	FaultNonCanonicalReady    Fault = "noncanonical_ready"
	FaultCrossADDomain        Fault = "cross_ad_domain"
	FaultOversizeControl      Fault = "oversize_control"
	FaultAuthentication       Fault = "authentication_failure"
	FaultCancelBeforeBurn     Fault = "cancel_before_burn"
	FaultCancelAfterHandshake Fault = "cancel_after_handshake"
	FaultCancelAfterFire      Fault = "cancel_after_fire"
	FaultCancelAfterTerminal  Fault = "cancel_after_terminal"
)

type Cost struct {
	RendezvousConnections  int
	RendezvousTargets      int
	DNSResolutions         int
	UDPSocketsPerEndpoint  int
	UDPTargetsPerEndpoint  int
	STUNPacketsPerEndpoint int
	DirectPacketsInitiator int
	DirectPacketsResponder int
	UDPOutboundInitiator   int
	UDPOutboundResponder   int
	ControlInitiator       int
	ControlResponder       int
	GlobalCancel           int
	HandshakePerDirection  int
	AttemptEnvelope        time.Duration
	PresenceEnvelope       time.Duration
	Retries                int
}

// FrozenWorstCase returns a copy of the N2 hard ceiling. Configuration may
// lower these values but no simulator or later adapter may raise them.
func FrozenWorstCase() Cost {
	return Cost{
		RendezvousConnections:  1,
		RendezvousTargets:      1,
		DNSResolutions:         1,
		UDPSocketsPerEndpoint:  1,
		UDPTargetsPerEndpoint:  2,
		STUNPacketsPerEndpoint: 3,
		DirectPacketsInitiator: 2,
		DirectPacketsResponder: 1,
		UDPOutboundInitiator:   5,
		UDPOutboundResponder:   4,
		ControlInitiator:       4,
		ControlResponder:       3,
		GlobalCancel:           1,
		HandshakePerDirection:  1,
		AttemptEnvelope:        15 * time.Second,
		PresenceEnvelope:       3 * time.Second,
		Retries:                0,
	}
}

type Config struct {
	InitiatorArtifact []byte
	ResponderArtifact []byte
	Now               time.Time
	InitiatorNAT      natsim.Model
	ResponderNAT      natsim.Model
	Fault             Fault
}

type Emissions struct {
	HandshakeInitiator int
	HandshakeResponder int
	ControlInitiator   int
	ControlResponder   int
	Cancel             int
	STUNInitiator      int
	STUNResponder      int
	DirectInitiator    int
	DirectResponder    int
}

type Resources struct {
	SocketsInitiator    int
	SocketsResponder    int
	TargetsInitiator    int
	TargetsResponder    int
	FiveTuplesInitiator int
	FiveTuplesResponder int
}

type Report struct {
	Stages                      []Stage
	Success                     bool
	Cancelled                   bool
	BurnedInitiator             bool
	BurnedResponder             bool
	Refunds                     int
	BlindSYNACKBeforeSYNReceive bool
	PostTerminalCancelRejected  bool
	Emissions                   Emissions
	Resources                   Resources
	SameSocketSTUNAndPunch      bool
	NetworkPeak                 natsim.Counters
	NetworkResidual             natsim.Counters
}

func (report Report) WithinFrozenCost() bool {
	cost := FrozenWorstCase()
	return report.Emissions.HandshakeInitiator <= cost.HandshakePerDirection &&
		report.Emissions.HandshakeResponder <= cost.HandshakePerDirection &&
		report.Emissions.ControlInitiator <= cost.ControlInitiator &&
		report.Emissions.ControlResponder <= cost.ControlResponder &&
		report.Emissions.Cancel <= cost.GlobalCancel &&
		report.Emissions.STUNInitiator <= cost.STUNPacketsPerEndpoint &&
		report.Emissions.STUNResponder <= cost.STUNPacketsPerEndpoint &&
		report.Emissions.DirectInitiator <= cost.DirectPacketsInitiator &&
		report.Emissions.DirectResponder <= cost.DirectPacketsResponder &&
		report.Emissions.STUNInitiator+report.Emissions.DirectInitiator <= cost.UDPOutboundInitiator &&
		report.Emissions.STUNResponder+report.Emissions.DirectResponder <= cost.UDPOutboundResponder &&
		report.Resources.SocketsInitiator <= cost.UDPSocketsPerEndpoint &&
		report.Resources.SocketsResponder <= cost.UDPSocketsPerEndpoint &&
		report.Resources.TargetsInitiator <= cost.UDPTargetsPerEndpoint &&
		report.Resources.TargetsResponder <= cost.UDPTargetsPerEndpoint &&
		report.Resources.FiveTuplesInitiator <= cost.UDPTargetsPerEndpoint &&
		report.Resources.FiveTuplesResponder <= cost.UDPTargetsPerEndpoint
}

type memoryLedger struct {
	burned   bool
	finished bool
	reason   string
}

func (ledger *memoryLedger) burn() error {
	if ledger == nil || ledger.burned {
		return ErrAttemptFailed
	}
	ledger.burned = true
	return nil
}

func (ledger *memoryLedger) finish(reason string) {
	if ledger == nil || !ledger.burned || ledger.finished {
		return
	}
	ledger.finished = true
	ledger.reason = reason
}

type runState struct {
	report                  Report
	leftLedger, rightLedger memoryLedger
	rendezvous              *MemoryRendezvous
	initiator, responder    *directattempt.Protocol
	binding                 directattempt.Binding
	network                 *natsim.Network
}

// Run executes one bounded in-memory attempt. It creates no socket and has no
// retry, reconnect, ticker, goroutine, or real rendezvous path.
func Run(ctx context.Context, config Config) (Report, error) {
	state := &runState{}
	if ctx == nil || config.Now.IsZero() || len(config.InitiatorArtifact) == 0 || len(config.ResponderArtifact) == 0 || !validFault(config.Fault) {
		return state.fail(ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return state.fail(err)
	}
	initiatorArtifact, err := directattempt.ParseArtifact(config.InitiatorArtifact, config.Now)
	if err != nil {
		return state.fail(err)
	}
	defer initiatorArtifact.Close()
	responderArtifact, err := directattempt.ParseArtifact(config.ResponderArtifact, config.Now)
	if err != nil {
		return state.fail(err)
	}
	defer responderArtifact.Close()
	if initiatorArtifact.LocalRole != directattempt.RoleInitiator || responderArtifact.LocalRole != directattempt.RoleResponder ||
		initiatorArtifact.AttemptID != responderArtifact.AttemptID || initiatorArtifact.CredentialID != responderArtifact.CredentialID ||
		initiatorArtifact.RendezvousAssociationID != responderArtifact.RendezvousAssociationID || initiatorArtifact.Fingerprint != responderArtifact.Fingerprint {
		return state.fail(ErrInvalidConfig)
	}
	initiatorContext, _ := initiatorArtifact.PairingContext()
	responderContext, _ := responderArtifact.PairingContext()
	initiatorDigest, _ := initiatorArtifact.ContextDigest()
	responderDigest, _ := responderArtifact.ContextDigest()
	if initiatorContext != responderContext || initiatorDigest != responderDigest {
		return state.fail(ErrInvalidConfig)
	}
	if config.Fault == FaultWrongGeneration {
		return state.fail(errors.Join(ErrAttemptFailed, directattempt.ErrInvalidBinding))
	}

	state.rendezvous, err = NewMemoryRendezvous(initiatorArtifact.RendezvousAssociationID)
	if err != nil {
		return state.fail(err)
	}
	presenceA := Presence{Profile: directattempt.RendezvousPresenceProfile, AssociationID: initiatorArtifact.RendezvousAssociationID, Slot: PresenceSlotA}
	presenceB := Presence{Profile: directattempt.RendezvousPresenceProfile, AssociationID: initiatorArtifact.RendezvousAssociationID, Slot: PresenceSlotB}
	if complete, err := state.rendezvous.Arrive(presenceA); err != nil || complete {
		return state.fail(errors.Join(ErrAttemptFailed, err))
	}
	if complete, err := state.rendezvous.Arrive(presenceB); err != nil || !complete {
		return state.fail(errors.Join(ErrAttemptFailed, err))
	}
	state.stage(StagePresence)
	if config.Fault == FaultCancelBeforeBurn {
		state.report.Cancelled = true
		return state.fail(ErrAttemptFailed)
	}
	if err := state.leftLedger.burn(); err != nil {
		return state.fail(err)
	}
	state.report.BurnedInitiator = true
	if err := state.rightLedger.burn(); err != nil {
		return state.fail(err)
	}
	state.report.BurnedResponder = true
	if err := state.rendezvous.MarkDurablyBurned(); err != nil {
		return state.fail(err)
	}
	state.stage(StageDurableBurn)

	initiatorPSK, err := initiatorArtifact.TakePSK()
	if err != nil {
		return state.fail(err)
	}
	responderPSK, err := responderArtifact.TakePSK()
	if err != nil {
		clear(initiatorPSK[:])
		return state.fail(err)
	}
	state.initiator, state.responder, err = state.handshake(initiatorContext, initiatorArtifact.AttemptID, initiatorDigest, initiatorPSK, responderPSK, config.Fault)
	clear(initiatorPSK[:])
	clear(responderPSK[:])
	if err != nil {
		return state.fail(err)
	}
	if config.Fault == FaultCancelAfterHandshake {
		cancel, err := state.initiator.Seal(directattempt.FrameCancel, nil)
		if err != nil {
			return state.fail(err)
		}
		state.report.Emissions.Cancel++
		if err := state.rendezvous.SendControl(directattempt.RoleInitiator, cancel); err != nil {
			return state.fail(err)
		}
		received, err := state.rendezvous.ReceiveControl(directattempt.RoleResponder)
		if err != nil {
			return state.fail(err)
		}
		if _, err := state.responder.Open(received); err != nil {
			return state.fail(err)
		}
		state.report.Cancelled = true
		return state.fail(ErrAttemptFailed)
	}

	if err := state.exchangePrepare(config.Fault); err != nil {
		return state.fail(err)
	}
	state.stage(StagePrepare)
	if err := ctx.Err(); err != nil {
		return state.fail(err)
	}

	networkState, err := openSimulationNetwork(config.InitiatorNAT, config.ResponderNAT)
	if err != nil {
		return state.fail(err)
	}
	state.network = networkState.network
	state.report.Resources = Resources{
		SocketsInitiator: 1, SocketsResponder: 1,
		TargetsInitiator: 1, TargetsResponder: 1,
		FiveTuplesInitiator: 1, FiveTuplesResponder: 1,
	}
	initiatorObserved, responderObserved, err := state.observeMappings(networkState)
	if err != nil {
		return state.fail(err)
	}
	state.stage(StageSameSocketSTUN)
	if config.Fault == FaultNonCanonicalReady {
		initiatorObserved = netip.MustParseAddrPort("[::ffff:192.0.2.10]:41000")
	}
	if err := state.exchangeReady(initiatorObserved, responderObserved); err != nil {
		return state.fail(err)
	}
	state.report.Resources.TargetsInitiator = 2
	state.report.Resources.TargetsResponder = 2
	state.report.Resources.FiveTuplesInitiator = 2
	state.report.Resources.FiveTuplesResponder = 2
	state.stage(StageReady)
	if err := state.exchangeOneWayControl(directattempt.RoleInitiator, directattempt.FrameFire); err != nil {
		return state.fail(err)
	}
	state.stage(StageFire)
	if config.Fault == FaultCancelAfterFire {
		cancel, err := state.initiator.Seal(directattempt.FrameCancel, nil)
		if err != nil {
			return state.fail(err)
		}
		state.report.Emissions.Cancel++
		if err := state.rendezvous.SendControl(directattempt.RoleInitiator, cancel); err != nil {
			return state.fail(err)
		}
		received, err := state.rendezvous.ReceiveControl(directattempt.RoleResponder)
		if err != nil {
			return state.fail(err)
		}
		if _, err := state.responder.Open(received); err != nil {
			return state.fail(err)
		}
		state.report.Cancelled = true
		return state.fail(ErrAttemptFailed)
	}
	state.stage(StageSimultaneousPunch)
	if err := state.punch(networkState, initiatorObserved, responderObserved, config.Fault); err != nil {
		return state.fail(err)
	}
	if err := state.exchangeVerify(); err != nil {
		return state.fail(err)
	}
	state.stage(StageVerify)
	if !state.initiator.Status().Success || !state.responder.Status().Success {
		return state.fail(ErrAttemptFailed)
	}
	state.report.Success = true
	if config.Fault == FaultCancelAfterTerminal {
		before := state.report.Emissions
		if _, err := state.initiator.Seal(directattempt.FrameCancel, nil); !errors.Is(err, directattempt.ErrTerminal) {
			return state.fail(errors.Join(ErrAttemptFailed, err))
		}
		state.report.PostTerminalCancelRejected = state.report.Emissions == before
		if !state.report.PostTerminalCancelRejected {
			return state.fail(ErrBudgetExceeded)
		}
	}
	return state.succeed()
}

type staticPSK [noisecore.PSKSize]byte

func (source staticPSK) LoadPSK() ([noisecore.PSKSize]byte, error) { return source, nil }

func (state *runState) handshake(pairingContext pairingcontext.PairingContext, attemptID string, contextDigest [sha256.Size]byte, initiatorPSK, responderPSK [32]byte, fault Fault) (*directattempt.Protocol, *directattempt.Protocol, error) {
	prologue, err := directattempt.BuildNoisePrologue(pairingContext)
	if err != nil {
		return nil, nil, err
	}
	defer clear(prologue)
	responderPrologue := append([]byte(nil), prologue...)
	if fault == FaultWrongContext {
		responderPrologue[len(responderPrologue)-1] ^= 1
	}
	defer clear(responderPrologue)
	initiatorSession, err := noisecore.NewInitiator(noisecore.Config{
		Prologue: prologue,
		PSK:      staticPSK(initiatorPSK),
		Random:   bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)),
	})
	if err != nil {
		return nil, nil, err
	}
	defer initiatorSession.Close()
	responderSession, err := noisecore.NewResponder(noisecore.Config{
		Prologue: responderPrologue,
		PSK:      staticPSK(responderPSK),
		Random:   bytes.NewReader(bytes.Repeat([]byte{0x71}, 32)),
	})
	if err != nil {
		return nil, nil, err
	}
	defer responderSession.Close()
	first, err := initiatorSession.WriteMessage(nil)
	if err != nil {
		return nil, nil, err
	}
	state.report.Emissions.HandshakeInitiator++
	if err := state.rendezvous.SendHandshake(directattempt.RoleInitiator, first); err != nil {
		clear(first)
		return nil, nil, err
	}
	clear(first)
	state.stage(StageFirstHandshakeByte)
	receivedFirst, err := state.rendezvous.ReceiveHandshake(directattempt.RoleResponder)
	if err != nil {
		return nil, nil, err
	}
	payload, err := responderSession.ReadMessage(receivedFirst)
	clear(receivedFirst)
	clear(payload)
	if err != nil {
		return nil, nil, err
	}
	second, err := responderSession.WriteMessage(nil)
	if err != nil {
		return nil, nil, err
	}
	state.report.Emissions.HandshakeResponder++
	if err := state.rendezvous.SendHandshake(directattempt.RoleResponder, second); err != nil {
		clear(second)
		return nil, nil, err
	}
	clear(second)
	receivedSecond, err := state.rendezvous.ReceiveHandshake(directattempt.RoleInitiator)
	if err != nil {
		return nil, nil, err
	}
	payload, err = initiatorSession.ReadMessage(receivedSecond)
	clear(receivedSecond)
	clear(payload)
	if err != nil {
		return nil, nil, err
	}
	initiatorHash, err := initiatorSession.HandshakeHash()
	if err != nil {
		return nil, nil, err
	}
	responderHash, err := responderSession.HandshakeHash()
	if err != nil || initiatorHash != responderHash {
		return nil, nil, errors.Join(ErrAttemptFailed, err)
	}
	initiatorPackets, err := initiatorSession.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		return nil, nil, err
	}
	responderPackets, err := responderSession.TakePacketCipher(directattempt.MaxSequence)
	if err != nil {
		_ = initiatorPackets.Close()
		return nil, nil, err
	}
	if err := state.rendezvous.MarkHandshakeComplete(); err != nil {
		_ = initiatorPackets.Close()
		_ = responderPackets.Close()
		return nil, nil, err
	}
	binding := directattempt.Binding{
		AttemptID: attemptID, ContextDigest: contextDigest,
		HandshakeHash: initiatorHash, Generation: directattempt.Generation,
	}
	state.binding = binding
	initiator, err := directattempt.NewProtocol(directattempt.RoleInitiator, binding, initiatorPackets)
	if err != nil {
		_ = responderPackets.Close()
		return nil, nil, err
	}
	responder, err := directattempt.NewProtocol(directattempt.RoleResponder, binding, responderPackets)
	if err != nil {
		_ = initiator.Close()
		return nil, nil, err
	}
	return initiator, responder, nil
}

func (state *runState) exchangePrepare(fault Fault) error {
	initiatorFrame, err := state.initiator.Seal(directattempt.FramePrepare, nil)
	if err != nil {
		return err
	}
	state.report.Emissions.ControlInitiator++
	initiatorFrame = mutateControlFrame(initiatorFrame, fault)
	if err := state.rendezvous.SendControl(directattempt.RoleInitiator, initiatorFrame); err != nil {
		clear(initiatorFrame)
		return err
	}
	received, err := state.rendezvous.ReceiveControl(directattempt.RoleResponder)
	if err != nil {
		clear(initiatorFrame)
		return err
	}
	if _, err := state.responder.Open(received); err != nil {
		clear(received)
		clear(initiatorFrame)
		return err
	}
	clear(received)
	if fault == FaultDuplicateControl {
		if err := state.rendezvous.injectControl(directattempt.RoleInitiator, initiatorFrame); err != nil {
			clear(initiatorFrame)
			return err
		}
		replayed, err := state.rendezvous.ReceiveControl(directattempt.RoleResponder)
		if err != nil {
			clear(initiatorFrame)
			return err
		}
		_, openErr := state.responder.Open(replayed)
		clear(replayed)
		clear(initiatorFrame)
		if openErr == nil {
			return ErrAttemptFailed
		}
		return openErr
	}
	responderFrame, err := state.responder.Seal(directattempt.FramePrepare, nil)
	if err != nil {
		clear(initiatorFrame)
		return err
	}
	state.report.Emissions.ControlResponder++
	if err := state.rendezvous.SendControl(directattempt.RoleResponder, responderFrame); err != nil {
		clear(initiatorFrame)
		clear(responderFrame)
		return err
	}
	responderReceived, err := state.rendezvous.ReceiveControl(directattempt.RoleInitiator)
	if err != nil {
		clear(initiatorFrame)
		clear(responderFrame)
		return err
	}
	if _, err := state.initiator.Open(responderReceived); err != nil {
		clear(initiatorFrame)
		clear(responderFrame)
		clear(responderReceived)
		return err
	}
	clear(responderFrame)
	clear(responderReceived)
	if fault == FaultReplayControl {
		if err := state.rendezvous.injectControl(directattempt.RoleInitiator, initiatorFrame); err != nil {
			clear(initiatorFrame)
			return err
		}
		replayed, err := state.rendezvous.ReceiveControl(directattempt.RoleResponder)
		if err != nil {
			clear(initiatorFrame)
			return err
		}
		_, openErr := state.responder.Open(replayed)
		clear(replayed)
		clear(initiatorFrame)
		if openErr == nil {
			return ErrAttemptFailed
		}
		return openErr
	}
	clear(initiatorFrame)
	return nil
}

func mutateControlFrame(frame []byte, fault Fault) []byte {
	result := append([]byte(nil), frame...)
	clear(frame)
	switch fault {
	case FaultWrongRole:
		result[7] = 2
	case FaultCrossADDomain:
		result[5] = 2
	case FaultOversizeControl:
		result = append(result, bytes.Repeat([]byte{0}, directattempt.MaxFrameBytes-len(result)+1)...)
	case FaultAuthentication:
		result[len(result)-1] ^= 1
	}
	return result
}

type simulationNetwork struct {
	network              *natsim.Network
	initiator, responder *natsim.PacketConn
	stun                 *natsim.PacketConn
}

func openSimulationNetwork(initiatorModel, responderModel natsim.Model) (*simulationNetwork, error) {
	if initiatorModel.Mapping == "" || responderModel.Mapping == "" {
		return nil, ErrInvalidConfig
	}
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 3, MaxMappings: 8, QueueCapacity: 8, MaxDatagram: directattempt.MaxFrameBytes})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*simulationNetwork, error) {
		_ = network.Close()
		return nil, err
	}
	initiatorNAT, err := network.NewNAT(natsim.NATConfig{Name: "initiator-nat", PublicAddr: netip.MustParseAddr("198.51.100.10"), Model: initiatorModel})
	if err != nil {
		return fail(err)
	}
	responderNAT, err := network.NewNAT(natsim.NATConfig{Name: "responder-nat", PublicAddr: netip.MustParseAddr("198.51.100.20"), Model: responderModel})
	if err != nil {
		return fail(err)
	}
	initiator, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.10:31001"), NATChain: []*natsim.NAT{initiatorNAT}})
	if err != nil {
		return fail(err)
	}
	responder, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.20:31002"), NATChain: []*natsim.NAT{responderNAT}})
	if err != nil {
		return fail(err)
	}
	stun, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: netip.MustParseAddrPort("203.0.113.1:3478")})
	if err != nil {
		return fail(err)
	}
	return &simulationNetwork{network: network, initiator: initiator, responder: responder, stun: stun}, nil
}

func (state *runState) observeMappings(network *simulationNetwork) (netip.AddrPort, netip.AddrPort, error) {
	stunTarget := netip.MustParseAddrPort("203.0.113.1:3478")
	state.report.Emissions.STUNInitiator++
	if _, err := network.initiator.WriteToAddrPort([]byte("stun-i"), stunTarget); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	state.report.Emissions.STUNResponder++
	if _, err := network.responder.WriteToAddrPort([]byte("stun-r"), stunTarget); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	initiatorObserved, err := network.network.MappedAddr(network.initiator, stunTarget)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	responderObserved, err := network.network.MappedAddr(network.responder, stunTarget)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	frames, err := readAll(network.stun)
	if err != nil || len(frames) != 2 {
		return netip.AddrPort{}, netip.AddrPort{}, errors.Join(ErrAttemptFailed, err)
	}
	for _, frame := range frames {
		clear(frame)
	}
	return initiatorObserved, responderObserved, nil
}

func (state *runState) exchangeReady(initiatorEndpoint, responderEndpoint netip.AddrPort) error {
	initiatorBinding := state.initiatorBinding()
	responderBinding := state.responderBinding()
	initiatorReady, err := directattempt.NewReadyPayload(initiatorBinding, directattempt.RoleInitiator, initiatorEndpoint)
	if err != nil {
		return err
	}
	responderReady, err := directattempt.NewReadyPayload(responderBinding, directattempt.RoleResponder, responderEndpoint)
	if err != nil {
		return err
	}
	initiatorFrame, err := state.initiator.Seal(directattempt.FrameReady, &initiatorReady)
	if err != nil {
		return err
	}
	state.report.Emissions.ControlInitiator++
	responderFrame, err := state.responder.Seal(directattempt.FrameReady, &responderReady)
	if err != nil {
		clear(initiatorFrame)
		return err
	}
	state.report.Emissions.ControlResponder++
	if err := state.rendezvous.SendControl(directattempt.RoleInitiator, initiatorFrame); err != nil {
		return err
	}
	toResponder, err := state.rendezvous.ReceiveControl(directattempt.RoleResponder)
	if err != nil {
		return err
	}
	if _, err := state.responder.Open(toResponder); err != nil {
		return err
	}
	if err := state.rendezvous.SendControl(directattempt.RoleResponder, responderFrame); err != nil {
		return err
	}
	toInitiator, err := state.rendezvous.ReceiveControl(directattempt.RoleInitiator)
	if err != nil {
		return err
	}
	_, err = state.initiator.Open(toInitiator)
	clear(initiatorFrame)
	clear(responderFrame)
	clear(toResponder)
	clear(toInitiator)
	return err
}

// The protocol deliberately does not export keys or arbitrary binding state.
// READY construction uses the authenticated binding cached by the simulator at
// handshake completion.
func (state *runState) initiatorBinding() directattempt.Binding { return state.binding }
func (state *runState) responderBinding() directattempt.Binding { return state.binding }

func (state *runState) exchangeOneWayControl(sender directattempt.Role, frameType directattempt.FrameType) error {
	var source, target *directattempt.Protocol
	if sender == directattempt.RoleInitiator {
		source, target = state.initiator, state.responder
		state.report.Emissions.ControlInitiator++
	} else {
		source, target = state.responder, state.initiator
		state.report.Emissions.ControlResponder++
	}
	frame, err := source.Seal(frameType, nil)
	if err != nil {
		return err
	}
	defer clear(frame)
	if err := state.rendezvous.SendControl(sender, frame); err != nil {
		return err
	}
	received, err := state.rendezvous.ReceiveControl(sender.Peer())
	if err != nil {
		return err
	}
	defer clear(received)
	opened, err := target.Open(received)
	if err != nil {
		return err
	}
	if opened.Type != frameType {
		return ErrAttemptFailed
	}
	return nil
}

func (state *runState) punch(network *simulationNetwork, initiatorEndpoint, responderEndpoint netip.AddrPort, fault Fault) error {
	state.report.SameSocketSTUNAndPunch = network.initiator != nil && network.responder != nil
	syn, err := state.initiator.Seal(directattempt.FrameSYN, nil)
	if err != nil {
		return err
	}
	defer clear(syn)
	// Blind by construction: seal SYN_ACK before inspecting responder inbound.
	synACK, err := state.responder.Seal(directattempt.FrameSYNACK, nil)
	if err != nil {
		return err
	}
	defer clear(synACK)
	state.report.BlindSYNACKBeforeSYNReceive = true

	writeInitiator := func() error {
		state.report.Emissions.DirectInitiator++
		_, err := network.initiator.WriteToAddrPort(syn, responderEndpoint)
		return err
	}
	writeResponder := func() error {
		state.report.Emissions.DirectResponder++
		_, err := network.responder.WriteToAddrPort(synACK, initiatorEndpoint)
		return err
	}
	if err := writeInitiator(); err != nil {
		return err
	}
	if err := writeResponder(); err != nil {
		return err
	}

	toInitiator, err := readAll(network.initiator)
	if err != nil {
		return err
	}
	initiatorSawSYNACK, err := deliverDirectFrames(state.initiator, toInitiator, fault, false)
	if err != nil {
		return err
	}
	if !initiatorSawSYNACK {
		return ErrAttemptFailed
	}
	ack, err := state.initiator.Seal(directattempt.FrameACK, nil)
	if err != nil {
		return err
	}
	defer clear(ack)
	state.report.Emissions.DirectInitiator++
	if _, err := network.initiator.WriteToAddrPort(ack, responderEndpoint); err != nil {
		return err
	}
	toResponder, err := readAll(network.responder)
	if err != nil {
		return err
	}
	if fault == FaultReorderDirect {
		sort.SliceStable(toResponder, func(left, right int) bool {
			return frameTypeOf(toResponder[left]) == directattempt.FrameACK && frameTypeOf(toResponder[right]) != directattempt.FrameACK
		})
	}
	responderSawACK, err := deliverDirectFrames(state.responder, toResponder, fault, true)
	if err != nil {
		return err
	}
	if !responderSawACK {
		return ErrAttemptFailed
	}
	return nil
}

func deliverDirectFrames(protocol *directattempt.Protocol, frames [][]byte, fault Fault, responder bool) (bool, error) {
	completed := false
	for _, frame := range frames {
		frameType := frameTypeOf(frame)
		if shouldDrop(fault, frameType) {
			clear(frame)
			continue
		}
		opened, err := protocol.Open(frame)
		if err != nil {
			clear(frame)
			return false, err
		}
		if !responder && opened.Type == directattempt.FrameSYNACK || responder && opened.Type == directattempt.FrameACK {
			completed = true
		}
		if shouldDuplicate(fault, frameType) {
			if _, err := protocol.Open(frame); err == nil {
				clear(frame)
				return false, ErrAttemptFailed
			} else {
				clear(frame)
				return false, err
			}
		}
		clear(frame)
	}
	return completed, nil
}

func shouldDrop(fault Fault, frameType directattempt.FrameType) bool {
	return fault == FaultDropSYN && frameType == directattempt.FrameSYN ||
		fault == FaultDropSYNACK && frameType == directattempt.FrameSYNACK ||
		fault == FaultDropACK && frameType == directattempt.FrameACK
}

func shouldDuplicate(fault Fault, frameType directattempt.FrameType) bool {
	return fault == FaultDuplicateSYN && frameType == directattempt.FrameSYN ||
		fault == FaultDuplicateSYNACK && frameType == directattempt.FrameSYNACK ||
		fault == FaultDuplicateACK && frameType == directattempt.FrameACK
}

func frameTypeOf(frame []byte) directattempt.FrameType {
	if len(frame) <= 6 {
		return 255
	}
	return directattempt.FrameType(frame[6])
}

func readAll(connection *natsim.PacketConn) ([][]byte, error) {
	var frames [][]byte
	for {
		buffer := make([]byte, directattempt.MaxFrameBytes)
		n, _, ok, err := connection.TryReadFromAddrPort(buffer)
		if err != nil {
			clear(buffer)
			return nil, err
		}
		if !ok {
			clear(buffer)
			return frames, nil
		}
		frames = append(frames, append([]byte(nil), buffer[:n]...))
		clear(buffer)
	}
}

func (state *runState) exchangeVerify() error {
	initiatorFrame, err := state.initiator.Seal(directattempt.FrameVerify, nil)
	if err != nil {
		return err
	}
	defer clear(initiatorFrame)
	state.report.Emissions.ControlInitiator++
	responderFrame, err := state.responder.Seal(directattempt.FrameVerify, nil)
	if err != nil {
		return err
	}
	defer clear(responderFrame)
	state.report.Emissions.ControlResponder++
	if err := state.rendezvous.SendControl(directattempt.RoleInitiator, initiatorFrame); err != nil {
		return err
	}
	toResponder, err := state.rendezvous.ReceiveControl(directattempt.RoleResponder)
	if err != nil {
		return err
	}
	if err := state.rendezvous.SendControl(directattempt.RoleResponder, responderFrame); err != nil {
		return err
	}
	toInitiator, err := state.rendezvous.ReceiveControl(directattempt.RoleInitiator)
	if err != nil {
		return err
	}
	if _, err := state.initiator.Open(toInitiator); err != nil {
		return err
	}
	if _, err := state.responder.Open(toResponder); err != nil {
		return err
	}
	clear(toResponder)
	clear(toInitiator)
	return nil
}

func (state *runState) stage(stage Stage) {
	state.report.Stages = append(state.report.Stages, stage)
}

func (state *runState) succeed() (Report, error) {
	state.leftLedger.finish("success")
	state.rightLedger.finish("success")
	state.stage(StageTerminal)
	state.cleanup()
	if !state.report.WithinFrozenCost() {
		return state.report, ErrBudgetExceeded
	}
	return state.report, nil
}

func (state *runState) fail(cause error) (Report, error) {
	if state == nil {
		return Report{Stages: []Stage{StageTerminal}}, cause
	}
	state.leftLedger.finish("failed")
	state.rightLedger.finish("failed")
	if len(state.report.Stages) == 0 || state.report.Stages[len(state.report.Stages)-1] != StageTerminal {
		state.stage(StageTerminal)
	}
	state.cleanup()
	if !state.report.WithinFrozenCost() {
		cause = errors.Join(cause, ErrBudgetExceeded)
	}
	return state.report, errors.Join(ErrAttemptFailed, cause)
}

func (state *runState) cleanup() {
	if state.initiator != nil {
		_ = state.initiator.Close()
	}
	if state.responder != nil {
		_ = state.responder.Close()
	}
	if state.rendezvous != nil {
		_ = state.rendezvous.Close()
	}
	if state.network != nil {
		state.report.NetworkPeak = state.network.Snapshot()
		_ = state.network.Close()
		state.report.NetworkResidual = state.network.Snapshot()
	}
}

func validFault(fault Fault) bool {
	switch fault {
	case FaultNone, FaultDropSYN, FaultDropSYNACK, FaultDropACK, FaultReorderDirect,
		FaultDuplicateSYN, FaultDuplicateSYNACK, FaultDuplicateACK, FaultDuplicateControl,
		FaultReplayControl, FaultWrongRole, FaultWrongGeneration, FaultWrongContext,
		FaultNonCanonicalReady, FaultCrossADDomain, FaultOversizeControl, FaultAuthentication,
		FaultCancelBeforeBurn, FaultCancelAfterHandshake, FaultCancelAfterFire, FaultCancelAfterTerminal:
		return true
	default:
		return false
	}
}

func (report Report) String() string {
	return fmt.Sprintf("directsim success=%t burned=%t/%t", report.Success, report.BurnedInitiator, report.BurnedResponder)
}
