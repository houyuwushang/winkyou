package stunobserve

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
)

const GateAMappingObservationStrategy = "gate_a_same_socket_multi_stun"

var (
	ErrGateAMappingTerminal = errors.New("stunobserve: Gate A mapping adapter is terminal")
	ErrGateAMappingRejected = errors.New("stunobserve: Gate A mapping evidence is not directly usable")
)

// GateASameSocketCost freezes the UDP slice for two serial STUN targets and
// one later authenticated direct target. directOutbound is role-specific and
// can only be one (responder) or two (initiator).
func GateASameSocketCost(directOutbound int) (governor.AttemptCost, error) {
	if directOutbound != 1 && directOutbound != 2 {
		return governor.AttemptCost{}, ErrInvalidConfig
	}
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets: 1, Targets: 3, FiveTuples: 3,
			PacketsPerSecond: 5, Packets: 2*MaxTransmissions + directOutbound,
		},
		Duration: 15 * time.Second, Heavyweight: true,
	}, nil
}

type GateASameSocketConfig struct {
	Socket             *probeio.ProbeSocket
	Generation         probeio.GenerationSource
	ExpectedGeneration uint64
	DirectOutbound     int
	AllowNonLoopback   bool
}

// GateAMappingObservation is current-generation, process-local evidence. It
// intentionally has no default JSON representation for endpoint-bearing data.
type GateAMappingObservation struct {
	Classification MappingClassification      `json:"-"`
	Results        []MappingTargetObservation `json:"-"`
	LocalEndpoint  netip.AddrPort             `json:"-"`
	MappedEndpoint netip.AddrPort             `json:"-"`
	Generation     uint64                     `json:"generation"`
	Transmissions  int                        `json:"transmissions"`
}

// GateASameSocketClient performs exactly two serial STUN exchanges and later
// authorizes exactly one peer endpoint on the same caller-owned ProbeSocket.
// It has no Factory and cannot open a second socket.
type GateASameSocketClient struct {
	mu sync.Mutex

	socket             *probeio.ProbeSocket
	generation         probeio.GenerationSource
	expectedGeneration uint64
	allowNonLoopback   bool
	now                func() time.Time
	initialRTO         time.Duration
	exchanges          [2]mappingExchange

	used           bool
	terminal       bool
	observed       bool
	peerRegistered bool
	stunTargets    [2]netip.AddrPort
}

func NewGateASameSocket(config GateASameSocketConfig) (*GateASameSocketClient, error) {
	return newGateASameSocket(config, rand.Reader, time.Now, InitialRTO)
}

func newGateASameSocket(config GateASameSocketConfig, random io.Reader, now func() time.Time, initialRTO time.Duration) (*GateASameSocketClient, error) {
	if config.Socket == nil || config.Generation == nil || config.ExpectedGeneration == 0 || random == nil || now == nil || initialRTO <= 0 {
		return nil, ErrInvalidConfig
	}
	if config.Generation.CurrentGeneration() != config.ExpectedGeneration {
		return nil, probeio.ErrStaleGeneration
	}
	required, err := GateASameSocketCost(config.DirectOutbound)
	if err != nil {
		return nil, err
	}
	reservation, err := config.Socket.Reservation()
	if err != nil {
		return nil, err
	}
	if reservation.Operation != governor.OperationConnectTest || reservation.Generation != config.ExpectedGeneration ||
		!coversSameSocketCost(reservation.Cost, required) {
		return nil, ErrInsufficientBudget
	}
	client := &GateASameSocketClient{
		socket: config.Socket, generation: config.Generation, expectedGeneration: config.ExpectedGeneration,
		allowNonLoopback: config.AllowNonLoopback, now: now, initialRTO: initialRTO,
	}
	for index := range client.exchanges {
		request, transaction, requestErr := newBindingRequest(random)
		if requestErr != nil {
			return nil, requestErr
		}
		client.exchanges[index] = mappingExchange{request: request, transaction: transaction}
	}
	return client, nil
}

// Observe validates and registers both targets before emitting, then performs
// the two exchanges serially. Any failed exchange is terminal; partial
// evidence is returned only for diagnosis and can never authorize READY.
func (client *GateASameSocketClient) Observe(ctx context.Context, targets []netip.AddrPort) (GateAMappingObservation, error) {
	result := GateAMappingObservation{Generation: clientGeneration(client)}
	if client == nil || client.socket == nil || client.generation == nil || ctx == nil {
		return result, ErrInvalidConfig
	}
	client.mu.Lock()
	if client.used || client.terminal {
		client.mu.Unlock()
		return result, ErrGateAMappingTerminal
	}
	client.used = true
	client.mu.Unlock()

	canonical, err := canonicalMappingTargets(targets, 2, client.allowNonLoopback)
	if err != nil {
		client.terminate()
		return result, err
	}
	if client.generation.CurrentGeneration() != client.expectedGeneration {
		client.terminate()
		return result, probeio.ErrStaleGeneration
	}
	local, err := client.socket.LocalAddr()
	if err != nil {
		client.terminate()
		return result, err
	}
	result.LocalEndpoint = local
	for _, target := range canonical {
		if err := client.socket.RegisterTarget(target); err != nil {
			client.terminate()
			return result, err
		}
	}

	runCtx, cancelRun := context.WithTimeout(ctx, 2*MaxObservationDuration)
	defer cancelRun()
	classified := make([]MappingEndpoint, 0, 2)
	result.Results = make([]MappingTargetObservation, 0, 2)
	for index, target := range canonical {
		observation := newBindingObservation(client.now().UTC(), target)
		observation.Strategy = GateAMappingObservationStrategy
		observation.LocalAddr = local.String()
		targetCtx, cancelTarget := context.WithTimeout(runCtx, MaxObservationDuration)
		finished, exchangeErr := runBindingExchange(ctx, targetCtx, client.socket, target,
			client.exchanges[index].request, client.exchanges[index].transaction,
			client.initialRTO, client.now, observation)
		cancelTarget()
		transmissions, _ := strconv.Atoi(finished.Details["transmissions"])
		result.Transmissions += transmissions
		result.Results = append(result.Results, MappingTargetObservation{Target: target, Observation: finished, Err: exchangeErr})
		endpoint := MappingEndpoint{Target: target}
		if exchangeErr == nil {
			mapped, parseErr := netip.ParseAddrPort(finished.Details["mapped_address"])
			if parseErr == nil && mapped.IsValid() {
				endpoint.Mapped = netip.AddrPortFrom(mapped.Addr().Unmap(), mapped.Port())
			} else {
				exchangeErr = ErrMappedAddressInvalid
			}
		}
		classified = append(classified, endpoint)
		if exchangeErr != nil {
			result.Classification = ClassifyMapping(classified)
			client.terminate()
			return result, exchangeErr
		}
		if client.generation.CurrentGeneration() != client.expectedGeneration {
			result.Classification = ClassifyMapping(classified)
			client.terminate()
			return result, probeio.ErrStaleGeneration
		}
	}
	result.Classification = ClassifyMapping(classified)
	if len(classified) == 2 && classified[0].Mapped == classified[1].Mapped {
		result.MappedEndpoint = classified[0].Mapped
	}
	client.mu.Lock()
	if client.terminal || client.generation.CurrentGeneration() != client.expectedGeneration {
		client.mu.Unlock()
		client.terminate()
		return result, probeio.ErrStaleGeneration
	}
	client.observed = true
	copy(client.stunTargets[:], canonical)
	client.mu.Unlock()
	return result, nil
}

// RegisterPeerTarget consumes the third and final target slot only after both
// current-generation STUN observations completed. Mapping admission remains a
// caller decision so port-dependent evidence can terminate with direct=0.
func (client *GateASameSocketClient) RegisterPeerTarget(peer netip.AddrPort, generation uint64) error {
	if client == nil || client.socket == nil || client.generation == nil {
		return ErrInvalidConfig
	}
	client.mu.Lock()
	if client.terminal {
		client.mu.Unlock()
		return ErrGateAMappingTerminal
	}
	if !client.observed || generation != client.expectedGeneration || client.generation.CurrentGeneration() != client.expectedGeneration {
		client.mu.Unlock()
		client.terminate()
		return ErrPeerBeforeObservation
	}
	if client.peerRegistered {
		client.mu.Unlock()
		client.terminate()
		return ErrPeerAlreadyRegistered
	}
	client.peerRegistered = true
	targets := client.stunTargets
	client.mu.Unlock()
	canonical, err := canonicalTarget(peer, client.allowNonLoopback)
	if err != nil {
		client.terminate()
		return err
	}
	if canonical == targets[0] || canonical == targets[1] {
		client.terminate()
		return ErrPeerMatchesSTUNTarget
	}
	if err := client.socket.RegisterTarget(canonical); err != nil {
		client.terminate()
		return err
	}
	return nil
}

func (client *GateASameSocketClient) terminate() {
	if client == nil {
		return
	}
	client.mu.Lock()
	if client.terminal {
		client.mu.Unlock()
		return
	}
	client.terminal = true
	socket := client.socket
	client.mu.Unlock()
	if socket != nil {
		_ = socket.Close()
	}
}

func clientGeneration(client *GateASameSocketClient) uint64 {
	if client == nil {
		return 0
	}
	return client.expectedGeneration
}
