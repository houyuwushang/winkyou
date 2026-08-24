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
	"winkyou/pkg/solver"
)

const SameSocketObservationStrategy = "stun_observe_same_socket"

var (
	ErrSameSocketTerminal    = errors.New("stunobserve: same-socket adapter is terminal")
	ErrPeerBeforeObservation = errors.New("stunobserve: peer target requires a successful current-generation observation")
	ErrPeerAlreadyRegistered = errors.New("stunobserve: peer target is already registered")
	ErrPeerMatchesSTUNTarget = errors.New("stunobserve: peer target must differ from the STUN target")
)

// N2SameSocketCost is the UDP portion that must be present in the complete N2
// reservation. It includes the future direct punch so STUN cannot consume a
// budget that leaves the authenticated peer target or fixed punch packets
// unreserved. The enclosing N2 carrier reservation additionally accounts for
// one TCP connection/target/five-tuple and a coarse optional-DNS
// socket/target/five-tuple.
func N2SameSocketCost() governor.AttemptCost {
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets:          1,
			Targets:          2,
			PacketsPerSecond: 5,
			Packets:          5,
			FiveTuples:       2,
		},
		Duration:    15 * time.Second,
		Heavyweight: true,
	}
}

// SameSocketConfig binds one single-use observer to a ProbeSocket that the
// caller already opened through probeio. The adapter owns no Factory and has
// no operation that can open another socket.
type SameSocketConfig struct {
	Socket             *probeio.ProbeSocket
	Generation         probeio.GenerationSource
	ExpectedGeneration uint64
	// AllowNonLoopback does not grant network authority. The supplied socket's
	// reviewed Factory scope and the disconnected N2 architecture gate remain
	// authoritative. Its zero value preserves literal-loopback-only use.
	AllowNonLoopback bool
}

// SameSocketObservation is process-local evidence for one generation. Raw
// observation and endpoint values are explicitly excluded from default JSON
// encoding and must not be logged or persisted by the adapter.
type SameSocketObservation struct {
	Observation    solver.Observation `json:"-"`
	LocalEndpoint  netip.AddrPort     `json:"-"`
	MappedEndpoint netip.AddrPort     `json:"-"`
	Generation     uint64             `json:"generation"`
	Transmissions  int                `json:"transmissions"`
}

// SameSocketClient performs STUN and then authorizes exactly one peer target
// on the same caller-owned ProbeSocket. Any STUN or ordering failure closes the
// handle so the attempt cannot continue with stale or unauthenticated data.
type SameSocketClient struct {
	mu sync.Mutex

	socket             *probeio.ProbeSocket
	generation         probeio.GenerationSource
	expectedGeneration uint64
	allowNonLoopback   bool
	now                func() time.Time
	initialRTO         time.Duration
	request            []byte
	transaction        transactionID

	used           bool
	terminal       bool
	observed       bool
	peerRegistered bool
	stunTarget     netip.AddrPort
}

// NewSameSocket validates the current generation and the already-reserved N2
// budget without registering a target or emitting a packet.
func NewSameSocket(config SameSocketConfig) (*SameSocketClient, error) {
	return newSameSocket(config, rand.Reader, time.Now, InitialRTO)
}

func newSameSocket(config SameSocketConfig, random io.Reader, now func() time.Time, initialRTO time.Duration) (*SameSocketClient, error) {
	if config.Socket == nil || config.Generation == nil || config.ExpectedGeneration == 0 || random == nil || now == nil || initialRTO <= 0 {
		return nil, ErrInvalidConfig
	}
	if config.Generation.CurrentGeneration() != config.ExpectedGeneration {
		return nil, probeio.ErrStaleGeneration
	}
	reservation, err := config.Socket.Reservation()
	if err != nil {
		return nil, err
	}
	if reservation.Operation != governor.OperationConnectTest || reservation.Generation != config.ExpectedGeneration ||
		!coversSameSocketCost(reservation.Cost, N2SameSocketCost()) {
		return nil, ErrInsufficientBudget
	}
	request, transaction, err := newBindingRequest(random)
	if err != nil {
		return nil, err
	}
	return &SameSocketClient{
		socket:             config.Socket,
		generation:         config.Generation,
		expectedGeneration: config.ExpectedGeneration,
		allowNonLoopback:   config.AllowNonLoopback,
		now:                now,
		initialRTO:         initialRTO,
		request:            request,
		transaction:        transaction,
	}, nil
}

// Observe registers the STUN target first and runs at most three Binding
// transmissions through the existing socket. It leaves the socket open only
// after a successful, current-generation result.
func (client *SameSocketClient) Observe(ctx context.Context, target netip.AddrPort) (SameSocketObservation, error) {
	startedAt := time.Now().UTC()
	if client != nil && client.now != nil {
		startedAt = client.now().UTC()
	}
	observation := newBindingObservation(startedAt, target)
	observation.Strategy = SameSocketObservationStrategy
	if client == nil || client.socket == nil || client.generation == nil || ctx == nil {
		return SameSocketObservation{Observation: observation}, ErrInvalidConfig
	}

	client.mu.Lock()
	if client.terminal || client.used {
		client.mu.Unlock()
		return SameSocketObservation{Observation: observation}, ErrSameSocketTerminal
	}
	client.used = true
	client.mu.Unlock()

	canonical, err := canonicalTarget(target, client.allowNonLoopback)
	if err != nil {
		client.terminate()
		finished, _ := finishBindingObservation(client.now, observation, 0, netip.AddrPort{}, "", err)
		return SameSocketObservation{Observation: finished}, err
	}
	if client.generation.CurrentGeneration() != client.expectedGeneration {
		client.terminate()
		finished, _ := finishBindingObservation(client.now, observation, 0, netip.AddrPort{}, "", probeio.ErrStaleGeneration)
		return SameSocketObservation{Observation: finished}, probeio.ErrStaleGeneration
	}

	local, err := client.socket.LocalAddr()
	if err != nil {
		client.terminate()
		finished, _ := finishBindingObservation(client.now, observation, 0, netip.AddrPort{}, "", err)
		return SameSocketObservation{Observation: finished}, err
	}
	observation.LocalAddr = local.String()
	observation.RemoteAddr = canonical.String()
	if err := client.socket.RegisterTarget(canonical); err != nil {
		client.terminate()
		finished, _ := finishBindingObservation(client.now, observation, 0, netip.AddrPort{}, "", err)
		return SameSocketObservation{Observation: finished}, err
	}

	operationCtx, cancel := context.WithTimeout(ctx, MaxObservationDuration)
	finished, exchangeErr := runBindingExchange(ctx, operationCtx, client.socket, canonical, client.request, client.transaction, client.initialRTO, client.now, observation)
	cancel()
	transmissions, _ := strconv.Atoi(finished.Details["transmissions"])
	if exchangeErr != nil {
		client.terminate()
		return SameSocketObservation{Observation: finished, LocalEndpoint: local, Generation: client.expectedGeneration, Transmissions: transmissions}, exchangeErr
	}
	mapped, parseErr := netip.ParseAddrPort(finished.Details["mapped_address"])
	if parseErr != nil || !mapped.IsValid() || client.generation.CurrentGeneration() != client.expectedGeneration {
		client.terminate()
		cause := probeio.ErrStaleGeneration
		if parseErr != nil || !mapped.IsValid() {
			cause = ErrMappedAddressInvalid
		}
		finished.ErrorClass, finished.Reason = classifyError(cause)
		return SameSocketObservation{Observation: solver.NormalizeObservation(finished), LocalEndpoint: local, Generation: client.expectedGeneration, Transmissions: transmissions}, cause
	}
	finished.Details["generation"] = strconv.FormatUint(client.expectedGeneration, 10)
	finished = solver.NormalizeObservation(finished)

	client.mu.Lock()
	if client.terminal {
		client.mu.Unlock()
		finished.ErrorClass, finished.Reason = classifyError(ErrSameSocketTerminal)
		return SameSocketObservation{Observation: solver.NormalizeObservation(finished), LocalEndpoint: local, Generation: client.expectedGeneration, Transmissions: transmissions}, ErrSameSocketTerminal
	}
	client.observed = true
	client.stunTarget = canonical
	client.mu.Unlock()
	return SameSocketObservation{
		Observation: finished, LocalEndpoint: local, MappedEndpoint: mapped,
		Generation: client.expectedGeneration, Transmissions: transmissions,
	}, nil
}

// RegisterPeerTarget registers the authenticated READY endpoint only after a
// successful STUN observation in the same generation. It performs no send.
func (client *SameSocketClient) RegisterPeerTarget(peer netip.AddrPort, generation uint64) error {
	if client == nil || client.socket == nil || client.generation == nil {
		return ErrInvalidConfig
	}
	client.mu.Lock()
	if client.terminal {
		client.mu.Unlock()
		return ErrSameSocketTerminal
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
	// Reserve the one peer slot before validation/I/O so concurrent callers
	// cannot race into two registrations. Any subsequent failure is terminal.
	client.peerRegistered = true
	stunTarget := client.stunTarget
	client.mu.Unlock()

	canonical, err := canonicalTarget(peer, client.allowNonLoopback)
	if err != nil {
		client.terminate()
		return err
	}
	if canonical == stunTarget {
		client.terminate()
		return ErrPeerMatchesSTUNTarget
	}
	if err := client.socket.RegisterTarget(canonical); err != nil {
		client.terminate()
		return err
	}
	return nil
}

func (client *SameSocketClient) terminate() {
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

func coversSameSocketCost(actual, required governor.AttemptCost) bool {
	return actual.Resources.Sockets >= required.Resources.Sockets &&
		actual.Resources.Targets >= required.Resources.Targets &&
		actual.Resources.PacketsPerSecond >= required.Resources.PacketsPerSecond &&
		actual.Resources.Packets >= required.Resources.Packets &&
		actual.Resources.FiveTuples >= required.Resources.FiveTuples &&
		actual.Duration >= required.Duration && actual.Heavyweight
}
