package stunobserve

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/pkg/solver"
)

const (
	MinAllocationSockets     = 3
	MaxAllocationSockets     = 8
	DefaultAllocationSockets = 5

	AllocationBehaviorSequentialUniform   AllocationBehavior = "sequential_uniform"
	AllocationBehaviorMonotonicNonuniform AllocationBehavior = "monotonic_nonuniform"
	AllocationBehaviorApparentlyRandom    AllocationBehavior = "apparently_random"
	AllocationBehaviorInsufficientData    AllocationBehavior = "insufficient_data"

	AllocationEvidenceSingleTargetMultipleSockets AllocationEvidenceScope = "single_target_multiple_sockets"

	AllocationLimitationSingleTimeWindow AllocationLimitation = "single_time_window"
	AllocationLimitationSingleTarget     AllocationLimitation = "single_target"
	AllocationLimitationSmallSample      AllocationLimitation = "small_sample_not_permanent_nat_label"
)

var ErrInvalidAllocationSocketCount = errors.New("stunobserve: allocation observation requires three to eight sockets")

// AllocationBehavior summarizes only the mapped-port sequence observed in one
// bounded run. It is not a permanent NAT label or a prediction guarantee.
type AllocationBehavior string

// AllocationEvidenceScope describes how the port sequence was collected.
type AllocationEvidenceScope string

// AllocationLimitation is evidence that must remain attached to a result.
type AllocationLimitation string

// AllocationSample is the pure classifier input. Invalid Mapped endpoints are
// retained as failed samples and do not contribute to the successful sequence.
type AllocationSample struct {
	Local  netip.AddrPort
	Mapped netip.AddrPort
}

// AllocationClassification retains the signed adjacent deltas so operators
// can review the classification rather than treating the enum as ground truth.
type AllocationClassification struct {
	Behavior          AllocationBehavior
	EvidenceScope     AllocationEvidenceScope
	Limitations       []AllocationLimitation
	SuccessfulSockets int
	TotalSockets      int
	Deltas            []int
}

// AllocationSocketObservation retains one socket's local endpoint, complete
// time-windowed observation, and stable error when that exchange failed.
type AllocationSocketObservation struct {
	Local       netip.AddrPort
	Observation solver.Observation
	Err         error
}

// AllocationObservation is one serial, single-target, multi-socket run.
type AllocationObservation struct {
	Classification AllocationClassification
	Results        []AllocationSocketObservation
}

// AllocationWorstCaseCost reserves every socket before the run begins. All K
// sockets remain open until every exchange has completed. K+1 PPS covers a
// retransmission followed immediately by successful first transmissions on
// the remaining sockets inside one sliding one-second window.
func AllocationWorstCaseCost(socketCount int) (governor.AttemptCost, error) {
	if socketCount < MinAllocationSockets || socketCount > MaxAllocationSockets {
		return governor.AttemptCost{}, ErrInvalidAllocationSocketCount
	}
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets:          socketCount,
			Targets:          1,
			PacketsPerSecond: socketCount + 1,
			Packets:          socketCount * MaxTransmissions,
			FiveTuples:       socketCount,
		},
		Duration: time.Duration(socketCount) * MaxObservationDuration,
	}, nil
}

// ClassifyAllocation classifies successful mapped ports in observation order.
// A single numerical descent may be a 65535-to-1 wrap. More than one descent,
// a repeated port, or normalized variance above the documented threshold is
// reported only as apparently random.
func ClassifyAllocation(samples []AllocationSample) AllocationClassification {
	classification := AllocationClassification{
		Behavior:      AllocationBehaviorInsufficientData,
		EvidenceScope: AllocationEvidenceSingleTargetMultipleSockets,
		Limitations: []AllocationLimitation{
			AllocationLimitationSingleTimeWindow,
			AllocationLimitationSingleTarget,
			AllocationLimitationSmallSample,
		},
		TotalSockets: len(samples),
	}

	ports := make([]uint16, 0, len(samples))
	for _, sample := range samples {
		if !sample.Local.IsValid() || sample.Local.Port() == 0 || !sample.Mapped.IsValid() || sample.Mapped.Port() == 0 {
			continue
		}
		classification.SuccessfulSockets++
		ports = append(ports, sample.Mapped.Port())
	}
	if len(ports) < MinAllocationSockets {
		return classification
	}

	classification.Deltas = make([]int, 0, len(ports)-1)
	cyclic := make([]uint64, 0, len(ports)-1)
	descents := 0
	for index := 1; index < len(ports); index++ {
		delta := int(ports[index]) - int(ports[index-1])
		classification.Deltas = append(classification.Deltas, delta)
		if delta == 0 {
			classification.Behavior = AllocationBehaviorApparentlyRandom
			return classification
		}
		if delta < 0 {
			descents++
			delta += 65535
		}
		cyclic = append(cyclic, uint64(delta))
	}

	uniform := true
	for _, delta := range cyclic[1:] {
		if delta != cyclic[0] {
			uniform = false
			break
		}
	}
	if descents <= 1 && uniform {
		classification.Behavior = AllocationBehaviorSequentialUniform
		return classification
	}
	if descents > 1 || allocationDeltasHaveLargeVariance(cyclic) {
		classification.Behavior = AllocationBehaviorApparentlyRandom
		return classification
	}
	classification.Behavior = AllocationBehaviorMonotonicNonuniform
	return classification
}

// allocationDeltasHaveLargeVariance uses a coefficient-of-variation threshold
// of 0.5 without floating point: variance > mean^2/4.
func allocationDeltasHaveLargeVariance(deltas []uint64) bool {
	if len(deltas) < 2 {
		return false
	}
	var sum, sumSquares uint64
	for _, delta := range deltas {
		sum += delta
		sumSquares += delta * delta
	}
	n := uint64(len(deltas))
	return 4*n*sumSquares > 5*sum*sum
}

// AllocationClient performs exactly one bounded serial run against one target
// using three to eight governed sockets.
type AllocationClient struct {
	controller       *probeio.Controller
	now              func() time.Time
	initialRTO       time.Duration
	exchanges        []mappingExchange
	socketCount      int
	cost             governor.AttemptCost
	allowNonLoopback bool

	mu   sync.Mutex
	used bool
}

// NewAllocation validates the aggregate budget without opening a socket.
func NewAllocation(config Config, socketCount int) (*AllocationClient, error) {
	return newAllocationClient(config, socketCount, rand.Reader, time.Now, InitialRTO)
}

func newAllocationClient(config Config, socketCount int, random io.Reader, now func() time.Time, initialRTO time.Duration) (*AllocationClient, error) {
	cost, err := AllocationWorstCaseCost(socketCount)
	if err != nil {
		return nil, err
	}
	if config.Lease == nil || config.Generation == nil || config.Factory == nil || random == nil || now == nil || initialRTO <= 0 {
		return nil, fmt.Errorf("%w: lease, generation, factory, random source, clock, and RTO are required", ErrInvalidConfig)
	}
	if err := coversWorstCase(config.Lease.Request().Cost, cost); err != nil {
		return nil, err
	}
	exchanges := make([]mappingExchange, socketCount)
	for index := range exchanges {
		request, transaction, err := newBindingRequest(random)
		if err != nil {
			return nil, err
		}
		exchanges[index] = mappingExchange{request: request, transaction: transaction}
	}
	controller, err := newProbeController(config, now)
	if err != nil {
		return nil, err
	}
	return &AllocationClient{
		controller:       controller,
		now:              now,
		initialRTO:       initialRTO,
		exchanges:        exchanges,
		socketCount:      socketCount,
		cost:             cost,
		allowNonLoopback: config.AllowNonLoopback,
	}, nil
}

// Close releases the controller and its attempt. It is idempotent.
func (client *AllocationClient) Close() error {
	if client == nil || client.controller == nil {
		return nil
	}
	return client.controller.Close()
}

// Observe opens and registers every socket before sending. Exchanges are then
// run serially, and no socket is closed until the entire round has finished.
// Per-socket exchange failures are retained and do not skip later sockets.
func (client *AllocationClient) Observe(ctx context.Context, target netip.AddrPort) (result AllocationObservation, err error) {
	if client == nil || client.controller == nil || ctx == nil {
		return result, ErrInvalidConfig
	}
	client.mu.Lock()
	if client.used {
		client.mu.Unlock()
		return result, ErrAlreadyObserved
	}
	client.used = true
	client.mu.Unlock()
	defer func() {
		err = errors.Join(err, client.Close())
	}()

	canonical, err := canonicalTarget(target, client.allowNonLoopback)
	if err != nil {
		return result, err
	}
	runCtx, cancelRun := context.WithTimeout(ctx, client.cost.Duration)
	defer cancelRun()

	sockets := make([]*probeio.ProbeSocket, 0, client.socketCount)
	locals := make([]netip.AddrPort, 0, client.socketCount)
	defer func() {
		for index := len(sockets) - 1; index >= 0; index-- {
			err = errors.Join(err, sockets[index].Close())
		}
	}()
	for index := 0; index < client.socketCount; index++ {
		socket, openErr := client.controller.OpenProbeSocket(runCtx)
		if openErr != nil {
			return result, openErr
		}
		sockets = append(sockets, socket)
		local, localErr := socket.LocalAddr()
		if localErr != nil {
			return result, localErr
		}
		locals = append(locals, local)
		if registerErr := socket.RegisterTarget(canonical); registerErr != nil {
			return result, registerErr
		}
	}

	result.Results = make([]AllocationSocketObservation, 0, client.socketCount)
	samples := make([]AllocationSample, 0, client.socketCount)
	for index, socket := range sockets {
		startedAt := client.now().UTC()
		observation := newBindingObservation(startedAt, canonical)
		observation.LocalAddr = locals[index].String()
		exchangeCtx, cancelExchange := context.WithTimeout(runCtx, MaxObservationDuration)
		observation, observeErr := runBindingExchange(
			ctx,
			exchangeCtx,
			socket,
			canonical,
			client.exchanges[index].request,
			client.exchanges[index].transaction,
			client.initialRTO,
			client.now,
			observation,
		)
		cancelExchange()
		result.Results = append(result.Results, AllocationSocketObservation{Local: locals[index], Observation: observation, Err: observeErr})
		sample := AllocationSample{Local: locals[index]}
		if observeErr == nil {
			if mapped, parseErr := netip.ParseAddrPort(observation.Details["mapped_address"]); parseErr == nil {
				sample.Mapped = netip.AddrPortFrom(mapped.Addr().Unmap(), mapped.Port())
			}
		}
		samples = append(samples, sample)
	}
	result.Classification = ClassifyAllocation(samples)
	return result, nil
}
