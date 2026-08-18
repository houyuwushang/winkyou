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
	MinMappingTargets = 2
	MaxMappingTargets = 3

	MappingBehaviorConsistentSameAddress MappingBehavior = "consistent_same_address"
	MappingBehaviorPortDependent         MappingBehavior = "port_dependent"
	MappingBehaviorInconclusive          MappingBehavior = "inconclusive"

	MappingEvidenceSameAddressMultiplePorts MappingEvidenceScope = "same_address_multiple_ports"

	MappingLimitationAddressComparisonUnavailable MappingLimitation = "address_comparison_unavailable"
)

var (
	ErrInvalidMappingTargetCount = errors.New("stunobserve: mapping observation requires two or three targets")
	ErrDuplicateMappingTarget    = errors.New("stunobserve: mapping observation targets must be unique")
)

// MappingBehavior is deliberately narrower than an RFC 4787 NAT type. It
// describes only evidence obtained from one local socket in one bounded time
// window.
type MappingBehavior string

// MappingEvidenceScope identifies the comparison represented by Behavior.
type MappingEvidenceScope string

// MappingLimitation records evidence that the selected targets could not
// provide. It must not be interpreted as a mapping behavior.
type MappingLimitation string

// MappingEndpoint is the pure classifier input. An invalid Mapped endpoint
// represents a target that did not produce a successful observation.
type MappingEndpoint struct {
	Target netip.AddrPort
	Mapped netip.AddrPort
}

// MappingClassification is an honest same-address, multiple-port result. A
// caller must retain Limitations when displaying or serializing Behavior.
type MappingClassification struct {
	Behavior          MappingBehavior
	EvidenceScope     MappingEvidenceScope
	Limitations       []MappingLimitation
	SuccessfulTargets int
	TotalTargets      int
}

// MappingTargetObservation retains each target's full time-windowed domain
// observation and its stable per-target error, if any.
type MappingTargetObservation struct {
	Target      netip.AddrPort
	Observation solver.Observation
	Err         error
}

// MappingObservation is the result of one single-socket serial run.
type MappingObservation struct {
	Classification MappingClassification
	Results        []MappingTargetObservation
}

// MappingWorstCaseCost returns the aggregate reservation for one socket and
// targetCount serial Binding exchanges. The N+1 PPS ceiling covers a target
// succeeding after its second transmission followed immediately by the
// remaining targets succeeding on their first transmissions.
func MappingWorstCaseCost(targetCount int) (governor.AttemptCost, error) {
	if targetCount < MinMappingTargets || targetCount > MaxMappingTargets {
		return governor.AttemptCost{}, ErrInvalidMappingTargetCount
	}
	return governor.AttemptCost{
		Resources: governor.Resources{
			Sockets:          1,
			Targets:          targetCount,
			PacketsPerSecond: targetCount + 1,
			Packets:          targetCount * MaxTransmissions,
			FiveTuples:       targetCount,
		},
		Duration: time.Duration(targetCount) * MaxObservationDuration,
	}, nil
}

// ClassifyMapping evaluates only same-server-address, different-port
// evidence. Different mapped endpoints observed only across different server
// addresses remain inconclusive in this deliberately narrow classifier.
func ClassifyMapping(endpoints []MappingEndpoint) MappingClassification {
	classification := MappingClassification{
		Behavior:      MappingBehaviorInconclusive,
		EvidenceScope: MappingEvidenceSameAddressMultiplePorts,
		Limitations:   make([]MappingLimitation, 0, 1),
		TotalTargets:  len(endpoints),
	}

	targetAddresses := make(map[netip.Addr]struct{}, len(endpoints))
	type mappedByTargetPort struct {
		mapped netip.AddrPort
	}
	groups := make(map[netip.Addr]map[uint16]mappedByTargetPort)
	var firstMapped netip.AddrPort
	allMappedEqual := true

	for _, endpoint := range endpoints {
		if endpoint.Target.IsValid() && endpoint.Target.Port() != 0 {
			targetAddresses[endpoint.Target.Addr().Unmap()] = struct{}{}
		}
		if !endpoint.Target.IsValid() || endpoint.Target.Port() == 0 || !endpoint.Mapped.IsValid() || endpoint.Mapped.Port() == 0 {
			continue
		}
		classification.SuccessfulTargets++
		mapped := netip.AddrPortFrom(endpoint.Mapped.Addr().Unmap(), endpoint.Mapped.Port())
		if !firstMapped.IsValid() {
			firstMapped = mapped
		} else if mapped != firstMapped {
			allMappedEqual = false
		}
		address := endpoint.Target.Addr().Unmap()
		if groups[address] == nil {
			groups[address] = make(map[uint16]mappedByTargetPort)
		}
		groups[address][endpoint.Target.Port()] = mappedByTargetPort{mapped: mapped}
	}

	if len(targetAddresses) <= 1 {
		classification.Limitations = append(classification.Limitations, MappingLimitationAddressComparisonUnavailable)
	}
	if classification.SuccessfulTargets < 2 {
		return classification
	}

	hasSameAddressPortPair := false
	for _, byPort := range groups {
		if len(byPort) < 2 {
			continue
		}
		hasSameAddressPortPair = true
		var first netip.AddrPort
		for _, result := range byPort {
			if !first.IsValid() {
				first = result.mapped
				continue
			}
			if result.mapped != first {
				classification.Behavior = MappingBehaviorPortDependent
				return classification
			}
		}
	}
	if hasSameAddressPortPair && allMappedEqual {
		classification.Behavior = MappingBehaviorConsistentSameAddress
	}
	return classification
}

// MappingClient performs exactly one bounded serial run over two or three
// targets while retaining one governed local socket for every exchange.
type MappingClient struct {
	controller       *probeio.Controller
	now              func() time.Time
	initialRTO       time.Duration
	exchanges        []mappingExchange
	targetCount      int
	cost             governor.AttemptCost
	allowNonLoopback bool

	mu   sync.Mutex
	used bool
}

type mappingExchange struct {
	request     []byte
	transaction transactionID
}

// NewMapping validates the complete aggregate budget without opening a
// socket. Observe later validates every target before opening its one socket.
func NewMapping(config Config, targetCount int) (*MappingClient, error) {
	return newMappingClient(config, targetCount, rand.Reader, time.Now, InitialRTO)
}

func newMappingClient(config Config, targetCount int, random io.Reader, now func() time.Time, initialRTO time.Duration) (*MappingClient, error) {
	cost, err := MappingWorstCaseCost(targetCount)
	if err != nil {
		return nil, err
	}
	if config.Lease == nil || config.Generation == nil || config.Factory == nil || random == nil || now == nil || initialRTO <= 0 {
		return nil, fmt.Errorf("%w: lease, generation, factory, random source, clock, and RTO are required", ErrInvalidConfig)
	}
	if err := coversWorstCase(config.Lease.Request().Cost, cost); err != nil {
		return nil, err
	}
	exchanges := make([]mappingExchange, targetCount)
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
	return &MappingClient{
		controller:       controller,
		now:              now,
		initialRTO:       initialRTO,
		exchanges:        exchanges,
		targetCount:      targetCount,
		cost:             cost,
		allowNonLoopback: config.AllowNonLoopback,
	}, nil
}

// Close releases the controller and its attempt. It is idempotent.
func (client *MappingClient) Close() error {
	if client == nil || client.controller == nil {
		return nil
	}
	return client.controller.Close()
}

// Observe validates and registers all targets before sending, then performs
// their exchanges serially. Per-target failures are retained in Results and
// do not prevent later targets from being attempted. The top-level error is
// reserved for invalid/setup/cleanup failures that prevent a complete run.
func (client *MappingClient) Observe(ctx context.Context, targets []netip.AddrPort) (result MappingObservation, err error) {
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

	canonical, err := canonicalMappingTargets(targets, client.targetCount, client.allowNonLoopback)
	if err != nil {
		return result, err
	}
	runCtx, cancelRun := context.WithTimeout(ctx, client.cost.Duration)
	defer cancelRun()

	socket, err := client.controller.OpenProbeSocket(runCtx)
	if err != nil {
		return result, err
	}
	defer func() {
		err = errors.Join(err, socket.Close())
	}()
	local, err := socket.LocalAddr()
	if err != nil {
		return result, err
	}
	for _, target := range canonical {
		if err := socket.RegisterTarget(target); err != nil {
			return result, err
		}
	}

	result.Results = make([]MappingTargetObservation, 0, len(canonical))
	classified := make([]MappingEndpoint, 0, len(canonical))
	for index, target := range canonical {
		startedAt := client.now().UTC()
		observation := newBindingObservation(startedAt, target)
		observation.LocalAddr = local.String()
		targetCtx, cancelTarget := context.WithTimeout(runCtx, MaxObservationDuration)
		observation, observeErr := runBindingExchange(ctx, targetCtx, socket, target, client.exchanges[index].request, client.exchanges[index].transaction, client.initialRTO, client.now, observation)
		cancelTarget()
		result.Results = append(result.Results, MappingTargetObservation{Target: target, Observation: observation, Err: observeErr})
		endpoint := MappingEndpoint{Target: target}
		if observeErr == nil {
			if mapped, parseErr := netip.ParseAddrPort(observation.Details["mapped_address"]); parseErr == nil {
				endpoint.Mapped = netip.AddrPortFrom(mapped.Addr().Unmap(), mapped.Port())
			}
		}
		classified = append(classified, endpoint)
	}
	result.Classification = ClassifyMapping(classified)
	return result, nil
}

func canonicalMappingTargets(source []netip.AddrPort, expected int, allowNonLoopback bool) ([]netip.AddrPort, error) {
	if len(source) != expected || len(source) < MinMappingTargets || len(source) > MaxMappingTargets {
		return nil, ErrInvalidMappingTargetCount
	}
	result := make([]netip.AddrPort, 0, len(source))
	seen := make(map[netip.AddrPort]struct{}, len(source))
	for _, target := range source {
		canonical, err := canonicalTarget(target, allowNonLoopback)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[canonical]; exists {
			return nil, ErrDuplicateMappingTarget
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}
