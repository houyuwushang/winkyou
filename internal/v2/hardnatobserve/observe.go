package hardnatobserve

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"time"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
)

const (
	ObservationSocketCount = hardnatplan.MinSuccessfulAllocationSamples
	ObservationPacketCount = hardnatbudget.FreshEvidencePackets
	perReplyDeadline       = 250 * time.Millisecond
	maxResponseBytes       = 1024
)

var (
	ErrInvalidConfig       = errors.New("hardnatobserve: invalid configuration")
	ErrObservationFailed   = errors.New("hardnatobserve: observation failed")
	ErrRequiredReplyAbsent = errors.New("hardnatobserve: required reply absent")
)

// Topology is the RFC 5780 two-address/two-port observer topology. The fourth
// endpoint is derived rather than supplied, so a caller cannot provide an
// internally inconsistent cross-product.
type Topology struct {
	Primary netip.AddrPort // A1:P1
	Other   netip.AddrPort // A2:P2
}

func (topology Topology) Endpoints() ([4]netip.AddrPort, error) {
	var endpoints [4]netip.AddrPort
	primary, other := canonical(topology.Primary), canonical(topology.Other)
	if !validEndpoint(primary) || !validEndpoint(other) || primary.Addr() == other.Addr() || primary.Port() == other.Port() {
		return endpoints, ErrInvalidConfig
	}
	endpoints[0] = primary
	endpoints[1] = netip.AddrPortFrom(primary.Addr(), other.Port())
	endpoints[2] = netip.AddrPortFrom(other.Addr(), primary.Port())
	endpoints[3] = other
	return endpoints, nil
}

// TrustAnchors are values fixed by the attempt authority before observation.
// None may be derived from a received packet or a peer report.
type TrustAnchors struct {
	AttemptDigest        [32]byte
	MachineScopeDigest   [32]byte
	PeerDigest           [32]byte
	ObservationSetDigest [32]byte
	SocketOwnerDigest    [32]byte
	Generation           uint64
}

// Config deliberately accepts already-open ProbeSockets. Collect never owns
// a Factory and therefore cannot create a second or replacement socket.
type Config struct {
	Profile       hardnatplan.Profile
	ResourceClass hardnatplan.ResourceClass
	Sockets       []*probeio.ProbeSocket
	Topology      Topology
	Trust         TrustAnchors
	Random        io.Reader
	Now           func() time.Time
}

type Result struct {
	Graph         hardnatplan.EvidenceGraph
	Trusted       hardnatplan.TrustedValidationContext
	Model         hardnatplan.StateModel
	PublicAddress hardnatplan.Address
	PacketsSent   int
	Targets       int
	FiveTuples    int
}

type transaction struct {
	id          hardnatplan.TransactionID
	kind        hardnatplan.EvidenceKind
	source      hardnatplan.EvidenceSource
	observer    netip.AddrPort
	socketSlot  uint16
	ordinal     uint32
	change      hardnatplan.ChangeRequest
	discovery   hardnatplan.DiscoveryStep
	replyNeeded bool
}

// Collect performs exactly five RFC 5780 exchanges followed by eight
// allocation observations. It has no retransmission path.
func Collect(ctx context.Context, config Config) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	endpoints, err := config.Topology.Endpoints()
	if err != nil || len(config.Sockets) != ObservationSocketCount || !validTrust(config.Trust) {
		return Result{}, ErrInvalidConfig
	}
	envelope, err := hardnatbudget.For(config.Profile, config.ResourceClass)
	if err != nil {
		return Result{}, ErrInvalidConfig
	}
	operation, err := hardnatbudget.Operation(config.Profile)
	if err != nil {
		return Result{}, ErrInvalidConfig
	}
	for _, socket := range config.Sockets {
		if socket == nil {
			return Result{}, ErrInvalidConfig
		}
		reservation, reservationErr := socket.Reservation()
		if reservationErr != nil || reservation.Generation != config.Trust.Generation ||
			!hardnatbudget.Exact(config.Profile, config.ResourceClass, reservation.Operation, reservation.Cost) ||
			reservation.Operation != operation || reservation.Cost != envelope.Cost {
			return Result{}, errors.Join(ErrInvalidConfig, reservationErr)
		}
	}

	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	transactions, err := issueTransactions(random, endpoints)
	if err != nil {
		return Result{}, errors.Join(ErrInvalidConfig, err)
	}
	// Registration is deterministic and complete before the first emission.
	// Socket zero accepts all four legitimate RFC response sources. Each of the
	// remaining seven sockets registers its one allocation observer.
	for _, endpoint := range endpoints {
		if err := config.Sockets[0].RegisterTarget(endpoint); err != nil {
			return Result{}, errors.Join(ErrObservationFailed, err)
		}
	}
	for slot := 1; slot < ObservationSocketCount; slot++ {
		if err := config.Sockets[slot].RegisterTarget(allocationTarget(endpoints, slot)); err != nil {
			return Result{}, errors.Join(ErrObservationFailed, err)
		}
	}

	now := config.Now
	if now == nil {
		now = time.Now
	}
	started := positiveMilli(now())
	windowCtx, cancel := context.WithTimeout(ctx, hardnatbudget.EvidenceWindow)
	defer cancel()
	clock := logicalClock{now: now, last: started - 1}
	graph := hardnatplan.EvidenceGraph{
		AttemptDigest: config.Trust.AttemptDigest, MachineScopeDigest: config.Trust.MachineScopeDigest,
		PeerDigest: config.Trust.PeerDigest, ObservationSetDigest: config.Trust.ObservationSetDigest,
		SocketOwnerDigest: config.Trust.SocketOwnerDigest, Generation: config.Trust.Generation,
		StartedAtMilli: started,
	}
	var transcript hardnatplan.RFC5780Transcript
	transcript.Origin = hardnatplan.OriginLocalTransaction
	transcript.SocketSlot = 0
	packets := 0
	for index := 0; index < hardnatplan.RFC5780ExchangeCount; index++ {
		txn := transactions[index]
		exchange, exchangeErr := exchange(windowCtx, config.Sockets[0], txn, clock.stamp)
		packets++
		if exchangeErr != nil {
			return Result{}, exchangeErr
		}
		transcript.Exchanges[index] = exchange
	}
	graph.RFC5780 = []hardnatplan.RFC5780Transcript{transcript}

	for ordinal := 0; ordinal < ObservationSocketCount; ordinal++ {
		txn := transactions[hardnatplan.RFC5780ExchangeCount+ordinal]
		observation, exchangeErr := exchange(windowCtx, config.Sockets[ordinal], txn, clock.stamp)
		packets++
		if exchangeErr != nil || !observation.Received {
			if exchangeErr == nil {
				exchangeErr = ErrRequiredReplyAbsent
			}
			return Result{}, errors.Join(ErrObservationFailed, exchangeErr)
		}
		attributes, parseErr := hardnatplan.ParseBehaviorBindingSuccess(observation.Response, observation.TransactionID)
		if parseErr != nil {
			return Result{}, errors.Join(ErrObservationFailed, parseErr)
		}
		meta := hardnatplan.EvidenceMeta{
			Source: hardnatplan.SourceLocalTomography, Origin: hardnatplan.OriginLocalTransaction,
			ObserverAddress: toPlanAddress(txn.observer.Addr()), ObserverPort: txn.observer.Port(),
			SocketSlot: txn.socketSlot, TransactionID: txn.id, AttemptDigest: config.Trust.AttemptDigest,
			Generation: config.Trust.Generation, ObservedAtMilli: observation.ObservedAtMilli,
		}
		graph.Allocation = append(graph.Allocation, hardnatplan.AllocationSample{
			Meta: meta, SocketSlot: txn.socketSlot, Ordinal: txn.ordinal,
			MappedAddress: attributes.Mapped.Address, MappedPort: attributes.Mapped.Port, Success: true,
		})
	}

	finished := clock.stamp()
	if finished-started > hardnatplan.MaxEvidenceWindowMillis {
		return Result{}, errors.Join(ErrObservationFailed, hardnatplan.ErrEvidenceInsufficient)
	}
	graph.FinishedAtMilli = finished
	graph.ExpiresAtMilli = finished + hardnatplan.MaxEvidenceAgeMillis
	issued := make([]hardnatplan.IssuedTransaction, len(transactions))
	for index, txn := range transactions {
		issued[index] = hardnatplan.IssuedTransaction{
			Kind: txn.kind, TransactionID: txn.id, Source: txn.source, Observer: toPlanEndpoint(txn.observer),
			SocketSlot: txn.socketSlot, Ordinal: txn.ordinal, NotBeforeMilli: started, NotAfterMilli: finished,
		}
	}
	trusted := hardnatplan.TrustedValidationContext{
		NowMilli: finished, ExpectedAttemptDigest: config.Trust.AttemptDigest,
		ExpectedMachineScopeDigest: config.Trust.MachineScopeDigest, ExpectedPeerDigest: config.Trust.PeerDigest,
		ExpectedObservationSetDigest: config.Trust.ObservationSetDigest, ExpectedSocketOwnerDigest: config.Trust.SocketOwnerDigest,
		ExpectedGeneration: config.Trust.Generation, ExpectedStartedAtMilli: started,
		ExpectedFinishedAtMilli: finished, ExpectedExpiresAtMilli: graph.ExpiresAtMilli, Issued: issued,
	}
	model, err := hardnatplan.InferStateModel(graph, trusted)
	if err != nil {
		return Result{}, errors.Join(ErrObservationFailed, err)
	}
	publicAddress := graph.Allocation[0].MappedAddress
	return Result{Graph: graph, Trusted: trusted, Model: model, PublicAddress: publicAddress,
		PacketsSent: packets, Targets: 4, FiveTuples: 11}, nil
}

func issueTransactions(random io.Reader, endpoints [4]netip.AddrPort) ([]transaction, error) {
	steps := [...]struct {
		step   hardnatplan.DiscoveryStep
		target netip.AddrPort
		change hardnatplan.ChangeRequest
		needed bool
	}{
		{hardnatplan.StepPrimary, endpoints[0], hardnatplan.ChangeRequest{}, true},
		{hardnatplan.StepSameAddressOtherPort, endpoints[1], hardnatplan.ChangeRequest{}, true},
		{hardnatplan.StepOtherAddress, endpoints[2], hardnatplan.ChangeRequest{}, true},
		{hardnatplan.StepChangeIPPort, endpoints[0], hardnatplan.ChangeRequest{ChangeIP: true, ChangePort: true}, false},
		{hardnatplan.StepChangePort, endpoints[0], hardnatplan.ChangeRequest{ChangePort: true}, false},
	}
	result := make([]transaction, 0, ObservationPacketCount)
	seen := make(map[hardnatplan.TransactionID]struct{}, ObservationPacketCount)
	appendTransaction := func(value transaction) error {
		if _, err := io.ReadFull(random, value.id[:]); err != nil || allZero(value.id[:]) {
			if err == nil {
				err = ErrInvalidConfig
			}
			return err
		}
		if _, duplicate := seen[value.id]; duplicate {
			return ErrInvalidConfig
		}
		seen[value.id] = struct{}{}
		result = append(result, value)
		return nil
	}
	for ordinal, step := range steps {
		if err := appendTransaction(transaction{kind: hardnatplan.EvidenceKindRFC5780, source: hardnatplan.SourceRFC5780,
			observer: step.target, socketSlot: 0, ordinal: uint32(ordinal), change: step.change,
			discovery: step.step, replyNeeded: step.needed}); err != nil {
			return nil, err
		}
	}
	for ordinal := 0; ordinal < ObservationSocketCount; ordinal++ {
		if err := appendTransaction(transaction{kind: hardnatplan.EvidenceKindAllocation, source: hardnatplan.SourceLocalTomography,
			observer: allocationTarget(endpoints, ordinal), socketSlot: uint16(ordinal), ordinal: uint32(ordinal), replyNeeded: true}); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func exchange(ctx context.Context, socket *probeio.ProbeSocket, txn transaction, stamp func() int64) (hardnatplan.RFC5780Exchange, error) {
	request, err := hardnatplan.BuildBehaviorBindingRequest(txn.id, txn.change)
	if err != nil {
		return hardnatplan.RFC5780Exchange{}, errors.Join(ErrObservationFailed, err)
	}
	result := hardnatplan.RFC5780Exchange{
		Step: txn.discovery, TransactionID: txn.id, RequestDestination: toPlanEndpoint(txn.observer), Request: append([]byte(nil), request...),
	}
	if err := socket.SendProbe(ctx, txn.observer, request); err != nil {
		clear(request)
		return hardnatplan.RFC5780Exchange{}, errors.Join(ErrObservationFailed, err)
	}
	clear(request)
	replyCtx, cancel := context.WithTimeout(ctx, perReplyDeadline)
	defer cancel()
	buffer := make([]byte, maxResponseBytes)
	var attributes hardnatplan.BehaviorAttributes
	n, from, err := socket.ReceiveReply(replyCtx, buffer, func(packet []byte, source netip.AddrPort) error {
		parsed, parseErr := hardnatplan.ParseBehaviorBindingSuccess(packet, txn.id)
		if parseErr != nil {
			return parseErr
		}
		if !parsed.HasResponseOrigin || toPlanEndpoint(source) != parsed.ResponseOrigin {
			return hardnatplan.ErrInvalidEvidence
		}
		attributes = parsed
		return nil
	})
	result.ObservedAtMilli = stamp()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && !txn.replyNeeded {
			return result, nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return result, ErrRequiredReplyAbsent
		}
		return result, errors.Join(ErrObservationFailed, err)
	}
	if n == 0 || !attributes.HasMapped {
		return result, errors.Join(ErrObservationFailed, hardnatplan.ErrInvalidEvidence)
	}
	result.Received = true
	result.ResponseSource = toPlanEndpoint(from)
	result.Response = append([]byte(nil), buffer[:n]...)
	return result, nil
}

func allocationTarget(endpoints [4]netip.AddrPort, slot int) netip.AddrPort {
	return endpoints[slot%len(endpoints)]
}

func validTrust(trust TrustAnchors) bool {
	return trust.Generation > 0 && !allZero(trust.AttemptDigest[:]) && !allZero(trust.MachineScopeDigest[:]) &&
		!allZero(trust.PeerDigest[:]) && !allZero(trust.ObservationSetDigest[:]) && !allZero(trust.SocketOwnerDigest[:])
}

func validEndpoint(endpoint netip.AddrPort) bool {
	return endpoint.IsValid() && endpoint.Port() != 0 && !endpoint.Addr().IsUnspecified() &&
		!endpoint.Addr().IsMulticast() && !endpoint.Addr().Is4In6()
}

func canonical(endpoint netip.AddrPort) netip.AddrPort {
	if !endpoint.IsValid() {
		return endpoint
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}

func toPlanEndpoint(endpoint netip.AddrPort) hardnatplan.AddressPort {
	return hardnatplan.AddressPort{Address: toPlanAddress(endpoint.Addr()), Port: endpoint.Port()}
}

func toPlanAddress(address netip.Addr) hardnatplan.Address {
	address = address.Unmap()
	if address.Is4() {
		return hardnatplan.Address4(address.As4())
	}
	return hardnatplan.Address6(address.As16())
}

type logicalClock struct {
	now  func() time.Time
	last int64
}

func (clock *logicalClock) stamp() int64 {
	value := positiveMilli(clock.now())
	if value <= clock.last {
		value = clock.last + 1
	}
	clock.last = value
	return value
}

func positiveMilli(value time.Time) int64 {
	millis := value.UTC().UnixMilli()
	if millis <= 0 {
		return 1
	}
	return millis
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
