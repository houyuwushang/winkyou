package hardnatobserve

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
)

func TestCollectBindsThirteenFreshTransactionsToElevenTuples(t *testing.T) {
	topology := Topology{
		Primary: netip.MustParseAddrPort("192.0.2.10:3478"),
		Other:   netip.MustParseAddrPort("192.0.2.11:3479"),
	}
	config, controller, factory := newCollectorFixture(t, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, topology)
	result, err := Collect(context.Background(), config)
	if err != nil {
		t.Fatalf("Collect = %v", err)
	}
	if result.PacketsSent != 13 || result.Targets != 4 || result.FiveTuples != 11 || factory.opens.Load() != 8 || factory.writes.Load() != 13 {
		t.Fatalf("resource witness = result=%+v opens=%d writes=%d", result, factory.opens.Load(), factory.writes.Load())
	}
	if len(result.Trusted.Issued) != 13 || len(result.Graph.RFC5780) != 1 || len(result.Graph.Allocation) != 8 {
		t.Fatalf("evidence shape = issued:%d rfc:%d allocation:%d", len(result.Trusted.Issued), len(result.Graph.RFC5780), len(result.Graph.Allocation))
	}
	if result.Model.Mapping != hardnatplan.MappingEIM || result.Model.Filtering != hardnatplan.FilteringEIF ||
		result.Model.Allocation != hardnatplan.AllocationSequentialUniform || result.Model.SuccessfulSamples != 8 ||
		result.Model.ObserverAddressCount != 2 || !result.Model.HasAlternatePort {
		t.Fatalf("model = %+v", result.Model)
	}
	wantPublic := hardnatplan.Address4([4]byte{198, 51, 100, 50})
	if result.PublicAddress != wantPublic || result.Model.ReusableEndpoint.Port != 50000 || result.Model.ReusableEndpointSlot != 0 {
		t.Fatalf("public/reusable = %+v %+v/%d", result.PublicAddress, result.Model.ReusableEndpoint, result.Model.ReusableEndpointSlot)
	}
	if result.Graph.FinishedAtMilli-result.Graph.StartedAtMilli > hardnatplan.MaxEvidenceWindowMillis {
		t.Fatalf("evidence window = %dms", result.Graph.FinishedAtMilli-result.Graph.StartedAtMilli)
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCollectRejectsEnvelopeMismatchBeforeEmission(t *testing.T) {
	topology := Topology{Primary: netip.MustParseAddrPort("192.0.2.20:4000"), Other: netip.MustParseAddrPort("192.0.2.21:4001")}
	config, controller, factory := newCollectorFixture(t, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, topology)
	config.Profile = hardnatplan.ProfileAsymmetricBirthday
	config.ResourceClass = hardnatplan.ResourceAsymmetric
	if _, err := Collect(context.Background(), config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Collect mismatch = %v", err)
	}
	if factory.writes.Load() != 0 {
		t.Fatalf("mismatch emitted %d packets", factory.writes.Load())
	}
	_ = controller.Close()
}

func TestTopologyRequiresTwoAddressesAndTwoPorts(t *testing.T) {
	for _, topology := range []Topology{
		{},
		{Primary: netip.MustParseAddrPort("192.0.2.1:3478"), Other: netip.MustParseAddrPort("192.0.2.1:3479")},
		{Primary: netip.MustParseAddrPort("192.0.2.1:3478"), Other: netip.MustParseAddrPort("192.0.2.2:3478")},
	} {
		if _, err := topology.Endpoints(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("topology %+v = %v", topology, err)
		}
	}
}

func newCollectorFixture(t testing.TB, profile hardnatplan.Profile, resource hardnatplan.ResourceClass, topology Topology) (Config, *probeio.Controller, *memoryFactory) {
	t.Helper()
	envelope, err := hardnatbudget.For(profile, resource)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := hardnatbudget.Operation(profile)
	if err != nil {
		t.Fatal(err)
	}
	lease := newObserveLease(governor.AttemptRequest{ID: "hardnat-observe-attempt", Operation: operation, Cost: envelope.Cost})
	endpoints, err := topology.Endpoints()
	if err != nil {
		t.Fatal(err)
	}
	factory := &memoryFactory{endpoints: endpoints}
	controller, err := probeio.New(probeio.Config{
		Lease: lease, Generation: probeio.NewGeneration(1), ExpectedGeneration: 1,
		Factory: factory, EnforcedCost: &envelope.Cost, BuildVersion: "hardnatobserve-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = controller.Close()
		_ = lease.Close()
	})
	sockets := make([]*probeio.ProbeSocket, ObservationSocketCount)
	for index := range sockets {
		sockets[index], err = controller.OpenProbeSocket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	random := make([]byte, ObservationPacketCount*12)
	for index := 0; index < ObservationPacketCount; index++ {
		random[index*12] = byte(index + 1)
		for offset := 1; offset < 12; offset++ {
			random[index*12+offset] = byte(0xa0 + offset)
		}
	}
	trust := TrustAnchors{Generation: 1}
	fill := func(target *[32]byte, value byte) {
		for index := range target {
			target[index] = value
		}
	}
	fill(&trust.AttemptDigest, 1)
	fill(&trust.MachineScopeDigest, 2)
	fill(&trust.PeerDigest, 3)
	fill(&trust.ObservationSetDigest, 4)
	fill(&trust.SocketOwnerDigest, 5)
	return Config{
		Profile: profile, ResourceClass: resource, Sockets: sockets, Topology: topology, Trust: trust,
		Random: bytes.NewReader(random), Now: func() time.Time { return time.Unix(2_000_000_000, 0).UTC() },
	}, controller, factory
}

type memoryFactory struct {
	endpoints [4]netip.AddrPort
	opens     atomic.Int32
	writes    atomic.Int32
}

func (factory *memoryFactory) Open(context.Context) (probeio.Datagram, error) {
	slot := int(factory.opens.Add(1) - 1)
	return &memoryDatagram{
		factory: factory, slot: slot, local: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.100"), uint16(30000+slot)),
		queue: make(chan memoryPacket, 2), closed: make(chan struct{}),
	}, nil
}

type memoryPacket struct {
	payload []byte
	from    netip.AddrPort
}

type memoryDatagram struct {
	factory *memoryFactory
	slot    int
	local   netip.AddrPort
	queue   chan memoryPacket
	closed  chan struct{}
	once    sync.Once
}

func (datagram *memoryDatagram) ReadFrom(ctx context.Context, target []byte) (int, netip.AddrPort, error) {
	select {
	case packet := <-datagram.queue:
		return copy(target, packet.payload), packet.from, nil
	case <-ctx.Done():
		return 0, netip.AddrPort{}, ctx.Err()
	case <-datagram.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (datagram *memoryDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	datagram.factory.writes.Add(1)
	transaction, change, err := hardnatplan.ParseBehaviorBindingRequest(packet)
	if err != nil {
		return 0, err
	}
	responseSource := target
	if change.ChangeIP && change.ChangePort {
		responseSource = datagram.factory.endpoints[3]
	} else if change.ChangePort {
		responseSource = datagram.factory.endpoints[1]
	}
	mapped := hardnatplan.AddressPort{Address: hardnatplan.Address4([4]byte{198, 51, 100, 50}), Port: uint16(50000 + datagram.slot)}
	response, err := hardnatplan.BuildBehaviorBindingSuccess(transaction, hardnatplan.BehaviorAttributes{
		Mapped: mapped, HasMapped: true, ResponseOrigin: toPlanEndpoint(responseSource), HasResponseOrigin: true,
		OtherAddress: toPlanEndpoint(datagram.factory.endpoints[3]), HasOtherAddress: true,
	})
	if err != nil {
		return 0, err
	}
	select {
	case datagram.queue <- memoryPacket{payload: response, from: responseSource}:
		return len(packet), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-datagram.closed:
		return 0, net.ErrClosed
	}
}

func (datagram *memoryDatagram) SetDeadline(time.Time) error { return nil }
func (datagram *memoryDatagram) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(datagram.local)
}
func (datagram *memoryDatagram) Close() error {
	datagram.once.Do(func() { close(datagram.closed) })
	return nil
}

type observeLease struct {
	request  governor.AttemptRequest
	stopping chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	drains   int
	stopped  bool
	closed   bool
}

func newObserveLease(request governor.AttemptRequest) *observeLease {
	return &observeLease{request: request, stopping: make(chan struct{}), done: make(chan struct{})}
}
func (lease *observeLease) Request() governor.AttemptRequest { return lease.request }
func (lease *observeLease) PeerID() string                   { return "hardnat-observe-peer" }
func (lease *observeLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *observeLease) Done() <-chan struct{}            { return lease.done }
func (lease *observeLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.stopped {
		return nil, governor.ErrLeaseClosed
	}
	lease.drains++
	return &observeDrain{lease: lease}, nil
}
func (lease *observeLease) Trip(event governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	lease.stop()
	return governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true,
		Record: governor.SafetyTripRecord{SchemaVersion: 1, State: governor.SafetyTripTripped, Reason: event.Reason}}, nil
}
func (lease *observeLease) Close() error {
	lease.stop()
	<-lease.done
	return nil
}
func (lease *observeLease) stop() {
	lease.mu.Lock()
	if !lease.stopped {
		lease.stopped = true
		close(lease.stopping)
	}
	if lease.drains == 0 && !lease.closed {
		lease.closed = true
		close(lease.done)
	}
	lease.mu.Unlock()
}

type observeDrain struct {
	lease *observeLease
	once  sync.Once
}

func (drain *observeDrain) Complete() error {
	drain.once.Do(func() {
		drain.lease.mu.Lock()
		if drain.lease.drains > 0 {
			drain.lease.drains--
		}
		if drain.lease.stopped && drain.lease.drains == 0 && !drain.lease.closed {
			drain.lease.closed = true
			close(drain.lease.done)
		}
		drain.lease.mu.Unlock()
	})
	return nil
}
