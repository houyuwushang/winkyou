package stunobserve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
)

func TestClassifyAllocationMatrix(t *testing.T) {
	sample := func(ports ...uint16) []AllocationSample {
		result := make([]AllocationSample, 0, len(ports))
		for index, port := range ports {
			result = append(result, AllocationSample{
				Local:  netip.AddrPortFrom(loopbackIPv4, uint16(30000+index)),
				Mapped: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port),
			})
		}
		return result
	}
	tests := []struct {
		name      string
		samples   []AllocationSample
		behavior  AllocationBehavior
		deltas    []int
		successes int
	}{
		{name: "uniform", samples: sample(40000, 40010, 40020, 40030), behavior: AllocationBehaviorSequentialUniform, deltas: []int{10, 10, 10}, successes: 4},
		{name: "uniform wrap", samples: sample(65530, 5, 15), behavior: AllocationBehaviorSequentialUniform, deltas: []int{-65525, 10}, successes: 3},
		{name: "monotonic nonuniform", samples: sample(40000, 40002, 40005, 40009), behavior: AllocationBehaviorMonotonicNonuniform, deltas: []int{2, 3, 4}, successes: 4},
		{name: "nonmonotonic", samples: sample(40000, 40100, 40050, 40200), behavior: AllocationBehaviorApparentlyRandom, deltas: []int{100, -50, 150}, successes: 4},
		{name: "large variance", samples: sample(40000, 40001, 41001), behavior: AllocationBehaviorApparentlyRandom, deltas: []int{1, 1000}, successes: 3},
		{name: "repeated port", samples: sample(40000, 40000, 40001), behavior: AllocationBehaviorApparentlyRandom, deltas: []int{0}, successes: 3},
		{name: "insufficient", samples: sample(40000, 40001), behavior: AllocationBehaviorInsufficientData, successes: 2},
		{
			name: "failed sample is retained in total but omitted from sequence",
			samples: []AllocationSample{
				{Local: netip.MustParseAddrPort("127.0.0.1:30000"), Mapped: netip.MustParseAddrPort("192.0.2.10:40000")},
				{Local: netip.MustParseAddrPort("127.0.0.1:30001")},
				{Local: netip.MustParseAddrPort("127.0.0.1:30002"), Mapped: netip.MustParseAddrPort("192.0.2.10:40010")},
			},
			behavior: AllocationBehaviorInsufficientData, successes: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ClassifyAllocation(test.samples)
			if got.Behavior != test.behavior || got.EvidenceScope != AllocationEvidenceSingleTargetMultipleSockets {
				t.Fatalf("classification = %+v, want behavior=%q", got, test.behavior)
			}
			if got.SuccessfulSockets != test.successes || got.TotalSockets != len(test.samples) {
				t.Fatalf("counts = %d/%d, want %d/%d", got.SuccessfulSockets, got.TotalSockets, test.successes, len(test.samples))
			}
			if !slices.Equal(got.Deltas, test.deltas) {
				t.Fatalf("deltas = %v, want %v", got.Deltas, test.deltas)
			}
			wantLimitations := []AllocationLimitation{
				AllocationLimitationSingleTimeWindow,
				AllocationLimitationSingleTarget,
				AllocationLimitationSmallSample,
			}
			if !slices.Equal(got.Limitations, wantLimitations) {
				t.Fatalf("limitations = %v, want %v", got.Limitations, wantLimitations)
			}
		})
	}
}

func TestAllocationWorstCaseCostIsAggregateAndFrozen(t *testing.T) {
	for _, sockets := range []int{MinAllocationSockets, DefaultAllocationSockets, MaxAllocationSockets} {
		got, err := AllocationWorstCaseCost(sockets)
		want := governor.AttemptCost{
			Resources: governor.Resources{
				Sockets:          sockets,
				Targets:          1,
				PacketsPerSecond: sockets + 1,
				Packets:          sockets * MaxTransmissions,
				FiveTuples:       sockets,
			},
			Duration: time.Duration(sockets) * MaxObservationDuration,
		}
		if err != nil || got != want {
			t.Errorf("AllocationWorstCaseCost(%d) = %+v, %v; want %+v", sockets, got, err, want)
		}
	}
	for _, sockets := range []int{0, 2, 9} {
		if _, err := AllocationWorstCaseCost(sockets); !errors.Is(err, ErrInvalidAllocationSocketCount) {
			t.Errorf("AllocationWorstCaseCost(%d) error = %v", sockets, err)
		}
	}
}

func TestAllocationClientKeepsEverySocketOpenAndUsesDistinctEndpoints(t *testing.T) {
	target, packets := startAllocationResponder(t, false)
	cost, err := AllocationWorstCaseCost(DefaultAllocationSockets)
	if err != nil {
		t.Fatalf("allocation cost: %v", err)
	}
	// The accelerated test schedule may put all writes inside one second.
	cost.Resources.PacketsPerSecond = cost.Resources.Packets
	tracked := &allocationTrackingFactory{inner: mustLoopbackFactory(t), expectedOpenAtWrite: DefaultAllocationSockets}
	client, err := newAllocationClient(Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            tracked,
		BuildVersion:       "stunobserve-allocation-test",
	}, DefaultAllocationSockets, deterministicAllocationRandom(DefaultAllocationSockets), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new allocation client: %v", err)
	}

	result, err := client.Observe(context.Background(), target)
	if err != nil {
		t.Fatalf("observe allocation: %v", err)
	}
	if tracked.opens.Load() != DefaultAllocationSockets || tracked.active.Load() != 0 || tracked.prematureClose.Load() {
		t.Fatalf("socket lifecycle: opens=%d active=%d premature_close=%t", tracked.opens.Load(), tracked.active.Load(), tracked.prematureClose.Load())
	}
	if tracked.writes.Load() != DefaultAllocationSockets || packets.Load() != int32(DefaultAllocationSockets) {
		t.Fatalf("packet counts: client=%d server=%d", tracked.writes.Load(), packets.Load())
	}
	if len(result.Results) != DefaultAllocationSockets || result.Classification.SuccessfulSockets != DefaultAllocationSockets {
		t.Fatalf("allocation result = %+v", result)
	}
	seen := make(map[netip.AddrPort]struct{}, DefaultAllocationSockets)
	for _, socketResult := range result.Results {
		if socketResult.Err != nil {
			t.Fatalf("socket result error = %v", socketResult.Err)
		}
		if _, exists := seen[socketResult.Local]; exists {
			t.Fatalf("local endpoint reused: %v", socketResult.Local)
		}
		seen[socketResult.Local] = struct{}{}
		mapped, parseErr := netip.ParseAddrPort(socketResult.Observation.Details["mapped_address"])
		if parseErr != nil || mapped != socketResult.Local {
			t.Fatalf("mapped endpoint = %q local=%v err=%v", socketResult.Observation.Details["mapped_address"], socketResult.Local, parseErr)
		}
	}
}

func TestAllocationClientContinuesAfterOneExchangeFailure(t *testing.T) {
	target, packets := startAllocationResponder(t, true)
	cost, err := AllocationWorstCaseCost(MinAllocationSockets)
	if err != nil {
		t.Fatalf("allocation cost: %v", err)
	}
	client, err := newAllocationClient(Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            mustLoopbackFactory(t),
		BuildVersion:       "stunobserve-allocation-test",
	}, MinAllocationSockets, deterministicAllocationRandom(MinAllocationSockets), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new allocation client: %v", err)
	}
	result, err := client.Observe(context.Background(), target)
	if err != nil {
		t.Fatalf("observe allocation: %v", err)
	}
	if len(result.Results) != MinAllocationSockets || !errors.Is(result.Results[0].Err, ErrMagicCookieMismatch) || result.Results[1].Err != nil || result.Results[2].Err != nil {
		t.Fatalf("per-socket results = %+v", result.Results)
	}
	if packets.Load() != int32(MinAllocationSockets) || result.Classification.Behavior != AllocationBehaviorInsufficientData || result.Classification.SuccessfulSockets != 2 {
		t.Fatalf("continued result = %+v packets=%d", result.Classification, packets.Load())
	}
}

func TestAllocationClientRejectsBudgetAndTargetBeforeOpening(t *testing.T) {
	cost, err := AllocationWorstCaseCost(MinAllocationSockets)
	if err != nil {
		t.Fatalf("allocation cost: %v", err)
	}
	tracked := &allocationTrackingFactory{inner: mustLoopbackFactory(t), expectedOpenAtWrite: MinAllocationSockets}
	insufficient := cost
	insufficient.Resources.Sockets--
	if _, err := NewAllocation(Config{
		Lease:              newTestLease(insufficient),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            tracked,
		BuildVersion:       "stunobserve-allocation-test",
	}, MinAllocationSockets); !errors.Is(err, ErrInsufficientBudget) {
		t.Fatalf("insufficient budget error = %v", err)
	}
	if tracked.opens.Load() != 0 {
		t.Fatalf("opens after budget rejection = %d", tracked.opens.Load())
	}

	client, err := newAllocationClient(Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            tracked,
		BuildVersion:       "stunobserve-allocation-test",
	}, MinAllocationSockets, deterministicAllocationRandom(MinAllocationSockets), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new allocation client: %v", err)
	}
	if _, err := client.Observe(context.Background(), netip.MustParseAddrPort("192.0.2.10:3478")); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("non-loopback error = %v", err)
	}
	if tracked.opens.Load() != 0 {
		t.Fatalf("opens after target rejection = %d", tracked.opens.Load())
	}
}

func deterministicAllocationRandom(sockets int) *bytes.Reader {
	material := make([]byte, sockets*len(transactionID{}))
	for index := range material {
		material[index] = byte(index)
	}
	return bytes.NewReader(material)
}

func startAllocationResponder(t *testing.T, corruptFirst bool) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopbackIPv4, 0)))
	if err != nil {
		t.Fatalf("listen allocation responder: %v", err)
	}
	packets := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxSTUNMessageBytes+1)
		for {
			n, from, readErr := connection.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				return
			}
			sequence := packets.Add(1)
			if n < stunHeaderBytes {
				continue
			}
			var transaction transactionID
			copy(transaction[:], buffer[8:20])
			mapped := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			response := bindingSuccess(transaction, stunAttribute(attributeXORMappedAddress, mappedAddressValue(mapped, transaction, true), nil))
			if corruptFirst && sequence == 1 {
				binary.BigEndian.PutUint32(response[4:8], 0)
			}
			_, _ = connection.WriteToUDPAddrPort(response, from)
		}
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("allocation responder did not exit")
		}
	})
	return connection.LocalAddr().(*net.UDPAddr).AddrPort(), packets
}

type allocationTrackingFactory struct {
	inner               probeio.Factory
	expectedOpenAtWrite int
	opens               atomic.Int32
	active              atomic.Int32
	writes              atomic.Int32
	prematureClose      atomic.Bool
}

func (factory *allocationTrackingFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	datagram, err := factory.inner.Open(ctx)
	if err != nil {
		return nil, err
	}
	factory.opens.Add(1)
	factory.active.Add(1)
	return &allocationTrackingDatagram{Datagram: datagram, factory: factory}, nil
}

type allocationTrackingDatagram struct {
	probeio.Datagram
	factory *allocationTrackingFactory
	once    sync.Once
}

func (datagram *allocationTrackingDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if datagram.factory.active.Load() != int32(datagram.factory.expectedOpenAtWrite) {
		datagram.factory.prematureClose.Store(true)
	}
	datagram.factory.writes.Add(1)
	return datagram.Datagram.WriteTo(ctx, packet, target)
}

func (datagram *allocationTrackingDatagram) Close() error {
	var err error
	datagram.once.Do(func() {
		err = datagram.Datagram.Close()
		datagram.factory.active.Add(-1)
	})
	return err
}
