package stunobserve

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
)

func TestClassifyMappingSameAddressEvidenceMatrix(t *testing.T) {
	targetA := netip.MustParseAddrPort("192.0.2.10:3478")
	targetB := netip.MustParseAddrPort("192.0.2.10:3479")
	targetOtherAddress := netip.MustParseAddrPort("198.51.100.20:3478")
	mappedA := netip.MustParseAddrPort("198.51.100.40:41000")
	mappedB := netip.MustParseAddrPort("198.51.100.40:41001")

	tests := []struct {
		name             string
		endpoints        []MappingEndpoint
		wantBehavior     MappingBehavior
		wantSuccesses    int
		wantAddressLimit bool
	}{
		{
			name: "same server address and stable mapping",
			endpoints: []MappingEndpoint{
				{Target: targetA, Mapped: mappedA},
				{Target: targetB, Mapped: mappedA},
			},
			wantBehavior:     MappingBehaviorConsistentSameAddress,
			wantSuccesses:    2,
			wantAddressLimit: true,
		},
		{
			name: "same server address and changed mapping",
			endpoints: []MappingEndpoint{
				{Target: targetA, Mapped: mappedA},
				{Target: targetB, Mapped: mappedB},
			},
			wantBehavior:     MappingBehaviorPortDependent,
			wantSuccesses:    2,
			wantAddressLimit: true,
		},
		{
			name: "one success and one timeout",
			endpoints: []MappingEndpoint{
				{Target: targetA, Mapped: mappedA},
				{Target: targetB},
			},
			wantBehavior:     MappingBehaviorInconclusive,
			wantSuccesses:    1,
			wantAddressLimit: true,
		},
		{
			name: "all targets timeout",
			endpoints: []MappingEndpoint{
				{Target: targetA},
				{Target: targetB},
			},
			wantBehavior:     MappingBehaviorInconclusive,
			wantAddressLimit: true,
		},
		{
			name:             "single target cannot classify",
			endpoints:        []MappingEndpoint{{Target: targetA, Mapped: mappedA}},
			wantBehavior:     MappingBehaviorInconclusive,
			wantSuccesses:    1,
			wantAddressLimit: true,
		},
		{
			name: "different server addresses are not port evidence",
			endpoints: []MappingEndpoint{
				{Target: targetA, Mapped: mappedA},
				{Target: targetOtherAddress, Mapped: mappedB},
			},
			wantBehavior:  MappingBehaviorInconclusive,
			wantSuccesses: 2,
		},
		{
			name: "same-address pair remains decisive with another address",
			endpoints: []MappingEndpoint{
				{Target: targetA, Mapped: mappedA},
				{Target: targetB, Mapped: mappedB},
				{Target: targetOtherAddress, Mapped: mappedB},
			},
			wantBehavior:  MappingBehaviorPortDependent,
			wantSuccesses: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ClassifyMapping(test.endpoints)
			if got.Behavior != test.wantBehavior || got.EvidenceScope != MappingEvidenceSameAddressMultiplePorts {
				t.Fatalf("classification = %+v, want behavior=%q scope=%q", got, test.wantBehavior, MappingEvidenceSameAddressMultiplePorts)
			}
			if got.SuccessfulTargets != test.wantSuccesses || got.TotalTargets != len(test.endpoints) {
				t.Fatalf("counts = %d/%d, want %d/%d", got.SuccessfulTargets, got.TotalTargets, test.wantSuccesses, len(test.endpoints))
			}
			if hasMappingLimitation(got.Limitations, MappingLimitationAddressComparisonUnavailable) != test.wantAddressLimit {
				t.Fatalf("limitations = %v, want address limit=%t", got.Limitations, test.wantAddressLimit)
			}
		})
	}
}

func TestMappingWorstCaseCostIsAggregateAndFrozen(t *testing.T) {
	tests := []struct {
		targets int
		want    governor.AttemptCost
	}{
		{
			targets: 2,
			want: governor.AttemptCost{
				Resources: governor.Resources{Sockets: 1, Targets: 2, PacketsPerSecond: 3, Packets: 6, FiveTuples: 2},
				Duration:  8 * time.Second,
			},
		},
		{
			targets: 3,
			want: governor.AttemptCost{
				Resources: governor.Resources{Sockets: 1, Targets: 3, PacketsPerSecond: 4, Packets: 9, FiveTuples: 3},
				Duration:  12 * time.Second,
			},
		},
	}
	for _, test := range tests {
		got, err := MappingWorstCaseCost(test.targets)
		if err != nil || got != test.want {
			t.Errorf("MappingWorstCaseCost(%d) = %+v, %v; want %+v", test.targets, got, err, test.want)
		}
	}
	for _, count := range []int{0, 1, 4} {
		if _, err := MappingWorstCaseCost(count); !errors.Is(err, ErrInvalidMappingTargetCount) {
			t.Errorf("MappingWorstCaseCost(%d) error = %v", count, err)
		}
	}
}

func TestMappingClientUsesOneSocketAndRetainsPartialResult(t *testing.T) {
	successTarget, successPackets := startLoopbackResponder(t, responderSuccess)
	silentTarget, silentPackets := startLoopbackResponder(t, responderSilent)
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	counted := &countingFactory{inner: factory}
	cost, err := MappingWorstCaseCost(2)
	if err != nil {
		t.Fatalf("mapping cost: %v", err)
	}
	// The accelerated test schedule can place every transmission inside one
	// second; this raises only the test reservation, never the production cap.
	cost.Resources.PacketsPerSecond = cost.Resources.Packets
	client, err := newMappingClient(Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            counted,
		BuildVersion:       "stunobserve-mapping-test",
	}, 2, deterministicMappingRandom(2), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new mapping client: %v", err)
	}

	result, err := client.Observe(context.Background(), []netip.AddrPort{successTarget, silentTarget})
	if err != nil {
		t.Fatalf("observe mapping: %v", err)
	}
	if counted.opens.Load() != 1 || counted.writes.Load() != 1+MaxTransmissions {
		t.Fatalf("actual resources: opens=%d writes=%d", counted.opens.Load(), counted.writes.Load())
	}
	if successPackets.Load() != 1 || silentPackets.Load() != MaxTransmissions {
		t.Fatalf("server packets: success=%d silent=%d", successPackets.Load(), silentPackets.Load())
	}
	if len(result.Results) != 2 || result.Results[0].Err != nil || !errors.Is(result.Results[1].Err, ErrTimeout) {
		t.Fatalf("per-target results = %+v", result.Results)
	}
	if result.Results[0].Observation.LocalAddr == "" || result.Results[0].Observation.LocalAddr != result.Results[1].Observation.LocalAddr {
		t.Fatalf("local endpoints = %q / %q", result.Results[0].Observation.LocalAddr, result.Results[1].Observation.LocalAddr)
	}
	if result.Classification.Behavior != MappingBehaviorInconclusive || result.Classification.SuccessfulTargets != 1 {
		t.Fatalf("classification = %+v", result.Classification)
	}
}

func TestMappingClientContinuesSeriallyAfterTargetFailure(t *testing.T) {
	failingTarget, failingPackets := startLoopbackResponder(t, responderWrongCookie)
	successTarget, successPackets := startLoopbackResponder(t, responderSuccess)
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	counted := &countingFactory{inner: factory}
	cost, err := MappingWorstCaseCost(2)
	if err != nil {
		t.Fatalf("mapping cost: %v", err)
	}
	client, err := newMappingClient(Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            counted,
		BuildVersion:       "stunobserve-mapping-test",
	}, 2, deterministicMappingRandom(2), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new mapping client: %v", err)
	}

	result, err := client.Observe(context.Background(), []netip.AddrPort{failingTarget, successTarget})
	if err != nil {
		t.Fatalf("observe mapping: %v", err)
	}
	if len(result.Results) != 2 || !errors.Is(result.Results[0].Err, ErrMagicCookieMismatch) || result.Results[1].Err != nil {
		t.Fatalf("per-target results = %+v", result.Results)
	}
	if failingPackets.Load() != 1 || successPackets.Load() != 1 || counted.opens.Load() != 1 || counted.writes.Load() != 2 {
		t.Fatalf("actual activity: failing=%d success=%d opens=%d writes=%d", failingPackets.Load(), successPackets.Load(), counted.opens.Load(), counted.writes.Load())
	}
	if result.Results[0].Observation.LocalAddr != result.Results[1].Observation.LocalAddr {
		t.Fatalf("local endpoints = %q / %q", result.Results[0].Observation.LocalAddr, result.Results[1].Observation.LocalAddr)
	}
	if result.Classification.Behavior != MappingBehaviorInconclusive || result.Classification.SuccessfulTargets != 1 {
		t.Fatalf("classification = %+v", result.Classification)
	}
}

func TestMappingClientRejectsInvalidTargetsAndBudgetBeforeOpeningSocket(t *testing.T) {
	factory := &countingFactory{inner: mustLoopbackFactory(t)}
	cost, err := MappingWorstCaseCost(2)
	if err != nil {
		t.Fatalf("mapping cost: %v", err)
	}
	insufficient := cost
	insufficient.Resources.Targets--
	if _, err := NewMapping(Config{
		Lease:              newTestLease(insufficient),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "stunobserve-mapping-test",
	}, 2); !errors.Is(err, ErrInsufficientBudget) {
		t.Fatalf("insufficient budget error = %v", err)
	}
	if factory.opens.Load() != 0 {
		t.Fatalf("factory opens after budget rejection = %d", factory.opens.Load())
	}

	client, err := newMappingClient(Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "stunobserve-mapping-test",
	}, 2, deterministicMappingRandom(2), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new mapping client: %v", err)
	}
	_, err = client.Observe(context.Background(), []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:3478"),
		netip.MustParseAddrPort("127.0.0.1:3478"),
	})
	if !errors.Is(err, ErrDuplicateMappingTarget) {
		t.Fatalf("duplicate target error = %v", err)
	}
	if factory.opens.Load() != 0 {
		t.Fatalf("factory opens after target rejection = %d", factory.opens.Load())
	}
}

func hasMappingLimitation(values []MappingLimitation, want MappingLimitation) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func deterministicMappingRandom(targets int) *bytes.Reader {
	material := make([]byte, targets*len(transactionID{}))
	for index := range material {
		material[index] = byte(index)
	}
	return bytes.NewReader(material)
}
