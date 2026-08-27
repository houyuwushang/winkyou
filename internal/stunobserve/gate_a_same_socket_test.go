package stunobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
)

func TestGateAMappingReusesOneSocketForTwoSTUNTargetsAndPeer(t *testing.T) {
	firstTarget, firstPackets := startLoopbackResponder(t, responderSuccess)
	secondTarget, secondPackets := startLoopbackResponder(t, responderSuccess)
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopbackIPv4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	client, socket, controller, factory, generation := newGateASameSocketTestClient(t, 2)
	result, err := client.Observe(context.Background(), []netip.AddrPort{firstTarget, secondTarget})
	if err != nil {
		t.Fatalf("Observe = %v", err)
	}
	if result.Classification.Behavior != MappingBehaviorConsistentSameAddress ||
		result.Classification.SuccessfulTargets != 2 || result.Generation != 1 ||
		result.Transmissions != 2 || result.MappedEndpoint != result.LocalEndpoint {
		t.Fatalf("mapping result = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"generation":1,"transmissions":2}` {
		t.Fatalf("default JSON leaked endpoint evidence: %s", encoded)
	}
	peerTarget := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := client.RegisterPeerTarget(peerTarget, generation.CurrentGeneration()); err != nil {
		t.Fatalf("RegisterPeerTarget = %v", err)
	}
	if err := socket.SendProbe(context.Background(), peerTarget, []byte("direct")); err != nil {
		t.Fatalf("direct send = %v", err)
	}
	if factory.opens.Load() != 1 || factory.writes.Load() != 3 || firstPackets.Load() != 1 || secondPackets.Load() != 1 {
		t.Fatalf("OS witness opens=%d writes=%d STUN=%d/%d", factory.opens.Load(), factory.writes.Load(), firstPackets.Load(), secondPackets.Load())
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGateAMappingFailureIsTerminalAndBounded(t *testing.T) {
	firstTarget, firstPackets := startLoopbackResponder(t, responderSuccess)
	secondTarget, secondPackets := startLoopbackResponder(t, responderSilent)
	client, socket, controller, factory, _ := newGateASameSocketTestClient(t, 2)
	result, err := client.Observe(context.Background(), []netip.AddrPort{firstTarget, secondTarget})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Observe = %v, want timeout", err)
	}
	if result.Transmissions != 1+MaxTransmissions || firstPackets.Load() != 1 || secondPackets.Load() != MaxTransmissions || factory.opens.Load() != 1 {
		t.Fatalf("bounded witness = transmissions:%d server:%d/%d opens:%d", result.Transmissions, firstPackets.Load(), secondPackets.Load(), factory.opens.Load())
	}
	if _, err := socket.LocalAddr(); !errors.Is(err, probeio.ErrSocketClosed) {
		t.Fatalf("terminal socket = %v", err)
	}
	if err := client.RegisterPeerTarget(netip.MustParseAddrPort("127.0.0.1:65001"), 1); !errors.Is(err, ErrGateAMappingTerminal) {
		t.Fatalf("peer after failure = %v", err)
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGateAMappingRejectsTargetAndBudgetBeforeEmission(t *testing.T) {
	t.Run("duplicate target", func(t *testing.T) {
		client, socket, controller, factory, _ := newGateASameSocketTestClient(t, 1)
		target := netip.MustParseAddrPort("127.0.0.1:3478")
		if _, err := client.Observe(context.Background(), []netip.AddrPort{target, target}); !errors.Is(err, ErrDuplicateMappingTarget) {
			t.Fatalf("duplicate = %v", err)
		}
		if factory.writes.Load() != 0 {
			t.Fatalf("duplicate emitted %d packets", factory.writes.Load())
		}
		if _, err := socket.LocalAddr(); !errors.Is(err, probeio.ErrSocketClosed) {
			t.Fatalf("duplicate did not terminate socket: %v", err)
		}
		_ = controller.Close()
	})

	for _, mutate := range []func(*governor.AttemptCost){
		func(cost *governor.AttemptCost) { cost.Resources.Targets-- },
		func(cost *governor.AttemptCost) { cost.Resources.FiveTuples-- },
		func(cost *governor.AttemptCost) { cost.Resources.Packets-- },
		func(cost *governor.AttemptCost) { cost.Resources.PacketsPerSecond-- },
		func(cost *governor.AttemptCost) { cost.Duration-- },
		func(cost *governor.AttemptCost) { cost.Heavyweight = false },
	} {
		cost, err := GateASameSocketCost(2)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&cost)
		factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0)})
		if err != nil {
			t.Fatal(err)
		}
		counted := &countingFactory{inner: factory}
		lease := newTestLease(cost)
		lease.request.Operation = governor.OperationConnectTest
		generation := probeio.NewGeneration(1)
		controller, err := probeio.New(probeio.Config{Lease: lease, Generation: generation, ExpectedGeneration: 1, Factory: counted, BuildVersion: "gate-a-test"})
		if err != nil {
			t.Fatal(err)
		}
		socket, err := controller.OpenProbeSocket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newGateASameSocket(GateASameSocketConfig{
			Socket: socket, Generation: generation, ExpectedGeneration: 1, DirectOutbound: 2,
		}, gateARandom(), time.Now, testRTO); !errors.Is(err, ErrInsufficientBudget) {
			t.Fatalf("insufficient cost %+v = %v", cost, err)
		}
		if counted.writes.Load() != 0 {
			t.Fatalf("constructor emitted %d packets", counted.writes.Load())
		}
		_ = controller.Close()
	}
}

func TestGateASameSocketCostFrozen(t *testing.T) {
	for direct, packets := range map[int]int{1: 7, 2: 8} {
		got, err := GateASameSocketCost(direct)
		if err != nil {
			t.Fatal(err)
		}
		want := governor.AttemptCost{
			Resources: governor.Resources{Sockets: 1, Targets: 3, FiveTuples: 3, PacketsPerSecond: 5, Packets: packets},
			Duration:  15 * time.Second, Heavyweight: true,
		}
		if got != want {
			t.Fatalf("direct=%d cost=%+v want=%+v", direct, got, want)
		}
	}
	if _, err := GateASameSocketCost(3); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid direct budget = %v", err)
	}
}

func newGateASameSocketTestClient(t testing.TB, directOutbound int) (*GateASameSocketClient, *probeio.ProbeSocket, *probeio.Controller, *countingFactory, *probeio.Generation) {
	t.Helper()
	cost, err := GateASameSocketCost(directOutbound)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0)})
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingFactory{inner: factory}
	lease := newTestLease(cost)
	lease.request.Operation = governor.OperationConnectTest
	generation := probeio.NewGeneration(1)
	controller, err := probeio.New(probeio.Config{
		Lease: lease, Generation: generation, ExpectedGeneration: 1, Factory: counted, BuildVersion: "gate-a-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	socket, err := controller.OpenProbeSocket(context.Background())
	if err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	client, err := newGateASameSocket(GateASameSocketConfig{
		Socket: socket, Generation: generation, ExpectedGeneration: 1, DirectOutbound: directOutbound,
	}, gateARandom(), time.Now, testRTO)
	if err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	return client, socket, controller, counted, generation
}

func gateARandom() *bytes.Reader {
	return bytes.NewReader([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
	})
}
