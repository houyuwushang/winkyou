package stunobserve

import (
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

func TestSameSocketSTUNThenPeerPunchUsesExactlyOneOSSocket(t *testing.T) {
	stunTarget, stunPackets := startLoopbackResponder(t, responderSuccess)
	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopbackIPv4, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	peerTarget := peer.LocalAddr().(*net.UDPAddr).AddrPort()

	client, socket, controller, factory, generation := newSameSocketTestClient(t, N2SameSocketCost())
	result, err := client.Observe(context.Background(), stunTarget)
	if err != nil {
		t.Fatalf("same-socket observe: %v", err)
	}
	if result.Generation != 1 || result.Transmissions != 1 || result.Observation.Details["generation"] != "1" ||
		result.LocalEndpoint != result.MappedEndpoint {
		t.Fatalf("same-socket result = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"generation":1,"transmissions":1}` {
		t.Fatalf("default JSON leaked endpoint-bearing evidence: %s", encoded)
	}
	if err := client.RegisterPeerTarget(peerTarget, generation.CurrentGeneration()); err != nil {
		t.Fatalf("register authenticated peer: %v", err)
	}
	if err := socket.SendProbe(context.Background(), peerTarget, []byte("synthetic-punch")); err != nil {
		t.Fatalf("send peer punch: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	n, from, err := peer.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "synthetic-punch" || from.Port() != result.LocalEndpoint.Port() {
		t.Fatalf("peer packet bytes/source = %q/%v, want source port %d", buffer[:n], from, result.LocalEndpoint.Port())
	}
	if factory.opens.Load() != 1 || factory.writes.Load() != 2 || stunPackets.Load() != 1 {
		t.Fatalf("OS witness opens=%d writes=%d STUN=%d", factory.opens.Load(), factory.writes.Load(), stunPackets.Load())
	}
	third := netip.MustParseAddrPort("127.0.0.1:65001")
	if err := socket.RegisterTarget(third); !errors.Is(err, probeio.ErrHardLimit) {
		t.Fatalf("third target error = %v", err)
	}
	if err := controller.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSameSocketOrderingGenerationAndFailureAreTerminal(t *testing.T) {
	t.Run("duplicate peer registration", func(t *testing.T) {
		stunTarget, _ := startLoopbackResponder(t, responderSuccess)
		client, socket, controller, _, generation := newSameSocketTestClient(t, N2SameSocketCost())
		if _, err := client.Observe(context.Background(), stunTarget); err != nil {
			t.Fatal(err)
		}
		if err := client.RegisterPeerTarget(netip.MustParseAddrPort("127.0.0.1:65000"), generation.CurrentGeneration()); err != nil {
			t.Fatal(err)
		}
		if err := client.RegisterPeerTarget(netip.MustParseAddrPort("127.0.0.1:65001"), generation.CurrentGeneration()); !errors.Is(err, ErrPeerAlreadyRegistered) {
			t.Fatalf("duplicate peer target error = %v", err)
		}
		if _, err := socket.LocalAddr(); !errors.Is(err, probeio.ErrSocketClosed) {
			t.Fatalf("duplicate peer target did not terminate socket: %v", err)
		}
		_ = controller.Close()
	})

	t.Run("peer before observation", func(t *testing.T) {
		client, socket, controller, _, _ := newSameSocketTestClient(t, N2SameSocketCost())
		if err := client.RegisterPeerTarget(netip.MustParseAddrPort("127.0.0.1:65002"), 1); !errors.Is(err, ErrPeerBeforeObservation) {
			t.Fatalf("ordering error = %v", err)
		}
		if _, err := socket.LocalAddr(); !errors.Is(err, probeio.ErrSocketClosed) {
			t.Fatalf("terminal socket error = %v", err)
		}
		_ = controller.Close()
	})

	t.Run("stale after observation", func(t *testing.T) {
		stunTarget, _ := startLoopbackResponder(t, responderSuccess)
		client, socket, controller, _, generation := newSameSocketTestClient(t, N2SameSocketCost())
		if _, err := client.Observe(context.Background(), stunTarget); err != nil {
			t.Fatal(err)
		}
		if err := generation.Advance(2); err != nil {
			t.Fatal(err)
		}
		if err := client.RegisterPeerTarget(netip.MustParseAddrPort("127.0.0.1:65003"), 1); !errors.Is(err, ErrPeerBeforeObservation) {
			t.Fatalf("stale peer error = %v", err)
		}
		client.mu.Lock()
		terminal := client.terminal
		client.mu.Unlock()
		if _, err := socket.LocalAddr(); !errors.Is(err, probeio.ErrStaleGeneration) || !terminal {
			t.Fatalf("stale terminal witness terminal=%t socket=%v", terminal, err)
		}
		_ = controller.Close()
	})

	t.Run("silent STUN", func(t *testing.T) {
		stunTarget, stunPackets := startLoopbackResponder(t, responderSilent)
		client, socket, controller, factory, _ := newSameSocketTestClient(t, N2SameSocketCost())
		if _, err := client.Observe(context.Background(), stunTarget); !errors.Is(err, ErrTimeout) {
			t.Fatalf("silent error = %v", err)
		}
		if stunPackets.Load() != MaxTransmissions || factory.writes.Load() != MaxTransmissions {
			t.Fatalf("bounded transmissions server=%d adapter=%d", stunPackets.Load(), factory.writes.Load())
		}
		if _, err := socket.LocalAddr(); !errors.Is(err, probeio.ErrSocketClosed) {
			t.Fatalf("silent terminal socket error = %v", err)
		}
		_ = controller.Close()
	})

	for _, test := range []struct {
		name string
		mode responderMode
		want error
	}{
		{name: "source mismatch", mode: responderWrongSource, want: ErrSourceMismatch},
		{name: "protocol error", mode: responderWrongCookie, want: ErrMagicCookieMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			stunTarget, _ := startLoopbackResponder(t, test.mode)
			client, socket, controller, factory, _ := newSameSocketTestClient(t, N2SameSocketCost())
			if _, err := client.Observe(context.Background(), stunTarget); !errors.Is(err, test.want) {
				t.Fatalf("observe error = %v, want %v", err, test.want)
			}
			if factory.writes.Load() != 1 {
				t.Fatalf("terminal failure writes = %d, want 1", factory.writes.Load())
			}
			if _, err := socket.LocalAddr(); !errors.Is(err, probeio.ErrSocketClosed) {
				t.Fatalf("terminal socket error = %v", err)
			}
			_ = controller.Close()
		})
	}
}

func TestSameSocketRejectsInsufficientOrWrongReservationBeforeIO(t *testing.T) {
	for _, mutate := range []func(*governor.AttemptCost){
		func(cost *governor.AttemptCost) { cost.Resources.Targets-- },
		func(cost *governor.AttemptCost) { cost.Resources.FiveTuples-- },
		func(cost *governor.AttemptCost) { cost.Resources.Packets-- },
		func(cost *governor.AttemptCost) { cost.Resources.PacketsPerSecond-- },
		func(cost *governor.AttemptCost) { cost.Duration-- },
		func(cost *governor.AttemptCost) { cost.Heavyweight = false },
	} {
		cost := N2SameSocketCost()
		mutate(&cost)
		factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0)})
		if err != nil {
			t.Fatal(err)
		}
		counted := &countingFactory{inner: factory}
		lease := newTestLease(cost)
		lease.request.Operation = governor.OperationConnectTest
		generation := probeio.NewGeneration(1)
		controller, err := probeio.New(probeio.Config{Lease: lease, Generation: generation, ExpectedGeneration: 1, Factory: counted, BuildVersion: "n2c-test"})
		if err != nil {
			t.Fatal(err)
		}
		socket, err := controller.OpenProbeSocket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newSameSocket(SameSocketConfig{Socket: socket, Generation: generation, ExpectedGeneration: 1}, deterministicRandom(), time.Now, testRTO); !errors.Is(err, ErrInsufficientBudget) {
			t.Fatalf("insufficient reservation %+v error = %v", cost, err)
		}
		if counted.opens.Load() != 1 || counted.writes.Load() != 0 {
			t.Fatalf("constructor I/O opens=%d writes=%d", counted.opens.Load(), counted.writes.Load())
		}
		_ = controller.Close()
	}
}

func TestN2SameSocketCostIsFrozen(t *testing.T) {
	want := governor.AttemptCost{
		Resources: governor.Resources{Sockets: 1, Targets: 2, PacketsPerSecond: 5, Packets: 5, FiveTuples: 2},
		Duration:  15 * time.Second, Heavyweight: true,
	}
	if got := N2SameSocketCost(); got != want {
		t.Fatalf("same-socket cost = %+v, want %+v", got, want)
	}
}

func newSameSocketTestClient(t testing.TB, cost governor.AttemptCost) (*SameSocketClient, *probeio.ProbeSocket, *probeio.Controller, *countingFactory, *probeio.Generation) {
	t.Helper()
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0)})
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingFactory{inner: factory}
	lease := newTestLease(cost)
	lease.request.Operation = governor.OperationConnectTest
	generation := probeio.NewGeneration(1)
	controller, err := probeio.New(probeio.Config{Lease: lease, Generation: generation, ExpectedGeneration: 1, Factory: counted, BuildVersion: "n2c-test"})
	if err != nil {
		t.Fatal(err)
	}
	socket, err := controller.OpenProbeSocket(context.Background())
	if err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	client, err := newSameSocket(SameSocketConfig{Socket: socket, Generation: generation, ExpectedGeneration: 1}, deterministicRandom(), time.Now, testRTO)
	if err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	return client, socket, controller, counted, generation
}
