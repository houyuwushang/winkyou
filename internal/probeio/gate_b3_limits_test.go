package probeio

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/governor"
)

func TestGateB3ExactFirstOveragesTripBeforeFactoryIO(t *testing.T) {
	hard := governor.Resources{Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512}

	t.Run("17th socket", func(t *testing.T) {
		harness := newHarness(t, hard)
		for index := 0; index < hard.Sockets; index++ {
			if _, err := harness.controller.OpenProbeSocket(context.Background()); err != nil {
				t.Fatalf("open %d: %v", index, err)
			}
		}
		if _, err := harness.controller.OpenProbeSocket(context.Background()); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("17th socket = %v", err)
		}
		if harness.factory.count() != hard.Sockets {
			t.Fatalf("factory opens = %d", harness.factory.count())
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("16401st target", func(t *testing.T) {
		harness := newHarness(t, hard)
		socket, _ := openSocket(t, harness)
		for index := 0; index < hard.Targets; index++ {
			if err := socket.RegisterTarget(gateB3LimitTarget(index)); err != nil {
				t.Fatalf("target %d: %v", index, err)
			}
		}
		if err := socket.RegisterTarget(gateB3LimitTarget(hard.Targets)); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("16401st target = %v", err)
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("16401st five tuple", func(t *testing.T) {
		harness := newHarness(t, hard)
		first, _ := openSocket(t, harness)
		second, _ := openSocket(t, harness)
		for index := 0; index < hard.Targets; index++ {
			if err := first.RegisterTarget(gateB3LimitTarget(index)); err != nil {
				t.Fatalf("tuple %d: %v", index, err)
			}
		}
		if err := second.RegisterTarget(gateB3LimitTarget(0)); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("16401st five tuple = %v", err)
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("16433rd packet", func(t *testing.T) {
		harness := newHarness(t, hard)
		socket, datagram := openSocket(t, harness)
		target := gateB3LimitTarget(0)
		if err := socket.RegisterTarget(target); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < hard.Packets; index++ {
			if index > 0 && index%hard.PacketsPerSecond == 0 {
				harness.clock.Advance(time.Second + time.Millisecond)
			}
			if err := socket.SendProbe(context.Background(), target, []byte("bounded")); err != nil {
				t.Fatalf("packet %d: %v", index, err)
			}
		}
		if err := socket.SendProbe(context.Background(), target, []byte("blocked")); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("16433rd packet = %v", err)
		}
		if datagram.writeCount() != hard.Packets {
			t.Fatalf("factory writes = %d", datagram.writeCount())
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("513th packet in one second", func(t *testing.T) {
		harness := newHarness(t, hard)
		socket, datagram := openSocket(t, harness)
		target := gateB3LimitTarget(0)
		if err := socket.RegisterTarget(target); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < hard.PacketsPerSecond; index++ {
			if err := socket.SendProbe(context.Background(), target, []byte("bounded")); err != nil {
				t.Fatalf("PPS packet %d: %v", index, err)
			}
		}
		if err := socket.SendProbe(context.Background(), target, []byte("blocked")); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("513th PPS packet = %v", err)
		}
		if datagram.writeCount() != hard.PacketsPerSecond {
			t.Fatalf("PPS factory writes = %d", datagram.writeCount())
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})
}

func gateB3LimitTarget(index int) netip.AddrPort {
	third := byte(index/250 + 1)
	fourth := byte(index%250 + 1)
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 2, third, fourth}), uint16(40_000+index))
}
