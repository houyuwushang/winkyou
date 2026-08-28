package probeio

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/governor"
)

func TestGateB2ExactFirstOveragesTripBeforeIO(t *testing.T) {
	asymmetric := governor.Resources{Sockets: 128, Targets: 516, FiveTuples: 523, Packets: 526, PacketsPerSecond: 64}

	t.Run("129th socket", func(t *testing.T) {
		harness := newHarness(t, asymmetric)
		for index := 0; index < asymmetric.Sockets; index++ {
			if _, err := harness.controller.OpenProbeSocket(context.Background()); err != nil {
				t.Fatalf("open %d: %v", index, err)
			}
		}
		if _, err := harness.controller.OpenProbeSocket(context.Background()); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("129th socket error=%v", err)
		}
		if harness.factory.count() != asymmetric.Sockets {
			t.Fatalf("factory opens=%d", harness.factory.count())
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("517th target", func(t *testing.T) {
		harness := newHarness(t, asymmetric)
		socket, _ := openSocket(t, harness)
		for index := 0; index < asymmetric.Targets; index++ {
			if err := socket.RegisterTarget(gateB2LimitTarget(index)); err != nil {
				t.Fatalf("target %d: %v", index, err)
			}
		}
		if err := socket.RegisterTarget(gateB2LimitTarget(asymmetric.Targets)); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("517th target error=%v", err)
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("524th five tuple", func(t *testing.T) {
		harness := newHarness(t, asymmetric)
		first, _ := openSocket(t, harness)
		second, _ := openSocket(t, harness)
		for index := 0; index < asymmetric.Targets; index++ {
			if err := first.RegisterTarget(gateB2LimitTarget(index)); err != nil {
				t.Fatalf("first tuple %d: %v", index, err)
			}
		}
		for index := 0; index < asymmetric.FiveTuples-asymmetric.Targets; index++ {
			if err := second.RegisterTarget(gateB2LimitTarget(index)); err != nil {
				t.Fatalf("extra tuple %d: %v", index, err)
			}
		}
		if err := second.RegisterTarget(gateB2LimitTarget(asymmetric.FiveTuples - asymmetric.Targets)); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("524th tuple error=%v", err)
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("527th packet", func(t *testing.T) {
		harness := newHarness(t, asymmetric)
		socket, datagram := openSocket(t, harness)
		target := gateB2LimitTarget(0)
		if err := socket.RegisterTarget(target); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < asymmetric.Packets; index++ {
			if index > 0 && index%asymmetric.PacketsPerSecond == 0 {
				harness.clock.Advance(time.Second + time.Millisecond)
			}
			if err := socket.SendProbe(context.Background(), target, []byte("bounded")); err != nil {
				t.Fatalf("packet %d: %v", index, err)
			}
		}
		if err := socket.SendProbe(context.Background(), target, []byte("blocked")); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("527th packet error=%v", err)
		}
		if datagram.writeCount() != asymmetric.Packets {
			t.Fatalf("OS writes=%d", datagram.writeCount())
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("predictive 65th packet", func(t *testing.T) {
		predictive := governor.Resources{Sockets: 8, Targets: 64, FiveTuples: 64, Packets: 64, PacketsPerSecond: 32}
		harness := newHarness(t, predictive)
		socket, datagram := openSocket(t, harness)
		target := gateB2LimitTarget(0)
		if err := socket.RegisterTarget(target); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < predictive.Packets; index++ {
			if index > 0 && index%predictive.PacketsPerSecond == 0 {
				harness.clock.Advance(time.Second + time.Millisecond)
			}
			if err := socket.SendProbe(context.Background(), target, []byte("bounded")); err != nil {
				t.Fatalf("packet %d: %v", index, err)
			}
		}
		if err := socket.SendProbe(context.Background(), target, []byte("blocked")); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("65th packet error=%v", err)
		}
		if datagram.writeCount() != predictive.Packets {
			t.Fatalf("OS writes=%d", datagram.writeCount())
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})
}

func gateB2LimitTarget(index int) netip.AddrPort {
	third := byte((index / 250) + 1)
	fourth := byte((index % 250) + 1)
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 1, third, fourth}), uint16(20000+index))
}

func TestGateB2LimitTargetsAreUniqueAndLoopback(t *testing.T) {
	seen := make(map[netip.AddrPort]struct{}, 517)
	for index := 0; index < 517; index++ {
		target := gateB2LimitTarget(index)
		if !target.Addr().IsLoopback() || target.Port() == 0 {
			t.Fatalf("target %d=%s", index, target)
		}
		if _, duplicate := seen[target]; duplicate {
			t.Fatal(fmt.Sprintf("duplicate target %d", index))
		}
		seen[target] = struct{}{}
	}
}
