package governor_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/natsim"
)

func TestGateB2ManualClockWaitObservesDrainWithoutChangingVirtualInterval(t *testing.T) {
	now := time.Unix(0, 0)
	clock := newGateB2ManualClock(now)
	reads := 0
	clock.queuedPackets = func() int {
		reads++
		if reads == 1 {
			return 1
		}
		return 0
	}
	if err := clock.Wait(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	if reads != 2 || clock.Now() != now.Add(time.Second) {
		t.Fatalf("queue reads=%d virtual advance=%s", reads, clock.Now().Sub(now))
	}
}

func TestGateB2ManualClockEmptyQueueRetainsPollingTurn(t *testing.T) {
	clock := newGateB2ManualClock(time.Unix(0, 0))
	started := time.Now()
	var firstSample time.Duration
	clock.queuedPackets = func() int {
		firstSample = time.Since(started)
		return 0
	}
	if err := clock.Wait(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	if firstSample < 2*time.Millisecond {
		t.Fatal("empty queue bypassed the existing polling turn")
	}
}

func TestGateB2ManualClockQueueWaitIsBoundedWithoutDiscardingPackets(t *testing.T) {
	if gateB2QueueDrainLimit != 20*time.Millisecond {
		t.Fatal("fixture queue wait cap changed")
	}
	network := gateB2QueuedClockNetwork(t, true)
	clock := newGateB2NATSimClock(time.Unix(0, 0), network)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	if err := clock.Wait(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	// No reader exists: only the real cap can end the queue wait. Scheduler
	// delay may make the observed wall time longer; never assert timer order.
	if time.Since(started) < gateB2QueueDrainLimit || network.Snapshot().QueuedPackets != 1 {
		t.Fatal("wait returned before its cap or consumed a packet itself")
	}
}

func TestGateB2ManualClockQueueWaitCancellation(t *testing.T) {
	for _, beforeWait := range []bool{true, false} {
		t.Run(map[bool]string{true: "before", false: "during"}[beforeWait], func(t *testing.T) {
			now := time.Unix(0, 0)
			clock := newGateB2ManualClock(now)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads := 0
			clock.queuedPackets = func() int {
				reads++
				cancel()
				return 1
			}
			if beforeWait {
				cancel()
			}
			if err := clock.Wait(ctx, time.Second); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled wait=%v", err)
			}
			wantReads, wantAdvance := 1, time.Second
			if beforeWait {
				wantReads, wantAdvance = 0, 0
			}
			if reads != wantReads || clock.Now() != now.Add(wantAdvance) {
				t.Fatalf("cancelled queue reads=%d virtual advance=%s", reads, clock.Now().Sub(now))
			}
		})
	}
}

func TestGateB2ManualClockPreservesLongRoleLeadAndUnboundClock(t *testing.T) {
	now := time.Unix(0, 0)
	clock := newGateB2ManualClock(now)
	clock.queuedPackets = func() int {
		t.Fatal("long role lead must not use queue drain")
		return 0
	}
	started := time.Now()
	if err := clock.Wait(context.Background(), 7*time.Second); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 100*time.Millisecond || clock.Now() != now.Add(7*time.Second) {
		t.Fatal("seven-second role lead compression changed")
	}
	// C1b embeds this unbound constructor and owns its separate timing policy.
	if newGateB2ManualClock(now).queuedPackets != nil {
		t.Fatal("unbound clock gained an implicit network")
	}
}

func TestGateB2NATSimClockBindsOnlyItsFixtureNetwork(t *testing.T) {
	queued, empty := gateB2QueuedClockNetwork(t, true), gateB2QueuedClockNetwork(t, false)
	a := newGateB2NATSimClock(time.Unix(0, 0), queued)
	b := newGateB2NATSimClock(time.Unix(0, 0), empty)
	if a.queuedPackets() != 1 || b.queuedPackets() != 0 {
		t.Fatal("clock did not observe its own network queue")
	}
}

func gateB2QueuedClockNetwork(t *testing.T, enqueue bool) *natsim.Network {
	t.Helper()
	network, err := natsim.NewNetwork(natsim.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = network.Close() })
	if !enqueue {
		return network
	}
	left, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.10:30000")})
	if err != nil {
		t.Fatal(err)
	}
	right := netip.MustParseAddrPort("192.0.2.20:30000")
	if _, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: right}); err != nil {
		t.Fatal(err)
	}
	if _, err := left.WriteToAddrPort([]byte("queue-witness"), right); err != nil {
		t.Fatal(err)
	}
	return network
}
