package governor_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/internal/natsim"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatcontrol"
)

// gateB2PairedSchedule belongs to one two-sided Hard16 memory fixture. The
// compressed clocks may advance only after BOTH senders have completed the
// current sender's candidate prefix. In particular, the final receive interval
// cannot finish while the other sender is still emitting its frozen schedule.
// This is virtual-time scheduling, not a delivery/acceptance or success oracle.
// The original candidate/active contexts bound the barrier; it adds no timer,
// retry, packet, or grace period. The separate queue drain remains capped at 20ms.
type gateB2PairedSchedule struct {
	mu        sync.Mutex
	completed [2]uint32
	inFlight  [2]uint32
	waiting   [2]bool
	changed   chan struct{}
}

func newGateB2PairedSchedule() *gateB2PairedSchedule {
	return &gateB2PairedSchedule{changed: make(chan struct{})}
}

func (schedule *gateB2PairedSchedule) notifyLocked() {
	close(schedule.changed)
	schedule.changed = make(chan struct{})
}

func (schedule *gateB2PairedSchedule) begin(side int) {
	schedule.mu.Lock()
	schedule.inFlight[side]++
	schedule.mu.Unlock()
}

func (schedule *gateB2PairedSchedule) complete(side int, accepted bool) {
	schedule.mu.Lock()
	schedule.inFlight[side]--
	if accepted {
		schedule.completed[side]++
	}
	schedule.notifyLocked()
	schedule.mu.Unlock()
}

func (schedule *gateB2PairedSchedule) wait(ctx context.Context, side int) error {
	defer func() {
		schedule.mu.Lock()
		schedule.waiting[side] = false
		schedule.mu.Unlock()
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		schedule.mu.Lock()
		// Zero is pre-candidate work, not a synthetic peer-presence barrier.
		ready := schedule.completed[side] == 0 ||
			schedule.completed[1-side] >= schedule.completed[side] && schedule.inFlight[1-side] == 0
		schedule.waiting[side] = !ready
		changed := schedule.changed
		schedule.mu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (schedule *gateB2PairedSchedule) clock(now time.Time, network *natsim.Network, side int) *gateB2ManualClock {
	clock := newGateB2NATSimClock(now, network)
	clock.beforeAdvance = func(ctx context.Context) error { return schedule.wait(ctx, side) }
	return clock
}

func (schedule *gateB2PairedSchedule) factory(base probeio.Factory, side int) probeio.Factory {
	return &gateB2ScheduledFactory{base: base, schedule: schedule, side: side}
}

type gateB2ScheduledFactory struct {
	base     probeio.Factory
	schedule *gateB2PairedSchedule
	side     int
}

func (factory *gateB2ScheduledFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	datagram, err := factory.base.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &gateB2ScheduledDatagram{Datagram: datagram, schedule: factory.schedule, side: factory.side}, nil
}

type gateB2ScheduledDatagram struct {
	probeio.Datagram
	schedule *gateB2PairedSchedule
	side     int
}

func (datagram *gateB2ScheduledDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	metadata, inspectErr := hardnatcontrol.InspectFrame(packet)
	if inspectErr != nil || metadata.Type != hardnatcontrol.FrameCandidate {
		return datagram.Datagram.WriteTo(ctx, packet, target)
	}
	datagram.schedule.begin(datagram.side)
	n, err := datagram.Datagram.WriteTo(ctx, packet, target)
	// Wrap OUTSIDE the fault factory: an injected network drop still completes
	// a sender step; a short/failed write does not. Nothing is inferred about
	// delivery. In-flight includes the complete synchronous natsim enqueue.
	datagram.schedule.complete(datagram.side, err == nil && n == len(packet))
	return n, err
}

func TestGateB2PairedClockCannotOutrunPeerSendOrInFlightEnqueue(t *testing.T) {
	for _, mode := range []string{"peer_completes", "peer_prefix_done_but_next_write_in_flight", "caller_cancels"} {
		t.Run(mode, func(t *testing.T) {
			terminal := mode == "caller_cancels"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			schedule := newGateB2PairedSchedule()
			schedule.begin(0)
			schedule.complete(0, true)
			if mode == "peer_prefix_done_but_next_write_in_flight" {
				schedule.begin(1)
				schedule.complete(1, true)
			}
			schedule.begin(1) // Peer WriteTo has entered but has not enqueued/returned.
			now := time.Unix(0, 0)
			clock := schedule.clock(now, gateB2QueuedClockNetwork(t, false), 0)
			result := make(chan error, 1)
			go func() { result <- clock.Wait(ctx, time.Second) }()
			gateB2ObservePairedWait(t, ctx, schedule, 0, result)
			if clock.Now() != now {
				t.Fatal("virtual time advanced before the peer completed its send")
			}
			if terminal {
				cancel()
			} else {
				schedule.complete(1, true)
			}
			select {
			case err := <-result:
				if terminal {
					if !errors.Is(err, context.Canceled) || clock.Now() != now {
						t.Fatalf("cancelled barrier advanced virtual time: %v", err)
					}
					schedule.complete(1, false)
				} else if err != nil || clock.Now() != now.Add(time.Second) {
					t.Fatalf("completed peer did not release exactly one virtual interval: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("paired clock worker did not drain")
			}
			schedule.mu.Lock()
			waiting, inFlight := schedule.waiting, schedule.inFlight
			schedule.mu.Unlock()
			if waiting != [2]bool{} || inFlight != [2]uint32{} {
				t.Fatal("paired scheduler retained an in-flight worker")
			}
		})
	}
}

func TestGateB2PairedClockDoesNotBorrowAnotherFixturesProgress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, second := newGateB2PairedSchedule(), newGateB2PairedSchedule()
	first.begin(0)
	first.complete(0, true)
	second.begin(1)
	second.complete(1, true)
	result := make(chan error, 1)
	go func() { result <- first.wait(ctx, 0) }()
	gateB2ObservePairedWait(t, ctx, first, 0, result)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("peer absence barrier ignored cancellation: %v", err)
	}
}

// Observe the predicate itself, not an assumed ordering of independent timers.
// Disabling clock.beforeAdvance makes result win deterministically and is RED.
func gateB2ObservePairedWait(t *testing.T, ctx context.Context, schedule *gateB2PairedSchedule, side int, result <-chan error) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		schedule.mu.Lock()
		waiting := schedule.waiting[side]
		schedule.mu.Unlock()
		if waiting {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("clock crossed an empty queue while peer send was unfinished: %v", err)
		case <-ctx.Done():
			t.Fatal("fixture never observed the paired progress barrier")
		case <-ticker.C:
		}
	}
}

func TestGateB2PairedFactoryCountsCompletedWritesNotDelivery(t *testing.T) {
	// Header-only fixture from hardnatcontrol's candidate-header golden. It is
	// never delivered to a protocol and makes no claim of authentication.
	packet, err := hex.DecodeString("5759484201020401000000000000001000070000002a0010" + "00000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"accepted_drop", "short", "failed", "not_candidate"} {
		t.Run(kind, func(t *testing.T) {
			schedule := newGateB2PairedSchedule()
			var calls int
			var wantCount uint32
			frame := packet
			if kind == "not_candidate" {
				frame = []byte("STUN-or-data-not-a-candidate")
			}
			base := &gateB2WriteOnlyDatagram{write: func(_ context.Context, payload []byte, _ netip.AddrPort) (int, error) {
				calls++
				wantInFlight := [2]uint32{1, 0}
				if kind == "not_candidate" {
					wantInFlight = [2]uint32{}
				}
				if schedule.inFlight != wantInFlight || schedule.completed != [2]uint32{} {
					t.Fatal("candidate was counted before the underlying write returned")
				}
				switch kind {
				case "short":
					return len(payload) - 1, nil
				case "failed":
					return 0, context.Canceled
				case "accepted_drop":
					wantCount = 1
				}
				return len(payload), nil // Successful fault-drop, not a fake delivery.
			}}
			datagram := &gateB2ScheduledDatagram{Datagram: base, schedule: schedule, side: 0}
			_, _ = datagram.WriteTo(context.Background(), frame, netip.AddrPort{})
			if calls != 1 || schedule.completed != [2]uint32{wantCount, 0} || schedule.inFlight != [2]uint32{} {
				t.Fatalf("write progress differs: calls=%d completed=%v in_flight=%v", calls, schedule.completed, schedule.inFlight)
			}
		})
	}
}

type gateB2WriteOnlyDatagram struct {
	probeio.Datagram
	write func(context.Context, []byte, netip.AddrPort) (int, error)
}

func (datagram *gateB2WriteOnlyDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	return datagram.write(ctx, packet, target)
}
