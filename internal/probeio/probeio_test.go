package probeio

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
)

var (
	targetA = netip.MustParseAddrPort("192.0.2.10:40000")
	targetB = netip.MustParseAddrPort("198.51.100.20:41000")
)

type fakeLease struct {
	request  governor.AttemptRequest
	peerID   string
	stopping chan struct{}
	done     chan struct{}

	mu             sync.Mutex
	trips          []governor.SafetyTripEvent
	drains         int
	stoppingClosed bool
	doneClosed     bool
}

func newFakeLease(resources governor.Resources) *fakeLease {
	return &fakeLease{
		request: governor.AttemptRequest{
			ID:        "attempt-probeio",
			Operation: governor.OperationConnectTest,
			Cost: governor.AttemptCost{
				Resources: resources,
				Duration:  time.Minute,
			},
		},
		peerID:   "peer-probeio",
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (lease *fakeLease) Request() governor.AttemptRequest { return lease.request }
func (lease *fakeLease) PeerID() string                   { return lease.peerID }
func (lease *fakeLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *fakeLease) Done() <-chan struct{}            { return lease.done }

func (lease *fakeLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.stoppingClosed {
		return nil, governor.ErrLeaseClosed
	}
	lease.drains++
	return &fakeDrain{lease: lease}, nil
}

func (lease *fakeLease) Close() error {
	lease.mu.Lock()
	lease.startStoppingLocked()
	if lease.drains == 0 {
		lease.finishDoneLocked()
	}
	done := lease.done
	lease.mu.Unlock()
	<-done
	return nil
}

func (lease *fakeLease) Trip(event governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	lease.mu.Lock()
	lease.trips = append(lease.trips, event)
	sequence := uint64(len(lease.trips))
	lease.startStoppingLocked()
	lease.mu.Unlock()
	return governor.SafetyTripStatus{
		State:            governor.SafetyTripTripped,
		BlocksActiveWork: true,
		Record: governor.SafetyTripRecord{
			SchemaVersion: 1,
			State:         governor.SafetyTripTripped,
			Sequence:      sequence,
			Reason:        event.Reason,
		},
	}, nil
}

func (lease *fakeLease) startStoppingLocked() {
	if lease.stoppingClosed {
		return
	}
	lease.stoppingClosed = true
	close(lease.stopping)
}

func (lease *fakeLease) finishDoneLocked() {
	if lease.doneClosed {
		return
	}
	lease.doneClosed = true
	close(lease.done)
}

type fakeDrain struct {
	lease *fakeLease
	once  sync.Once
}

func (drain *fakeDrain) Complete() error {
	if drain == nil || drain.lease == nil {
		return nil
	}
	drain.once.Do(func() {
		lease := drain.lease
		lease.mu.Lock()
		if lease.drains > 0 {
			lease.drains--
		}
		if lease.stoppingClosed && lease.drains == 0 {
			lease.finishDoneLocked()
		}
		lease.mu.Unlock()
	})
	return nil
}

func (lease *fakeLease) tripEvents() []governor.SafetyTripEvent {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return append([]governor.SafetyTripEvent(nil), lease.trips...)
}

type fakeFactory struct {
	mu        sync.Mutex
	datagrams []*fakeDatagram
	openErrs  []error
	block     <-chan struct{}
}

func (factory *fakeFactory) Open(ctx context.Context) (Datagram, error) {
	if factory.block != nil {
		select {
		case <-factory.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if len(factory.openErrs) > 0 {
		err := factory.openErrs[0]
		factory.openErrs = factory.openErrs[1:]
		return nil, err
	}
	datagram := newFakeDatagram()
	factory.datagrams = append(factory.datagrams, datagram)
	return datagram, nil
}

func (factory *fakeFactory) at(index int) *fakeDatagram {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return factory.datagrams[index]
}

func (factory *fakeFactory) count() int {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return len(factory.datagrams)
}

type fakeRead struct {
	packet []byte
	from   netip.AddrPort
	err    error
}

type fakeWrite struct {
	packet []byte
	target netip.AddrPort
}

type fakeDatagram struct {
	mu sync.Mutex

	closed        bool
	closeOnce     sync.Once
	closeCh       chan struct{}
	reads         chan fakeRead
	writes        []fakeWrite
	writeErrs     []error
	shortWrites   int
	deadlines     []time.Time
	deadlineError error
}

func newFakeDatagram() *fakeDatagram {
	return &fakeDatagram{
		closeCh: make(chan struct{}),
		reads:   make(chan fakeRead, 16),
	}
}

func (datagram *fakeDatagram) ReadFrom(ctx context.Context, dst []byte) (int, netip.AddrPort, error) {
	select {
	case <-ctx.Done():
		return 0, netip.AddrPort{}, ctx.Err()
	case <-datagram.closeCh:
		return 0, netip.AddrPort{}, net.ErrClosed
	case result := <-datagram.reads:
		if result.err != nil {
			return 0, netip.AddrPort{}, result.err
		}
		n := copy(dst, result.packet)
		if n != len(result.packet) {
			return n, result.from, io.ErrShortBuffer
		}
		return n, result.from, nil
	}
}

func (datagram *fakeDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	if datagram.closed {
		return 0, net.ErrClosed
	}
	datagram.writes = append(datagram.writes, fakeWrite{
		packet: append([]byte(nil), packet...),
		target: target,
	})
	if len(datagram.writeErrs) > 0 {
		err := datagram.writeErrs[0]
		datagram.writeErrs = datagram.writeErrs[1:]
		return 0, err
	}
	if datagram.shortWrites > 0 {
		datagram.shortWrites--
		if len(packet) == 0 {
			return 0, nil
		}
		return len(packet) - 1, nil
	}
	return len(packet), nil
}

func (datagram *fakeDatagram) SetDeadline(deadline time.Time) error {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	datagram.deadlines = append(datagram.deadlines, deadline)
	return datagram.deadlineError
}

func (datagram *fakeDatagram) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:32000"))
}

func (datagram *fakeDatagram) Close() error {
	datagram.closeOnce.Do(func() {
		datagram.mu.Lock()
		datagram.closed = true
		datagram.mu.Unlock()
		close(datagram.closeCh)
	})
	return nil
}

func (datagram *fakeDatagram) queueRead(packet []byte, from netip.AddrPort) {
	datagram.reads <- fakeRead{packet: append([]byte(nil), packet...), from: from}
}

func (datagram *fakeDatagram) setWriteErrors(errs ...error) {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	datagram.writeErrs = append([]error(nil), errs...)
}

func (datagram *fakeDatagram) writeCount() int {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	return len(datagram.writes)
}

func (datagram *fakeDatagram) lastWrite() fakeWrite {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	return datagram.writes[len(datagram.writes)-1]
}

func (datagram *fakeDatagram) isClosed() bool {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	return datagram.closed
}

func (datagram *fakeDatagram) clearedDeadline() bool {
	datagram.mu.Lock()
	defer datagram.mu.Unlock()
	return len(datagram.deadlines) == 1 && datagram.deadlines[0].IsZero()
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type manualTimer struct {
	ch chan time.Time
}

func (timer *manualTimer) C() <-chan time.Time { return timer.ch }
func (timer *manualTimer) Stop() bool          { return true }

type harness struct {
	controller *Controller
	lease      *fakeLease
	factory    *fakeFactory
	generation *Generation
	clock      *fakeClock
	timer      *manualTimer
}

func newHarness(t *testing.T, resources governor.Resources) *harness {
	t.Helper()
	lease := newFakeLease(resources)
	factory := &fakeFactory{}
	generation := NewGeneration(7)
	clock := &fakeClock{now: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)}
	timer := &manualTimer{ch: make(chan time.Time, 1)}
	controller, err := New(Config{
		Lease:              lease,
		Generation:         generation,
		ExpectedGeneration: 7,
		Factory:            factory,
		Now:                clock.Now,
		NewTimer:           func(time.Duration) Timer { return timer },
		BuildVersion:       "probeio-test",
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Errorf("close controller: %v", err)
		}
	})
	return &harness{
		controller: controller,
		lease:      lease,
		factory:    factory,
		generation: generation,
		clock:      clock,
		timer:      timer,
	}
}

func normalResources() governor.Resources {
	return governor.Resources{
		Sockets:          2,
		Targets:          2,
		PacketsPerSecond: 16,
		Packets:          32,
		FiveTuples:       2,
	}
}

func openSocket(t *testing.T, harness *harness) (*ProbeSocket, *fakeDatagram) {
	t.Helper()
	socket, err := harness.controller.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open socket: %v", err)
	}
	return socket, harness.factory.at(harness.factory.count() - 1)
}

func TestSocketReservationIsImmutableReadOnlyEvidence(t *testing.T) {
	harness := newHarness(t, normalResources())
	socket, _ := openSocket(t, harness)
	reservation, err := socket.Reservation()
	if err != nil {
		t.Fatal(err)
	}
	if reservation.Operation != governor.OperationConnectTest || reservation.Generation != 7 ||
		reservation.Cost != harness.lease.request.Cost {
		t.Fatalf("reservation = %+v, want request %+v generation 7", reservation, harness.lease.request)
	}
	reservation.Cost.Resources.Targets = 999
	again, err := socket.Reservation()
	if err != nil {
		t.Fatal(err)
	}
	if again.Cost.Resources.Targets != normalResources().Targets {
		t.Fatalf("caller mutated reservation: %+v", again)
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := socket.Reservation(); !errors.Is(err, ErrSocketClosed) {
		t.Fatalf("closed reservation error = %v", err)
	}
}

func TestSendRejectsUnregisteredTargetWithoutIO(t *testing.T) {
	harness := newHarness(t, normalResources())
	socket, datagram := openSocket(t, harness)

	err := socket.SendProbe(context.Background(), targetA, []byte("hello"))
	if !errors.Is(err, ErrUnregisteredTarget) {
		t.Fatalf("send error = %v, want ErrUnregisteredTarget", err)
	}
	if datagram.writeCount() != 0 {
		t.Fatalf("writes = %d, want 0", datagram.writeCount())
	}
	if len(harness.lease.tripEvents()) != 0 {
		t.Fatal("unregistered target caused a machine trip")
	}
}

func TestSendPacketBudgetBreachTripsAndCloses(t *testing.T) {
	resources := normalResources()
	resources.Packets = 1
	harness := newHarness(t, resources)
	socket, datagram := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	if err := socket.SendProbe(context.Background(), targetA, []byte("first")); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if err := socket.SendProbe(context.Background(), targetA, []byte("second")); !errors.Is(err, ErrHardLimit) {
		t.Fatalf("second send error = %v, want ErrHardLimit", err)
	}
	assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	select {
	case <-harness.controller.watchDone:
	case <-time.After(time.Second):
		t.Fatal("hard-limit trip did not finish controller drain")
	}
	if !datagram.isClosed() {
		t.Fatal("trip did not close the probe datagram")
	}
	if datagram.writeCount() != 1 {
		t.Fatalf("writes = %d, want 1", datagram.writeCount())
	}
}

func TestPacketsPerSecondBudgetUsesInjectedClock(t *testing.T) {
	resources := normalResources()
	resources.PacketsPerSecond = 1
	harness := newHarness(t, resources)
	socket, _ := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	if err := socket.SendProbe(context.Background(), targetA, []byte("first")); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if err := socket.SendProbe(context.Background(), targetA, []byte("too-fast")); !errors.Is(err, ErrHardLimit) {
		t.Fatalf("second send error = %v, want ErrHardLimit", err)
	}
	assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
}

func TestResourceExhaustionTripsImmediately(t *testing.T) {
	harness := newHarness(t, normalResources())
	socket, datagram := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	datagram.setWriteErrors(ErrResourceExhausted)
	err := socket.SendProbe(context.Background(), targetA, []byte("probe"))
	if !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("send error = %v, want ErrResourceExhausted", err)
	}
	assertTripReason(t, harness.lease, governor.SafetyTripResourceExhausted)
}

func TestPlatformResourceClassifierTripsOnWSAENOBUFSEquivalent(t *testing.T) {
	resources := normalResources()
	lease := newFakeLease(resources)
	factory := &fakeFactory{}
	generation := NewGeneration(1)
	timer := &manualTimer{ch: make(chan time.Time)}
	platformExhausted := errors.New("fake WSAENOBUFS")
	controller, err := New(Config{
		Lease:              lease,
		Generation:         generation,
		ExpectedGeneration: 1,
		Factory:            factory,
		NewTimer:           func(time.Duration) Timer { return timer },
		ResourceExhausted:  func(err error) bool { return errors.Is(err, platformExhausted) },
		BuildVersion:       "probeio-test",
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	socket, err := controller.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open socket: %v", err)
	}
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	factory.at(0).setWriteErrors(platformExhausted)
	if err := socket.SendProbe(context.Background(), targetA, []byte("probe")); !errors.Is(err, ErrResourceExhausted) {
		t.Fatalf("send error = %v, want ErrResourceExhausted", err)
	}
	assertTripReason(t, lease, governor.SafetyTripResourceExhausted)
}

func TestConsecutiveWriteFailuresTripAtCompiledThreshold(t *testing.T) {
	harness := newHarness(t, normalResources())
	socket, datagram := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	writeFailure := errors.New("fake write failure")
	datagram.setWriteErrors(writeFailure, writeFailure, writeFailure)
	for index := 0; index < consecutiveWriteFailureLimit-1; index++ {
		if err := socket.SendProbe(context.Background(), targetA, []byte("probe")); !errors.Is(err, writeFailure) {
			t.Fatalf("send %d error = %v, want write failure", index, err)
		}
		if len(harness.lease.tripEvents()) != 0 {
			t.Fatalf("send %d tripped before threshold", index)
		}
	}
	err := socket.SendProbe(context.Background(), targetA, []byte("probe"))
	if !errors.Is(err, ErrWriteFailures) {
		t.Fatalf("threshold send error = %v, want ErrWriteFailures", err)
	}
	assertTripReason(t, harness.lease, governor.SafetyTripWriteFailures)
}

func TestStaleGenerationSendTripsBeforeIO(t *testing.T) {
	harness := newHarness(t, normalResources())
	socket, datagram := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	if err := harness.generation.Advance(8); err != nil {
		t.Fatalf("advance generation: %v", err)
	}
	err := socket.SendProbe(context.Background(), targetA, []byte("stale"))
	if !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale send error = %v, want ErrStaleGeneration", err)
	}
	if datagram.writeCount() != 0 {
		t.Fatalf("stale generation wrote %d packets", datagram.writeCount())
	}
	assertTripReason(t, harness.lease, governor.SafetyTripStaleGeneration)
}

func TestLeaseCancellationClosesSocketAndBlockedRead(t *testing.T) {
	harness := newHarness(t, normalResources())
	socket, datagram := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	readResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 32)
		_, _, err := socket.ReceiveReply(context.Background(), buffer, func([]byte, netip.AddrPort) error { return nil })
		readResult <- err
	}()
	if err := harness.lease.Close(); err != nil {
		t.Fatalf("close lease: %v", err)
	}
	select {
	case err := <-readResult:
		if !errors.Is(err, ErrLeaseClosed) {
			t.Fatalf("read error = %v, want ErrLeaseClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read did not exit after lease cancellation")
	}
	select {
	case <-harness.controller.watchDone:
	case <-time.After(time.Second):
		t.Fatal("lifecycle watcher did not exit")
	}
	if !datagram.isClosed() {
		t.Fatal("lease cancellation did not close datagram")
	}
	if err := socket.SendProbe(context.Background(), targetA, []byte("late")); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("late send error = %v, want ErrLeaseClosed", err)
	}
}

func TestAttemptDurationTimerTrips(t *testing.T) {
	harness := newHarness(t, normalResources())
	_, datagram := openSocket(t, harness)
	harness.timer.ch <- harness.clock.Now().Add(time.Minute)
	select {
	case <-harness.controller.watchDone:
	case <-time.After(time.Second):
		t.Fatal("duration timer did not stop controller")
	}
	assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	if !datagram.isClosed() {
		t.Fatal("duration trip did not close datagram")
	}
}

func TestPromotionTransfersOneVerifiedFixedTarget(t *testing.T) {
	harness := newHarness(t, normalResources())
	winner, winnerDatagram := openSocket(t, harness)
	sibling, siblingDatagram := openSocket(t, harness)
	if err := winner.RegisterTarget(targetA); err != nil {
		t.Fatalf("register winner target: %v", err)
	}
	if err := sibling.RegisterTarget(targetB); err != nil {
		t.Fatalf("register sibling target: %v", err)
	}
	winnerDatagram.queueRead([]byte("authenticated-ack"), targetA)
	buffer := make([]byte, 64)
	n, from, err := winner.ReceiveReply(context.Background(), buffer, func(packet []byte, endpoint netip.AddrPort) error {
		if string(packet) != "authenticated-ack" || endpoint != targetA {
			return errors.New("unexpected reply")
		}
		return nil
	})
	if err != nil || n != len("authenticated-ack") || from != targetA {
		t.Fatalf("receive reply = %d/%v/%v", n, from, err)
	}

	promotion, err := winner.Promote(targetA, "direct/probeio")
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if promotion.PeerID != "peer-probeio" || promotion.AttemptID != "attempt-probeio" || promotion.Generation != 7 || promotion.Target != targetA {
		t.Fatalf("promotion metadata = %+v", promotion)
	}
	if !winnerDatagram.clearedDeadline() {
		t.Fatal("promotion did not clear the winner deadline exactly once")
	}
	if !siblingDatagram.isClosed() {
		t.Fatal("promotion did not close sibling datagram")
	}
	if winnerDatagram.isClosed() {
		t.Fatal("promotion closed the transferred datagram")
	}
	if err := winner.SendProbe(context.Background(), targetA, []byte("old-handle")); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("old handle send error = %v, want ErrLeaseClosed", err)
	}
	if err := winner.Close(); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("old handle close error = %v, want ErrLeaseClosed", err)
	}
	if _, err := winner.Promote(targetA, "again"); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("second promotion error = %v, want ErrLeaseClosed", err)
	}

	if err := promotion.Transport.WritePacket(context.Background(), []byte("transport")); err != nil {
		t.Fatalf("transport write: %v", err)
	}
	if write := winnerDatagram.lastWrite(); write.target != targetA || string(write.packet) != "transport" {
		t.Fatalf("transport write = %+v", write)
	}
	winnerDatagram.queueRead([]byte("payload"), targetA)
	n, meta, err := promotion.Transport.ReadPacket(context.Background(), buffer)
	if err != nil || string(buffer[:n]) != "payload" || meta.PathID != "direct/probeio" {
		t.Fatalf("transport read = %d/%+v/%v payload=%q", n, meta, err, buffer[:n])
	}
	if err := promotion.Transport.Close(); err != nil {
		t.Fatalf("close promoted transport: %v", err)
	}
	if !winnerDatagram.isClosed() {
		t.Fatal("promoted transport close did not close datagram")
	}
}

func TestTerminalPromotionRetainsLeaseUntilCallerFinishes(t *testing.T) {
	harness := newHarness(t, normalResources())
	socket, datagram := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}
	datagram.queueRead([]byte("authenticated-finish"), targetA)
	buffer := make([]byte, 64)
	if _, _, err := socket.ReceiveReply(context.Background(), buffer, func([]byte, netip.AddrPort) error { return nil }); err != nil {
		t.Fatalf("verify reply: %v", err)
	}

	promotion, err := socket.PromoteTerminal(targetA, "direct/terminal")
	if err != nil {
		t.Fatalf("promote terminal: %v", err)
	}
	select {
	case <-harness.lease.Stopping():
		t.Fatal("terminal promotion released the attempt before FINISH")
	default:
	}
	select {
	case <-harness.controller.watchDone:
	case <-time.After(time.Second):
		t.Fatal("terminal promotion did not retire the probeio drain")
	}
	if datagram.isClosed() {
		t.Fatal("terminal promotion closed the transferred datagram")
	}

	if err := promotion.Transport.Close(); err != nil {
		t.Fatalf("close promoted transport: %v", err)
	}
	if err := harness.controller.Close(); err != nil {
		t.Fatalf("release terminal attempt: %v", err)
	}
	select {
	case <-harness.lease.Done():
	default:
		t.Fatal("controller close did not release retained attempt")
	}
}

func TestRejectedOrUnknownReplyCannotPromote(t *testing.T) {
	t.Run("verifier rejected", func(t *testing.T) {
		harness := newHarness(t, normalResources())
		socket, datagram := openSocket(t, harness)
		if err := socket.RegisterTarget(targetA); err != nil {
			t.Fatalf("register target: %v", err)
		}
		datagram.queueRead([]byte("bad-ack"), targetA)
		buffer := make([]byte, 32)
		_, _, err := socket.ReceiveReply(context.Background(), buffer, func([]byte, netip.AddrPort) error {
			return errors.New("signature mismatch")
		})
		if !errors.Is(err, ErrReplyRejected) {
			t.Fatalf("receive error = %v, want ErrReplyRejected", err)
		}
		if _, err := socket.Promote(targetA, "direct"); !errors.Is(err, ErrReplyNotVerified) {
			t.Fatalf("promotion error = %v, want ErrReplyNotVerified", err)
		}
	})

	t.Run("unregistered source", func(t *testing.T) {
		harness := newHarness(t, normalResources())
		socket, datagram := openSocket(t, harness)
		if err := socket.RegisterTarget(targetA); err != nil {
			t.Fatalf("register target: %v", err)
		}
		datagram.queueRead([]byte("ack"), targetB)
		buffer := make([]byte, 32)
		_, _, err := socket.ReceiveReply(context.Background(), buffer, func([]byte, netip.AddrPort) error { return nil })
		if !errors.Is(err, ErrUnregisteredTarget) {
			t.Fatalf("receive error = %v, want ErrUnregisteredTarget", err)
		}
		if len(harness.lease.tripEvents()) != 0 {
			t.Fatal("unregistered inbound reply caused a machine trip")
		}
	})
}

func TestSocketTargetAndFiveTupleReservationsFailClosed(t *testing.T) {
	t.Run("socket", func(t *testing.T) {
		resources := normalResources()
		resources.Sockets = 1
		harness := newHarness(t, resources)
		_, _ = openSocket(t, harness)
		if _, err := harness.controller.OpenProbeSocket(context.Background()); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("second open error = %v, want ErrHardLimit", err)
		}
		if harness.factory.count() != 1 {
			t.Fatalf("factory opens = %d, want 1", harness.factory.count())
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("target", func(t *testing.T) {
		resources := normalResources()
		resources.Targets = 1
		harness := newHarness(t, resources)
		first, _ := openSocket(t, harness)
		second, _ := openSocket(t, harness)
		if err := first.RegisterTarget(targetA); err != nil {
			t.Fatalf("register first: %v", err)
		}
		if err := second.RegisterTarget(targetB); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("register second error = %v, want ErrHardLimit", err)
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})

	t.Run("five tuple", func(t *testing.T) {
		resources := normalResources()
		resources.Targets = 1
		resources.FiveTuples = 1
		harness := newHarness(t, resources)
		first, _ := openSocket(t, harness)
		second, _ := openSocket(t, harness)
		if err := first.RegisterTarget(targetA); err != nil {
			t.Fatalf("register first: %v", err)
		}
		if err := second.RegisterTarget(targetA); !errors.Is(err, ErrHardLimit) {
			t.Fatalf("register second error = %v, want ErrHardLimit", err)
		}
		assertTripReason(t, harness.lease, governor.SafetyTripHardLimit)
	})
}

func TestConcurrentSendsStayWithinOneReservedBudget(t *testing.T) {
	resources := normalResources()
	resources.Packets = 64
	resources.PacketsPerSecond = 64
	harness := newHarness(t, resources)
	socket, datagram := openSocket(t, harness)
	if err := socket.RegisterTarget(targetA); err != nil {
		t.Fatalf("register target: %v", err)
	}

	var wait sync.WaitGroup
	errorsCh := make(chan error, 64)
	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsCh <- socket.SendProbe(context.Background(), targetA, []byte("probe"))
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent send: %v", err)
		}
	}
	if datagram.writeCount() != 64 {
		t.Fatalf("writes = %d, want 64", datagram.writeCount())
	}
	if len(harness.lease.tripEvents()) != 0 {
		t.Fatal("in-budget concurrent sends caused a trip")
	}
}

func TestControllerCancellationInterruptsPendingFactoryOpen(t *testing.T) {
	resources := normalResources()
	lease := newFakeLease(resources)
	block := make(chan struct{})
	factory := &fakeFactory{block: block}
	generation := NewGeneration(1)
	timer := &manualTimer{ch: make(chan time.Time)}
	controller, err := New(Config{
		Lease:              lease,
		Generation:         generation,
		ExpectedGeneration: 1,
		Factory:            factory,
		NewTimer:           func(time.Duration) Timer { return timer },
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := controller.OpenProbeSocket(context.Background())
		result <- err
	}()
	if err := lease.Close(); err != nil {
		t.Fatalf("close lease: %v", err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrLeaseClosed) {
			t.Fatalf("open error = %v, want ErrLeaseClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending factory open did not observe controller cancellation")
	}
	if err := controller.Close(); err != nil {
		t.Fatalf("close controller: %v", err)
	}
}

func TestGenerationNeverRollsBackOrRepeats(t *testing.T) {
	generation := NewGeneration(10)
	if err := generation.Advance(11); err != nil {
		t.Fatalf("advance: %v", err)
	}
	for _, next := range []uint64{11, 10, 0} {
		if err := generation.Advance(next); !errors.Is(err, ErrInvalidGeneration) {
			t.Fatalf("advance to %d error = %v, want ErrInvalidGeneration", next, err)
		}
	}
	if generation.CurrentGeneration() != 11 {
		t.Fatalf("current generation = %d, want 11", generation.CurrentGeneration())
	}
}

func TestUntrustedConfigurationAndPoisonInputsAreRejected(t *testing.T) {
	resources := normalResources()
	lease := newFakeLease(resources)
	factory := &fakeFactory{}
	generation := NewGeneration(1)
	timer := &manualTimer{ch: make(chan time.Time)}
	_, err := New(Config{
		Lease:              lease,
		Generation:         generation,
		ExpectedGeneration: 1,
		Factory:            factory,
		NewTimer:           func(time.Duration) Timer { return timer },
		BuildVersion:       strings.Repeat("x", 129),
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("long build version error = %v, want ErrInvalidConfig", err)
	}

	harness := newHarness(t, resources)
	if err := harness.controller.Poison(governor.SafetyTripReason("unreviewed"), "bad reason"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid poison error = %v, want ErrInvalidConfig", err)
	}
	if len(harness.lease.tripEvents()) != 0 {
		t.Fatal("invalid poison reason reached the machine trip store")
	}
	socket, _ := openSocket(t, harness)
	if err := socket.RegisterTarget(netip.MustParseAddrPort("255.255.255.255:9")); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("broadcast target error = %v, want ErrInvalidTarget", err)
	}
	if _, err := socket.Promote(targetA, " path "); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid path error = %v, want ErrInvalidConfig", err)
	}
}

func assertTripReason(t *testing.T, lease *fakeLease, reason governor.SafetyTripReason) {
	t.Helper()
	events := lease.tripEvents()
	if len(events) != 1 {
		t.Fatalf("trip events = %d, want 1: %+v", len(events), events)
	}
	if events[0].Reason != reason {
		t.Fatalf("trip reason = %q, want %q", events[0].Reason, reason)
	}
	if events[0].BuildVersion != "probeio-test" {
		t.Fatalf("trip build version = %q, want probeio-test", events[0].BuildVersion)
	}
}
