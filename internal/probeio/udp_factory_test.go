package probeio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"winkyou/internal/governor"
)

var loopbackEphemeral = netip.MustParseAddrPort("127.0.0.1:0")

func TestUDPFactoryIsLoopbackOnly(t *testing.T) {
	for _, endpoint := range []netip.AddrPort{
		{},
		netip.MustParseAddrPort("0.0.0.0:0"),
		netip.MustParseAddrPort("192.0.2.1:0"),
	} {
		if _, err := NewUDPFactory(UDPFactoryConfig{LocalAddr: endpoint}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NewUDPFactory(%v) error = %v, want ErrInvalidConfig", endpoint, err)
		}
	}

	factory := mustUDPFactory(t)
	if _, err := factory.Open(context.Background()); !errors.Is(err, ErrFactoryUnauthorized) {
		t.Fatalf("direct factory open error = %v, want ErrFactoryUnauthorized", err)
	}
	controller, _ := newFakeController(t, factory, normalResources())
	socket, err := controller.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open governed loopback UDP datagram: %v", err)
	}
	if err := socket.RegisterTarget(netip.MustParseAddrPort("192.0.2.1:9")); err != nil {
		t.Fatalf("register syntactically valid non-loopback target: %v", err)
	}
	if err := socket.SendProbe(context.Background(), netip.MustParseAddrPort("192.0.2.1:9"), []byte("blocked")); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("non-loopback write error = %v, want ErrInvalidTarget", err)
	}
}

func TestUDPFactoryPermitCanOpenOnlyOneSocket(t *testing.T) {
	base := mustUDPFactory(t)
	double := &doubleOpenFactory{inner: base}
	controller, _ := newFakeController(t, double, normalResources())
	if _, err := controller.OpenProbeSocket(context.Background()); err != nil {
		t.Fatalf("governed open through double-open injector: %v", err)
	}
	if !errors.Is(double.secondError, ErrFactoryUnauthorized) {
		t.Fatalf("second open error = %v, want ErrFactoryUnauthorized", double.secondError)
	}
}

func TestUDPFactoryRoundTripCancellationAndPromotion(t *testing.T) {
	factoryA := &socketTrackingFactory{inner: mustUDPFactory(t)}
	factoryB := mustUDPFactory(t)
	resources := normalResources()
	resources.Targets = 1
	resources.FiveTuples = 1
	controllerA, _ := newFakeController(t, factoryA, resources)
	controllerB, _ := newFakeController(t, factoryB, resources)

	socketA, err := controllerA.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open socket A: %v", err)
	}
	siblingA, err := controllerA.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open sibling socket A: %v", err)
	}
	socketB, err := controllerB.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open socket B: %v", err)
	}
	addressA, err := socketA.LocalAddr()
	if err != nil {
		t.Fatalf("local address A: %v", err)
	}
	addressB, err := socketB.LocalAddr()
	if err != nil {
		t.Fatalf("local address B: %v", err)
	}
	if !addressA.Addr().IsLoopback() || !addressB.Addr().IsLoopback() {
		t.Fatalf("adapter escaped loopback: A=%v B=%v", addressA, addressB)
	}
	if err := socketA.RegisterTarget(addressB); err != nil {
		t.Fatalf("register B on A: %v", err)
	}
	if err := socketB.RegisterTarget(addressA); err != nil {
		t.Fatalf("register A on B: %v", err)
	}

	cancelled, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if _, _, err := socketA.ReceiveReply(cancelled, make([]byte, 32), acceptReply); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled read error = %v, want context deadline", err)
	}

	if err := socketA.SendProbe(context.Background(), addressB, []byte("hello")); err != nil {
		t.Fatalf("A send hello: %v", err)
	}
	buffer := make([]byte, 64)
	readContext, cancelRead := context.WithTimeout(context.Background(), time.Second)
	n, from, err := socketB.ReceiveReply(readContext, buffer, acceptReply)
	cancelRead()
	if err != nil || string(buffer[:n]) != "hello" || from != addressA {
		t.Fatalf("B receive = %d/%v/%v payload=%q", n, from, err, buffer[:n])
	}

	// A reply uses the same governed send path. The already-registered tuple is
	// not charged again, while PPS and total packet accounting still apply.
	if err := socketB.SendProbe(context.Background(), addressA, []byte("ack")); err != nil {
		t.Fatalf("B send reply: %v", err)
	}
	readContext, cancelRead = context.WithTimeout(context.Background(), time.Second)
	n, from, err = socketA.ReceiveReply(readContext, buffer, acceptReply)
	cancelRead()
	if err != nil || string(buffer[:n]) != "ack" || from != addressB {
		t.Fatalf("A receive = %d/%v/%v payload=%q", n, from, err, buffer[:n])
	}

	promotion, err := socketA.Promote(addressB, "direct/probeio-loopback")
	if err != nil {
		t.Fatalf("promote A: %v", err)
	}
	if err := socketA.SendProbe(context.Background(), addressB, []byte("poisoned")); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("old handle send error = %v, want ErrLeaseClosed", err)
	}
	if _, err := siblingA.LocalAddr(); !errors.Is(err, ErrLeaseClosed) {
		t.Fatalf("sibling handle after promotion = %v, want ErrLeaseClosed", err)
	}
	if active := factoryA.active.Load(); active != 1 {
		t.Fatalf("A sockets after promotion = %d, want only transferred socket", active)
	}
	if err := promotion.Transport.WritePacket(context.Background(), []byte("transport")); err != nil {
		t.Fatalf("promoted transport write: %v", err)
	}
	readContext, cancelRead = context.WithTimeout(context.Background(), time.Second)
	n, _, err = socketB.ReceiveReply(readContext, buffer, acceptReply)
	cancelRead()
	if err != nil || string(buffer[:n]) != "transport" {
		t.Fatalf("B transport receive = %d/%v payload=%q", n, err, buffer[:n])
	}
	if err := promotion.Transport.Close(); err != nil {
		t.Fatalf("close promoted transport: %v", err)
	}
	if active := factoryA.active.Load(); active != 0 {
		t.Fatalf("A sockets after transport close = %d, want 0", active)
	}
}

func TestUDPFactoryActualSocketCountNeverExceedsLease(t *testing.T) {
	base := mustUDPFactory(t)
	tracked := &socketTrackingFactory{inner: base}
	resources := normalResources()
	resources.Sockets = 2
	controller, _ := newFakeController(t, tracked, resources)

	for index := 0; index < resources.Sockets; index++ {
		if _, err := controller.OpenProbeSocket(context.Background()); err != nil {
			t.Fatalf("open socket %d: %v", index, err)
		}
	}
	if active, maximum := tracked.active.Load(), tracked.maximum.Load(); active != 2 || maximum != 2 {
		t.Fatalf("actual OS socket count active/max = %d/%d, want 2/2", active, maximum)
	}
	if _, err := controller.OpenProbeSocket(context.Background()); !errors.Is(err, ErrHardLimit) {
		t.Fatalf("third open error = %v, want ErrHardLimit", err)
	}
	waitForControllerStop(t, controller)
	if active, maximum := tracked.active.Load(), tracked.maximum.Load(); active != 0 || maximum > int64(resources.Sockets) {
		t.Fatalf("actual OS socket count after trip active/max = %d/%d, lease=%d", active, maximum, resources.Sockets)
	}
}

func TestUDPWriteFaultsStopAttemptAndPersistSafetyTrip(t *testing.T) {
	tests := []struct {
		name       string
		writeErrs  []error
		wantError  error
		wantReason governor.SafetyTripReason
	}{
		{
			name:       "WSAENOBUFS equivalent",
			writeErrs:  []error{syscall.Errno(10055)},
			wantError:  ErrResourceExhausted,
			wantReason: governor.SafetyTripResourceExhausted,
		},
		{
			name:       "consecutive writes",
			writeErrs:  []error{errors.New("injected write failure 1"), errors.New("injected write failure 2"), errors.New("injected write failure 3")},
			wantError:  ErrWriteFailures,
			wantReason: governor.SafetyTripWriteFailures,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := mustUDPFactory(t)
			tracked := &socketTrackingFactory{inner: base}
			faults := &writeFaultFactory{inner: tracked, firstSocketErrors: test.writeErrs}
			resources := normalResources()
			controller, machine, attempt, namespace := newGovernedController(t, faults, resources, 100*time.Millisecond)

			failing, err := controller.OpenProbeSocket(context.Background())
			if err != nil {
				t.Fatalf("open failing socket: %v", err)
			}
			sibling, err := controller.OpenProbeSocket(context.Background())
			if err != nil {
				t.Fatalf("open sibling socket: %v", err)
			}
			target := netip.MustParseAddrPort("127.0.0.1:9")
			if err := failing.RegisterTarget(target); err != nil {
				t.Fatalf("register failing target: %v", err)
			}
			if err := sibling.RegisterTarget(target); err != nil {
				t.Fatalf("register sibling target: %v", err)
			}

			var sendErr error
			for range test.writeErrs {
				sendErr = failing.SendProbe(context.Background(), target, []byte("probe"))
			}
			if !errors.Is(sendErr, test.wantError) {
				t.Fatalf("terminal send error = %v, want %v", sendErr, test.wantError)
			}
			waitForControllerStop(t, controller)
			if err := sibling.SendProbe(context.Background(), target, []byte("late")); !errors.Is(err, ErrLeaseClosed) {
				t.Fatalf("sibling send after trip = %v, want ErrLeaseClosed", err)
			}
			if active := tracked.active.Load(); active != 0 {
				t.Fatalf("OS sockets after attempt trip = %d, want 0", active)
			}
			status := machine.Snapshot().SafetyTrip
			if !status.BlocksActiveWork || status.Record.Reason != test.wantReason {
				t.Fatalf("safety trip = %+v, want blocking reason %q", status, test.wantReason)
			}
			select {
			case <-attempt.Done():
			case <-time.After(time.Second):
				t.Fatal("faulted attempt did not finish draining")
			}
			assertPersistentTripAfterRestart(t, controller, machine, namespace, test.wantReason)
		})
	}
}

func TestUDPCancellationTimeoutPersistsTripUntilDrainWitnessCompletes(t *testing.T) {
	base := mustUDPFactory(t)
	tracked := &socketTrackingFactory{inner: base}
	blocking := &blockingReadFactory{
		inner:   tracked,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	controller, machine, attempt, namespace := newGovernedController(t, blocking, normalResources(), 40*time.Millisecond)
	socket, err := controller.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open blocking socket: %v", err)
	}
	if err := socket.RegisterTarget(netip.MustParseAddrPort("127.0.0.1:9")); err != nil {
		t.Fatalf("register target: %v", err)
	}

	readResult := make(chan error, 1)
	go func() {
		_, _, readErr := socket.ReceiveReply(context.Background(), make([]byte, 32), acceptReply)
		readResult <- readErr
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("blocking read did not start")
	}

	if err := attempt.Close(); !errors.Is(err, governor.ErrCancellationDrainTimeout) {
		t.Fatalf("attempt close error = %v, want cancellation drain timeout", err)
	}
	status := machine.Snapshot().SafetyTrip
	if !status.BlocksActiveWork || status.Record.Reason != governor.SafetyTripCancellation {
		t.Fatalf("timeout safety trip = %+v", status)
	}
	if active := tracked.active.Load(); active != 0 {
		t.Fatalf("OS sockets while drain witness is pending = %d, want 0", active)
	}

	close(blocking.release)
	select {
	case err := <-readResult:
		if !errors.Is(err, ErrLeaseClosed) {
			t.Fatalf("released read error = %v, want ErrLeaseClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read worker did not exit after drain witness release")
	}
	waitForControllerStop(t, controller)
	assertPersistentTripAfterRestart(t, controller, machine, namespace, governor.SafetyTripCancellation)
}

func acceptReply([]byte, netip.AddrPort) error { return nil }

func mustUDPFactory(t *testing.T) *UDPFactory {
	t.Helper()
	factory, err := NewUDPFactory(UDPFactoryConfig{LocalAddr: loopbackEphemeral})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	return factory
}

func newFakeController(t *testing.T, factory Factory, resources governor.Resources) (*Controller, *fakeLease) {
	t.Helper()
	lease := newFakeLease(resources)
	controller, err := New(Config{
		Lease:              lease,
		Generation:         NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "probeio-udp-test",
	})
	if err != nil {
		t.Fatalf("new fake controller: %v", err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Errorf("close fake controller: %v", err)
		}
	})
	return controller, lease
}

func newGovernedController(t *testing.T, factory Factory, resources governor.Resources, drainTimeout time.Duration) (*Controller, *governor.Governor, *governor.AttemptLease, string) {
	t.Helper()
	namespace := t.TempDir()
	initializeTestSafetyTrip(t, namespace)
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "probeio-udp-test")
	if err != nil {
		t.Fatalf("acquire governor owner: %v", err)
	}
	limits, err := governor.HardLimits(governor.ProfilePhase1Machine)
	if err != nil {
		t.Fatalf("machine hard limits: %v", err)
	}
	limits.CancellationDrainTimeout = drainTimeout
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, &limits)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new machine governor: %v", err)
	}
	peer, err := machine.AcquirePeer("peer-probeio-udp")
	if err != nil {
		_ = machine.Close()
		t.Fatalf("acquire peer: %v", err)
	}
	attempt, err := peer.AcquireAttempt(context.Background(), governor.AttemptRequest{
		ID:        "attempt-probeio-udp",
		Operation: governor.OperationConnectTest,
		Cost: governor.AttemptCost{
			Resources: resources,
			Duration:  30 * time.Second,
		},
	})
	if err != nil {
		_ = machine.Close()
		t.Fatalf("acquire attempt: %v", err)
	}
	controller, err := New(Config{
		Lease:              attempt,
		Generation:         NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "probeio-udp-test",
	})
	if err != nil {
		_ = machine.Close()
		t.Fatalf("new governed controller: %v", err)
	}
	t.Cleanup(func() {
		_ = controller.Close()
		_ = machine.Close()
	})
	return controller, machine, attempt, namespace
}

func initializeTestSafetyTrip(t *testing.T, namespace string) {
	t.Helper()
	record := governor.SafetyTripRecord{
		SchemaVersion: 1,
		State:         governor.SafetyTripClear,
		UpdatedAt:     time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC),
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal clear safety record: %v", err)
	}
	checksum := sha256.Sum256(recordPayload)
	envelopePayload, err := json.Marshal(struct {
		Record   governor.SafetyTripRecord `json:"record"`
		Checksum string                    `json:"checksum"`
	}{
		Record:   record,
		Checksum: hex.EncodeToString(checksum[:]),
	})
	if err != nil {
		t.Fatalf("marshal clear safety envelope: %v", err)
	}
	data := append([]byte{'C'}, envelopePayload...)
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(namespace, "safety-trip.json"), data, 0o600); err != nil {
		t.Fatalf("write clear safety state: %v", err)
	}
}

func assertPersistentTripAfterRestart(t *testing.T, controller *Controller, machine *governor.Governor, namespace string, reason governor.SafetyTripReason) {
	t.Helper()
	if err := controller.Close(); err != nil && !errors.Is(err, governor.ErrCancellationDrainTimeout) {
		t.Fatalf("close controller before restart: %v", err)
	}
	if err := machine.Close(); err != nil && !errors.Is(err, governor.ErrCancellationDrainTimeout) {
		t.Fatalf("close governor before restart: %v", err)
	}
	restartedOwner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "probeio-udp-restart-test")
	if err != nil {
		t.Fatalf("reacquire governor owner: %v", err)
	}
	defer func() { _ = restartedOwner.Close() }()
	status := restartedOwner.SafetyTripStatus()
	if !status.BlocksActiveWork || status.Record.Reason != reason {
		t.Fatalf("reloaded safety trip = %+v, want reason %q", status, reason)
	}
	if restarted, err := governor.New(restartedOwner, governor.ProfilePhase1Machine, nil); !errors.Is(err, governor.ErrSafetyTripped) {
		if restarted != nil {
			_ = restarted.Close()
		}
		t.Fatalf("restarted governor error = %v, want ErrSafetyTripped", err)
	}
}

func waitForControllerStop(t *testing.T, controller *Controller) {
	t.Helper()
	select {
	case <-controller.watchDone:
	case <-time.After(time.Second):
		t.Fatal("probeio controller did not stop within one second")
	}
}

type socketTrackingFactory struct {
	inner   Factory
	active  atomic.Int64
	maximum atomic.Int64
}

func (factory *socketTrackingFactory) Open(ctx context.Context) (Datagram, error) {
	datagram, err := factory.inner.Open(ctx)
	if err != nil {
		return nil, err
	}
	active := factory.active.Add(1)
	for {
		maximum := factory.maximum.Load()
		if active <= maximum || factory.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	return &trackedDatagram{Datagram: datagram, onClose: func() { factory.active.Add(-1) }}, nil
}

type trackedDatagram struct {
	Datagram
	closeOnce sync.Once
	onClose   func()
	closeErr  error
}

func (datagram *trackedDatagram) Close() error {
	datagram.closeOnce.Do(func() {
		datagram.closeErr = datagram.Datagram.Close()
		datagram.onClose()
	})
	return datagram.closeErr
}

type writeFaultFactory struct {
	inner             Factory
	mu                sync.Mutex
	opened            int
	firstSocketErrors []error
}

func (factory *writeFaultFactory) Open(ctx context.Context) (Datagram, error) {
	datagram, err := factory.inner.Open(ctx)
	if err != nil {
		return nil, err
	}
	factory.mu.Lock()
	index := factory.opened
	factory.opened++
	factory.mu.Unlock()
	if index != 0 {
		return datagram, nil
	}
	return &writeFaultDatagram{Datagram: datagram, errors: append([]error(nil), factory.firstSocketErrors...)}, nil
}

type writeFaultDatagram struct {
	Datagram
	mu     sync.Mutex
	errors []error
}

func (datagram *writeFaultDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	datagram.mu.Lock()
	if len(datagram.errors) > 0 {
		err := datagram.errors[0]
		datagram.errors = datagram.errors[1:]
		datagram.mu.Unlock()
		return 0, &net.OpError{Op: "write", Net: "udp", Err: err}
	}
	datagram.mu.Unlock()
	return datagram.Datagram.WriteTo(ctx, packet, target)
}

type blockingReadFactory struct {
	inner   Factory
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (factory *blockingReadFactory) Open(ctx context.Context) (Datagram, error) {
	datagram, err := factory.inner.Open(ctx)
	if err != nil {
		return nil, err
	}
	return &blockingReadDatagram{
		Datagram: datagram,
		started:  factory.started,
		release:  factory.release,
		once:     &factory.once,
	}, nil
}

type blockingReadDatagram struct {
	Datagram
	started chan struct{}
	release chan struct{}
	once    *sync.Once
}

func (datagram *blockingReadDatagram) ReadFrom(ctx context.Context, dst []byte) (int, netip.AddrPort, error) {
	datagram.once.Do(func() { close(datagram.started) })
	<-datagram.release
	return datagram.Datagram.ReadFrom(ctx, dst)
}

type doubleOpenFactory struct {
	inner       Factory
	secondError error
}

func (factory *doubleOpenFactory) Open(ctx context.Context) (Datagram, error) {
	first, err := factory.inner.Open(ctx)
	if err != nil {
		return nil, err
	}
	second, secondErr := factory.inner.Open(ctx)
	factory.secondError = secondErr
	if second != nil {
		_ = second.Close()
		_ = first.Close()
		return nil, errors.New("second UDP socket escaped one-time controller permit")
	}
	return first, nil
}
