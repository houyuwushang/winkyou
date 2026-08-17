package stunobserve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
)

// Keep the accelerated schedule well below the 500 ms production RTO while
// leaving enough room for the loopback responder goroutine under race and
// high-repeat scheduler load.
const testRTO = 20 * time.Millisecond

var loopbackIPv4 = netip.MustParseAddr("127.0.0.1")

type responderMode string

const (
	responderSuccess          responderMode = "success"
	responderWrongCookie      responderMode = "wrong_cookie"
	responderWrongTransaction responderMode = "wrong_transaction"
	responderTruncated        responderMode = "truncated"
	responderUnknownRequired  responderMode = "unknown_required"
	responderWrongSource      responderMode = "wrong_source"
	responderSilent           responderMode = "silent"
)

func TestClientObservesBindingAndRejectsFaultModes(t *testing.T) {
	tests := []struct {
		name       string
		mode       responderMode
		wantError  error
		wantClass  string
		wantReason string
		wantSends  int32
	}{
		{name: "success", mode: responderSuccess, wantSends: 1},
		{name: "wrong cookie", mode: responderWrongCookie, wantError: ErrMagicCookieMismatch, wantClass: ErrorClassProtocol, wantReason: "magic_cookie_mismatch", wantSends: 1},
		{name: "wrong transaction", mode: responderWrongTransaction, wantError: ErrTransactionMismatch, wantClass: ErrorClassProtocol, wantReason: "transaction_id_mismatch", wantSends: 1},
		{name: "truncated attribute", mode: responderTruncated, wantError: ErrAttributeLength, wantClass: ErrorClassProtocol, wantReason: "attribute_length_invalid", wantSends: 1},
		{name: "unknown required", mode: responderUnknownRequired, wantError: ErrUnknownRequiredAttribute, wantClass: ErrorClassProtocol, wantReason: "unknown_required_attribute", wantSends: 1},
		{name: "wrong source port", mode: responderWrongSource, wantError: ErrSourceMismatch, wantClass: ErrorClassSource, wantReason: "response_source_mismatch", wantSends: 1},
		{name: "bounded timeout", mode: responderSilent, wantError: ErrTimeout, wantClass: ErrorClassTimeout, wantReason: "binding_timeout", wantSends: MaxTransmissions},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, serverPackets := startLoopbackResponder(t, test.mode)
			factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
				LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0),
			})
			if err != nil {
				t.Fatalf("new UDP factory: %v", err)
			}
			counted := &countingFactory{inner: factory}
			lease := newTestLease(acceleratedTestCost())
			client, err := newClient(Config{
				Lease:              lease,
				Generation:         probeio.NewGeneration(1),
				ExpectedGeneration: 1,
				Factory:            counted,
				BuildVersion:       "stunobserve-test",
			}, deterministicRandom(), time.Now, testRTO)
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			observation, observeErr := client.Observe(context.Background(), target)
			if !errors.Is(observeErr, test.wantError) {
				t.Fatalf("observe error = %v, want %v", observeErr, test.wantError)
			}
			if observation.ErrorClass != test.wantClass || observation.Reason != test.wantReason {
				t.Fatalf("observation error = %q/%q, want %q/%q", observation.ErrorClass, observation.Reason, test.wantClass, test.wantReason)
			}
			if observation.Strategy != ObservationStrategy || observation.Details["observation_scope"] != "time_window_only" {
				t.Fatalf("observation boundary = %+v", observation)
			}
			if observation.Details["transmissions"] != intString(test.wantSends) {
				t.Fatalf("transmissions = %q, want %d", observation.Details["transmissions"], test.wantSends)
			}
			if counted.opens.Load() != 1 || counted.writes.Load() > MaxTransmissions {
				t.Fatalf("actual resources: opens=%d writes=%d", counted.opens.Load(), counted.writes.Load())
			}
			if got := serverPackets.Load(); got != test.wantSends {
				t.Fatalf("server packets = %d, want %d", got, test.wantSends)
			}
			if test.mode == responderSuccess {
				if observation.Details["mapped_attribute"] != "xor_mapped_address" {
					t.Fatalf("success details = %#v", observation.Details)
				}
				mapped, err := netip.ParseAddrPort(observation.Details["mapped_address"])
				if err != nil || !mapped.Addr().IsLoopback() {
					t.Fatalf("mapped address = %q: %v", observation.Details["mapped_address"], err)
				}
			}
		})
	}
}

func TestClientRejectsInsufficientBudgetBeforeOpeningSocket(t *testing.T) {
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	counted := &countingFactory{inner: factory}
	cost := WorstCaseCost()
	cost.Resources.Packets--
	_, err = New(Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            counted,
		BuildVersion:       "stunobserve-test",
	})
	if !errors.Is(err, ErrInsufficientBudget) {
		t.Fatalf("new error = %v, want insufficient budget", err)
	}
	if counted.opens.Load() != 0 {
		t.Fatalf("factory opens = %d, want zero", counted.opens.Load())
	}
}

func TestWorstCaseCostIsFrozenAndCoversProductionSchedule(t *testing.T) {
	cost := WorstCaseCost()
	want := governor.Resources{
		Sockets:          1,
		Targets:          1,
		PacketsPerSecond: 2,
		Packets:          3,
		FiveTuples:       1,
	}
	if cost.Resources != want || cost.Duration != 4*time.Second || cost.Heavyweight {
		t.Fatalf("worst-case cost = %+v, want resources=%+v duration=4s non-heavy", cost, want)
	}
}

func TestClientRejectsNonLoopbackTargetWithoutSending(t *testing.T) {
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	counted := &countingFactory{inner: factory}
	client, err := newClient(Config{
		Lease:              newTestLease(WorstCaseCost()),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            counted,
		BuildVersion:       "stunobserve-test",
	}, deterministicRandom(), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	observation, err := client.Observe(context.Background(), netip.MustParseAddrPort("192.0.2.10:3478"))
	if !errors.Is(err, ErrInvalidTarget) || observation.ErrorClass != ErrorClassInvalidTarget {
		t.Fatalf("observe = %+v, %v", observation, err)
	}
	if counted.opens.Load() != 0 || counted.writes.Load() != 0 {
		t.Fatalf("resources = opens=%d writes=%d, want zero", counted.opens.Load(), counted.writes.Load())
	}
}

func TestClientAllowNonLoopbackDefaultsOffAndAcceptsOnlyExplicitUnicast(t *testing.T) {
	client, err := newClient(Config{
		Lease:              newTestLease(WorstCaseCost()),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            mustLoopbackFactory(t),
		BuildVersion:       "stunobserve-test",
	}, deterministicRandom(), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new default client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if client.allowNonLoopback {
		t.Fatal("AllowNonLoopback defaulted to true")
	}

	target := netip.MustParseAddrPort("192.0.2.10:3478")
	if _, err := canonicalTarget(target, false); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("default target error = %v, want loopback rejection", err)
	}
	if got, err := canonicalTarget(target, true); err != nil || got != target {
		t.Fatalf("explicit unicast target = %v, %v", got, err)
	}
	for _, invalid := range []netip.AddrPort{
		netip.MustParseAddrPort("0.0.0.0:3478"),
		netip.MustParseAddrPort("224.0.0.1:3478"),
		netip.MustParseAddrPort("[ff02::1]:3478"),
	} {
		if _, err := canonicalTarget(invalid, true); !errors.Is(err, ErrInvalidUnicastTarget) {
			t.Errorf("explicit invalid target %v error = %v, want unicast rejection", invalid, err)
		}
	}
}

func TestProbeSocketRejectsUnregisteredSTUNTarget(t *testing.T) {
	target, _ := startLoopbackResponder(t, responderSilent)
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	counted := &countingFactory{inner: factory}
	lease := newTestLease(WorstCaseCost())
	controller, err := probeio.New(probeio.Config{
		Lease:              lease,
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            counted,
		BuildVersion:       "stunobserve-test",
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	socket, err := controller.OpenProbeSocket(context.Background())
	if err != nil {
		t.Fatalf("open socket: %v", err)
	}
	packet, _, err := newBindingRequest(bytes.NewReader(make([]byte, 12)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := socket.SendProbe(context.Background(), target, packet); !errors.Is(err, probeio.ErrUnregisteredTarget) {
		t.Fatalf("send error = %v, want unregistered target", err)
	}
	if counted.writes.Load() != 0 {
		t.Fatalf("datagram writes = %d, want zero", counted.writes.Load())
	}
}

func TestClientIsSingleUse(t *testing.T) {
	target, _ := startLoopbackResponder(t, responderSuccess)
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0)})
	if err != nil {
		t.Fatalf("new factory: %v", err)
	}
	client, err := newClient(Config{
		Lease:              newTestLease(WorstCaseCost()),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "stunobserve-test",
	}, deterministicRandom(), time.Now, testRTO)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := client.Observe(context.Background(), target); err != nil {
		t.Fatalf("first observe: %v", err)
	}
	if _, err := client.Observe(context.Background(), target); !errors.Is(err, ErrAlreadyObserved) {
		t.Fatalf("second observe = %v, want single-use rejection", err)
	}
}

type countingFactory struct {
	inner  probeio.Factory
	opens  atomic.Int32
	writes atomic.Int32
}

func (factory *countingFactory) Open(ctx context.Context) (probeio.Datagram, error) {
	datagram, err := factory.inner.Open(ctx)
	if err != nil {
		return nil, err
	}
	factory.opens.Add(1)
	return &countingDatagram{Datagram: datagram, writes: &factory.writes}, nil
}

type countingDatagram struct {
	probeio.Datagram
	writes *atomic.Int32
}

func (datagram *countingDatagram) WriteTo(ctx context.Context, packet []byte, target netip.AddrPort) (int, error) {
	datagram.writes.Add(1)
	return datagram.Datagram.WriteTo(ctx, packet, target)
}

type testLease struct {
	request  governor.AttemptRequest
	stopping chan struct{}
	done     chan struct{}

	mu             sync.Mutex
	drains         int
	stoppingClosed bool
	doneClosed     bool
}

func newTestLease(cost governor.AttemptCost) *testLease {
	return &testLease{
		request: governor.AttemptRequest{
			ID:        "attempt-stunobserve",
			Operation: governor.OperationDiagnose,
			Cost:      cost,
		},
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (lease *testLease) Request() governor.AttemptRequest { return lease.request }
func (lease *testLease) PeerID() string                   { return "peer-stunobserve" }
func (lease *testLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *testLease) Done() <-chan struct{}            { return lease.done }

func (lease *testLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.stoppingClosed {
		return nil, governor.ErrLeaseClosed
	}
	lease.drains++
	return &testDrain{lease: lease}, nil
}

func (lease *testLease) Close() error {
	lease.mu.Lock()
	if !lease.stoppingClosed {
		lease.stoppingClosed = true
		close(lease.stopping)
	}
	if lease.drains == 0 && !lease.doneClosed {
		lease.doneClosed = true
		close(lease.done)
	}
	done := lease.done
	lease.mu.Unlock()
	<-done
	return nil
}

func (lease *testLease) Trip(event governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	lease.mu.Lock()
	if !lease.stoppingClosed {
		lease.stoppingClosed = true
		close(lease.stopping)
	}
	lease.mu.Unlock()
	return governor.SafetyTripStatus{
		State:            governor.SafetyTripTripped,
		BlocksActiveWork: true,
		Record: governor.SafetyTripRecord{
			SchemaVersion: 1,
			State:         governor.SafetyTripTripped,
			Reason:        event.Reason,
		},
	}, nil
}

type testDrain struct {
	lease *testLease
	once  sync.Once
}

func (drain *testDrain) Complete() error {
	drain.once.Do(func() {
		lease := drain.lease
		lease.mu.Lock()
		if lease.drains > 0 {
			lease.drains--
		}
		if lease.stoppingClosed && lease.drains == 0 && !lease.doneClosed {
			lease.doneClosed = true
			close(lease.done)
		}
		lease.mu.Unlock()
	})
	return nil
}

func startLoopbackResponder(t *testing.T, mode responderMode) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopbackIPv4, 0)))
	if err != nil {
		t.Fatalf("listen loopback responder: %v", err)
	}
	var alternate *net.UDPConn
	if mode == responderWrongSource {
		alternate, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopbackIPv4, 0)))
		if err != nil {
			_ = connection.Close()
			t.Fatalf("listen alternate responder: %v", err)
		}
	}
	done := make(chan struct{})
	packets := &atomic.Int32{}
	go func() {
		defer close(done)
		buffer := make([]byte, maxSTUNMessageBytes+1)
		for {
			n, from, readErr := connection.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				return
			}
			packets.Add(1)
			if mode == responderSilent {
				continue
			}
			if n < stunHeaderBytes {
				return
			}
			var transaction transactionID
			copy(transaction[:], buffer[8:20])
			mapped := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			response := bindingSuccess(transaction, stunAttribute(attributeXORMappedAddress, mappedAddressValue(mapped, transaction, true), nil))
			switch mode {
			case responderWrongCookie:
				binary.BigEndian.PutUint32(response[4:8], 0)
			case responderWrongTransaction:
				response[8] ^= 0xff
			case responderTruncated:
				response = response[:len(response)-1]
			case responderUnknownRequired:
				response = bindingSuccess(transaction, stunAttribute(0x0002, nil, nil))
			}
			writer := connection
			if alternate != nil {
				writer = alternate
			}
			_, _ = writer.WriteToUDPAddrPort(response, from)
			return
		}
	}()
	t.Cleanup(func() {
		_ = connection.Close()
		if alternate != nil {
			_ = alternate.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("loopback responder did not exit")
		}
	})
	return connection.LocalAddr().(*net.UDPAddr).AddrPort(), packets
}

func intString(value int32) string {
	if value == 0 {
		return "0"
	}
	var digits [10]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

func acceleratedTestCost() governor.AttemptCost {
	cost := WorstCaseCost()
	// Tests compress the 500 ms production RTO to 20 ms. Reserve all three
	// transmissions in one second so the accelerated clock cannot weaken the
	// probeio PPS guard being exercised.
	cost.Resources.PacketsPerSecond = MaxTransmissions
	return cost
}

func deterministicRandom() *bytes.Reader {
	return bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
}

func mustLoopbackFactory(t *testing.T) probeio.Factory {
	t.Helper()
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.AddrPortFrom(loopbackIPv4, 0),
	})
	if err != nil {
		t.Fatalf("new loopback factory: %v", err)
	}
	return factory
}
