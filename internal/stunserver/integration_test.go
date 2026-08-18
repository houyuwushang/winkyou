package stunserver_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/stunserver"
)

func TestResponseServerRoundTripsThroughProductionObserver(t *testing.T) {
	server, err := stunserver.Open(stunserver.Config{
		ListenAddr: netip.MustParseAddrPort("127.0.0.1:0"),
		MaxPPS:     20,
	})
	if err != nil {
		t.Fatalf("listen responder: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("serve responder: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("responder did not exit")
		}
	})

	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.MustParseAddrPort("127.0.0.1:0"),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	client, err := stunobserve.New(stunobserve.Config{
		Lease:              newTestLease(stunobserve.WorstCaseCost()),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "wink-stund-integration-test",
	})
	if err != nil {
		t.Fatalf("new observer: %v", err)
	}
	observation, err := client.Observe(context.Background(), server.ListenAddr())
	if err != nil {
		t.Fatalf("observe responder: %v", err)
	}
	mapped, err := netip.ParseAddrPort(observation.Details["mapped_address"])
	if err != nil || !mapped.Addr().IsLoopback() || mapped.Port() == 0 {
		t.Fatalf("mapped endpoint = %q: %v", observation.Details["mapped_address"], err)
	}
	if observation.Details["mapped_attribute"] != "xor_mapped_address" || observation.Details["transmissions"] != "1" {
		t.Fatalf("observation details = %#v", observation.Details)
	}
	stats := server.Snapshot()
	if stats.Received != 1 || stats.Responded != 1 {
		t.Fatalf("responder stats = %+v", stats)
	}
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
			ID:        "attempt-wink-stund-integration",
			Operation: governor.OperationDiagnose,
			Cost:      cost,
		},
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (lease *testLease) Request() governor.AttemptRequest { return lease.request }
func (lease *testLease) PeerID() string                   { return "peer-wink-stund-integration" }
func (lease *testLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *testLease) Done() <-chan struct{}            { return lease.done }

func (lease *testLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
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
		drain.lease.mu.Lock()
		if drain.lease.drains > 0 {
			drain.lease.drains--
		}
		if drain.lease.stoppingClosed && drain.lease.drains == 0 && !drain.lease.doneClosed {
			drain.lease.doneClosed = true
			close(drain.lease.done)
		}
		drain.lease.mu.Unlock()
	})
	return nil
}
