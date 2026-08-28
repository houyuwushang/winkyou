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
	// The client validating the response is not a synchronization witness for
	// the server-side Responded counter: the datagram can be received before
	// the responder loop resumes to increment it (issue #69). Wait with a
	// bounded conditional deadline; the final exact assertions are unchanged.
	stats := waitForResponderStats(t, server, 1)
	if stats.Received != 1 || stats.Responded != 1 || stats.Dropped.WriteFailure != 0 {
		t.Fatalf("responder stats = %+v", stats)
	}
}

// waitForResponderStats polls Snapshot with a bounded deadline until both
// Received and Responded reach want, then returns the final snapshot for
// exact assertions. It never sleeps past the observation becoming true.
func waitForResponderStats(t *testing.T, server *stunserver.Server, want uint64) stunserver.Stats {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		stats := server.Snapshot()
		if (stats.Received >= want && stats.Responded >= want) || !time.Now().Before(deadline) {
			return stats
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestTwoResponseServersObserveThroughOneGovernedSocket(t *testing.T) {
	first := startResponseServer(t)
	second := startResponseServer(t)
	cost, err := stunobserve.MappingWorstCaseCost(2)
	if err != nil {
		t.Fatalf("mapping cost: %v", err)
	}
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.MustParseAddrPort("127.0.0.1:0"),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	client, err := stunobserve.NewMapping(stunobserve.Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "wink-stund-mapping-integration-test",
	}, 2)
	if err != nil {
		t.Fatalf("new mapping observer: %v", err)
	}
	result, err := client.Observe(context.Background(), []netip.AddrPort{first.ListenAddr(), second.ListenAddr()})
	if err != nil {
		t.Fatalf("observe mapping: %v", err)
	}
	if len(result.Results) != 2 || result.Results[0].Err != nil || result.Results[1].Err != nil {
		t.Fatalf("mapping results = %+v", result.Results)
	}
	firstLocal, err := netip.ParseAddrPort(result.Results[0].Observation.LocalAddr)
	if err != nil {
		t.Fatalf("first local endpoint: %v", err)
	}
	secondLocal, err := netip.ParseAddrPort(result.Results[1].Observation.LocalAddr)
	if err != nil {
		t.Fatalf("second local endpoint: %v", err)
	}
	firstMapped, err := netip.ParseAddrPort(result.Results[0].Observation.Details["mapped_address"])
	if err != nil {
		t.Fatalf("first mapped endpoint: %v", err)
	}
	secondMapped, err := netip.ParseAddrPort(result.Results[1].Observation.Details["mapped_address"])
	if err != nil {
		t.Fatalf("second mapped endpoint: %v", err)
	}
	if firstLocal != secondLocal || firstMapped != secondMapped || firstMapped != firstLocal {
		t.Fatalf("single-socket endpoints: local=%v/%v mapped=%v/%v", firstLocal, secondLocal, firstMapped, secondMapped)
	}
	if result.Classification.Behavior != stunobserve.MappingBehaviorConsistentSameAddress ||
		len(result.Classification.Limitations) != 1 ||
		result.Classification.Limitations[0] != stunobserve.MappingLimitationAddressComparisonUnavailable {
		t.Fatalf("classification = %+v", result.Classification)
	}
}

func TestOneResponseServerObservesThroughMultipleGovernedSockets(t *testing.T) {
	server := startResponseServer(t)
	const sockets = stunobserve.DefaultAllocationSockets
	cost, err := stunobserve.AllocationWorstCaseCost(sockets)
	if err != nil {
		t.Fatalf("allocation cost: %v", err)
	}
	factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
		LocalAddr: netip.MustParseAddrPort("127.0.0.1:0"),
	})
	if err != nil {
		t.Fatalf("new UDP factory: %v", err)
	}
	client, err := stunobserve.NewAllocation(stunobserve.Config{
		Lease:              newTestLease(cost),
		Generation:         probeio.NewGeneration(1),
		ExpectedGeneration: 1,
		Factory:            factory,
		BuildVersion:       "wink-stund-allocation-integration-test",
	}, sockets)
	if err != nil {
		t.Fatalf("new allocation observer: %v", err)
	}
	result, err := client.Observe(context.Background(), server.ListenAddr())
	if err != nil {
		t.Fatalf("observe allocation: %v", err)
	}
	if len(result.Results) != sockets || result.Classification.SuccessfulSockets != sockets {
		t.Fatalf("allocation result = %+v", result)
	}
	locals := make(map[netip.AddrPort]struct{}, sockets)
	for _, socketResult := range result.Results {
		if socketResult.Err != nil {
			t.Fatalf("socket result = %+v", socketResult)
		}
		if _, exists := locals[socketResult.Local]; exists {
			t.Fatalf("local endpoint was reused: %v", socketResult.Local)
		}
		locals[socketResult.Local] = struct{}{}
		mapped, parseErr := netip.ParseAddrPort(socketResult.Observation.Details["mapped_address"])
		if parseErr != nil || mapped != socketResult.Local {
			t.Fatalf("mapped endpoint=%q local=%v err=%v", socketResult.Observation.Details["mapped_address"], socketResult.Local, parseErr)
		}
	}
	stats := waitForResponderStats(t, server, sockets)
	if stats.Received != sockets || stats.Responded != sockets || stats.Dropped.WriteFailure != 0 {
		t.Fatalf("responder stats = %+v", stats)
	}
}

func startResponseServer(t *testing.T) *stunserver.Server {
	t.Helper()
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
	return server
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
