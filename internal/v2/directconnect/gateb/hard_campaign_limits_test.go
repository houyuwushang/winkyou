package gateb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatattempt"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
)

func TestGateB3ProtocolFirstOveragesPersistSafetyTrip(t *testing.T) {
	tests := []struct {
		name      string
		emissions Emissions
	}{
		{
			name: "16385th candidate",
			emissions: Emissions{
				EvidencePackets:  hardnatbudget.FreshEvidencePackets,
				CandidatePackets: hardnatbudget.Hard16CandidatePackets + 1,
				UDPPacketsTotal:  hardnatbudget.Hard16ActualPacketsMaximum,
			},
		},
		{
			name: "16399th establishment packet",
			emissions: Emissions{
				EvidencePackets:  hardnatbudget.FreshEvidencePackets,
				CandidatePackets: hardnatbudget.Hard16CandidatePackets,
				WinnerPackets:    1,
				UDPPacketsTotal:  hardnatbudget.Hard16ActualPacketsMaximum + 1,
			},
		},
		{
			name: "second winner",
			emissions: Emissions{
				EvidencePackets:  hardnatbudget.FreshEvidencePackets,
				CandidatePackets: hardnatbudget.Hard16CandidatePackets - 1,
				WinnerPackets:    2,
				UDPPacketsTotal:  hardnatbudget.Hard16ActualPacketsMaximum,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, lease := newGateB3ProtocolTripController(t)
			runtime := &runtime{
				artifact: &hardnatattempt.Artifact{
					PlannerProfile: hardnatplan.ProfileHardBirthday,
					ResourceClass:  hardnatplan.ResourceHard16KLab,
				},
				controller: controller,
				emissions:  test.emissions,
			}
			if err := runtime.validateHardProtocolShape("mutation"); !errors.Is(err, probeio.ErrHardLimit) {
				t.Fatalf("first overage = %v, want probeio.ErrHardLimit", err)
			}
			events := lease.tripEvents()
			if len(events) != 1 || events[0].Reason != governor.SafetyTripHardLimit {
				t.Fatalf("persistent trip events = %+v", events)
			}
		})
	}
}

type gateB3ProtocolTripLease struct {
	request  governor.AttemptRequest
	stopping chan struct{}
	done     chan struct{}

	mu       sync.Mutex
	trips    []governor.SafetyTripEvent
	drains   int
	stopped  bool
	doneOnce sync.Once
}

func newGateB3ProtocolTripController(t *testing.T) (*probeio.Controller, *gateB3ProtocolTripLease) {
	t.Helper()
	lease := &gateB3ProtocolTripLease{
		request: governor.AttemptRequest{
			ID:        "gate-b3-protocol-mutation",
			Operation: governor.OperationBirthday,
			Cost: governor.AttemptCost{
				Resources: governor.Resources{Sockets: 16, Targets: 16_400, FiveTuples: 16_400, Packets: 16_432, PacketsPerSecond: 512},
				Duration:  47 * time.Second,
			},
		},
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
	controller, err := probeio.New(probeio.Config{
		Lease: lease, Generation: probeio.NewGeneration(1), ExpectedGeneration: 1,
		Factory: gateB3ProtocolNoIOFactory{}, BuildVersion: "gate-b3-protocol-mutation",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := controller.Close(); err != nil {
			t.Errorf("close controller: %v", err)
		}
	})
	return controller, lease
}

func (lease *gateB3ProtocolTripLease) Request() governor.AttemptRequest { return lease.request }
func (lease *gateB3ProtocolTripLease) PeerID() string                   { return "gate-b3-peer" }
func (lease *gateB3ProtocolTripLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *gateB3ProtocolTripLease) Done() <-chan struct{}            { return lease.done }

func (lease *gateB3ProtocolTripLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.stopped {
		return nil, governor.ErrLeaseClosed
	}
	lease.drains++
	return &gateB3ProtocolTripDrain{lease: lease}, nil
}

func (lease *gateB3ProtocolTripLease) Close() error {
	lease.mu.Lock()
	lease.stopLocked()
	lease.finishLocked()
	done := lease.done
	lease.mu.Unlock()
	<-done
	return nil
}

func (lease *gateB3ProtocolTripLease) Trip(event governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	lease.mu.Lock()
	lease.trips = append(lease.trips, event)
	lease.stopLocked()
	lease.mu.Unlock()
	return governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true}, nil
}

func (lease *gateB3ProtocolTripLease) tripEvents() []governor.SafetyTripEvent {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return append([]governor.SafetyTripEvent(nil), lease.trips...)
}

func (lease *gateB3ProtocolTripLease) stopLocked() {
	if !lease.stopped {
		lease.stopped = true
		close(lease.stopping)
	}
}

func (lease *gateB3ProtocolTripLease) finishLocked() {
	if lease.stopped && lease.drains == 0 {
		lease.doneOnce.Do(func() { close(lease.done) })
	}
}

type gateB3ProtocolTripDrain struct {
	lease *gateB3ProtocolTripLease
	once  sync.Once
}

func (drain *gateB3ProtocolTripDrain) Complete() error {
	drain.once.Do(func() {
		drain.lease.mu.Lock()
		drain.lease.drains--
		drain.lease.finishLocked()
		drain.lease.mu.Unlock()
	})
	return nil
}

type gateB3ProtocolNoIOFactory struct{}

func (gateB3ProtocolNoIOFactory) Open(context.Context) (probeio.Datagram, error) {
	return nil, errors.New("Gate B3 protocol mutation unexpectedly attempted I/O")
}

var _ probeio.AttemptLease = (*gateB3ProtocolTripLease)(nil)
var _ probeio.Factory = gateB3ProtocolNoIOFactory{}
