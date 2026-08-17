package diagnose

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/pkg/solver"
)

type fakeActiveSTUNAuthority struct {
	snapshot     governor.Snapshot
	peer         *fakeActiveSTUNPeer
	acquireCalls int
	closeCalls   int
}

func (authority *fakeActiveSTUNAuthority) Snapshot() governor.Snapshot { return authority.snapshot }

func (authority *fakeActiveSTUNAuthority) AcquireDiagnosticPeer(string) (ActiveSTUNPeer, error) {
	authority.acquireCalls++
	return authority.peer, nil
}

func (authority *fakeActiveSTUNAuthority) Close() error {
	authority.closeCalls++
	return nil
}

type fakeActiveSTUNPeer struct {
	requests   []governor.AttemptRequest
	closeCalls int
}

func (peer *fakeActiveSTUNPeer) AcquireDiagnosticAttempt(_ context.Context, id string, cost governor.AttemptCost) (probeio.AttemptLease, error) {
	request := governor.AttemptRequest{ID: id, Operation: governor.OperationDiagnose, Cost: cost}
	peer.requests = append(peer.requests, request)
	return &fakeActiveSTUNLease{request: request}, nil
}

func (peer *fakeActiveSTUNPeer) Close() error {
	peer.closeCalls++
	return nil
}

type fakeActiveSTUNLease struct {
	request governor.AttemptRequest
}

func (lease *fakeActiveSTUNLease) Request() governor.AttemptRequest { return lease.request }
func (*fakeActiveSTUNLease) PeerID() string                         { return "diagnose-active-stun" }
func (*fakeActiveSTUNLease) Stopping() <-chan struct{}              { return make(chan struct{}) }
func (*fakeActiveSTUNLease) Done() <-chan struct{}                  { return make(chan struct{}) }
func (*fakeActiveSTUNLease) RegisterDrain(string) (governor.DrainHandle, error) {
	return fakeActiveSTUNDrain{}, nil
}
func (*fakeActiveSTUNLease) Close() error { return nil }
func (*fakeActiveSTUNLease) Trip(governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	return governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true}, nil
}

type fakeActiveSTUNDrain struct{}

func (fakeActiveSTUNDrain) Complete() error { return nil }

type fakeActiveSTUNObserver struct {
	observation solver.Observation
	err         error
	closeCalls  int
}

func (observer *fakeActiveSTUNObserver) Observe(context.Context, netip.AddrPort) (solver.Observation, error) {
	return observer.observation, observer.err
}

func (observer *fakeActiveSTUNObserver) Close() error {
	observer.closeCalls++
	return nil
}

func readyActiveSTUNSnapshot(t *testing.T, scope governor.Scope) governor.Snapshot {
	t.Helper()
	profile := governor.ProfilePhase1Machine
	if scope == governor.ScopeUserAcknowledged {
		profile = governor.ProfilePhase1UserAcknowledged
	}
	limits, err := governor.HardLimits(profile)
	if err != nil {
		t.Fatalf("hard limits: %v", err)
	}
	return governor.Snapshot{
		Profile:    profile,
		Scope:      scope,
		Limits:     limits,
		SafetyTrip: governor.SafetyTripStatus{State: governor.SafetyTripClear},
	}
}

func TestActiveSTUNPreflightRejectsAggregateCostBeforePeerOrFactory(t *testing.T) {
	snapshot := readyActiveSTUNSnapshot(t, governor.ScopeMachine)
	snapshot.Limits.Aggregate.Sockets = 2
	peer := &fakeActiveSTUNPeer{}
	authority := &fakeActiveSTUNAuthority{snapshot: snapshot, peer: peer}
	factoryCalls := 0
	inspector := ActiveSTUNInspector{
		AcquireMachine: func(string) (ActiveSTUNAuthority, error) { return authority, nil },
		Factory: func(netip.AddrPort) (probeio.Factory, error) {
			factoryCalls++
			return nil, errors.New("must not be called")
		},
		BuildVersion: "test-build",
	}
	targets := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:10001"),
		netip.MustParseAddrPort("127.0.0.1:10002"),
		netip.MustParseAddrPort("127.0.0.1:10003"),
	}

	report, err := inspector.Run(context.Background(), ActiveSTUNOptions{Targets: targets, GovernorScope: governor.ScopeMachine})
	if !errors.Is(err, ErrActiveSTUNBudget) {
		t.Fatalf("preflight error = %v", err)
	}
	if report.State != ActiveSTUNStateBlocked || report.ErrorClass != "budget_rejected" || report.NetworkActivityStarted {
		t.Fatalf("blocked report = %+v", report)
	}
	if authority.acquireCalls != 0 || factoryCalls != 0 || len(peer.requests) != 0 {
		t.Fatalf("work before preflight: acquire_peer=%d factory=%d attempts=%d", authority.acquireCalls, factoryCalls, len(peer.requests))
	}
	if authority.closeCalls != 1 {
		t.Fatalf("authority close calls = %d", authority.closeCalls)
	}
}

func TestActiveSTUNSafetyTripRejectsBeforePeerOrFactory(t *testing.T) {
	snapshot := readyActiveSTUNSnapshot(t, governor.ScopeMachine)
	snapshot.SafetyTrip = governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true}
	authority := &fakeActiveSTUNAuthority{snapshot: snapshot, peer: &fakeActiveSTUNPeer{}}
	factoryCalls := 0
	inspector := ActiveSTUNInspector{
		AcquireMachine: func(string) (ActiveSTUNAuthority, error) { return authority, nil },
		Factory: func(netip.AddrPort) (probeio.Factory, error) {
			factoryCalls++
			return nil, errors.New("must not be called")
		},
	}

	report, err := inspector.Run(context.Background(), ActiveSTUNOptions{
		Targets:       []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478")},
		GovernorScope: governor.ScopeMachine,
	})
	if !errors.Is(err, ErrActiveSTUNSafetyTrip) || report.ErrorClass != "safety_trip" || report.NetworkActivityStarted {
		t.Fatalf("safety-trip result = %+v err=%v", report, err)
	}
	if authority.acquireCalls != 0 || factoryCalls != 0 {
		t.Fatalf("active work ran under trip: peer=%d factory=%d", authority.acquireCalls, factoryCalls)
	}
}

func TestActiveSTUNSerialTargetsRetainMixedPerTargetResults(t *testing.T) {
	peer := &fakeActiveSTUNPeer{}
	authority := &fakeActiveSTUNAuthority{snapshot: readyActiveSTUNSnapshot(t, governor.ScopeMachine), peer: peer}
	observers := []*fakeActiveSTUNObserver{
		{observation: solver.Observation{
			LocalAddr: "127.0.0.1:41000",
			Details: map[string]string{
				"mapped_address":    "198.51.100.10:41000",
				"transmissions":     "1",
				"observation_scope": "time_window_only",
			},
		}},
		{observation: solver.Observation{
			ErrorClass: stunobserve.ErrorClassProtocol,
			Reason:     "magic_cookie_mismatch",
			Details: map[string]string{
				"transmissions":     "1",
				"observation_scope": "time_window_only",
			},
		}, err: stunobserve.ErrMagicCookieMismatch},
	}
	nextObserver := 0
	inspector := ActiveSTUNInspector{
		Now:            func() time.Time { return time.UnixMilli(int64(nextObserver * 5)) },
		AcquireMachine: func(string) (ActiveSTUNAuthority, error) { return authority, nil },
		Factory: func(netip.AddrPort) (probeio.Factory, error) {
			return fakeUnusedProbeFactory{}, nil
		},
		Observer: func(stunobserve.Config) (ActiveSTUNObserver, error) {
			observer := observers[nextObserver]
			nextObserver++
			return observer, nil
		},
		BuildVersion: "test-build",
	}
	targets := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:3478"),
		netip.MustParseAddrPort("198.51.100.20:3478"),
	}

	report, err := inspector.Run(context.Background(), ActiveSTUNOptions{Targets: targets, GovernorScope: governor.ScopeMachine})
	if err != nil {
		t.Fatalf("run active STUN: %v", err)
	}
	if report.State != ActiveSTUNStateCompletedWithErrs || !report.NetworkActivityStarted || len(report.Results) != 2 {
		t.Fatalf("mixed report = %+v", report)
	}
	if report.Results[0].MappedAddress != "198.51.100.10:41000" || report.Results[0].PortBehavior != "preserved" || report.Results[0].Transmissions != 1 {
		t.Fatalf("success result = %+v", report.Results[0])
	}
	if report.Results[1].ErrorClass != stunobserve.ErrorClassProtocol || report.Results[1].Reason != "magic_cookie_mismatch" {
		t.Fatalf("failure result = %+v", report.Results[1])
	}
	if len(peer.requests) != 2 || peer.requests[0].Cost != stunobserve.WorstCaseCost() || peer.requests[1].Cost != stunobserve.WorstCaseCost() {
		t.Fatalf("attempt declarations = %+v", peer.requests)
	}
	for index, observer := range observers {
		if observer.closeCalls != 1 {
			t.Fatalf("observer %d close calls = %d", index, observer.closeCalls)
		}
	}
}

func TestApplyActiveSTUNLeavesPassiveReportUnchangedUntilExplicitlyCalled(t *testing.T) {
	report := readyInspector().Run(context.Background(), Options{})
	if report.ActiveSTUN != nil || report.NetworkActivityStarted {
		t.Fatalf("passive report acquired active section: %+v", report)
	}
	ApplyActiveSTUN(&report, ActiveSTUNReport{State: ActiveSTUNStateCompleted, NetworkActivityStarted: true})
	if report.ActiveSTUN == nil || report.Mode != "active_stun" || !report.NetworkActivityStarted || report.ActiveProbe.State != "active_probe_completed" {
		t.Fatalf("attached active report = %+v", report)
	}
}

type fakeUnusedProbeFactory struct{}

func (fakeUnusedProbeFactory) Open(context.Context) (probeio.Datagram, error) {
	return nil, errors.New("unused fake factory was opened")
}
