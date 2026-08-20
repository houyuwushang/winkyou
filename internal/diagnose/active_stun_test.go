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

type fakeActiveSTUNMappingObserver struct {
	result     stunobserve.MappingObservation
	err        error
	targets    []netip.AddrPort
	closeCalls int
}

type fakeActiveSTUNAllocationObserver struct {
	result     stunobserve.AllocationObservation
	err        error
	target     netip.AddrPort
	closeCalls int
}

func (observer *fakeActiveSTUNAllocationObserver) Observe(_ context.Context, target netip.AddrPort) (stunobserve.AllocationObservation, error) {
	observer.target = target
	return observer.result, observer.err
}

func (observer *fakeActiveSTUNAllocationObserver) Close() error {
	observer.closeCalls++
	return nil
}

func (observer *fakeActiveSTUNMappingObserver) Observe(_ context.Context, targets []netip.AddrPort) (stunobserve.MappingObservation, error) {
	observer.targets = append([]netip.AddrPort(nil), targets...)
	return observer.result, observer.err
}

func (observer *fakeActiveSTUNMappingObserver) Close() error {
	observer.closeCalls++
	return nil
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

func TestActiveSTUNMappingUsesOneAggregateAttemptAndNestedEvidence(t *testing.T) {
	targets := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:3478"),
		netip.MustParseAddrPort("192.0.2.10:3479"),
	}
	mapped := netip.MustParseAddrPort("198.51.100.10:41000")
	classification := stunobserve.ClassifyMapping([]stunobserve.MappingEndpoint{
		{Target: targets[0], Mapped: mapped},
		{Target: targets[1], Mapped: mapped},
	})
	observer := &fakeActiveSTUNMappingObserver{result: stunobserve.MappingObservation{
		Classification: classification,
		Results: []stunobserve.MappingTargetObservation{
			{Target: targets[0], Observation: mappingTestObservation(targets[0], mapped, "2026-08-18T00:00:00Z", "2026-08-18T00:00:00.005Z")},
			{Target: targets[1], Observation: mappingTestObservation(targets[1], mapped, "2026-08-18T00:00:00.005Z", "2026-08-18T00:00:00.011Z")},
		},
	}}
	peer := &fakeActiveSTUNPeer{}
	authority := &fakeActiveSTUNAuthority{snapshot: readyActiveSTUNSnapshot(t, governor.ScopeMachine), peer: peer}
	factoryCalls := 0
	inspector := ActiveSTUNInspector{
		AcquireMachine: func(string) (ActiveSTUNAuthority, error) { return authority, nil },
		Factory: func(target netip.AddrPort) (probeio.Factory, error) {
			factoryCalls++
			if target != targets[0] {
				t.Fatalf("factory target = %v, want %v", target, targets[0])
			}
			return fakeUnusedProbeFactory{}, nil
		},
		Observer: func(stunobserve.Config) (ActiveSTUNObserver, error) {
			t.Fatal("default per-target observer used in mapping mode")
			return nil, nil
		},
		MappingObserver: func(_ stunobserve.Config, targetCount int) (ActiveSTUNMappingObserver, error) {
			if targetCount != 2 {
				t.Fatalf("mapping target count = %d", targetCount)
			}
			return observer, nil
		},
		BuildVersion: "test-build",
	}

	report, err := inspector.Run(context.Background(), ActiveSTUNOptions{Targets: targets, GovernorScope: governor.ScopeMachine, MapBehavior: true})
	if err != nil {
		t.Fatalf("run mapping STUN: %v", err)
	}
	if report.State != ActiveSTUNStateCompleted || !report.NetworkActivityStarted || len(report.Results) != 0 || report.MappingBehavior == nil {
		t.Fatalf("mapping report = %+v", report)
	}
	mapping := report.MappingBehavior
	if mapping.Behavior != stunobserve.MappingBehaviorConsistentSameAddress || mapping.SuccessfulTargets != 2 || len(mapping.Results) != 2 {
		t.Fatalf("mapping evidence = %+v", mapping)
	}
	if len(mapping.Limitations) != 1 || mapping.Limitations[0] != stunobserve.MappingLimitationAddressComparisonUnavailable {
		t.Fatalf("mapping limitations = %v", mapping.Limitations)
	}
	if mapping.Results[0].DurationMS != 5 || mapping.Results[1].DurationMS != 6 || mapping.Results[0].MappedAddress != mapped.String() {
		t.Fatalf("mapping target reports = %+v", mapping.Results)
	}
	wantCost, costErr := stunobserve.MappingWorstCaseCost(2)
	if costErr != nil {
		t.Fatalf("mapping cost: %v", costErr)
	}
	if len(peer.requests) != 1 || peer.requests[0].Cost != wantCost || factoryCalls != 1 || observer.closeCalls != 1 {
		t.Fatalf("mapping lifecycle: attempts=%+v factories=%d closes=%d", peer.requests, factoryCalls, observer.closeCalls)
	}
	if len(observer.targets) != 2 || observer.targets[0] != targets[0] || observer.targets[1] != targets[1] {
		t.Fatalf("mapping targets = %v", observer.targets)
	}
}

func TestActiveSTUNAllocationUsesOneAggregateAttemptAndNestedEvidence(t *testing.T) {
	target := netip.MustParseAddrPort("203.0.113.10:3478")
	locals := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.20:31001"),
		netip.MustParseAddrPort("192.0.2.20:31002"),
		netip.MustParseAddrPort("192.0.2.20:31003"),
	}
	mapped := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.10:41000"),
		netip.MustParseAddrPort("198.51.100.10:41010"),
		netip.MustParseAddrPort("198.51.100.10:41020"),
	}
	samples := make([]stunobserve.AllocationSample, 0, len(locals))
	results := make([]stunobserve.AllocationSocketObservation, 0, len(locals))
	for index := range locals {
		samples = append(samples, stunobserve.AllocationSample{Local: locals[index], Mapped: mapped[index]})
		results = append(results, stunobserve.AllocationSocketObservation{
			Local:       locals[index],
			Observation: mappingTestObservation(target, mapped[index], "2026-08-20T00:00:00Z", "2026-08-20T00:00:00.005Z"),
		})
	}
	observer := &fakeActiveSTUNAllocationObserver{result: stunobserve.AllocationObservation{
		Classification: stunobserve.ClassifyAllocation(samples),
		Results:        results,
	}}
	peer := &fakeActiveSTUNPeer{}
	authority := &fakeActiveSTUNAuthority{snapshot: readyActiveSTUNSnapshot(t, governor.ScopeMachine), peer: peer}
	factoryCalls := 0
	inspector := ActiveSTUNInspector{
		AcquireMachine: func(string) (ActiveSTUNAuthority, error) { return authority, nil },
		Factory: func(got netip.AddrPort) (probeio.Factory, error) {
			factoryCalls++
			if got != target {
				t.Fatalf("factory target = %v, want %v", got, target)
			}
			return fakeUnusedProbeFactory{}, nil
		},
		Observer: func(stunobserve.Config) (ActiveSTUNObserver, error) {
			t.Fatal("default observer used in allocation mode")
			return nil, nil
		},
		AllocationObserver: func(_ stunobserve.Config, socketCount int) (ActiveSTUNAllocationObserver, error) {
			if socketCount != 3 {
				t.Fatalf("allocation socket count = %d", socketCount)
			}
			return observer, nil
		},
		BuildVersion: "test-build",
	}

	report, err := inspector.Run(context.Background(), ActiveSTUNOptions{Targets: []netip.AddrPort{target}, GovernorScope: governor.ScopeMachine, PortAllocationSockets: 3})
	if err != nil {
		t.Fatalf("run allocation STUN: %v", err)
	}
	if report.State != ActiveSTUNStateCompleted || !report.NetworkActivityStarted || len(report.Results) != 0 || report.PortAllocation == nil {
		t.Fatalf("allocation report = %+v", report)
	}
	allocation := report.PortAllocation
	if allocation.Behavior != stunobserve.AllocationBehaviorSequentialUniform || allocation.SuccessfulSockets != 3 || allocation.TotalSockets != 3 || len(allocation.Results) != 3 {
		t.Fatalf("allocation evidence = %+v", allocation)
	}
	if len(allocation.Deltas) != 2 || allocation.Deltas[0] != 10 || allocation.Deltas[1] != 10 || allocation.Results[0].LocalAddress != locals[0].String() {
		t.Fatalf("allocation samples = %+v", allocation)
	}
	wantCost, costErr := stunobserve.AllocationWorstCaseCost(3)
	if costErr != nil {
		t.Fatalf("allocation cost: %v", costErr)
	}
	if len(peer.requests) != 1 || peer.requests[0].Cost != wantCost || factoryCalls != 1 || observer.closeCalls != 1 || observer.target != target {
		t.Fatalf("allocation lifecycle: attempts=%+v factories=%d closes=%d target=%v", peer.requests, factoryCalls, observer.closeCalls, observer.target)
	}
}

func TestActiveSTUNAllocationDefaultCountFailsClosedUnderUserScope(t *testing.T) {
	target := netip.MustParseAddrPort("127.0.0.1:3478")
	authority := &fakeActiveSTUNAuthority{snapshot: readyActiveSTUNSnapshot(t, governor.ScopeUserAcknowledged), peer: &fakeActiveSTUNPeer{}}
	factoryCalls := 0
	inspector := ActiveSTUNInspector{
		AcquireUser: func(string) (ActiveSTUNAuthority, error) { return authority, nil },
		Factory: func(netip.AddrPort) (probeio.Factory, error) {
			factoryCalls++
			return nil, errors.New("must not be called")
		},
	}
	report, err := inspector.Run(context.Background(), ActiveSTUNOptions{
		Targets:               []netip.AddrPort{target},
		GovernorScope:         governor.ScopeUserAcknowledged,
		PortAllocationSockets: stunobserve.DefaultAllocationSockets,
	})
	if !errors.Is(err, ErrActiveSTUNBudget) || report.ErrorClass != "budget_rejected" || report.NetworkActivityStarted || report.PortAllocation == nil {
		t.Fatalf("user allocation budget result = %+v err=%v", report, err)
	}
	if authority.acquireCalls != 0 || factoryCalls != 0 {
		t.Fatalf("work ran before user budget rejection: peer=%d factory=%d", authority.acquireCalls, factoryCalls)
	}
}

func TestActiveSTUNMappingSafetyTripAndValidationRejectBeforeFactory(t *testing.T) {
	targets := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:3478"),
		netip.MustParseAddrPort("127.0.0.1:3479"),
	}
	t.Run("safety trip", func(t *testing.T) {
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
		report, err := inspector.Run(context.Background(), ActiveSTUNOptions{Targets: targets, GovernorScope: governor.ScopeMachine, MapBehavior: true})
		if !errors.Is(err, ErrActiveSTUNSafetyTrip) || report.NetworkActivityStarted || report.MappingBehavior == nil {
			t.Fatalf("safety result = %+v err=%v", report, err)
		}
		if authority.acquireCalls != 0 || factoryCalls != 0 {
			t.Fatalf("work ran under trip: peer=%d factory=%d", authority.acquireCalls, factoryCalls)
		}
	})
	t.Run("aggregate attempt budget", func(t *testing.T) {
		snapshot := readyActiveSTUNSnapshot(t, governor.ScopeMachine)
		snapshot.Limits.PerAttempt.Targets = 1
		authority := &fakeActiveSTUNAuthority{snapshot: snapshot, peer: &fakeActiveSTUNPeer{}}
		factoryCalls := 0
		inspector := ActiveSTUNInspector{
			AcquireMachine: func(string) (ActiveSTUNAuthority, error) { return authority, nil },
			Factory: func(netip.AddrPort) (probeio.Factory, error) {
				factoryCalls++
				return nil, errors.New("must not be called")
			},
		}
		report, err := inspector.Run(context.Background(), ActiveSTUNOptions{Targets: targets, GovernorScope: governor.ScopeMachine, MapBehavior: true})
		if !errors.Is(err, ErrActiveSTUNBudget) || report.ErrorClass != "budget_rejected" || report.NetworkActivityStarted {
			t.Fatalf("budget result = %+v err=%v", report, err)
		}
		if authority.acquireCalls != 0 || factoryCalls != 0 {
			t.Fatalf("work ran before budget rejection: peer=%d factory=%d", authority.acquireCalls, factoryCalls)
		}
	})

	for _, test := range []struct {
		name    string
		targets []netip.AddrPort
	}{
		{name: "one target", targets: targets[:1]},
		{name: "mixed address families", targets: []netip.AddrPort{targets[0], netip.MustParseAddrPort("[::1]:3479")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			acquireCalls := 0
			inspector := ActiveSTUNInspector{AcquireMachine: func(string) (ActiveSTUNAuthority, error) {
				acquireCalls++
				return nil, errors.New("must not acquire")
			}}
			report, err := inspector.Run(context.Background(), ActiveSTUNOptions{Targets: test.targets, GovernorScope: governor.ScopeMachine, MapBehavior: true})
			if !errors.Is(err, ErrActiveSTUNInvalidRequest) || report.NetworkActivityStarted || acquireCalls != 0 {
				t.Fatalf("validation result = %+v err=%v acquire=%d", report, err, acquireCalls)
			}
		})
	}
}

func mappingTestObservation(target, mapped netip.AddrPort, started, finished string) solver.Observation {
	return solver.Observation{
		LocalAddr:  mapped.String(),
		RemoteAddr: target.String(),
		Details: map[string]string{
			"mapped_address":     mapped.String(),
			"transmissions":      "1",
			"observation_scope":  "time_window_only",
			"window_started_at":  started,
			"window_finished_at": finished,
		},
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
