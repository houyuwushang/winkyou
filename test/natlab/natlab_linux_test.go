//go:build linux && natlab

package natlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/stunobserve/testkit"
	"winkyou/pkg/solver"
)

var scenarioSequence atomic.Uint32

func TestLinuxNATMatrix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("netns NAT lab requires root")
	}
	for _, program := range []string{"ip", "iptables", "iptables-restore", "sysctl"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Skipf("netns NAT lab requires %s", program)
		}
	}
	for _, scenario := range []Scenario{
		ScenarioEIMPreserving,
		ScenarioRandomFully,
		ScenarioUDPBlocked,
		ScenarioCGNAT,
		ScenarioBehaviorSwap,
	} {
		t.Run(string(scenario), func(t *testing.T) {
			runLinuxScenario(t, scenario)
		})
	}
}

func runLinuxScenario(t *testing.T, scenario Scenario) {
	t.Helper()
	recipe, err := RecipeFor(scenario)
	if err != nil {
		t.Fatalf("recipe: %v", err)
	}
	sequence := scenarioSequence.Add(1)
	suffix := fmt.Sprintf("%06x", (uint32(time.Now().UnixNano())+sequence)&0xffffff)
	plan, err := NewTopologyPlan(suffix, recipe.DoubleNAT)
	if err != nil {
		t.Fatalf("topology plan: %v", err)
	}
	topology, err := CreateTopology(plan)
	if err != nil {
		t.Fatalf("create topology: %v", err)
	}
	defer func() {
		if err := topology.Cleanup(); err != nil {
			t.Errorf("cleanup topology: %v", err)
		}
		if err := topology.AssertNoLeaks(); err != nil {
			t.Errorf("topology leak witness: %v", err)
		}
	}()
	if err := topology.ApplyRecipe(recipe); err != nil {
		t.Fatalf("apply recipe: %v", err)
	}
	responder, err := startNetnsSTUNResponder(topology)
	if err != nil {
		t.Fatalf("start STUN responder: %v", err)
	}
	defer func() {
		if err := responder.Close(); err != nil {
			t.Errorf("close STUN responder: %v", err)
		}
	}()

	switch scenario {
	case ScenarioEIMPreserving:
		observation := requireSuccessfulObservation(t, topology)
		assertMappedAddress(t, observation, plan.OuterAddress)
		if behavior := portBehavior(t, observation); behavior != "preserved" {
			t.Fatalf("default MASQUERADE port behavior = %s, want preserved", behavior)
		}
	case ScenarioRandomFully:
		observation := requireTranslatedObservation(t, topology, 3)
		assertMappedAddress(t, observation, plan.OuterAddress)
	case ScenarioUDPBlocked:
		observation, observeErr := observeFromClientA(topology)
		if !errors.Is(observeErr, stunobserve.ErrTimeout) || observation.ErrorClass != stunobserve.ErrorClassTimeout || observation.Reason != "binding_timeout" {
			t.Fatalf("blocked observation = %+v err=%v", observation, observeErr)
		}
		if observation.Details["transmissions"] != strconv.Itoa(stunobserve.MaxTransmissions) {
			t.Fatalf("blocked transmissions = %q", observation.Details["transmissions"])
		}
		if responder.Packets() != 0 {
			t.Fatalf("DROP scenario delivered %d packet(s) to responder", responder.Packets())
		}
	case ScenarioCGNAT:
		observation := requireSuccessfulObservation(t, topology)
		assertMappedAddress(t, observation, plan.OuterAddress)
		for _, namespace := range []string{plan.NATA, plan.NATA2} {
			packets, err := topology.MasqueradePackets(namespace)
			if err != nil {
				t.Fatalf("read %s MASQUERADE counter: %v", namespace, err)
			}
			if packets == 0 {
				t.Fatalf("%s did not translate an outbound packet", namespace)
			}
		}
	case ScenarioBehaviorSwap:
		before := requireSuccessfulObservation(t, topology)
		if behavior := portBehavior(t, before); behavior != "preserved" {
			t.Fatalf("pre-transition behavior = %s", behavior)
		}
		if recipe.TransitionNAT == nil {
			t.Fatal("behavior-change recipe has no transition")
		}
		if err := topology.ApplyNAT(plan.NATA, *recipe.TransitionNAT); err != nil {
			t.Fatalf("atomic NAT replacement: %v", err)
		}
		after := requireTranslatedObservation(t, topology, 3)
		assertMappedAddress(t, after, plan.OuterAddress)
	default:
		t.Fatalf("unhandled scenario %q", scenario)
	}
}

func requireSuccessfulObservation(t *testing.T, topology *Topology) solver.Observation {
	t.Helper()
	observation, err := observeFromClientA(topology)
	if err != nil {
		t.Fatalf("STUN observation: %v (%+v)", err, observation)
	}
	if observation.ErrorClass != "" || observation.Details["observation_scope"] != "time_window_only" {
		t.Fatalf("successful observation = %+v", observation)
	}
	return observation
}

func requireTranslatedObservation(t *testing.T, topology *Topology, attempts int) solver.Observation {
	t.Helper()
	var last solver.Observation
	for attempt := 0; attempt < attempts; attempt++ {
		last = requireSuccessfulObservation(t, topology)
		if portBehavior(t, last) == "translated" {
			return last
		}
	}
	t.Fatalf("--random-fully preserved the port in %d independent observations; last=%+v", attempts, last)
	return solver.Observation{}
}

func observeFromClientA(topology *Topology) (solver.Observation, error) {
	var observation solver.Observation
	var observeErr error
	target, err := netip.ParseAddrPort(topology.Plan.STUNAddress)
	if err != nil {
		return observation, err
	}
	err = RunInNamespace(topology.Plan.ClientA, func() error {
		factory, err := probeio.NewUDPFactory(probeio.UDPFactoryConfig{
			LocalAddr:          netip.MustParseAddrPort("0.0.0.0:0"),
			AllowedTargetScope: probeio.AllowedTargetScopeUnicast,
		})
		if err != nil {
			return err
		}
		lease := newLabLease(stunobserve.WorstCaseCost())
		client, err := stunobserve.New(stunobserve.Config{
			Lease:              lease,
			Generation:         probeio.NewGeneration(1),
			ExpectedGeneration: 1,
			Factory:            factory,
			BuildVersion:       "natlab-test",
			AllowNonLoopback:   true,
		})
		if err != nil {
			_ = lease.Close()
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		observation, observeErr = client.Observe(ctx, target)
		return client.Close()
	})
	return observation, errors.Join(observeErr, err)
}

func assertMappedAddress(t *testing.T, observation solver.Observation, wantAddress string) {
	t.Helper()
	mapped, err := netip.ParseAddrPort(observation.Details["mapped_address"])
	if err != nil {
		t.Fatalf("mapped address %q: %v", observation.Details["mapped_address"], err)
	}
	if mapped.Addr().String() != wantAddress {
		t.Fatalf("mapped address = %s, want outer %s", mapped, wantAddress)
	}
}

func portBehavior(t *testing.T, observation solver.Observation) string {
	t.Helper()
	mapped, err := netip.ParseAddrPort(observation.Details["mapped_address"])
	if err != nil {
		t.Fatalf("parse mapped address: %v", err)
	}
	local, err := netip.ParseAddrPort(observation.LocalAddr)
	if err != nil {
		t.Fatalf("parse local address: %v", err)
	}
	if mapped.Port() == local.Port() {
		return "preserved"
	}
	return "translated"
}

type netnsSTUNResponder struct {
	connection *net.UDPConn
	done       chan struct{}
	err        chan error
	packets    atomic.Uint32
}

func startNetnsSTUNResponder(topology *Topology) (*netnsSTUNResponder, error) {
	address, err := netip.ParseAddrPort(topology.Plan.STUNAddress)
	if err != nil {
		return nil, err
	}
	responder := &netnsSTUNResponder{done: make(chan struct{}), err: make(chan error, 1)}
	err = RunInNamespace(topology.Plan.Internet, func() error {
		connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(address))
		if err != nil {
			return err
		}
		responder.connection = connection
		go responder.serve()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return responder, nil
}

func (responder *netnsSTUNResponder) serve() {
	defer close(responder.done)
	buffer := make([]byte, 1025)
	for {
		count, source, err := responder.connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				responder.err <- err
			}
			return
		}
		responder.packets.Add(1)
		response, err := testkit.BindingSuccess(buffer[:count], source)
		if err != nil {
			responder.err <- err
			return
		}
		if _, err := responder.connection.WriteToUDPAddrPort(response, source); err != nil {
			responder.err <- err
			return
		}
	}
}

func (responder *netnsSTUNResponder) Packets() uint32 {
	if responder == nil {
		return 0
	}
	return responder.packets.Load()
}

func (responder *netnsSTUNResponder) Close() error {
	if responder == nil || responder.connection == nil {
		return nil
	}
	closeErr := responder.connection.Close()
	select {
	case <-responder.done:
	case <-time.After(time.Second):
		return errors.New("natlab: STUN responder did not stop")
	}
	select {
	case serveErr := <-responder.err:
		return errors.Join(closeErr, serveErr)
	default:
		return closeErr
	}
}

type labLease struct {
	request  governor.AttemptRequest
	stopping chan struct{}
	done     chan struct{}

	mu             sync.Mutex
	drains         int
	stoppingClosed bool
	doneClosed     bool
}

func newLabLease(cost governor.AttemptCost) *labLease {
	return &labLease{
		request:  governor.AttemptRequest{ID: "natlab-stun", Operation: governor.OperationDiagnose, Cost: cost},
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

func (lease *labLease) Request() governor.AttemptRequest { return lease.request }
func (*labLease) PeerID() string                         { return "natlab-client" }
func (lease *labLease) Stopping() <-chan struct{}        { return lease.stopping }
func (lease *labLease) Done() <-chan struct{}            { return lease.done }

func (lease *labLease) RegisterDrain(string) (governor.DrainHandle, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.stoppingClosed {
		return nil, governor.ErrLeaseClosed
	}
	lease.drains++
	return &labDrain{lease: lease}, nil
}

func (lease *labLease) Close() error {
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

func (lease *labLease) Trip(event governor.SafetyTripEvent) (governor.SafetyTripStatus, error) {
	lease.mu.Lock()
	if !lease.stoppingClosed {
		lease.stoppingClosed = true
		close(lease.stopping)
	}
	lease.mu.Unlock()
	return governor.SafetyTripStatus{
		State:            governor.SafetyTripTripped,
		BlocksActiveWork: true,
		Record:           governor.SafetyTripRecord{SchemaVersion: 1, State: governor.SafetyTripTripped, Reason: event.Reason},
	}, nil
}

type labDrain struct {
	lease *labLease
	once  sync.Once
}

func (drain *labDrain) Complete() error {
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
