package natsim

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHarnessEIMEIMDirectSuccess(t *testing.T) {
	scenario := Scenario{
		Name:        "eim-eim-direct",
		Repetitions: 100,
		Network: Config{
			MaxPacketConns: 2,
			MaxMappings:    2,
			QueueCapacity:  2,
			MaxDatagram:    256,
		},
		Resources: ResourceLimits{PacketConns: 2, Mappings: 2, QueuedPackets: 1},
		Execute: func(_ context.Context, network *Network) error {
			model := testModel(MappingEndpointIndependent, PortPreserving, FilterEndpointIndependent)
			natA, err := network.NewNAT(NATConfig{Name: "nat-a", PublicAddr: netip.MustParseAddr("203.0.113.10"), Model: model})
			if err != nil {
				return err
			}
			natB, err := network.NewNAT(NATConfig{Name: "nat-b", PublicAddr: netip.MustParseAddr("203.0.113.20"), Model: model})
			if err != nil {
				return err
			}
			connectionA, err := network.NewPacketConn(EndpointConfig{
				LocalAddr: netip.MustParseAddrPort("192.0.2.10:45010"),
				NATChain:  []*NAT{natA},
			})
			if err != nil {
				return err
			}
			defer connectionA.Close()
			connectionB, err := network.NewPacketConn(EndpointConfig{
				LocalAddr: netip.MustParseAddrPort("198.51.100.20:45020"),
				NATChain:  []*NAT{natB},
			})
			if err != nil {
				return err
			}
			defer connectionB.Close()

			observer := netip.MustParseAddrPort("203.0.113.250:3478")
			if _, err := connectionA.WriteTo([]byte("map-a"), udpAddr(observer)); err != nil {
				return err
			}
			if _, err := connectionB.WriteTo([]byte("map-b"), udpAddr(observer)); err != nil {
				return err
			}
			mappedA, err := network.MappedAddr(connectionA, observer)
			if err != nil {
				return err
			}
			mappedB, err := network.MappedAddr(connectionB, observer)
			if err != nil {
				return err
			}

			if _, err := connectionA.WriteTo([]byte("hello"), udpAddr(mappedB)); err != nil {
				return err
			}
			packet, source, err := readVirtualPacket(connectionB)
			if err != nil {
				return err
			}
			if string(packet) != "hello" || source != mappedA {
				return errors.New("B received unexpected EIM packet")
			}
			if _, err := connectionB.WriteTo([]byte("ack"), udpAddr(mappedA)); err != nil {
				return err
			}
			packet, source, err = readVirtualPacket(connectionA)
			if err != nil {
				return err
			}
			if string(packet) != "ack" || source != mappedB {
				return errors.New("A received unexpected EIM reply")
			}
			return nil
		},
	}

	report, err := RunScenario(context.Background(), scenario)
	if err != nil {
		t.Fatalf("run EIM x EIM scenario: %v", err)
	}
	if report.CompletedRepetitions != 100 || report.PeakPacketConns != 2 || report.PeakMappings != 2 || report.PeakQueuedPackets != 1 {
		t.Fatalf("EIM x EIM report = %+v", report)
	}
}

func TestHarnessUDPBlockedFailsWithinBudget(t *testing.T) {
	scenario := Scenario{
		Name:        "udp-blocked-bounded-failure",
		Repetitions: 100,
		Network: Config{
			MaxPacketConns: 1,
			MaxMappings:    1,
			QueueCapacity:  1,
			MaxDatagram:    64,
		},
		Resources: ResourceLimits{PacketConns: 1, Mappings: 0, QueuedPackets: 0},
		Execute: func(_ context.Context, network *Network) error {
			model := testModel(MappingEndpointIndependent, PortPreserving, FilterEndpointIndependent)
			model.UDPBlocked = true
			nat, err := network.NewNAT(NATConfig{Name: "blocked-nat", PublicAddr: netip.MustParseAddr("203.0.113.30"), Model: model})
			if err != nil {
				return err
			}
			connection, err := network.NewPacketConn(EndpointConfig{
				LocalAddr: netip.MustParseAddrPort("192.0.2.30:45030"),
				NATChain:  []*NAT{nat},
			})
			if err != nil {
				return err
			}
			defer connection.Close()
			n, err := connection.WriteTo([]byte("probe"), udpAddr(netip.MustParseAddrPort("198.51.100.30:40000")))
			if n != 0 || !errors.Is(err, ErrUDPBlocked) {
				return errors.New("UDP-blocked model did not return the stable failure class")
			}
			counters := network.Snapshot()
			if counters.ActiveMappings != 0 || counters.PacketsRejected != 1 {
				return errors.New("UDP-blocked attempt allocated a mapping or missed rejection accounting")
			}
			return nil
		},
	}

	report, err := RunScenario(context.Background(), scenario)
	if err != nil {
		t.Fatalf("run UDP-blocked scenario: %v", err)
	}
	if report.CompletedRepetitions != 100 || report.PeakPacketConns != 1 || report.PeakMappings != 0 || report.PeakQueuedPackets != 0 {
		t.Fatalf("UDP-blocked report = %+v", report)
	}
}

func TestMappingAndPortAllocationModels(t *testing.T) {
	t.Run("EIM reuses preserved port", func(t *testing.T) {
		network := mustNetwork(t, Config{})
		defer network.Close()
		nat := mustNAT(t, network, NATConfig{
			Name:       "eim-preserving",
			PublicAddr: netip.MustParseAddr("203.0.113.40"),
			Model:      testModel(MappingEndpointIndependent, PortPreserving, FilterEndpointIndependent),
		})
		connection := mustPacketConn(t, network, EndpointConfig{
			LocalAddr: netip.MustParseAddrPort("192.0.2.40:45100"),
			NATChain:  []*NAT{nat},
		})
		defer connection.Close()
		destinationA := netip.MustParseAddrPort("198.51.100.40:40000")
		destinationB := netip.MustParseAddrPort("198.51.100.41:40001")
		mustWrite(t, connection, destinationA, "a")
		mustWrite(t, connection, destinationB, "b")
		mappedA := mustMappedAddr(t, network, connection, destinationA)
		mappedB := mustMappedAddr(t, network, connection, destinationB)
		if mappedA != mappedB || mappedA.Port() != 45100 {
			t.Fatalf("EIM mappings = %v/%v, want one preserved port", mappedA, mappedB)
		}
		if snapshot := nat.Snapshot(); snapshot.ActiveMappings != 1 {
			t.Fatalf("EIM NAT snapshot = %+v", snapshot)
		}
	})

	t.Run("EDM allocates deterministic increments", func(t *testing.T) {
		network := mustNetwork(t, Config{})
		defer network.Close()
		model := testModel(MappingEndpointDependent, PortIncrement, FilterEndpointIndependent)
		model.PortMin, model.PortMax = 41000, 41002
		nat := mustNAT(t, network, NATConfig{Name: "edm-increment", PublicAddr: netip.MustParseAddr("203.0.113.41"), Model: model})
		connection := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.41:45101"), NATChain: []*NAT{nat}})
		defer connection.Close()
		destinationA := netip.MustParseAddrPort("198.51.100.42:40000")
		destinationB := netip.MustParseAddrPort("198.51.100.43:40000")
		mustWrite(t, connection, destinationA, "a")
		mustWrite(t, connection, destinationB, "b")
		if first, second := mustMappedAddr(t, network, connection, destinationA), mustMappedAddr(t, network, connection, destinationB); first.Port() != 41000 || second.Port() != 41001 || first == second {
			t.Fatalf("EDM incremental mappings = %v/%v", first, second)
		}
	})

	t.Run("random allocation is seeded and repeatable", func(t *testing.T) {
		first := randomPortSequence(t, 77)
		second := randomPortSequence(t, 77)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("seeded random sequences differ: %v vs %v", first, second)
		}
		seen := make(map[uint16]struct{}, len(first))
		for _, port := range first {
			if port < 42000 || port > 42009 {
				t.Fatalf("random port %d escaped configured range", port)
			}
			seen[port] = struct{}{}
		}
		if len(seen) != len(first) {
			t.Fatalf("random sequence reused a live port: %v", first)
		}
	})
}

func TestAddressPortFilteringRequiresReciprocalTraffic(t *testing.T) {
	network := mustNetwork(t, Config{})
	defer network.Close()
	model := testModel(MappingEndpointIndependent, PortPreserving, FilterAddressPortDependent)
	natA := mustNAT(t, network, NATConfig{Name: "filter-a", PublicAddr: netip.MustParseAddr("203.0.113.50"), Model: model})
	natB := mustNAT(t, network, NATConfig{Name: "filter-b", PublicAddr: netip.MustParseAddr("203.0.113.51"), Model: model})
	connectionA := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.50:45200"), NATChain: []*NAT{natA}})
	defer connectionA.Close()
	connectionB := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("198.51.100.50:45201"), NATChain: []*NAT{natB}})
	defer connectionB.Close()
	observer := netip.MustParseAddrPort("203.0.113.250:3478")
	mustWrite(t, connectionA, observer, "map-a")
	mustWrite(t, connectionB, observer, "map-b")
	mappedA := mustMappedAddr(t, network, connectionA, observer)
	mappedB := mustMappedAddr(t, network, connectionB, observer)

	mustWrite(t, connectionA, mappedB, "first-a")
	if err := connectionB.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		t.Fatalf("set B read deadline: %v", err)
	}
	if _, _, err := connectionB.ReadFrom(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unreciprocated B read error = %v, want deadline", err)
	}
	if err := connectionB.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear B read deadline: %v", err)
	}

	mustWrite(t, connectionB, mappedA, "from-b")
	packet, source, err := readVirtualPacket(connectionA)
	if err != nil || string(packet) != "from-b" || source != mappedB {
		t.Fatalf("A reciprocal read = %q/%v/%v", packet, source, err)
	}
	mustWrite(t, connectionA, mappedB, "second-a")
	packet, source, err = readVirtualPacket(connectionB)
	if err != nil || string(packet) != "second-a" || source != mappedA {
		t.Fatalf("B reciprocal read = %q/%v/%v", packet, source, err)
	}
	if dropped := network.Snapshot().PacketsDropped; dropped < 3 {
		// Two observer sends plus the first filtered peer packet are dropped.
		t.Fatalf("dropped packets = %d, want at least 3", dropped)
	}
}

func TestAddressDependentFilteringAllowsAContactedAddressOnAnotherPort(t *testing.T) {
	network := mustNetwork(t, Config{})
	defer network.Close()
	model := testModel(MappingEndpointIndependent, PortPreserving, FilterAddressDependent)
	nat := mustNAT(t, network, NATConfig{Name: "address-filter", PublicAddr: netip.MustParseAddr("203.0.113.52"), Model: model})
	behindNAT := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.52:45210"), NATChain: []*NAT{nat}})
	defer behindNAT.Close()
	contacted := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("198.51.100.52:45211")})
	defer contacted.Close()
	otherPort := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("198.51.100.52:45212")})
	defer otherPort.Close()

	mustWrite(t, behindNAT, contacted.localAddr, "contact")
	if _, _, err := readVirtualPacket(contacted); err != nil {
		t.Fatalf("contacted endpoint read: %v", err)
	}
	mapped := mustMappedAddr(t, network, behindNAT, contacted.localAddr)
	mustWrite(t, otherPort, mapped, "same-address")
	packet, source, err := readVirtualPacket(behindNAT)
	if err != nil || string(packet) != "same-address" || source != otherPort.localAddr {
		t.Fatalf("address-dependent read = %q/%v/%v", packet, source, err)
	}
}

func TestCGNATChainTranslatesBothLayers(t *testing.T) {
	network := mustNetwork(t, Config{})
	defer network.Close()
	model := testModel(MappingEndpointIndependent, PortIncrement, FilterEndpointIndependent)
	inner := mustNAT(t, network, NATConfig{Name: "cgnat-inner", PublicAddr: netip.MustParseAddr("100.64.0.10"), Model: model})
	outer := mustNAT(t, network, NATConfig{Name: "cgnat-outer", PublicAddr: netip.MustParseAddr("203.0.113.60"), Model: model})
	behindCGNAT := mustPacketConn(t, network, EndpointConfig{
		LocalAddr: netip.MustParseAddrPort("192.0.2.60:45300"),
		NATChain:  []*NAT{inner, outer},
	})
	defer behindCGNAT.Close()
	direct := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("198.51.100.60:45301")})
	defer direct.Close()

	mustWrite(t, behindCGNAT, direct.localAddr, "outbound")
	packet, source, err := readVirtualPacket(direct)
	if err != nil || string(packet) != "outbound" || source.Addr() != outer.publicAddr {
		t.Fatalf("direct read through CGNAT = %q/%v/%v", packet, source, err)
	}
	mapped := mustMappedAddr(t, network, behindCGNAT, direct.localAddr)
	mustWrite(t, direct, mapped, "inbound")
	packet, source, err = readVirtualPacket(behindCGNAT)
	if err != nil || string(packet) != "inbound" || source != direct.localAddr {
		t.Fatalf("CGNAT inbound read = %q/%v/%v", packet, source, err)
	}
	if mappings := network.Snapshot().ActiveMappings; mappings != 2 {
		t.Fatalf("CGNAT mappings = %d, want 2 layers", mappings)
	}
}

func TestBehaviorChangeInvalidatesMappingsAndChangesPublicAddress(t *testing.T) {
	network := mustNetwork(t, Config{})
	defer network.Close()
	initial := testModel(MappingEndpointIndependent, PortPreserving, FilterEndpointIndependent)
	changed := testModel(MappingEndpointDependent, PortIncrement, FilterAddressDependent)
	changed.PortMin, changed.PortMax = 43000, 43010
	nat := mustNAT(t, network, NATConfig{
		Name:       "changing-nat",
		PublicAddr: netip.MustParseAddr("203.0.113.70"),
		Model:      initial,
		Changes: []BehaviorChange{{
			AfterOutboundPackets: 1,
			Model:                changed,
			PublicAddr:           netip.MustParseAddr("203.0.113.71"),
		}},
	})
	connection := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.70:45400"), NATChain: []*NAT{nat}})
	defer connection.Close()
	destinationA := netip.MustParseAddrPort("198.51.100.70:40000")
	destinationB := netip.MustParseAddrPort("198.51.100.71:40000")
	mustWrite(t, connection, destinationA, "before")
	before := mustMappedAddr(t, network, connection, destinationA)
	mustWrite(t, connection, destinationB, "after")
	if _, err := network.MappedAddr(connection, destinationA); !errors.Is(err, ErrNoMapping) {
		t.Fatalf("stale mapping error = %v, want ErrNoMapping", err)
	}
	after := mustMappedAddr(t, network, connection, destinationB)
	if before.Addr() != netip.MustParseAddr("203.0.113.70") || after.Addr() != netip.MustParseAddr("203.0.113.71") || after.Port() != 43000 {
		t.Fatalf("mapping before/after change = %v/%v", before, after)
	}
	snapshot := nat.Snapshot()
	if snapshot.AppliedChanges != 1 || snapshot.OutboundPackets != 2 || snapshot.ActiveMappings != 1 || snapshot.Model.Mapping != MappingEndpointDependent {
		t.Fatalf("changed NAT snapshot = %+v", snapshot)
	}
}

func TestPacketConnDeadlinesAndClose(t *testing.T) {
	network := mustNetwork(t, Config{})
	defer network.Close()
	connection := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.80:45500")})
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := connection.ReadFrom(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline error = %v", err)
	}
	if err := connection.SetWriteDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := connection.WriteTo([]byte("late"), udpAddr(netip.MustParseAddrPort("198.51.100.80:45501"))); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline error = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close PacketConn: %v", err)
	}
	if _, _, err := connection.ReadFrom(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed read error = %v", err)
	}
	if _, err := connection.WriteTo([]byte("closed"), udpAddr(netip.MustParseAddrPort("198.51.100.80:45501"))); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed write error = %v", err)
	}
}

func TestPacketConnCopiesPayloadAndSupportsConcurrentClose(t *testing.T) {
	network := mustNetwork(t, Config{MaxPacketConns: 2, MaxMappings: 1, QueueCapacity: 64})
	defer network.Close()
	connectionA := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.81:45510")})
	connectionB := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("198.51.100.81:45511")})
	payload := []byte("owned")
	if _, err := connectionA.WriteTo(payload, connectionB.LocalAddr()); err != nil {
		t.Fatalf("write ownership packet: %v", err)
	}
	copy(payload, "xxxxx")
	received, _, err := readVirtualPacket(connectionB)
	if err != nil || string(received) != "owned" {
		t.Fatalf("received copied payload = %q/%v", received, err)
	}

	start := make(chan struct{})
	errorsCh := make(chan error, 32)
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, writeErr := connectionA.WriteTo([]byte("concurrent"), connectionB.LocalAddr())
			if writeErr != nil && !errors.Is(writeErr, net.ErrClosed) {
				errorsCh <- writeErr
			}
		}()
	}
	close(start)
	_ = connectionA.Close()
	_ = connectionB.Close()
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("concurrent write/close: %v", err)
	}
	if counters := network.Snapshot(); counters.ActivePacketConns != 0 || counters.QueuedPackets != 0 {
		t.Fatalf("resources after concurrent close = %+v", counters)
	}
}

func TestHarnessStopsOnFirstFailureAndChecksResources(t *testing.T) {
	t.Run("fail fast", func(t *testing.T) {
		injected := errors.New("injected scenario failure")
		var calls atomic.Int32
		report, err := RunScenario(context.Background(), Scenario{
			Name:        "fail-fast",
			Repetitions: 10,
			Resources:   ResourceLimits{},
			Execute: func(context.Context, *Network) error {
				if calls.Add(1) == 3 {
					return injected
				}
				return nil
			},
		})
		if !errors.Is(err, ErrScenarioFailed) || !errors.Is(err, injected) {
			t.Fatalf("fail-fast error = %v", err)
		}
		if report.CompletedRepetitions != 2 || calls.Load() != 3 {
			t.Fatalf("fail-fast report/calls = %+v/%d", report, calls.Load())
		}
	})

	t.Run("leak witness", func(t *testing.T) {
		report, err := RunScenario(context.Background(), Scenario{
			Name:        "leak-witness",
			Repetitions: 2,
			Resources:   ResourceLimits{PacketConns: 1},
			Execute: func(_ context.Context, network *Network) error {
				_, createErr := network.NewPacketConn(EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.90:45600")})
				return createErr
			},
		})
		if !errors.Is(err, ErrResourceLeak) || report.CompletedRepetitions != 0 {
			t.Fatalf("leak witness report/error = %+v/%v", report, err)
		}
	})

	t.Run("peak assertion", func(t *testing.T) {
		_, err := RunScenario(context.Background(), Scenario{
			Name:        "peak-assertion",
			Repetitions: 1,
			Resources:   ResourceLimits{},
			Execute: func(_ context.Context, network *Network) error {
				connection, createErr := network.NewPacketConn(EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.91:45601")})
				if createErr != nil {
					return createErr
				}
				return connection.Close()
			},
		})
		if !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("peak assertion error = %v, want ErrResourceLimit", err)
		}
	})
}

func testModel(mapping MappingBehavior, allocation PortAllocation, filtering FilteringBehavior) Model {
	return Model{
		Mapping:    mapping,
		Allocation: allocation,
		Filtering:  filtering,
		PortMin:    defaultPortMin,
		PortMax:    defaultPortMax,
		RandomSeed: 1,
	}
}

func randomPortSequence(t *testing.T, seed uint64) []uint16 {
	t.Helper()
	network := mustNetwork(t, Config{})
	defer network.Close()
	model := testModel(MappingEndpointDependent, PortRandom, FilterEndpointIndependent)
	model.PortMin, model.PortMax, model.RandomSeed = 42000, 42009, seed
	nat := mustNAT(t, network, NATConfig{Name: "random", PublicAddr: netip.MustParseAddr("203.0.113.42"), Model: model})
	connection := mustPacketConn(t, network, EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.42:45102"), NATChain: []*NAT{nat}})
	defer connection.Close()
	ports := make([]uint16, 0, 4)
	for index := 0; index < 4; index++ {
		destination := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.44"), uint16(40100+index))
		mustWrite(t, connection, destination, "random")
		ports = append(ports, mustMappedAddr(t, network, connection, destination).Port())
	}
	return ports
}

func mustNetwork(t *testing.T, config Config) *Network {
	t.Helper()
	network, err := NewNetwork(config)
	if err != nil {
		t.Fatalf("new network: %v", err)
	}
	return network
}

func mustNAT(t *testing.T, network *Network, config NATConfig) *NAT {
	t.Helper()
	nat, err := network.NewNAT(config)
	if err != nil {
		t.Fatalf("new NAT %q: %v", config.Name, err)
	}
	return nat
}

func mustPacketConn(t *testing.T, network *Network, config EndpointConfig) *PacketConn {
	t.Helper()
	connection, err := network.NewPacketConn(config)
	if err != nil {
		t.Fatalf("new PacketConn %s: %v", config.LocalAddr, err)
	}
	return connection
}

func mustWrite(t *testing.T, connection *PacketConn, destination netip.AddrPort, payload string) {
	t.Helper()
	n, err := connection.WriteTo([]byte(payload), udpAddr(destination))
	if err != nil || n != len(payload) {
		t.Fatalf("write %q to %s = %d/%v", payload, destination, n, err)
	}
}

func mustMappedAddr(t *testing.T, network *Network, connection *PacketConn, destination netip.AddrPort) netip.AddrPort {
	t.Helper()
	mapped, err := network.MappedAddr(connection, destination)
	if err != nil {
		t.Fatalf("mapped address for %s: %v", destination, err)
	}
	return mapped
}

func readVirtualPacket(connection *PacketConn) ([]byte, netip.AddrPort, error) {
	if err := connection.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		return nil, netip.AddrPort{}, err
	}
	buffer := make([]byte, 256)
	n, source, err := connection.ReadFrom(buffer)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	udpSource, ok := source.(*net.UDPAddr)
	if !ok || udpSource == nil {
		return nil, netip.AddrPort{}, ErrInvalidConfig
	}
	return append([]byte(nil), buffer[:n]...), udpSource.AddrPort(), nil
}

func udpAddr(endpoint netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(endpoint)
}
