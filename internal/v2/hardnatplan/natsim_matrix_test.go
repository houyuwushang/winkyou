package hardnatplan

import (
	"net/netip"
	"slices"
	"testing"

	"winkyou/internal/natsim"
)

func TestNATSimSequentialAPDMPredictiveWindowAndStealing(t *testing.T) {
	t.Run("next allocation hits frozen window", func(t *testing.T) {
		ports, next := natsimSequentialEvidence(t, 0)
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, ports)
		plan, err := BuildPlan(planInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph))
		if err != nil {
			t.Fatal(err)
		}
		if !planContainsPort(plan, next) {
			t.Fatalf("next mapped port %d was not in predictive window", next)
		}
	})

	t.Run("stealing outside window fails without expansion", func(t *testing.T) {
		ports, next := natsimSequentialEvidence(t, 40)
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, ports)
		plan, err := BuildPlan(planInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph))
		if err != nil {
			t.Fatal(err)
		}
		if planContainsPort(plan, next) {
			t.Fatalf("stolen next mapped port %d unexpectedly remained in the fixed window", next)
		}
		if len(plan.Candidates) != PredictiveWindowPorts {
			t.Fatalf("stealing expanded candidate window to %d", len(plan.Candidates))
		}
	})
}

func TestNATSimAsymmetricBirthdayBothPhysicalRolesLandInInterval(t *testing.T) {
	const repetitions = 128
	const minimumHits = 65
	const maximumHits = 98

	for _, orientation := range []string{"edm-left-eim-right", "eim-left-edm-right"} {
		t.Run(orientation, func(t *testing.T) {
			graph := syntheticEvidence(MappingEIM, FilteringAPDF, apparentlyRandomPorts())
			input := planInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, graph)
			input.KeySource = keySource("asymmetric-statistics:" + orientation)
			plan, err := BuildPlan(input)
			if err != nil {
				t.Fatal(err)
			}
			targets := make(map[uint16]struct{}, len(plan.Candidates))
			for _, candidate := range plan.Candidates {
				targets[candidate.TargetPort] = struct{}{}
			}
			hits := 0
			for repetition := 1; repetition <= repetitions; repetition++ {
				mapped := natsimRandomMappingSet(t, uint64(repetition), 128, 1, 65535)
				if intersects(targets, mapped) {
					hits++
				}
			}
			if hits < minimumHits || hits > maximumHits {
				t.Fatalf("%s hits = %d/%d, want predeclared interval [%d,%d]", orientation, hits, repetitions, minimumHits, maximumHits)
			}
			t.Logf("%s asymmetric hits=%d/%d interval=[%d,%d]", orientation, hits, repetitions, minimumHits, maximumHits)
		})
	}
}

func TestNATSimRandomAPDM16KDistributionMatchesCompiledUniverse(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
	plan, err := BuildPlan(planInput(ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph))
	if err != nil {
		t.Fatal(err)
	}
	planPorts := make([]uint16, 0, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		planPorts = append(planPorts, candidate.TargetPort)
	}
	slices.Sort(planPorts)
	for index, port := range planPorts {
		if port != uint16(DynamicPortMin+index) {
			t.Fatalf("compiled plan universe[%d] = %d", index, port)
		}
	}

	mapped := natsimRandomMappingSequence(t, 77, DynamicPortCount, DynamicPortMin, DynamicPortMax)
	slices.Sort(mapped)
	if !slices.Equal(mapped, planPorts) {
		t.Fatal("natsim random allocator did not cover the exact compiled 16K universe without replacement")
	}
	if plan.Probability.Primary.FloorPartsPerTrillion < 632_000_000_000 ||
		plan.Probability.FullRangeBaseline.FloorPartsPerTrillion < 60_000_000_000 ||
		!plan.Probability.Conditional {
		t.Fatalf("hard16 conditional/full probability = %+v", plan.Probability)
	}
	t.Logf("hard16 conditional_pptrillion=%d full_range_pptrillion=%d mappings=%d",
		plan.Probability.Primary.FloorPartsPerTrillion, plan.Probability.FullRangeBaseline.FloorPartsPerTrillion, len(mapped))
}

func natsimSequentialEvidence(t *testing.T, steals int) ([]uint16, uint16) {
	t.Helper()
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 1, MaxMappings: 128, QueueCapacity: 1, MaxDatagram: 32})
	if err != nil {
		t.Fatal(err)
	}
	model := natsim.Model{
		Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement, Filtering: natsim.FilterAddressPortDependent,
		PortMin: 50000, PortMax: 50200, RandomSeed: 1,
	}
	nat, err := network.NewNAT(natsim.NATConfig{Name: "sequential-apdm", PublicAddr: netip.MustParseAddr("203.0.113.10"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.10:30000"), NATChain: []*natsim.NAT{nat}})
	if err != nil {
		t.Fatal(err)
	}
	ports := make([]uint16, 0, MinSuccessfulAllocationSamples)
	for index := 0; index < MinSuccessfulAllocationSamples; index++ {
		destination := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.10"), uint16(40000+index))
		mustVirtualWrite(t, connection, destination)
		mapped, err := network.MappedAddr(connection, destination)
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, mapped.Port())
	}
	for index := 0; index < steals; index++ {
		destination := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.11"), uint16(41000+index))
		mustVirtualWrite(t, connection, destination)
	}
	nextDestination := netip.MustParseAddrPort("198.51.100.12:42000")
	mustVirtualWrite(t, connection, nextDestination)
	next, err := network.MappedAddr(connection, nextDestination)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	assertNATSimDrained(t, network)
	return ports, next.Port()
}

func natsimRandomMappingSet(t *testing.T, seed uint64, count int, minimum, maximum int) []uint16 {
	t.Helper()
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: count, MaxMappings: count, QueueCapacity: 1, MaxDatagram: 8})
	if err != nil {
		t.Fatal(err)
	}
	model := natsim.Model{
		Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortRandom, Filtering: natsim.FilterAddressPortDependent,
		PortMin: minimum, PortMax: maximum, RandomSeed: seed,
	}
	nat, err := network.NewNAT(natsim.NATConfig{Name: "random-edm", PublicAddr: netip.MustParseAddr("203.0.113.20"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddrPort("198.51.100.20:45000")
	connections := make([]*natsim.PacketConn, 0, count)
	ports := make([]uint16, 0, count)
	for index := 0; index < count; index++ {
		connection, err := network.NewPacketConn(natsim.EndpointConfig{
			LocalAddr: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.20"), uint16(20000+index)), NATChain: []*natsim.NAT{nat},
		})
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		mustVirtualWrite(t, connection, target)
		mapped, err := network.MappedAddr(connection, target)
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, mapped.Port())
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	assertNATSimDrained(t, network)
	return ports
}

func natsimRandomMappingSequence(t *testing.T, seed uint64, count int, minimum, maximum int) []uint16 {
	t.Helper()
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 1, MaxMappings: count, QueueCapacity: 1, MaxDatagram: 8})
	if err != nil {
		t.Fatal(err)
	}
	model := natsim.Model{
		Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortRandom, Filtering: natsim.FilterAddressPortDependent,
		PortMin: minimum, PortMax: maximum, RandomSeed: seed,
	}
	nat, err := network.NewNAT(natsim.NATConfig{Name: "random-apdm-16k", PublicAddr: netip.MustParseAddr("203.0.113.30"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := network.NewPacketConn(natsim.EndpointConfig{LocalAddr: netip.MustParseAddrPort("192.0.2.30:30000"), NATChain: []*natsim.NAT{nat}})
	if err != nil {
		t.Fatal(err)
	}
	ports := make([]uint16, 0, count)
	for index := 0; index < count; index++ {
		destination := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.30"), uint16(index+1))
		mustVirtualWrite(t, connection, destination)
		mapped, err := network.MappedAddr(connection, destination)
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, mapped.Port())
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	assertNATSimDrained(t, network)
	return ports
}

func mustVirtualWrite(t *testing.T, connection *natsim.PacketConn, destination netip.AddrPort) {
	t.Helper()
	if n, err := connection.WriteToAddrPort([]byte{0x01}, destination); err != nil || n != 1 {
		t.Fatalf("virtual write to %s = %d/%v", destination, n, err)
	}
}

func assertNATSimDrained(t *testing.T, network *natsim.Network) {
	t.Helper()
	snapshot := network.Snapshot()
	if snapshot.ActivePacketConns != 0 || snapshot.ActiveMappings != 0 || snapshot.QueuedPackets != 0 {
		t.Fatalf("natsim residual = %+v", snapshot)
	}
}

func planContainsPort(plan Plan, port uint16) bool {
	for _, candidate := range plan.Candidates {
		if candidate.TargetPort == port {
			return true
		}
	}
	return false
}

func intersects(targets map[uint16]struct{}, mapped []uint16) bool {
	for _, port := range mapped {
		if _, hit := targets[port]; hit {
			return true
		}
	}
	return false
}
