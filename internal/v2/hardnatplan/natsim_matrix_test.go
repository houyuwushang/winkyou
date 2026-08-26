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
		commitment, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph))
		if err != nil {
			t.Fatal(err)
		}
		if !sourceCommitmentContainsPort(commitment, next) {
			t.Fatalf("next mapped port %d was not in predicted source schedule", next)
		}
	})

	t.Run("stealing outside window fails without expansion", func(t *testing.T) {
		ports, next := natsimSequentialEvidence(t, 40)
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, ports)
		commitment, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph))
		if err != nil {
			t.Fatal(err)
		}
		if sourceCommitmentContainsPort(commitment, next) {
			t.Fatalf("stolen next mapped port %d unexpectedly remained in the fixed source schedule", next)
		}
		if len(commitment.SourceSlots) != PredictiveWindowPorts {
			t.Fatalf("stealing expanded source schedule to %d", len(commitment.SourceSlots))
		}
	})
}

func TestNATSimBilateralSequentialAPDMPlansActuallyConnect(t *testing.T) {
	network, err := natsim.NewNetwork(natsim.Config{MaxPacketConns: 16, MaxMappings: 128, QueueCapacity: 128, MaxDatagram: 32})
	if err != nil {
		t.Fatal(err)
	}
	modelA := natsim.Model{
		Mapping: natsim.MappingEndpointDependent, Allocation: natsim.PortIncrement, Filtering: natsim.FilterAddressPortDependent,
		PortMin: 50000, PortMax: 50100, RandomSeed: 1,
	}
	modelB := modelA
	modelB.PortMin, modelB.PortMax = 60000, 60100
	natA, err := network.NewNAT(natsim.NATConfig{Name: "bilateral-a", PublicAddr: netip.MustParseAddr("203.0.113.10"), Model: modelA})
	if err != nil {
		t.Fatal(err)
	}
	natB, err := network.NewNAT(natsim.NATConfig{Name: "bilateral-b", PublicAddr: netip.MustParseAddr("203.0.113.20"), Model: modelB})
	if err != nil {
		t.Fatal(err)
	}
	connectionsA := make([]*natsim.PacketConn, 8)
	connectionsB := make([]*natsim.PacketConn, 8)
	for index := 0; index < 8; index++ {
		connectionsA[index], err = network.NewPacketConn(natsim.EndpointConfig{
			LocalAddr: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(30000+index)), NATChain: []*natsim.NAT{natA},
		})
		if err != nil {
			t.Fatal(err)
		}
		connectionsB[index], err = network.NewPacketConn(natsim.EndpointConfig{
			LocalAddr: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.20"), uint16(31000+index)), NATChain: []*natsim.NAT{natB},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	portsA := collectSequentialEvidence(t, network, connectionsA, "203.0.113.200", 40000)
	portsB := collectSequentialEvidence(t, network, connectionsB, "203.0.113.201", 41000)
	left, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator,
		syntheticEvidence(MappingAPDM, FilteringAPDF, portsA)))
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleResponder,
		syntheticEvidence(MappingAPDM, FilteringAPDF, portsB)))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := BuildBilateralPlan(BilateralPlannerInput{First: left, Second: right, KeySource: keySource("bilateral-apdm")})
	if err != nil {
		t.Fatal(err)
	}
	planA, _ := pair.PlanForRole(RoleInitiator)
	planB, _ := pair.PlanForRole(RoleResponder)

	publicA := netip.MustParseAddr("203.0.113.10")
	publicB := netip.MustParseAddr("203.0.113.20")
	writePredictivePlan(t, network, connectionsA, publicB, planA, "syn-a")
	writePredictivePlan(t, network, connectionsB, publicA, planB, "syn-b")
	if got := drainVirtualPackets(t, connectionsA); got != len(planB.Candidates) {
		t.Fatalf("A received %d/%d reciprocal packets", got, len(planB.Candidates))
	}
	// The first A flight opened its APDF filters. Reusing the same directional
	// tuples is the fixed reciprocal confirmation, not candidate expansion.
	writePredictivePlan(t, network, connectionsA, publicB, planA, "ack-a")
	if got := drainVirtualPackets(t, connectionsB); got != len(planA.Candidates) {
		t.Fatalf("B received %d/%d reciprocal confirmations", got, len(planA.Candidates))
	}

	for _, connection := range append(connectionsA, connectionsB...) {
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	assertNATSimDrained(t, network)
	t.Logf("bilateral APDM success: evidence=%d/%d candidates=%d/%d", len(portsA), len(portsB), len(planA.Candidates), len(planB.Candidates))
}

func TestNATSimAsymmetricBirthdayBothPhysicalRolesLandInInterval(t *testing.T) {
	const repetitions = 128
	const minimumHits = 65
	const maximumHits = 98

	for _, orientation := range []string{"edm-left-eim-right", "eim-left-edm-right"} {
		t.Run(orientation, func(t *testing.T) {
			graph := syntheticEvidence(MappingEIM, FilteringAPDF, apparentlyRandomPorts())
			target, err := BuildLocalCommitment(localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleTargetSet, graph))
			if err != nil {
				t.Fatal(err)
			}
			mappingGraph := syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
			mapping, err := BuildLocalCommitment(localCommitmentInput(ProfileAsymmetricBirthday, ResourceAsymmetric, RoleMappingSet, mappingGraph))
			if err != nil {
				t.Fatal(err)
			}
			pair, err := BuildBilateralPlan(BilateralPlannerInput{First: target, Second: mapping, KeySource: keySource("asymmetric-statistics:" + orientation)})
			if err != nil {
				t.Fatal(err)
			}
			plan, _ := pair.PlanForRole(RoleTargetSet)
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
	plan := buildPlanForRole(t, ProfileHardBirthday, ResourceHard16KLab, RoleInitiator, graph)
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

func collectSequentialEvidence(t *testing.T, network *natsim.Network, connections []*natsim.PacketConn, observerAddress string, firstPort uint16) []uint16 {
	t.Helper()
	ports := make([]uint16, 0, MinSuccessfulAllocationSamples)
	address := netip.MustParseAddr(observerAddress)
	for index := 0; index < MinSuccessfulAllocationSamples; index++ {
		destination := netip.AddrPortFrom(address, firstPort+uint16(index))
		mustVirtualWrite(t, connections[index%len(connections)], destination)
		mapped, err := network.MappedAddr(connections[index%len(connections)], destination)
		if err != nil {
			t.Fatal(err)
		}
		ports = append(ports, mapped.Port())
	}
	return ports
}

func writePredictivePlan(t *testing.T, network *natsim.Network, connections []*natsim.PacketConn, peerAddress netip.Addr, plan Plan, payload string) {
	t.Helper()
	for _, candidate := range plan.Candidates {
		destination := netip.AddrPortFrom(peerAddress, candidate.TargetPort)
		connection := connections[candidate.SocketSlot]
		if n, err := connection.WriteToAddrPort([]byte(payload), destination); err != nil || n != len(payload) {
			t.Fatalf("write candidate %+v = %d/%v", candidate, n, err)
		}
		mapped, err := network.MappedAddr(connection, destination)
		if err != nil {
			t.Fatal(err)
		}
		if mapped.Port() != candidate.ExpectedSourcePort {
			t.Fatalf("candidate %+v produced source %d", candidate, mapped.Port())
		}
	}
}

func drainVirtualPackets(t *testing.T, connections []*natsim.PacketConn) int {
	t.Helper()
	count := 0
	buffer := make([]byte, 32)
	for _, connection := range connections {
		for {
			n, source, ok, err := connection.TryReadFromAddrPort(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				break
			}
			if n == 0 || !source.IsValid() {
				t.Fatalf("invalid virtual packet %d/%s", n, source)
			}
			count++
		}
	}
	return count
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

func sourceCommitmentContainsPort(commitment LocalSourceCommitment, port uint16) bool {
	for _, slot := range commitment.SourceSlots {
		if slot.ExpectedPublicSourcePort == port {
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
