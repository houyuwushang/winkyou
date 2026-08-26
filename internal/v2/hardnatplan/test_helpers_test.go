package hardnatplan

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

type fixedKeySource struct {
	key [32]byte
	err error
}

func (source fixedKeySource) DerivePlannerKey(PlannerKeyContext) ([32]byte, error) {
	return source.key, source.err
}

func syntheticDigest(label string) [32]byte { return sha256.Sum256([]byte(label)) }

func syntheticAddress(last byte) Address4Value {
	return Address4Value{192, 0, 2, last}
}

type Address4Value [4]byte

func (value Address4Value) Address() Address { return Address4([4]byte(value)) }

func sequentialPorts(first uint16, count int, step uint16) []uint16 {
	result := make([]uint16, count)
	value := first
	for index := range result {
		result[index] = value
		value = addPort(value, step)
	}
	return result
}

func apparentlyRandomPorts() []uint16 {
	return []uint16{50000, 51117, 49303, 62001, 54009, 65000, 50101, 58777}
}

func syntheticEvidence(mapping MappingBehavior, filtering FilteringBehavior, ports []uint16) EvidenceGraph {
	attempt := syntheticDigest("attempt")
	graph := EvidenceGraph{
		AttemptDigest: attempt, MachineScopeDigest: syntheticDigest("machine"), PeerDigest: syntheticDigest("peer"),
		ObservationSetDigest: syntheticDigest("observer-set"), SocketOwnerDigest: syntheticDigest("socket-owner"), Generation: 1,
		StartedAtMilli: 1_000, FinishedAtMilli: 2_000, ExpiresAtMilli: 3_000,
	}
	public := syntheticAddress(200).Address()
	pool := syntheticDigest("pool")
	graph.Mapping = []MappingEvidence{{
		Meta: evidenceMeta(graph, 200, SourceRFC5780, OriginLocalTransaction, syntheticAddress(10).Address(), 3478), Behavior: mapping,
	}}
	graph.Filtering = []FilteringEvidence{{
		Meta: evidenceMeta(graph, 201, SourceRFC5780, OriginLocalTransaction, syntheticAddress(10).Address(), 3478), Behavior: filtering,
	}}
	graph.IPPooling = []IPPoolingEvidence{{
		Meta: evidenceMeta(graph, 202, SourceRFC5780, OriginLocalTransaction, syntheticAddress(10).Address(), 3478), Stable: true, PoolDigest: pool,
	}}
	for index, port := range ports {
		observerAddress := syntheticAddress(10).Address()
		observerPort := uint16(3478)
		switch index % 3 {
		case 1:
			observerPort = 3479
		case 2:
			observerAddress = syntheticAddress(11).Address()
		}
		meta := evidenceMeta(graph, byte(index+1), SourceLocalTomography, OriginLocalTransaction, observerAddress, observerPort)
		meta.SocketSlot = uint16(index)
		graph.Allocation = append(graph.Allocation, AllocationSample{
			Meta:       meta,
			SocketSlot: uint16(index), Ordinal: uint32(index), MappedAddress: public, MappedPort: port, Success: true,
		})
	}
	return graph
}

func evidenceMeta(graph EvidenceGraph, marker byte, source EvidenceSource, origin EvidenceOrigin, observer Address, port uint16) EvidenceMeta {
	var transaction [12]byte
	transaction[0] = marker
	transaction[11] = marker ^ 0xa5
	return EvidenceMeta{
		Source: source, Origin: origin, ObserverAddress: observer, ObserverPort: port, TransactionID: transaction,
		AttemptDigest: graph.AttemptDigest, Generation: graph.Generation, ObservedAtMilli: 1_100 + int64(marker),
	}
}

func generousBudget() Cost {
	return Cost{Sockets: 64_000, Targets: 64_000, FiveTuples: 64_000, Packets: 64_000, PacketsPerSecond: 64_000, ActiveMillis: 60_000}
}

func keySource(label string) fixedKeySource {
	return fixedKeySource{key: syntheticDigest("planner-key:" + label)}
}

func trustedValidation(graph EvidenceGraph) TrustedValidationContext {
	trusted := TrustedValidationContext{
		NowMilli:              graph.FinishedAtMilli + 500,
		ExpectedAttemptDigest: graph.AttemptDigest, ExpectedMachineScopeDigest: graph.MachineScopeDigest,
		ExpectedPeerDigest: graph.PeerDigest, ExpectedObservationSetDigest: graph.ObservationSetDigest,
		ExpectedSocketOwnerDigest: graph.SocketOwnerDigest, ExpectedGeneration: graph.Generation,
		ExpectedStartedAtMilli: graph.StartedAtMilli, ExpectedFinishedAtMilli: graph.FinishedAtMilli,
		ExpectedExpiresAtMilli: graph.ExpiresAtMilli,
	}
	seen := make(map[[12]byte]struct{})
	appendIssued := func(kind EvidenceKind, meta EvidenceMeta, slot uint16, ordinal uint32) {
		if meta.Origin != OriginLocalTransaction {
			return
		}
		if _, duplicate := seen[meta.TransactionID]; duplicate {
			return
		}
		seen[meta.TransactionID] = struct{}{}
		trusted.Issued = append(trusted.Issued, IssuedTransaction{
			Kind: kind, TransactionID: meta.TransactionID, Source: meta.Source,
			Observer: AddressPort{Address: meta.ObserverAddress, Port: meta.ObserverPort}, SocketSlot: slot, Ordinal: ordinal,
			NotBeforeMilli: graph.StartedAtMilli, NotAfterMilli: graph.FinishedAtMilli,
		})
	}
	for _, entry := range graph.Mapping {
		appendIssued(EvidenceKindMapping, entry.Meta, 0, 0)
	}
	for _, entry := range graph.Filtering {
		appendIssued(EvidenceKindFiltering, entry.Meta, 0, 0)
	}
	for _, entry := range graph.IPPooling {
		appendIssued(EvidenceKindIPPooling, entry.Meta, 0, 0)
	}
	for _, entry := range graph.Allocation {
		appendIssued(EvidenceKindAllocation, entry.Meta, entry.SocketSlot, entry.Ordinal)
	}
	return trusted
}

func inferStateModel(graph EvidenceGraph) (StateModel, error) {
	return InferStateModel(graph, trustedValidation(graph))
}

func localCommitmentInput(profile Profile, resource ResourceClass, role Role, graph EvidenceGraph) LocalCommitmentInput {
	input := LocalCommitmentInput{
		Profile: profile, ResourceClass: resource,
		Context:  AttemptContext{AttemptDigest: graph.AttemptDigest, Generation: graph.Generation, Role: role},
		Evidence: graph, Validation: trustedValidation(graph), Budget: generousBudget(),
	}
	if profile == ProfileAsymmetricBirthday && role == RoleTargetSet {
		input.ReceiveEndpoint = AddressPort{Address: syntheticAddress(220).Address(), Port: 55000}
	}
	return input
}

func buildPlanForRole(t testing.TB, profile Profile, resource ResourceClass, role Role, graph EvidenceGraph) Plan {
	t.Helper()
	var peerRole Role
	peerGraph := graph
	switch profile {
	case ProfilePredictiveEdm, ProfileHardBirthday:
		peerRole = RoleResponder
		if role == RoleResponder {
			peerRole = RoleInitiator
		}
	case ProfileAsymmetricBirthday:
		if role == RoleMappingSet {
			peerRole = RoleTargetSet
			peerGraph = syntheticEvidence(MappingEIM, FilteringAPDF, apparentlyRandomPorts())
		} else {
			peerRole = RoleMappingSet
			peerGraph = syntheticEvidence(MappingAPDM, FilteringAPDF, apparentlyRandomPorts())
		}
	default:
		t.Fatalf("unsupported profile %q", profile)
	}
	local, err := BuildLocalCommitment(localCommitmentInput(profile, resource, role, graph))
	if err != nil {
		t.Fatalf("build local commitment: %v", err)
	}
	peer, err := BuildLocalCommitment(localCommitmentInput(profile, resource, peerRole, peerGraph))
	if err != nil {
		t.Fatalf("build peer commitment: %v", err)
	}
	pair, err := BuildBilateralPlan(BilateralPlannerInput{First: local, Second: peer, KeySource: keySource(fmt.Sprintf("%s:pair", profile))})
	if err != nil {
		t.Fatalf("build bilateral plan: %v", err)
	}
	plan, ok := pair.PlanForRole(role)
	if !ok {
		t.Fatalf("role %q missing from bilateral plan", role)
	}
	return plan
}
