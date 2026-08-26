package hardnatplan

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
)

const evidenceEncodingLabel = "winkyou-hardnat-evidence-v1\x00"

// InferStateModel deterministically validates and merges one attempt's
// evidence. Invalid, replayed, duplicate, or remote-reported observations can
// never become candidate-control input. Insufficient or drifted evidence
// returns the same fail-closed class and an empty candidate window.
func InferStateModel(graph EvidenceGraph) (StateModel, error) {
	model := StateModel{
		Mapping:              MappingUnknown,
		Filtering:            FilteringUnknown,
		Allocation:           AllocationInsufficientData,
		AllocationLimitation: "insufficient_bound_samples",
		ExpiresAtMilli:       graph.ExpiresAtMilli,
		Conditional:          true,
	}
	rawDigest, digestErr := DigestEvidence(graph)
	model.RawEvidenceDigest = rawDigest
	if digestErr != nil {
		return model, digestErr
	}
	if !validGraphHeader(graph) {
		return model, ErrInvalidEvidence
	}
	digest, digestErr := DigestEvidence(actionableEvidenceGraph(graph))
	model.EvidenceDigest = digest
	if digestErr != nil {
		return model, digestErr
	}

	mapping, mappingSource, mappingErr := mergeMapping(graph)
	if mappingErr != nil {
		return model, ErrEvidenceInsufficient
	}
	filtering, filteringSource, filteringErr := mergeFiltering(graph)
	if filteringErr != nil {
		return model, ErrEvidenceInsufficient
	}
	model.Mapping, model.MappingSource = mapping, mappingSource
	model.Filtering, model.FilteringSource = filtering, filteringSource

	samples, failedSamples, remoteReports, sampleErr := actionableAllocation(graph)
	if sampleErr != nil {
		return model, ErrEvidenceInsufficient
	}
	model.SuccessfulSamples = len(samples)
	model.FailedSamples = failedSamples
	model.ObserverAddressCount, model.HasAlternatePort = observerCoverage(samples)
	if len(samples) < MinSuccessfulAllocationSamples || model.ObserverAddressCount < 2 || !model.HasAlternatePort {
		model.Coverage = coverageString(graph, model, remoteReports)
		return model, ErrEvidenceInsufficient
	}

	publicAddress := samples[0].MappedAddress
	for _, sample := range samples[1:] {
		if sample.MappedAddress != publicAddress {
			model.Coverage = coverageString(graph, model, remoteReports)
			return model, ErrEvidenceInsufficient
		}
	}
	stable, poolingErr := mergeIPPooling(graph)
	if poolingErr != nil || !stable {
		model.Coverage = coverageString(graph, model, remoteReports)
		return model, ErrEvidenceInsufficient
	}
	model.PublicAddressStable = true

	allocation, minimum, maximum, predicted := classifyAllocation(samples)
	model.Allocation = allocation
	model.MinimumDelta = minimum
	model.MaximumDelta = maximum
	model.PredictedNextPort = predicted
	if allocation == AllocationSequentialUniform || allocation == AllocationMonotonicNonuniform {
		model.CandidateWindow = predictiveWindow(predicted)
		model.ResidualUniverse = uint32(len(model.CandidateWindow))
		model.AllocationLimitation = "short_window_only;competing_allocations_unbounded"
	} else {
		model.ResidualUniverse = 65535
		model.AllocationLimitation = "samples_do_not_bound_future_allocator;full_range_unknown"
	}
	model.Coverage = coverageString(graph, model, remoteReports)
	return model, nil
}

func validGraphHeader(graph EvidenceGraph) bool {
	return !allZero(graph.AttemptDigest[:]) && !allZero(graph.MachineScopeDigest[:]) &&
		!allZero(graph.PeerDigest[:]) && !allZero(graph.ObservationSetDigest[:]) &&
		!allZero(graph.SocketOwnerDigest[:]) && graph.Generation > 0 && graph.StartedAtMilli > 0 &&
		graph.StartedAtMilli <= graph.FinishedAtMilli && graph.FinishedAtMilli < graph.ExpiresAtMilli
}

func actionableMeta(meta EvidenceMeta, graph EvidenceGraph) bool {
	return meta.Origin == OriginLocalTransaction && meta.Source.strength() > 0 &&
		meta.ObserverAddress.Valid() && meta.ObserverPort != 0 && !allZero(meta.TransactionID[:]) &&
		meta.AttemptDigest == graph.AttemptDigest && meta.Generation == graph.Generation &&
		meta.ObservedAtMilli >= graph.StartedAtMilli && meta.ObservedAtMilli <= graph.FinishedAtMilli
}

func mergeMapping(graph EvidenceGraph) (MappingBehavior, EvidenceSource, error) {
	entries := append([]MappingEvidence(nil), graph.Mapping...)
	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare(encodeMappingEvidence(entries[left]), encodeMappingEvidence(entries[right])) < 0
	})
	seen := make(map[[12]byte]MappingEvidence)
	behavior := MappingUnknown
	var strongest EvidenceSource
	for _, entry := range entries {
		if !actionableMeta(entry.Meta, graph) || !entry.Behavior.valid() {
			continue
		}
		if previous, duplicate := seen[entry.Meta.TransactionID]; duplicate {
			if previous != entry {
				return MappingUnknown, "", ErrEvidenceInsufficient
			}
			continue
		}
		seen[entry.Meta.TransactionID] = entry
		if behavior != MappingUnknown && behavior != entry.Behavior {
			return MappingUnknown, "", ErrEvidenceInsufficient
		}
		behavior = entry.Behavior
		if entry.Meta.Source.strength() > strongest.strength() {
			strongest = entry.Meta.Source
		}
	}
	return behavior, strongest, nil
}

func mergeFiltering(graph EvidenceGraph) (FilteringBehavior, EvidenceSource, error) {
	entries := append([]FilteringEvidence(nil), graph.Filtering...)
	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare(encodeFilteringEvidence(entries[left]), encodeFilteringEvidence(entries[right])) < 0
	})
	seen := make(map[[12]byte]FilteringEvidence)
	behavior := FilteringUnknown
	var strongest EvidenceSource
	for _, entry := range entries {
		if !actionableMeta(entry.Meta, graph) || !entry.Behavior.valid() {
			continue
		}
		if previous, duplicate := seen[entry.Meta.TransactionID]; duplicate {
			if previous != entry {
				return FilteringUnknown, "", ErrEvidenceInsufficient
			}
			continue
		}
		seen[entry.Meta.TransactionID] = entry
		if behavior != FilteringUnknown && behavior != entry.Behavior {
			return FilteringUnknown, "", ErrEvidenceInsufficient
		}
		behavior = entry.Behavior
		if entry.Meta.Source.strength() > strongest.strength() {
			strongest = entry.Meta.Source
		}
	}
	return behavior, strongest, nil
}

func mergeIPPooling(graph EvidenceGraph) (bool, error) {
	entries := append([]IPPoolingEvidence(nil), graph.IPPooling...)
	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare(encodeIPPoolingEvidence(entries[left]), encodeIPPoolingEvidence(entries[right])) < 0
	})
	seen := make(map[[12]byte]IPPoolingEvidence)
	var poolDigest [32]byte
	hasPoolDigest := false
	for _, entry := range entries {
		if !actionableMeta(entry.Meta, graph) {
			continue
		}
		if previous, duplicate := seen[entry.Meta.TransactionID]; duplicate {
			if previous != entry {
				return false, ErrEvidenceInsufficient
			}
			continue
		}
		seen[entry.Meta.TransactionID] = entry
		if !entry.Stable || allZero(entry.PoolDigest[:]) {
			return false, ErrEvidenceInsufficient
		}
		if hasPoolDigest && poolDigest != entry.PoolDigest {
			return false, ErrEvidenceInsufficient
		}
		poolDigest = entry.PoolDigest
		hasPoolDigest = true
	}
	// The allocation samples independently prove same-address stability in the
	// bounded window. Explicit pooling evidence, when present, may only agree.
	return true, nil
}

func actionableAllocation(graph EvidenceGraph) ([]AllocationSample, int, int, error) {
	entries := append([]AllocationSample(nil), graph.Allocation...)
	sort.Slice(entries, func(left, right int) bool {
		return bytes.Compare(encodeAllocationSample(entries[left]), encodeAllocationSample(entries[right])) < 0
	})
	seenTransactions := make(map[[12]byte]AllocationSample)
	remoteReports := 0
	failedSamples := 0
	var samples []AllocationSample
	for _, entry := range entries {
		if entry.Meta.Origin == OriginRemoteReport {
			remoteReports++
			continue
		}
		if !actionableMeta(entry.Meta, graph) {
			continue
		}
		if previous, duplicate := seenTransactions[entry.Meta.TransactionID]; duplicate {
			if previous != entry {
				return nil, failedSamples, remoteReports, ErrEvidenceInsufficient
			}
			continue
		}
		seenTransactions[entry.Meta.TransactionID] = entry
		if !entry.Success {
			failedSamples++
			continue
		}
		if !entry.MappedAddress.Valid() || entry.MappedPort == 0 {
			continue
		}
		samples = append(samples, entry)
	}
	sort.Slice(samples, func(left, right int) bool {
		if samples[left].Ordinal != samples[right].Ordinal {
			return samples[left].Ordinal < samples[right].Ordinal
		}
		return bytes.Compare(samples[left].Meta.TransactionID[:], samples[right].Meta.TransactionID[:]) < 0
	})
	for index := 1; index < len(samples); index++ {
		if samples[index-1].Ordinal == samples[index].Ordinal ||
			samples[index-1].Meta.ObservedAtMilli > samples[index].Meta.ObservedAtMilli {
			return nil, failedSamples, remoteReports, ErrEvidenceInsufficient
		}
	}
	return samples, failedSamples, remoteReports, nil
}

func observerCoverage(samples []AllocationSample) (int, bool) {
	addresses := make(map[Address]map[uint16]struct{})
	for _, sample := range samples {
		ports := addresses[sample.Meta.ObserverAddress]
		if ports == nil {
			ports = make(map[uint16]struct{})
			addresses[sample.Meta.ObserverAddress] = ports
		}
		ports[sample.Meta.ObserverPort] = struct{}{}
	}
	hasAlternatePort := false
	for _, ports := range addresses {
		if len(ports) >= 2 {
			hasAlternatePort = true
		}
	}
	return len(addresses), hasAlternatePort
}

func classifyAllocation(samples []AllocationSample) (AllocationBehavior, uint16, uint16, uint16) {
	if len(samples) < MinSuccessfulAllocationSamples {
		return AllocationInsufficientData, 0, 0, 0
	}
	deltas := make([]uint16, 0, len(samples)-1)
	minimum, maximum := uint16(65535), uint16(0)
	for index := 1; index < len(samples); index++ {
		delta := forwardPortDelta(samples[index-1].MappedPort, samples[index].MappedPort)
		deltas = append(deltas, delta)
		if delta < minimum {
			minimum = delta
		}
		if delta > maximum {
			maximum = delta
		}
	}
	behavior := AllocationApparentlyRandom
	if minimum == maximum && maximum <= MaxMonotonicDelta {
		behavior = AllocationSequentialUniform
	} else if maximum <= MaxMonotonicDelta && uint32(maximum)-uint32(minimum) <= MaxMonotonicDeltaSpread {
		behavior = AllocationMonotonicNonuniform
	}
	median := append([]uint16(nil), deltas...)
	sort.Slice(median, func(left, right int) bool { return median[left] < median[right] })
	predicted := addPort(samples[len(samples)-1].MappedPort, median[len(median)/2])
	return behavior, minimum, maximum, predicted
}

func forwardPortDelta(previous, next uint16) uint16 {
	if next > previous {
		return next - previous
	}
	return uint16((65535 - uint32(previous)) + uint32(next))
}

func addPort(port, delta uint16) uint16 {
	value := (uint32(port)-1+uint32(delta))%65535 + 1
	return uint16(value)
}

func predictiveWindow(predicted uint16) []uint16 {
	if predicted == 0 {
		return nil
	}
	result := make([]uint16, 0, PredictiveWindowPorts)
	seen := make(map[uint16]struct{}, PredictiveWindowPorts)
	for radius := uint16(0); len(result) < PredictiveWindowPorts; radius++ {
		values := []uint16{addPort(predicted, radius)}
		if radius > 0 {
			values = append(values, addPort(predicted, uint16(65535)-radius))
		}
		for _, value := range values {
			if _, duplicate := seen[value]; duplicate {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
			if len(result) == PredictiveWindowPorts {
				break
			}
		}
	}
	return result
}

func coverageString(graph EvidenceGraph, model StateModel, remoteReports int) string {
	return fmt.Sprintf(
		"local_successes=%d;local_failures=%d;observer_addresses=%d;alternate_port=%t;remote_reports_untrusted=%d;mapping=%s;filtering=%s;allocation=%s;residual_universe=%d;limitation=%s",
		model.SuccessfulSamples, model.FailedSamples, model.ObserverAddressCount, model.HasAlternatePort, remoteReports,
		model.Mapping, model.Filtering, model.Allocation, model.ResidualUniverse, model.AllocationLimitation,
	)
}

// DigestEvidence freezes the complete raw evidence graph, including ignored
// remote reports, so that dropping or adding an untrusted sample still changes
// the evidence digest without granting that sample control authority.
func DigestEvidence(graph EvidenceGraph) ([32]byte, error) {
	var records [][]byte
	for _, entry := range graph.Mapping {
		records = append(records, encodeMappingEvidence(entry))
	}
	for _, entry := range graph.Filtering {
		records = append(records, encodeFilteringEvidence(entry))
	}
	for _, entry := range graph.IPPooling {
		records = append(records, encodeIPPoolingEvidence(entry))
	}
	for _, entry := range graph.Allocation {
		records = append(records, encodeAllocationSample(entry))
	}
	sort.Slice(records, func(left, right int) bool { return bytes.Compare(records[left], records[right]) < 0 })

	var encoded bytes.Buffer
	encoded.WriteString(evidenceEncodingLabel)
	encoded.Write(graph.AttemptDigest[:])
	encoded.Write(graph.MachineScopeDigest[:])
	encoded.Write(graph.PeerDigest[:])
	encoded.Write(graph.ObservationSetDigest[:])
	encoded.Write(graph.SocketOwnerDigest[:])
	appendUint64(&encoded, graph.Generation)
	appendInt64(&encoded, graph.StartedAtMilli)
	appendInt64(&encoded, graph.FinishedAtMilli)
	appendInt64(&encoded, graph.ExpiresAtMilli)
	appendUint32(&encoded, uint32(len(records)))
	for _, record := range records {
		appendUint32(&encoded, uint32(len(record)))
		encoded.Write(record)
		clear(record)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func actionableEvidenceGraph(graph EvidenceGraph) EvidenceGraph {
	filtered := EvidenceGraph{
		AttemptDigest: graph.AttemptDigest, MachineScopeDigest: graph.MachineScopeDigest, PeerDigest: graph.PeerDigest,
		ObservationSetDigest: graph.ObservationSetDigest, SocketOwnerDigest: graph.SocketOwnerDigest,
		Generation: graph.Generation, StartedAtMilli: graph.StartedAtMilli, FinishedAtMilli: graph.FinishedAtMilli, ExpiresAtMilli: graph.ExpiresAtMilli,
	}
	for _, entry := range graph.Mapping {
		if actionableMeta(entry.Meta, graph) && entry.Behavior.valid() {
			filtered.Mapping = append(filtered.Mapping, entry)
		}
	}
	for _, entry := range graph.Filtering {
		if actionableMeta(entry.Meta, graph) && entry.Behavior.valid() {
			filtered.Filtering = append(filtered.Filtering, entry)
		}
	}
	for _, entry := range graph.IPPooling {
		if actionableMeta(entry.Meta, graph) && entry.Stable && !allZero(entry.PoolDigest[:]) {
			filtered.IPPooling = append(filtered.IPPooling, entry)
		}
	}
	for _, entry := range graph.Allocation {
		if actionableMeta(entry.Meta, graph) && ((!entry.Success) || (entry.MappedAddress.Valid() && entry.MappedPort != 0)) {
			filtered.Allocation = append(filtered.Allocation, entry)
		}
	}
	return filtered
}

func encodeMappingEvidence(entry MappingEvidence) []byte {
	return encodeEvidenceRecord(1, entry.Meta, string(entry.Behavior), nil)
}

func encodeFilteringEvidence(entry FilteringEvidence) []byte {
	return encodeEvidenceRecord(2, entry.Meta, string(entry.Behavior), nil)
}

func encodeIPPoolingEvidence(entry IPPoolingEvidence) []byte {
	extra := make([]byte, 33)
	if entry.Stable {
		extra[0] = 1
	}
	copy(extra[1:], entry.PoolDigest[:])
	return encodeEvidenceRecord(3, entry.Meta, "", extra)
}

func encodeAllocationSample(entry AllocationSample) []byte {
	var extra bytes.Buffer
	appendUint16(&extra, entry.SocketSlot)
	appendUint32(&extra, entry.Ordinal)
	appendAddress(&extra, entry.MappedAddress)
	appendUint16(&extra, entry.MappedPort)
	if entry.Success {
		extra.WriteByte(1)
	} else {
		extra.WriteByte(0)
	}
	return encodeEvidenceRecord(4, entry.Meta, "", extra.Bytes())
}

func encodeEvidenceRecord(kind byte, meta EvidenceMeta, value string, extra []byte) []byte {
	var encoded bytes.Buffer
	encoded.WriteByte(kind)
	appendString(&encoded, string(meta.Source))
	appendString(&encoded, string(meta.Origin))
	appendAddress(&encoded, meta.ObserverAddress)
	appendUint16(&encoded, meta.ObserverPort)
	encoded.Write(meta.TransactionID[:])
	encoded.Write(meta.AttemptDigest[:])
	appendUint64(&encoded, meta.Generation)
	appendInt64(&encoded, meta.ObservedAtMilli)
	appendString(&encoded, value)
	appendUint32(&encoded, uint32(len(extra)))
	encoded.Write(extra)
	return encoded.Bytes()
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
