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
// returns the same fail-closed class and an empty predicted source schedule.
func InferStateModel(graph EvidenceGraph, trusted TrustedValidationContext) (StateModel, error) {
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
	normalized, validationDigest, normalizeErr := normalizeEvidence(graph, trusted)
	model.ValidationDigest = validationDigest
	if normalizeErr != nil {
		return model, normalizeErr
	}
	digest, digestErr := digestValidatedEvidence(normalized, validationDigest)
	model.EvidenceDigest = digest
	if digestErr != nil {
		return model, digestErr
	}

	mapping, mappingSource, mappingErr := mergeMapping(normalized)
	if mappingErr != nil {
		return model, ErrEvidenceInsufficient
	}
	filtering, filteringSource, filteringErr := mergeFiltering(normalized)
	if filteringErr != nil {
		return model, ErrEvidenceInsufficient
	}
	model.Mapping, model.MappingSource = mapping, mappingSource
	model.Filtering, model.FilteringSource = filtering, filteringSource
	reusableEndpoint, reusableEndpointSlot, endpointErr := reusableRFC5780Endpoint(normalized.RFC5780)
	if endpointErr != nil {
		return model, ErrEvidenceInsufficient
	}

	samples, failedSamples, sampleErr := continuousSuccessfulAllocationSuffix(normalized.Allocation)
	if sampleErr != nil {
		return model, ErrEvidenceInsufficient
	}
	model.SuccessfulSamples = len(samples)
	model.FailedSamples = failedSamples
	model.ObserverAddressCount, model.HasAlternatePort = observerCoverage(samples)
	if len(samples) < MinSuccessfulAllocationSamples || model.ObserverAddressCount < 2 || !model.HasAlternatePort {
		model.Coverage = coverageString(model)
		return model, ErrEvidenceInsufficient
	}

	publicAddress := samples[0].MappedAddress
	for _, sample := range samples[1:] {
		if sample.MappedAddress != publicAddress {
			model.Coverage = coverageString(model)
			return model, ErrEvidenceInsufficient
		}
	}
	if reusableEndpoint.Valid() {
		witnessed := false
		for _, sample := range samples {
			if sample.SocketSlot == reusableEndpointSlot && sample.MappedAddress == reusableEndpoint.Address && sample.MappedPort == reusableEndpoint.Port {
				witnessed = true
				break
			}
		}
		if !witnessed {
			model.Coverage = coverageString(model)
			return model, ErrEvidenceInsufficient
		}
		model.ReusableEndpoint = reusableEndpoint
		model.ReusableEndpointSlot = reusableEndpointSlot
	}
	stable, poolingErr := mergeIPPooling(normalized)
	if poolingErr != nil || !stable {
		model.Coverage = coverageString(model)
		return model, ErrEvidenceInsufficient
	}
	model.PublicAddressStable = true

	allocation, minimum, maximum, predicted, predictedStep := classifyAllocation(samples)
	model.Allocation = allocation
	model.MinimumDelta = minimum
	model.MaximumDelta = maximum
	model.PredictedNextPort = predicted
	if allocation == AllocationSequentialUniform || allocation == AllocationMonotonicNonuniform {
		model.PredictedSourcePorts = predictiveSourceSchedule(samples[len(samples)-1].MappedPort, predictedStep)
		model.ResidualUniverse = uint32(len(model.PredictedSourcePorts))
		model.AllocationLimitation = "short_window_only;competing_allocations_unbounded"
	} else {
		model.ResidualUniverse = 65535
		model.AllocationLimitation = "samples_do_not_bound_future_allocator;full_range_unknown"
	}
	model.Coverage = coverageString(model)
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

func continuousSuccessfulAllocationSuffix(entries []AllocationSample) ([]AllocationSample, int, error) {
	byOrdinal := make(map[uint32]AllocationSample, len(entries))
	failedSamples := 0
	var maximumOrdinal uint32
	hasAllocation := false
	for _, entry := range entries {
		if _, duplicate := byOrdinal[entry.Ordinal]; duplicate {
			return nil, failedSamples, ErrEvidenceInsufficient
		}
		byOrdinal[entry.Ordinal] = entry
		if !entry.Success {
			failedSamples++
		}
		if !hasAllocation || entry.Ordinal > maximumOrdinal {
			maximumOrdinal = entry.Ordinal
			hasAllocation = true
		}
	}
	if !hasAllocation {
		return nil, failedSamples, ErrEvidenceInsufficient
	}
	var reversed []AllocationSample
	for ordinal := maximumOrdinal; ; ordinal-- {
		entry, ok := byOrdinal[ordinal]
		if !ok || !entry.Success || !entry.MappedAddress.Valid() || entry.MappedPort == 0 {
			break
		}
		reversed = append(reversed, entry)
		if ordinal == 0 {
			break
		}
	}
	if len(reversed) < MinSuccessfulAllocationSamples {
		return nil, failedSamples, ErrEvidenceInsufficient
	}
	samples := make([]AllocationSample, len(reversed))
	for index := range reversed {
		samples[len(reversed)-1-index] = reversed[index]
	}
	for index := 1; index < len(samples); index++ {
		if samples[index-1].Ordinal+1 != samples[index].Ordinal || samples[index-1].Meta.ObservedAtMilli > samples[index].Meta.ObservedAtMilli {
			return nil, failedSamples, ErrEvidenceInsufficient
		}
	}
	return samples, failedSamples, nil
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

func classifyAllocation(samples []AllocationSample) (AllocationBehavior, uint16, uint16, uint16, uint16) {
	if len(samples) < MinSuccessfulAllocationSamples {
		return AllocationInsufficientData, 0, 0, 0, 0
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
	predictedStep := median[len(median)/2]
	predicted := addPort(samples[len(samples)-1].MappedPort, predictedStep)
	return behavior, minimum, maximum, predicted, predictedStep
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

func predictiveSourceSchedule(last, step uint16) []uint16 {
	if last == 0 || step == 0 {
		return nil
	}
	result := make([]uint16, 0, PredictiveWindowPorts)
	current := last
	for len(result) < PredictiveWindowPorts {
		current = addPort(current, step)
		result = append(result, current)
	}
	return result
}

func coverageString(model StateModel) string {
	return fmt.Sprintf(
		"local_successes=%d;local_failures=%d;observer_addresses=%d;alternate_port=%t;mapping=%s;filtering=%s;allocation=%s;residual_universe=%d;limitation=%s",
		model.SuccessfulSamples, model.FailedSamples, model.ObserverAddressCount, model.HasAlternatePort,
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
	for _, transcript := range graph.RFC5780 {
		records = append(records, encodeRFC5780Transcript(transcript))
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

func encodeRFC5780Transcript(transcript RFC5780Transcript) []byte {
	var encoded bytes.Buffer
	encoded.WriteByte(5)
	appendString(&encoded, string(transcript.Origin))
	appendUint16(&encoded, transcript.SocketSlot)
	appendUint32(&encoded, RFC5780ExchangeCount)
	for _, exchange := range transcript.Exchanges {
		record := encodeRFC5780Exchange(exchange)
		appendUint32(&encoded, uint32(len(record)))
		encoded.Write(record)
		clear(record)
	}
	return encoded.Bytes()
}

func encodeRFC5780Exchange(exchange RFC5780Exchange) []byte {
	var encoded bytes.Buffer
	appendString(&encoded, string(exchange.Step))
	encoded.Write(exchange.TransactionID[:])
	appendAddress(&encoded, exchange.RequestDestination.Address)
	appendUint16(&encoded, exchange.RequestDestination.Port)
	appendAddress(&encoded, exchange.ResponseSource.Address)
	appendUint16(&encoded, exchange.ResponseSource.Port)
	appendInt64(&encoded, exchange.ObservedAtMilli)
	if exchange.Received {
		encoded.WriteByte(1)
	} else {
		encoded.WriteByte(0)
	}
	appendUint32(&encoded, uint32(len(exchange.Request)))
	encoded.Write(exchange.Request)
	appendUint32(&encoded, uint32(len(exchange.Response)))
	encoded.Write(exchange.Response)
	return encoded.Bytes()
}

func encodeEvidenceRecord(kind byte, meta EvidenceMeta, value string, extra []byte) []byte {
	var encoded bytes.Buffer
	encoded.WriteByte(kind)
	appendString(&encoded, string(meta.Source))
	appendString(&encoded, string(meta.Origin))
	appendAddress(&encoded, meta.ObserverAddress)
	appendUint16(&encoded, meta.ObserverPort)
	appendUint16(&encoded, meta.SocketSlot)
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
