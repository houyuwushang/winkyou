package hardnatplan

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
)

const validationEncodingLabel = "winkyou-hardnat-validation-v1\x00"

type issuedTransactionKey [12]byte

func normalizeEvidence(graph EvidenceGraph, trusted TrustedValidationContext) (EvidenceGraph, [32]byte, error) {
	var empty EvidenceGraph
	if err := validateTrustedHeader(graph, trusted); err != nil {
		return empty, [32]byte{}, err
	}
	validationDigest, err := DigestValidationContext(trusted)
	if err != nil {
		return empty, [32]byte{}, err
	}
	manifest := make(map[issuedTransactionKey]IssuedTransaction, len(trusted.Issued))
	for _, issued := range trusted.Issued {
		key := issuedTransactionKey(issued.TransactionID)
		if _, duplicate := manifest[key]; duplicate || !validIssuedTransaction(issued, trusted) {
			return empty, [32]byte{}, ErrInvalidEvidence
		}
		manifest[key] = issued
	}
	if len(manifest) == 0 {
		return empty, [32]byte{}, ErrEvidenceInsufficient
	}

	normalized := EvidenceGraph{
		AttemptDigest: graph.AttemptDigest, MachineScopeDigest: graph.MachineScopeDigest, PeerDigest: graph.PeerDigest,
		ObservationSetDigest: graph.ObservationSetDigest, SocketOwnerDigest: graph.SocketOwnerDigest,
		Generation: graph.Generation, StartedAtMilli: graph.StartedAtMilli, FinishedAtMilli: graph.FinishedAtMilli, ExpiresAtMilli: graph.ExpiresAtMilli,
	}
	seen := make(map[issuedTransactionKey][]byte, len(manifest))

	acceptBound := func(
		kind EvidenceKind,
		transaction TransactionID,
		source EvidenceSource,
		observer AddressPort,
		socketSlot uint16,
		ordinal uint32,
		observedAtMilli int64,
		record []byte,
	) (bool, error) {
		defer clear(record)
		key := issuedTransactionKey(transaction)
		issued, ok := manifest[key]
		if !ok || issued.Kind != kind || issued.TransactionID != transaction || issued.Source != source ||
			issued.Observer != observer || issued.SocketSlot != socketSlot || issued.Ordinal != ordinal ||
			observedAtMilli < issued.NotBeforeMilli || observedAtMilli > issued.NotAfterMilli {
			return false, ErrInvalidEvidence
		}
		if previous, duplicate := seen[key]; duplicate {
			if !bytes.Equal(previous, record) {
				return false, ErrEvidenceInsufficient
			}
			return true, nil
		}
		seen[key] = append([]byte(nil), record...)
		return false, nil
	}

	for _, entry := range graph.Mapping {
		entry := entry
		if entry.Meta.Origin == OriginRemoteReport {
			continue
		}
		if entry.Meta.Source == SourceRFC5780 || !actionableMeta(entry.Meta, graph) {
			return empty, validationDigest, ErrInvalidEvidence
		}
		duplicate, acceptErr := acceptBound(
			EvidenceKindMapping, entry.Meta.TransactionID, entry.Meta.Source,
			AddressPort{Address: entry.Meta.ObserverAddress, Port: entry.Meta.ObserverPort},
			entry.Meta.SocketSlot, 0, entry.Meta.ObservedAtMilli, encodeMappingEvidence(entry),
		)
		if acceptErr != nil {
			return empty, validationDigest, acceptErr
		}
		if !duplicate {
			normalized.Mapping = append(normalized.Mapping, entry)
		}
	}
	for _, entry := range graph.Filtering {
		entry := entry
		if entry.Meta.Origin == OriginRemoteReport {
			continue
		}
		if entry.Meta.Source == SourceRFC5780 || !actionableMeta(entry.Meta, graph) {
			return empty, validationDigest, ErrInvalidEvidence
		}
		duplicate, acceptErr := acceptBound(
			EvidenceKindFiltering, entry.Meta.TransactionID, entry.Meta.Source,
			AddressPort{Address: entry.Meta.ObserverAddress, Port: entry.Meta.ObserverPort},
			entry.Meta.SocketSlot, 0, entry.Meta.ObservedAtMilli, encodeFilteringEvidence(entry),
		)
		if acceptErr != nil {
			return empty, validationDigest, acceptErr
		}
		if !duplicate {
			normalized.Filtering = append(normalized.Filtering, entry)
		}
	}
	for _, entry := range graph.IPPooling {
		entry := entry
		if entry.Meta.Origin == OriginRemoteReport {
			continue
		}
		if !actionableMeta(entry.Meta, graph) {
			return empty, validationDigest, ErrInvalidEvidence
		}
		duplicate, acceptErr := acceptBound(
			EvidenceKindIPPooling, entry.Meta.TransactionID, entry.Meta.Source,
			AddressPort{Address: entry.Meta.ObserverAddress, Port: entry.Meta.ObserverPort},
			entry.Meta.SocketSlot, 0, entry.Meta.ObservedAtMilli, encodeIPPoolingEvidence(entry),
		)
		if acceptErr != nil {
			return empty, validationDigest, acceptErr
		}
		if !duplicate {
			normalized.IPPooling = append(normalized.IPPooling, entry)
		}
	}
	for _, entry := range graph.Allocation {
		entry := entry
		if entry.Meta.Origin == OriginRemoteReport {
			continue
		}
		if !actionableMeta(entry.Meta, graph) || entry.Meta.SocketSlot != entry.SocketSlot {
			return empty, validationDigest, ErrInvalidEvidence
		}
		duplicate, acceptErr := acceptBound(
			EvidenceKindAllocation, entry.Meta.TransactionID, entry.Meta.Source,
			AddressPort{Address: entry.Meta.ObserverAddress, Port: entry.Meta.ObserverPort},
			entry.SocketSlot, entry.Ordinal, entry.Meta.ObservedAtMilli, encodeAllocationSample(entry),
		)
		if acceptErr != nil {
			return empty, validationDigest, acceptErr
		}
		if !duplicate {
			normalized.Allocation = append(normalized.Allocation, entry)
		}
	}
	for _, transcript := range graph.RFC5780 {
		if transcript.Origin == OriginRemoteReport {
			continue
		}
		if transcript.Origin != OriginLocalTransaction {
			return empty, validationDigest, ErrInvalidEvidence
		}
		derived, deriveErr := deriveRFC5780Transcript(transcript)
		if deriveErr != nil {
			return empty, validationDigest, deriveErr
		}
		duplicates := 0
		for index, exchange := range transcript.Exchanges {
			duplicate, acceptErr := acceptBound(
				EvidenceKindRFC5780, exchange.TransactionID, SourceRFC5780, exchange.RequestDestination,
				transcript.SocketSlot, uint32(index), exchange.ObservedAtMilli, encodeRFC5780Exchange(exchange),
			)
			if acceptErr != nil {
				return empty, validationDigest, acceptErr
			}
			if duplicate {
				duplicates++
			}
		}
		if duplicates != 0 && duplicates != RFC5780ExchangeCount {
			return empty, validationDigest, ErrEvidenceInsufficient
		}
		if duplicates == RFC5780ExchangeCount {
			continue
		}
		normalized.RFC5780 = append(normalized.RFC5780, transcript.Clone())
		mappingExchange := transcript.Exchanges[2]
		filteringExchange := transcript.Exchanges[4]
		normalized.Mapping = append(normalized.Mapping, MappingEvidence{
			Meta:     derivedRFC5780Meta(graph, transcript, mappingExchange),
			Behavior: derived.mapping,
		})
		normalized.Filtering = append(normalized.Filtering, FilteringEvidence{
			Meta:     derivedRFC5780Meta(graph, transcript, filteringExchange),
			Behavior: derived.filtering,
		})
	}
	if len(seen) != len(manifest) {
		return empty, validationDigest, ErrEvidenceInsufficient
	}
	for _, value := range seen {
		clear(value)
	}
	return normalized, validationDigest, nil
}

func validateTrustedHeader(graph EvidenceGraph, trusted TrustedValidationContext) error {
	if !validGraphHeader(graph) || trusted.NowMilli <= 0 ||
		allZero(trusted.ExpectedAttemptDigest[:]) || allZero(trusted.ExpectedMachineScopeDigest[:]) ||
		allZero(trusted.ExpectedPeerDigest[:]) || allZero(trusted.ExpectedObservationSetDigest[:]) ||
		allZero(trusted.ExpectedSocketOwnerDigest[:]) || trusted.ExpectedGeneration == 0 {
		return ErrInvalidEvidence
	}
	if graph.AttemptDigest != trusted.ExpectedAttemptDigest || graph.MachineScopeDigest != trusted.ExpectedMachineScopeDigest ||
		graph.PeerDigest != trusted.ExpectedPeerDigest || graph.ObservationSetDigest != trusted.ExpectedObservationSetDigest ||
		graph.SocketOwnerDigest != trusted.ExpectedSocketOwnerDigest || graph.Generation != trusted.ExpectedGeneration ||
		graph.StartedAtMilli != trusted.ExpectedStartedAtMilli || graph.FinishedAtMilli != trusted.ExpectedFinishedAtMilli ||
		graph.ExpiresAtMilli != trusted.ExpectedExpiresAtMilli {
		return ErrInvalidEvidence
	}
	if graph.FinishedAtMilli-graph.StartedAtMilli > MaxEvidenceWindowMillis || trusted.NowMilli < graph.FinishedAtMilli ||
		trusted.NowMilli-graph.FinishedAtMilli > MaxEvidenceAgeMillis || trusted.NowMilli >= graph.ExpiresAtMilli ||
		graph.ExpiresAtMilli-graph.FinishedAtMilli > MaxEvidenceAgeMillis {
		return ErrEvidenceInsufficient
	}
	return nil
}

func validIssuedTransaction(issued IssuedTransaction, trusted TrustedValidationContext) bool {
	if allZero(issued.TransactionID[:]) || issued.Source.strength() == 0 || !issued.Observer.Valid() ||
		issued.NotBeforeMilli < trusted.ExpectedStartedAtMilli || issued.NotAfterMilli > trusted.ExpectedFinishedAtMilli ||
		issued.NotBeforeMilli > issued.NotAfterMilli {
		return false
	}
	switch issued.Kind {
	case EvidenceKindMapping, EvidenceKindFiltering, EvidenceKindIPPooling:
		return issued.Ordinal == 0
	case EvidenceKindAllocation:
		return true
	case EvidenceKindRFC5780:
		return issued.Source == SourceRFC5780 && issued.Ordinal < RFC5780ExchangeCount
	default:
		return false
	}
}

func derivedRFC5780Meta(graph EvidenceGraph, transcript RFC5780Transcript, exchange RFC5780Exchange) EvidenceMeta {
	return EvidenceMeta{
		Source: SourceRFC5780, Origin: OriginLocalTransaction,
		ObserverAddress: exchange.RequestDestination.Address, ObserverPort: exchange.RequestDestination.Port,
		SocketSlot: transcript.SocketSlot, TransactionID: exchange.TransactionID,
		AttemptDigest: graph.AttemptDigest, Generation: graph.Generation, ObservedAtMilli: exchange.ObservedAtMilli,
	}
}

// DigestValidationContext commits the stable trust anchors and issued
// transaction manifest. NowMilli is deliberately excluded: it is used only
// for freshness admission, so two valid evaluations of the same acquisition
// window cannot produce different actionable or plan digests.
func DigestValidationContext(trusted TrustedValidationContext) ([32]byte, error) {
	if trusted.NowMilli <= 0 || len(trusted.Issued) == 0 {
		return [32]byte{}, ErrInvalidEvidence
	}
	issued := append([]IssuedTransaction(nil), trusted.Issued...)
	sort.Slice(issued, func(left, right int) bool {
		return bytes.Compare(encodeIssuedTransaction(issued[left]), encodeIssuedTransaction(issued[right])) < 0
	})
	var encoded bytes.Buffer
	encoded.WriteString(validationEncodingLabel)
	encoded.Write(trusted.ExpectedAttemptDigest[:])
	encoded.Write(trusted.ExpectedMachineScopeDigest[:])
	encoded.Write(trusted.ExpectedPeerDigest[:])
	encoded.Write(trusted.ExpectedObservationSetDigest[:])
	encoded.Write(trusted.ExpectedSocketOwnerDigest[:])
	appendUint64(&encoded, trusted.ExpectedGeneration)
	appendInt64(&encoded, trusted.ExpectedStartedAtMilli)
	appendInt64(&encoded, trusted.ExpectedFinishedAtMilli)
	appendInt64(&encoded, trusted.ExpectedExpiresAtMilli)
	appendUint32(&encoded, uint32(len(issued)))
	for _, transaction := range issued {
		record := encodeIssuedTransaction(transaction)
		appendUint32(&encoded, uint32(len(record)))
		encoded.Write(record)
		clear(record)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func encodeIssuedTransaction(issued IssuedTransaction) []byte {
	var encoded bytes.Buffer
	appendString(&encoded, string(issued.Kind))
	encoded.Write(issued.TransactionID[:])
	appendString(&encoded, string(issued.Source))
	appendAddress(&encoded, issued.Observer.Address)
	appendUint16(&encoded, issued.Observer.Port)
	appendUint16(&encoded, issued.SocketSlot)
	appendUint32(&encoded, issued.Ordinal)
	appendInt64(&encoded, issued.NotBeforeMilli)
	appendInt64(&encoded, issued.NotAfterMilli)
	return encoded.Bytes()
}

func digestValidatedEvidence(graph EvidenceGraph, validationDigest [32]byte) ([32]byte, error) {
	graphDigest, err := DigestEvidence(graph)
	if err != nil {
		return [32]byte{}, err
	}
	if allZero(validationDigest[:]) {
		return [32]byte{}, fmt.Errorf("%w: empty validation digest", ErrInvalidEvidence)
	}
	var encoded bytes.Buffer
	encoded.WriteString("winkyou-hardnat-actionable-evidence-v1\x00")
	encoded.Write(validationDigest[:])
	encoded.Write(graphDigest[:])
	return sha256.Sum256(encoded.Bytes()), nil
}
