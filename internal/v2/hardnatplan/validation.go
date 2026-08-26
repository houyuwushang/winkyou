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

	accept := func(kind EvidenceKind, meta EvidenceMeta, record []byte, appendRecord func()) error {
		defer clear(record)
		if meta.Origin == OriginRemoteReport {
			return nil
		}
		key := issuedTransactionKey(meta.TransactionID)
		issued, ok := manifest[key]
		if !ok || issued.Kind != kind || !metaMatchesIssued(meta, issued, graph) {
			return ErrInvalidEvidence
		}
		if previous, duplicate := seen[key]; duplicate {
			if !bytes.Equal(previous, record) {
				return ErrEvidenceInsufficient
			}
			return nil
		}
		seen[key] = append([]byte(nil), record...)
		appendRecord()
		return nil
	}

	for _, entry := range graph.Mapping {
		entry := entry
		if err := accept(EvidenceKindMapping, entry.Meta, encodeMappingEvidence(entry), func() {
			normalized.Mapping = append(normalized.Mapping, entry)
		}); err != nil {
			return empty, validationDigest, err
		}
	}
	for _, entry := range graph.Filtering {
		entry := entry
		if err := accept(EvidenceKindFiltering, entry.Meta, encodeFilteringEvidence(entry), func() {
			normalized.Filtering = append(normalized.Filtering, entry)
		}); err != nil {
			return empty, validationDigest, err
		}
	}
	for _, entry := range graph.IPPooling {
		entry := entry
		if err := accept(EvidenceKindIPPooling, entry.Meta, encodeIPPoolingEvidence(entry), func() {
			normalized.IPPooling = append(normalized.IPPooling, entry)
		}); err != nil {
			return empty, validationDigest, err
		}
	}
	for _, entry := range graph.Allocation {
		entry := entry
		if err := accept(EvidenceKindAllocation, entry.Meta, encodeAllocationSample(entry), func() {
			normalized.Allocation = append(normalized.Allocation, entry)
		}); err != nil {
			return empty, validationDigest, err
		}
		if entry.Meta.Origin == OriginLocalTransaction {
			issued := manifest[issuedTransactionKey(entry.Meta.TransactionID)]
			if entry.Meta.SocketSlot != entry.SocketSlot || issued.SocketSlot != entry.SocketSlot || issued.Ordinal != entry.Ordinal {
				return empty, validationDigest, ErrInvalidEvidence
			}
		}
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
	default:
		return false
	}
}

func metaMatchesIssued(meta EvidenceMeta, issued IssuedTransaction, graph EvidenceGraph) bool {
	return meta.Origin == OriginLocalTransaction && meta.Source == issued.Source &&
		meta.ObserverAddress == issued.Observer.Address && meta.ObserverPort == issued.Observer.Port &&
		meta.SocketSlot == issued.SocketSlot &&
		meta.AttemptDigest == graph.AttemptDigest && meta.Generation == graph.Generation &&
		meta.ObservedAtMilli >= issued.NotBeforeMilli && meta.ObservedAtMilli <= issued.NotAfterMilli
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
