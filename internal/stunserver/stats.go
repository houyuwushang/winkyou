package stunserver

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

// DropStats contains only stable aggregate categories. It never contains a
// client address, port, packet, or transaction ID.
type DropStats struct {
	GlobalRateLimit          uint64 `json:"global_rate_limit"`
	SourceRateLimit          uint64 `json:"source_rate_limit"`
	SourceTableFull          uint64 `json:"source_table_full"`
	InvalidSource            uint64 `json:"invalid_source"`
	MessageTooLarge          uint64 `json:"message_too_large"`
	TruncatedMessage         uint64 `json:"truncated_message"`
	UnexpectedMessage        uint64 `json:"unexpected_message"`
	MagicCookieMismatch      uint64 `json:"magic_cookie_mismatch"`
	AttributeLength          uint64 `json:"attribute_length"`
	UnknownRequiredAttribute uint64 `json:"unknown_required_attribute"`
	InvalidMappedEndpoint    uint64 `json:"invalid_mapped_endpoint"`
	WriteFailure             uint64 `json:"write_failure"`
}

// Stats is a point-in-time aggregate snapshot. ResponsePrefixes is populated
// only when Config.LogPrefixes is explicitly enabled and contains only /24 or
// /48 prefixes. PrefixesOmitted counts responses whose new prefix could not be
// retained because the bounded prefix table was full.
type Stats struct {
	Received         uint64            `json:"received"`
	Responded        uint64            `json:"responded"`
	Dropped          DropStats         `json:"dropped"`
	ResponsePrefixes map[string]uint64 `json:"response_prefixes,omitempty"`
	PrefixesOmitted  uint64            `json:"prefixes_omitted,omitempty"`
}

type counters struct {
	received                 atomic.Uint64
	responded                atomic.Uint64
	globalRateLimit          atomic.Uint64
	sourceRateLimit          atomic.Uint64
	sourceTableFull          atomic.Uint64
	invalidSource            atomic.Uint64
	messageTooLarge          atomic.Uint64
	truncatedMessage         atomic.Uint64
	unexpectedMessage        atomic.Uint64
	magicCookieMismatch      atomic.Uint64
	attributeLength          atomic.Uint64
	unknownRequiredAttribute atomic.Uint64
	invalidMappedEndpoint    atomic.Uint64
	writeFailure             atomic.Uint64
	prefixesOmitted          atomic.Uint64
	logPrefixes              bool
	prefixMu                 sync.Mutex
	responsePrefixes         map[string]uint64
}

func newCounters(logPrefixes bool) *counters {
	result := &counters{logPrefixes: logPrefixes}
	if logPrefixes {
		result.responsePrefixes = make(map[string]uint64, MaxLoggedPrefixes)
	}
	return result
}

func (current *counters) responseFrom(address netip.Addr) {
	current.responded.Add(1)
	if !current.logPrefixes {
		return
	}
	prefix := redactedPrefix(address)
	if prefix == "" {
		return
	}
	current.prefixMu.Lock()
	defer current.prefixMu.Unlock()
	if _, found := current.responsePrefixes[prefix]; !found && len(current.responsePrefixes) >= MaxLoggedPrefixes {
		current.prefixesOmitted.Add(1)
		return
	}
	current.responsePrefixes[prefix]++
}

func (current *counters) snapshot() Stats {
	result := Stats{
		Received:  current.received.Load(),
		Responded: current.responded.Load(),
		Dropped: DropStats{
			GlobalRateLimit:          current.globalRateLimit.Load(),
			SourceRateLimit:          current.sourceRateLimit.Load(),
			SourceTableFull:          current.sourceTableFull.Load(),
			InvalidSource:            current.invalidSource.Load(),
			MessageTooLarge:          current.messageTooLarge.Load(),
			TruncatedMessage:         current.truncatedMessage.Load(),
			UnexpectedMessage:        current.unexpectedMessage.Load(),
			MagicCookieMismatch:      current.magicCookieMismatch.Load(),
			AttributeLength:          current.attributeLength.Load(),
			UnknownRequiredAttribute: current.unknownRequiredAttribute.Load(),
			InvalidMappedEndpoint:    current.invalidMappedEndpoint.Load(),
			WriteFailure:             current.writeFailure.Load(),
		},
		PrefixesOmitted: current.prefixesOmitted.Load(),
	}
	if current.logPrefixes {
		current.prefixMu.Lock()
		result.ResponsePrefixes = make(map[string]uint64, len(current.responsePrefixes))
		for prefix, count := range current.responsePrefixes {
			result.ResponsePrefixes[prefix] = count
		}
		current.prefixMu.Unlock()
	}
	return result
}

func redactedPrefix(address netip.Addr) string {
	if !address.IsValid() {
		return ""
	}
	address = address.Unmap()
	bits := 48
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}
