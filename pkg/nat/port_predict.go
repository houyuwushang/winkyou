package nat

// port_predict.go — probe and classify a NAT's external-port allocation
// behavior. A birthday-paradox puncher uses this to decide whether it can
// predict a peer's next mapped port (preserving/sequential) or must fall back
// to random spraying (random/unknown).

import (
	"context"
	"fmt"
	"net"
	"strings"

	"winkyou/pkg/netutil"
)

// PortAllocationPattern classifies how a NAT assigns external (mapped) UDP ports
// to new mappings.
type PortAllocationPattern int

const (
	// PortAllocationUnknown: not enough evidence to classify.
	PortAllocationUnknown PortAllocationPattern = iota
	// PortAllocationPreserving: the external port equals the local port.
	PortAllocationPreserving
	// PortAllocationSequential: the external port advances by a roughly constant
	// delta for each new mapping, so the next port is predictable.
	PortAllocationSequential
	// PortAllocationRandom: no predictable relationship between successive mappings.
	PortAllocationRandom
)

func (p PortAllocationPattern) String() string {
	switch p {
	case PortAllocationPreserving:
		return "preserving"
	case PortAllocationSequential:
		return "sequential"
	case PortAllocationRandom:
		return "random"
	default:
		return "unknown"
	}
}

// defaultPortAllocationSamples is the number of fresh sockets probed when the
// caller does not specify one.
const defaultPortAllocationSamples = 8

// maxPortAllocationSamples bounds how many probes we send in one call.
const maxPortAllocationSamples = 64

// maxSequentialDelta is the largest |delta| still treated as a predictable
// sequential allocation; larger jumps are classified as random.
const maxSequentialDelta = 64

// sequentialConfidenceThreshold is the minimum fraction of adjacent deltas that
// must match the dominant delta to classify as sequential.
const sequentialConfidenceThreshold = 0.5

// PortAllocationSample is one observation from a fresh local UDP socket.
type PortAllocationSample struct {
	Index      int          `json:"index"`
	Server     string       `json:"server,omitempty"`
	ServerAddr *net.UDPAddr `json:"server_addr,omitempty"`
	LocalIP    net.IP       `json:"local_ip,omitempty"`
	LocalPort  int          `json:"local_port"`
	MappedIP   net.IP       `json:"mapped_ip"`
	MappedPort int          `json:"mapped_port"`
}

// PortAllocationReport summarizes a NAT's external-port allocation behavior,
// probed from multiple fresh sockets. MappingNATType is populated by
// ProbePortAllocationWithMapping when at least two STUN destinations are
// available; it distinguishes endpoint-dependent (symmetric) mapping from an
// allocation pattern that only happened to look stable against one server.
type PortAllocationReport struct {
	Pattern PortAllocationPattern
	// Delta is the dominant per-mapping port increment when Pattern is
	// Sequential (it may be negative).
	Delta int
	// MappedIP is the observed public IP; it is expected to be stable.
	MappedIP net.IP
	// StableIP reports whether every successful sample saw the same public IP.
	StableIP bool
	// Confidence is the fraction of adjacent deltas matching the dominant delta.
	Confidence float64
	Samples    []PortAllocationSample

	MappingNATType NATType
	MappingProbes  []STUNMappingProbe
	// MappingError records a best-effort mapping probe failure without hiding a
	// usable port-allocation sequence.
	MappingError string
}

// ProbePortAllocation opens up to `samples` fresh UDP sockets in quick, serial
// succession, sends a STUN binding from each to the same server, and analyzes
// the resulting mapped-port sequence to classify the NAT's external-port
// allocation behavior. Probes are serial so the observed order reflects the
// NAT's mapping-creation order (required to measure a sequential delta).
func ProbePortAllocation(ctx context.Context, server string, samples int) (PortAllocationReport, error) {
	return ProbePortAllocationBound(ctx, server, samples, nil)
}

// ProbePortAllocationBound is ProbePortAllocation with an optional,
// already-resolved underlay binding.
func ProbePortAllocationBound(ctx context.Context, server string, samples int, binding *netutil.UDPBinding) (PortAllocationReport, error) {
	return probePortAllocation(ctx, []string{server}, samples, binding)
}

// ProbePortAllocationWithMapping combines two complementary observations:
//
//   - the same local socket probes multiple STUN destinations to detect
//     endpoint-dependent (symmetric) mapping; and
//   - fresh sockets rotate across those destinations to learn the external-port
//     allocation sequence that will matter when punching an arbitrary peer.
//
// Rotating destinations fixes the single-STUN blind spot where an
// endpoint-dependent NAT can appear port-preserving only for that destination.
// Mapping detection is best-effort: when it cannot classify the mapping but the
// allocation probes succeed, the report remains usable with MappingNATType set
// to unknown and MappingError populated.
func ProbePortAllocationWithMapping(ctx context.Context, servers []string, samples int) (PortAllocationReport, error) {
	return ProbePortAllocationWithMappingBound(ctx, servers, samples, nil)
}

// ProbePortAllocationWithMappingBound is ProbePortAllocationWithMapping with
// one optional underlay binding reused by both the shared mapping socket and
// every fresh allocation-sample socket.
func ProbePortAllocationWithMappingBound(ctx context.Context, servers []string, samples int, binding *netutil.UDPBinding) (PortAllocationReport, error) {
	servers = normalizeSTUNServers(servers)
	if len(servers) == 0 {
		return PortAllocationReport{}, fmt.Errorf("nat: no STUN servers configured")
	}

	mapping := STUNMappingReport{NATType: NATTypeUnknown}
	var mappingErr error
	if len(servers) > 1 {
		mapping, mappingErr = ProbeSTUNMappingBound(ctx, servers, binding)
	}

	report, err := probePortAllocation(ctx, servers, samples, binding)
	if err != nil {
		return report, err
	}
	report.MappingNATType = mapping.NATType
	report.MappingProbes = append([]STUNMappingProbe(nil), mapping.Probes...)
	if mappingErr != nil {
		report.MappingError = mappingErr.Error()
	}
	return report, nil
}

func probePortAllocation(ctx context.Context, servers []string, samples int, binding *netutil.UDPBinding) (PortAllocationReport, error) {
	servers = normalizeSTUNServers(servers)
	if len(servers) == 0 {
		return PortAllocationReport{}, fmt.Errorf("nat: no STUN servers configured")
	}
	if samples <= 0 {
		samples = defaultPortAllocationSamples
	}
	if samples > maxPortAllocationSamples {
		samples = maxPortAllocationSamples
	}

	collected := make([]PortAllocationSample, 0, samples)
	var firstErr error
	for i := 0; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		server := servers[i%len(servers)]
		res, err := ProbeSTUNBound(ctx, server, binding)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if res.MappedAddr == nil || res.LocalAddr == nil {
			continue
		}
		collected = append(collected, PortAllocationSample{
			Index:      i,
			Server:     server,
			ServerAddr: cloneUDPAddr(res.ServerAddr),
			LocalIP:    append(net.IP(nil), res.LocalAddr.IP...),
			LocalPort:  res.LocalAddr.Port,
			MappedIP:   append(net.IP(nil), res.MappedAddr.IP...),
			MappedPort: res.MappedAddr.Port,
		})
	}

	if len(collected) == 0 {
		if firstErr != nil {
			return PortAllocationReport{}, fmt.Errorf("nat: port allocation probe failed: %w", firstErr)
		}
		return PortAllocationReport{}, fmt.Errorf("nat: port allocation probe produced no samples")
	}
	return analyzePortAllocation(collected), nil
}

func normalizeSTUNServers(servers []string) []string {
	seen := make(map[string]struct{}, len(servers))
	normalized := make([]string, 0, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		normalized = append(normalized, server)
	}
	return normalized
}

// analyzePortAllocation classifies a sample sequence. It is a pure function so
// the classification is unit-testable without real network access.
func analyzePortAllocation(samples []PortAllocationSample) PortAllocationReport {
	report := PortAllocationReport{Pattern: PortAllocationUnknown, Samples: samples}
	if len(samples) == 0 {
		return report
	}

	report.MappedIP = append(net.IP(nil), samples[0].MappedIP...)
	report.StableIP = true
	for _, s := range samples[1:] {
		if !s.MappedIP.Equal(report.MappedIP) {
			report.StableIP = false
			break
		}
	}

	if len(samples) < 2 {
		return report
	}

	// Port-preserving: mapped port equals local port for every sample.
	preserving := true
	for _, s := range samples {
		if s.MappedPort != s.LocalPort {
			preserving = false
			break
		}
	}
	if preserving {
		report.Pattern = PortAllocationPreserving
		report.Confidence = 1
		return report
	}

	// Sequential: the dominant adjacent delta is small and consistent.
	deltas := make([]int, 0, len(samples)-1)
	for i := 1; i < len(samples); i++ {
		deltas = append(deltas, samples[i].MappedPort-samples[i-1].MappedPort)
	}
	domDelta, count := dominantDelta(deltas)
	report.Confidence = float64(count) / float64(len(deltas))
	if domDelta != 0 && absInt(domDelta) <= maxSequentialDelta && report.Confidence >= sequentialConfidenceThreshold {
		report.Pattern = PortAllocationSequential
		report.Delta = domDelta
		return report
	}

	report.Pattern = PortAllocationRandom
	return report
}

// dominantDelta returns the most frequent delta and its count. On ties it
// prefers the smaller |delta| for a tighter prediction.
func dominantDelta(deltas []int) (delta, count int) {
	counts := make(map[int]int, len(deltas))
	for _, d := range deltas {
		counts[d]++
	}
	found := false
	for d, c := range counts {
		if !found || c > count || (c == count && absInt(d) < absInt(delta)) {
			delta = d
			count = c
			found = true
		}
	}
	return delta, count
}

// PredictMappedPorts returns candidate external ports a peer should target to
// reach this NAT, given the most recently observed mapped port `base` and the
// number of forward predictions `count`. Sequential NATs project forward by the
// dominant delta (with a small backward guard for jitter); preserving NATs use
// the caller's fixed local port, so this returns just `base`. Random/unknown
// NATs return nil, signaling the caller to fall back to random spraying.
func (r PortAllocationReport) PredictMappedPorts(base, count int) []int {
	if count <= 0 {
		count = 1
	}
	switch r.Pattern {
	case PortAllocationSequential:
		delta := r.Delta
		if delta == 0 {
			delta = 1
		}
		const backGuard = 2
		ports := make([]int, 0, count+backGuard+1)
		seen := make(map[int]struct{}, count+backGuard+1)
		for i := -backGuard; i <= count; i++ {
			p := base + delta*i
			if p < 1 || p > 65535 {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
		return ports
	case PortAllocationPreserving:
		if base >= 1 && base <= 65535 {
			return []int{base}
		}
		return nil
	default:
		return nil
	}
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
