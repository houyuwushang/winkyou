package nat

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func seqSamples(localBase, mappedBase, delta, n int, ip net.IP) []PortAllocationSample {
	s := make([]PortAllocationSample, n)
	for i := 0; i < n; i++ {
		s[i] = PortAllocationSample{
			Index:      i,
			LocalPort:  localBase + i,
			MappedIP:   ip,
			MappedPort: mappedBase + delta*i,
		}
	}
	return s
}

func TestAnalyzePortAllocationSequential(t *testing.T) {
	ip := net.ParseIP("210.30.106.93")
	// Real observed inner-gw sequence: 23984,23985,23986,23987 (delta +1).
	samples := []PortAllocationSample{
		{Index: 0, LocalPort: 49053, MappedIP: ip, MappedPort: 23984},
		{Index: 1, LocalPort: 49054, MappedIP: ip, MappedPort: 23985},
		{Index: 2, LocalPort: 49055, MappedIP: ip, MappedPort: 23986},
		{Index: 3, LocalPort: 49056, MappedIP: ip, MappedPort: 23987},
	}
	got := analyzePortAllocation(samples)
	if got.Pattern != PortAllocationSequential {
		t.Fatalf("Pattern = %v, want sequential", got.Pattern)
	}
	if got.Delta != 1 {
		t.Fatalf("Delta = %d, want 1", got.Delta)
	}
	if !got.StableIP {
		t.Fatalf("StableIP = false, want true")
	}
	if got.Confidence != 1 {
		t.Fatalf("Confidence = %v, want 1", got.Confidence)
	}
}

func TestAnalyzePortAllocationSequentialWithJitter(t *testing.T) {
	ip := net.ParseIP("203.0.113.7")
	// Mostly +1 with one foreign mapping inserted (delta 1,1,50,1,1).
	samples := []PortAllocationSample{
		{Index: 0, LocalPort: 40000, MappedIP: ip, MappedPort: 5000},
		{Index: 1, LocalPort: 40001, MappedIP: ip, MappedPort: 5001},
		{Index: 2, LocalPort: 40002, MappedIP: ip, MappedPort: 5002},
		{Index: 3, LocalPort: 40003, MappedIP: ip, MappedPort: 5052},
		{Index: 4, LocalPort: 40004, MappedIP: ip, MappedPort: 5053},
		{Index: 5, LocalPort: 40005, MappedIP: ip, MappedPort: 5054},
	}
	got := analyzePortAllocation(samples)
	if got.Pattern != PortAllocationSequential {
		t.Fatalf("Pattern = %v, want sequential", got.Pattern)
	}
	if got.Delta != 1 {
		t.Fatalf("Delta = %d, want 1", got.Delta)
	}
	if got.Confidence >= 1 {
		t.Fatalf("Confidence = %v, want < 1 (jitter present)", got.Confidence)
	}
}

func TestAnalyzePortAllocationPreserving(t *testing.T) {
	ip := net.ParseIP("198.51.100.9")
	// mapped == local for every sample (port-preserving), e.g. local 53381 -> public 53381.
	samples := []PortAllocationSample{
		{Index: 0, LocalPort: 53381, MappedIP: ip, MappedPort: 53381},
		{Index: 1, LocalPort: 53382, MappedIP: ip, MappedPort: 53382},
		{Index: 2, LocalPort: 53383, MappedIP: ip, MappedPort: 53383},
	}
	got := analyzePortAllocation(samples)
	if got.Pattern != PortAllocationPreserving {
		t.Fatalf("Pattern = %v, want preserving", got.Pattern)
	}
}

func TestAnalyzePortAllocationRandom(t *testing.T) {
	ip := net.ParseIP("192.0.2.44")
	samples := []PortAllocationSample{
		{Index: 0, LocalPort: 40000, MappedIP: ip, MappedPort: 12000},
		{Index: 1, LocalPort: 40001, MappedIP: ip, MappedPort: 51999},
		{Index: 2, LocalPort: 40002, MappedIP: ip, MappedPort: 3007},
		{Index: 3, LocalPort: 40003, MappedIP: ip, MappedPort: 40233},
	}
	got := analyzePortAllocation(samples)
	if got.Pattern != PortAllocationRandom {
		t.Fatalf("Pattern = %v, want random", got.Pattern)
	}
}

func TestAnalyzePortAllocationUnstableIP(t *testing.T) {
	samples := []PortAllocationSample{
		{Index: 0, LocalPort: 40000, MappedIP: net.ParseIP("192.0.2.1"), MappedPort: 5000},
		{Index: 1, LocalPort: 40001, MappedIP: net.ParseIP("192.0.2.2"), MappedPort: 5001},
	}
	got := analyzePortAllocation(samples)
	if got.StableIP {
		t.Fatalf("StableIP = true, want false")
	}
}

func TestAnalyzePortAllocationSingleSample(t *testing.T) {
	samples := []PortAllocationSample{
		{Index: 0, LocalPort: 40000, MappedIP: net.ParseIP("192.0.2.1"), MappedPort: 5000},
	}
	got := analyzePortAllocation(samples)
	if got.Pattern != PortAllocationUnknown {
		t.Fatalf("Pattern = %v, want unknown for single sample", got.Pattern)
	}
	if !got.StableIP {
		t.Fatalf("StableIP = false, want true for single sample")
	}
}

func TestAnalyzePortAllocationEmpty(t *testing.T) {
	got := analyzePortAllocation(nil)
	if got.Pattern != PortAllocationUnknown {
		t.Fatalf("Pattern = %v, want unknown for empty", got.Pattern)
	}
}

func TestPredictMappedPortsSequential(t *testing.T) {
	r := PortAllocationReport{Pattern: PortAllocationSequential, Delta: 1}
	got := r.PredictMappedPorts(25000, 4)
	// Expect backward guard (24998,24999) plus base and forward (25000..25004).
	want := map[int]bool{24998: true, 24999: true, 25000: true, 25001: true, 25002: true, 25003: true, 25004: true}
	if len(got) != len(want) {
		t.Fatalf("got %d ports %v, want %d", len(got), got, len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("unexpected predicted port %d in %v", p, got)
		}
	}
}

func TestPredictMappedPortsSequentialClampsRange(t *testing.T) {
	r := PortAllocationReport{Pattern: PortAllocationSequential, Delta: 1}
	got := r.PredictMappedPorts(65535, 3)
	for _, p := range got {
		if p < 1 || p > 65535 {
			t.Fatalf("predicted port %d out of range in %v", p, got)
		}
	}
}

func TestPredictMappedPortsPreserving(t *testing.T) {
	r := PortAllocationReport{Pattern: PortAllocationPreserving}
	got := r.PredictMappedPorts(53381, 4)
	if len(got) != 1 || got[0] != 53381 {
		t.Fatalf("got %v, want [53381]", got)
	}
}

func TestPredictMappedPortsRandomReturnsNil(t *testing.T) {
	r := PortAllocationReport{Pattern: PortAllocationRandom}
	if got := r.PredictMappedPorts(25000, 4); got != nil {
		t.Fatalf("got %v, want nil for random", got)
	}
}

func TestPredictMappedPortsNegativeDelta(t *testing.T) {
	r := PortAllocationReport{Pattern: PortAllocationSequential, Delta: -1}
	got := r.PredictMappedPorts(25000, 3)
	// base 25000 with delta -1: forward -> 24997..25000, backward guard -> 25001,25002.
	for _, p := range got {
		if p < 24997 || p > 25002 {
			t.Fatalf("predicted port %d outside expected window in %v", p, got)
		}
	}
	if len(got) == 0 {
		t.Fatalf("got no ports for negative-delta sequential")
	}
}

func TestProbePortAllocationWithMappingRotatesDestinations(t *testing.T) {
	s1 := startFakeSTUNServer(t, net.IPv4(203, 0, 113, 10), 12000)
	defer s1.Close()
	s2 := startFakeSTUNServer(t, net.IPv4(203, 0, 113, 10), 52000)
	defer s2.Close()

	servers := []string{s1.LocalAddr().String(), s2.LocalAddr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := ProbePortAllocationWithMapping(ctx, servers, 6)
	if err != nil {
		t.Fatalf("ProbePortAllocationWithMapping() error = %v", err)
	}
	if report.MappingNATType != NATTypeSymmetric {
		t.Fatalf("MappingNATType = %v, want symmetric", report.MappingNATType)
	}
	if report.Pattern != PortAllocationRandom {
		t.Fatalf("Pattern = %v, want random across destinations", report.Pattern)
	}
	if len(report.Samples) != 6 {
		t.Fatalf("sample count = %d, want 6", len(report.Samples))
	}
	for i, sample := range report.Samples {
		wantServer := servers[i%len(servers)]
		if sample.Server != wantServer {
			t.Fatalf("sample %d server = %q, want %q", i, sample.Server, wantServer)
		}
		if sample.ServerAddr == nil {
			t.Fatalf("sample %d has no resolved server address", i)
		}
	}
}

func TestProbePortAllocationWithMappingKeepsGlobalSequence(t *testing.T) {
	var (
		mu       sync.Mutex
		nextPort = 30000
	)
	next := func() int {
		mu.Lock()
		defer mu.Unlock()
		nextPort++
		return nextPort
	}
	s1 := startSequencedSTUNServer(t, next)
	defer s1.Close()
	s2 := startSequencedSTUNServer(t, next)
	defer s2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := ProbePortAllocationWithMapping(ctx, []string{s1.LocalAddr().String(), s2.LocalAddr().String()}, 6)
	if err != nil {
		t.Fatalf("ProbePortAllocationWithMapping() error = %v", err)
	}
	if report.MappingNATType != NATTypeSymmetric {
		t.Fatalf("MappingNATType = %v, want symmetric", report.MappingNATType)
	}
	if report.Pattern != PortAllocationSequential || report.Delta != 1 {
		t.Fatalf("allocation = %s delta %+d, want sequential +1", report.Pattern, report.Delta)
	}
}

func TestNormalizeSTUNServers(t *testing.T) {
	got := normalizeSTUNServers([]string{" stun:a.example:3478 ", "", "stun:b.example:3478", "stun:a.example:3478"})
	want := []string{"stun:a.example:3478", "stun:b.example:3478"}
	if len(got) != len(want) {
		t.Fatalf("normalizeSTUNServers() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizeSTUNServers()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func startSequencedSTUNServer(t *testing.T, nextPort func() int) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sequenced STUN server listen: %v", err)
	}
	go func() {
		buf := make([]byte, stunMaxPacket)
		for {
			n, clientAddr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			req, parseErr := parseSTUNMessage(buf[:n])
			if parseErr != nil || req.msgType != stunMsgTypeBindingReq {
				continue
			}
			resp := buildFakeBindingResponse(req.transactionID, net.IPv4(203, 0, 113, 11), nextPort())
			_, _ = conn.WriteTo(resp, clientAddr)
		}
	}()
	return conn
}
