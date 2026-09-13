package natlab

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatcontrol"
)

const (
	gateB3TailAccepted = iota
	gateB3TailQueued
	gateB3TailForwarded
	gateB3TailMappedRead
	gateB3TailTUNWritten
	gateB3TailSocketRead
	gateB3TailStages
)

// IPv4 INPUT, UDP only (the rule supplies -p udp). @ follows variable IHL;
// offsets then include the eight-byte UDP header. Count public metadata, not
// authenticity. In particular a NAT TUN write is NOT endpoint INPUT evidence.
func gateB3TailIngressU32() string {
	return fmt.Sprintf("4&0x3FFF=0&&0>>22&0x3C@8=0x%08X&&0>>22&0x3C@12>>8=0x%06X&&0>>22&0x3C@26=%d",
		binary.BigEndian.Uint32([]byte(hardnatcontrol.FrameMagic)),
		uint32(hardnatcontrol.FrameVersion)<<16|uint32(hardnatcontrol.DomainDirectPunch)<<8|uint32(hardnatcontrol.FrameCandidate),
		hardnatbudget.Hard16CandidatePackets-1)
}

func TestGateB3LifetimeTailIngressFilter(t *testing.T) {
	const golden = "4&0x3FFF=0&&0>>22&0x3C@8=0x57594842&&0>>22&0x3C@12>>8=0x010204&&0>>22&0x3C@26=16383"
	if gateB3TailIngressU32() != golden {
		t.Fatal("endpoint ingress filter drifted from frozen public header offsets")
	}
	for ihl := 20; ihl <= 60; ihl += 4 {
		packet := make([]byte, ihl+8+40)
		packet[0], packet[9] = 0x40|byte(ihl/4), 17
		copy(packet[ihl+8:], syntheticGateB3TailFrame(16383))
		// The same big-endian loads/shifts as u32, including IPv4 options.
		base := int(binary.BigEndian.Uint32(packet[:4]) >> 22 & 0x3C)
		if base != ihl || binary.BigEndian.Uint32(packet[4:8])&0x3FFF != 0 ||
			binary.BigEndian.Uint32(packet[base+8:base+12]) != 0x57594842 ||
			binary.BigEndian.Uint32(packet[base+12:base+16])>>8 != 0x010204 ||
			binary.BigEndian.Uint32(packet[base+26:base+30]) != 16383 {
			t.Fatal("endpoint ingress filter does not select the actual tail header")
		}
	}
}

type gateB3TailWitness struct {
	counts [gateB3TailStages]atomic.Uint64
	level  [2]atomic.Int64
	peak   [2]atomic.Int64
}

func (w *gateB3TailWitness) observe(stage int, packet []byte) bool {
	if w == nil || stage < 0 || stage >= gateB3TailStages {
		return false
	}
	metadata, err := hardnatcontrol.InspectFrame(packet)
	if err == nil && metadata.Type == hardnatcontrol.FrameCandidate && metadata.Ordinal == hardnatbudget.Hard16CandidatePackets-1 {
		w.counts[stage].Add(1)
		return true
	}
	return false
}

func (w *gateB3TailWitness) queue(direction, count int) {
	if w == nil || direction < 0 || direction >= len(w.level) || count < 0 {
		return
	}
	w.level[direction].Store(int64(count))
	for {
		old := w.peak[direction].Load()
		if old >= int64(count) || w.peak[direction].CompareAndSwap(old, int64(count)) {
			return
		}
	}
}

// No extra reads/writes/targets, and no retained payload. It wraps the exact
// governed datagram only in the test helper, never in a production adapter.
type gateB3TailDatagram struct {
	probeio.Datagram
	witness *gateB3TailWitness
}

func (d *gateB3TailDatagram) ReadFrom(ctx context.Context, packet []byte) (int, netip.AddrPort, error) {
	n, from, err := d.Datagram.ReadFrom(ctx, packet)
	if err == nil && n >= 0 && n <= len(packet) {
		d.witness.observe(gateB3TailSocketRead, packet[:n])
	}
	return n, from, err
}

func syntheticGateB3TailFrame(ordinal uint32) []byte {
	// Deliberately unauthenticated synthetic header: this tests counting only,
	// not a decryption or successful candidate authorization.
	frame := make([]byte, hardnatcontrol.FrameHeaderBytes+16)
	copy(frame, hardnatcontrol.FrameMagic)
	frame[4], frame[5], frame[6], frame[7] = hardnatcontrol.FrameVersion, byte(hardnatcontrol.DomainDirectPunch), byte(hardnatcontrol.FrameCandidate), 1
	binary.BigEndian.PutUint64(frame[8:16], hardnatcontrol.CandidateSequenceBase+uint64(ordinal))
	binary.BigEndian.PutUint16(frame[16:18], 15)
	binary.BigEndian.PutUint32(frame[18:22], ordinal)
	binary.BigEndian.PutUint16(frame[22:24], 16)
	return frame
}

type gateB3TailReadStub struct {
	probeio.Datagram
	packet []byte
	err    error
	reads  int
}

func (d *gateB3TailReadStub) ReadFrom(ctx context.Context, out []byte) (int, netip.AddrPort, error) {
	d.reads++
	return copy(out, d.packet), netip.MustParseAddrPort("192.0.2.1:51000"), d.err
}

func TestGateB3LifetimeTailWitness(t *testing.T) {
	tail := syntheticGateB3TailFrame(hardnatbudget.Hard16CandidatePackets - 1)
	var witness gateB3TailWitness
	for stage := range gateB3TailStages {
		witness.observe(stage, tail)
		witness.observe(stage, syntheticGateB3TailFrame(16382))
		witness.observe(stage, tail[:20])
		if got := witness.counts[stage].Load(); got != 1 {
			t.Errorf("tail stage=%d count=%d want=1", stage, got)
		}
	}
	witness.queue(0, 3)
	witness.queue(0, 1)
	if witness.level[0].Load() != 1 || witness.peak[0].Load() != 3 {
		t.Error("sampled queue watermark was not retained")
	}
	for _, injected := range []error{nil, context.Canceled, errors.New("synthetic_read_error")} {
		var reads gateB3TailWitness
		stub := &gateB3TailReadStub{packet: tail, err: injected}
		datagram := &gateB3TailDatagram{Datagram: stub, witness: &reads}
		out := make([]byte, len(tail))
		n, from, err := datagram.ReadFrom(context.Background(), out)
		want := uint64(0)
		if injected == nil {
			want = 1
		}
		if n != len(tail) || string(out) != string(tail) || err != injected || from.Port() != 51000 || stub.reads != 1 || reads.counts[gateB3TailSocketRead].Load() != want {
			t.Error("read witness changed I/O or missed a real successful read")
		}
	}
}

func TestGateB3LifetimeTailWitnessWiring(t *testing.T) {
	for filename, markers := range map[string][]string{
		"gate_b2_nat_linux_test.go":          {"router.tailWitness.observe(gateB3TailAccepted", "router.tailWitness.counts[gateB3TailQueued].Add(1)", "router.tailWitness.observe(gateB3TailForwarded", "router.tailWitness.observe(gateB3TailMappedRead", "router.tailWitness.observe(gateB3TailTUNWritten", "router.tailWitness.queue("},
		"gate_b3_endpoint_linux_test.go":     {"gateB3TailFactory{", "TailSocketRead", "TailReadWitness"},
		"gate_b3_netns_linux_test.go":        {"logGateB3TailDeliveryPair(t, topology, leftRouter, rightRouter, initiator, responder)", "topology.installGateB3TailIngressCounters()"},
		"gate_b3_tail_ingress_linux_test.go": {"topology.clientA, topology.clientB", "\"INPUT\"", "gateB3TailIngressU32()", "\"RETURN\"", "runNamespaced(namespace, \"iptables\"", "n2dChainPackets(namespace, gateB3TailIngressChain)"},
	} {
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal("tail witness fixture source unavailable")
		}
		valid := func(text string) bool {
			for _, marker := range markers {
				if !strings.Contains(text, marker) {
					return false
				}
			}
			return true
		}
		if !valid(string(data)) {
			t.Errorf("tail witness disconnected in %s", filename)
			continue
		}
		for _, marker := range markers {
			if valid(strings.ReplaceAll(string(data), marker, "removed")) {
				t.Fatal("tail witness removal escaped")
			}
		}
	}
	data, err := os.ReadFile("gate_b3_netns_linux_test.go")
	if err != nil {
		t.Fatal("tail ingress observation order source unavailable")
	}
	source := string(data)
	observation := strings.Index(source, "if !logGateB3TailDeliveryPair(")
	cleanup := strings.Index(source, "\n\tassertGateB3NoResidue(")
	if observation < 0 || cleanup < observation {
		t.Fatal("endpoint INPUT counter must be read before namespace teardown")
	}
}
