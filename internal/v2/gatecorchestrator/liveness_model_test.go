package gatecorchestrator

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
)

type fakeLivenessClock struct {
	mu   sync.Mutex
	mono time.Duration
	utc  time.Time
}

func (c *fakeLivenessClock) Mono() time.Duration     { c.mu.Lock(); defer c.mu.Unlock(); return c.mono }
func (c *fakeLivenessClock) UTC() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.utc }
func (c *fakeLivenessClock) advance(d time.Duration) { c.shift(d, d) }
func (c *fakeLivenessClock) shift(m, u time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mono += m
	c.utc = c.utc.Add(u)
}
func livenessTestBinding() echoBinding {
	return echoBinding{Role: directattempt.RoleInitiator, Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2"), AttemptID: "synthetic-liveness-attempt", ContextDigest: [32]byte{1, 2, 3, 4}}
}
func oppositeLivenessBinding(b echoBinding) echoBinding {
	b.Role = b.Role.Peer()
	b.Local, b.Remote = b.Remote, b.Local
	return b
}
func testLivenessModel(t *testing.T, rounds int) (*livenessModel, *fakeLivenessClock) {
	t.Helper()
	clock := &fakeLivenessClock{utc: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	budget, err := freezeLivenessBudget(10*time.Minute, rounds)
	if err != nil {
		t.Fatal(err)
	}
	m, err := newLivenessModel(livenessTestBinding(), budget, clock, clock.UTC().Add(budget.ceiling))
	if err != nil {
		t.Fatal(err)
	}
	return m, clock
}
func issueLivenessPing(t *testing.T, m *livenessModel) *livenessEmission {
	t.Helper()
	seq, err := m.preparePing()
	if err != nil || seq == 0 {
		t.Fatalf("ping slot sequence=%d err=%v", seq, err)
	}
	e, err := m.ping(seq, [16]byte{byte(seq), 0x55})
	if err != nil {
		t.Fatal(err)
	}
	if e != nil {
		ok, err := m.beginWrite(e)
		if err != nil || !ok {
			t.Fatal("admitted ping was not writable")
		}
		m.endWrite(true)
	}
	return e
}
func replyLiveness(t *testing.T, m *livenessModel) []byte {
	t.Helper()
	m.mu.Lock()
	message := m.pending.message
	m.mu.Unlock()
	message.kind = livenessPong
	b, err := buildLivenessPacket(oppositeLivenessBinding(m.binding), message)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLivenessFrozenBudgetArithmetic(t *testing.T) {
	for _, tc := range []struct {
		ceiling  time.Duration
		rounds   int
		n, total uint64
		lease    time.Duration
	}{{5 * time.Second, 2, 1, 3, 45 * time.Second}, {20 * time.Second, 3, 1, 3, 65 * time.Second}, {20*time.Second + 1, 3, 2, 5, 65 * time.Second}, {600 * time.Second, 3, 30, 61, 65 * time.Second}, {24 * time.Hour, 2, 4320, 8641, 45 * time.Second}} {
		b, err := freezeLivenessBudget(tc.ceiling, tc.rounds)
		if err != nil || b.pings != tc.n || b.pongs != tc.n+1 || b.total != tc.total || b.lease != tc.lease {
			t.Fatalf("budget mismatch: %+v %v", b, err)
		}
	}
	for _, d := range []time.Duration{0, -1, math.MaxInt64, 24*time.Hour + 1} {
		if _, err := freezeLivenessBudget(d, 3); err == nil {
			t.Fatal("invalid duration accepted")
		}
	}
	for _, m := range []int{0, 1, 4, math.MaxInt} {
		if _, err := freezeLivenessBudget(time.Minute, m); err == nil {
			t.Fatal("invalid rounds")
		}
	}
}

func TestLivenessBlackholeExactDeadlineAndPongCannotResurrect(t *testing.T) {
	for _, rounds := range []int{2, 3} {
		m, c := testLivenessModel(t, rounds)
		for i := 0; i < rounds; i++ {
			c.advance(20 * time.Second)
			if issueLivenessPing(t, m) == nil {
				t.Fatal("fixed ping rejected")
			}
		}
		pong := replyLiveness(t, m)
		c.advance(5 * time.Second)
		if _, err := m.receive(pong); !errors.Is(err, errLivenessTimeout) {
			t.Fatalf("at equality=%v", err)
		}
		if m.snapshot().PongValidated != 0 || m.snapshot().PingAdmitted != uint64(rounds) {
			t.Fatal("late pong revived lease")
		}
	}
}

func TestLivenessPongRenewsFromSendNotReceiveAndNoOtherTrafficRenews(t *testing.T) {
	m, c := testLivenessModel(t, 3)
	c.advance(20 * time.Second)
	issueLivenessPing(t, m)
	pong := replyLiveness(t, m)
	c.advance(4 * time.Second)
	if _, err := m.receive(pong); err != nil {
		t.Fatal(err)
	}
	if m.proofSent.mono+m.budget.lease != 85*time.Second {
		t.Fatal("receive time extended lease")
	}
	if _, err := m.receive(pong); err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 4; seq++ {
		packet, _ := buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: seq, nonce: [16]byte{byte(seq)}})
		e, err := m.receive(packet)
		if err != nil {
			t.Fatal(err)
		}
		if e != nil {
			m.discard(e)
		}
		if m.proofSent.mono+m.budget.lease != 85*time.Second {
			t.Fatal("peer ping renewed local permit")
		}
	}
	if m.snapshot().PongValidated != 1 || m.snapshot().PongDropped != 1 {
		t.Fatal("proof not single use")
	}
	c.advance(61 * time.Second)
	if !errors.Is(m.permit(), errLivenessTimeout) {
		t.Fatal("ordinary traffic extended permit")
	}
}

func TestLivenessLossToleranceThirdRoundAndMissingSlots(t *testing.T) {
	m, c := testLivenessModel(t, 3)
	c.advance(20 * time.Second)
	issueLivenessPing(t, m)
	if _, err := m.receive(replyLiveness(t, m)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		c.advance(20 * time.Second)
		issueLivenessPing(t, m)
	}
	c.advance(4 * time.Second)
	if _, err := m.receive(replyLiveness(t, m)); err != nil {
		t.Fatal(err)
	}
	if m.proofSent.mono+m.budget.lease != 145*time.Second || m.snapshot().PongValidated != 2 {
		t.Fatal("third round did not preserve lease")
	}
	m, c = testLivenessModel(t, 3)
	c.advance(41 * time.Second)
	issueLivenessPing(t, m)
	if seq, err := m.preparePing(); err != nil || seq != 0 {
		t.Fatal("missed slots backfilled")
	}
	if m.snapshot().PingAdmitted != 1 {
		t.Fatal("catch-up burst")
	}
}

func TestLivenessAdmissionRejectsOnlyEventAndConsumesPeerSequence(t *testing.T) {
	m, _ := testLivenessModel(t, 3)
	for seq := uint64(1); seq <= 5; seq++ {
		packet, _ := buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: seq, nonce: [16]byte{byte(seq)}})
		e, err := m.receive(packet)
		if err != nil {
			t.Fatal(err)
		}
		if e != nil {
			m.discard(e)
		}
		if seq == 5 && e != nil {
			t.Fatal("fifth admitted")
		}
	}
	w := m.snapshot()
	if w.PongAdmitted != 4 || w.LivenessAdmissionRejected != 1 || w.PongAdmissionRejected != 1 || w.PingAdmissionRejected != 0 || m.permit() != nil {
		t.Fatalf("normal rejection revoked/tripped: %+v", w)
	}
	packet, _ := buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: 5})
	if e, err := m.receive(packet); err != nil || e != nil || m.snapshot().ReplayDropped != 1 {
		t.Fatal("rejected sequence answered on replay")
	}
	m.mu.Lock()
	m.witness.PongAdmitted = m.budget.pongs
	m.windowUsed = 0
	m.mu.Unlock()
	packet, _ = buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: 6})
	if e, err := m.receive(packet); err != nil || e != nil || m.snapshot().PingAdmitted != 0 || m.permit() != nil {
		t.Fatal("pong borrowed ping or revoked local permit")
	}
}

func TestLivenessRejectedLocalPingNeverBackfills(t *testing.T) {
	m, c := testLivenessModel(t, 3)
	c.advance(19 * time.Second)
	for seq := uint64(1); seq <= 4; seq++ {
		packet, _ := buildLivenessPacket(oppositeLivenessBinding(m.binding), livenessMessage{kind: livenessPing, sequence: seq})
		e, err := m.receive(packet)
		if err != nil {
			t.Fatal(err)
		}
		m.discard(e)
	}
	c.advance(time.Second)
	if issueLivenessPing(t, m) != nil {
		t.Fatal("rolling cap bypass")
	}
	if m.snapshot().PingAdmissionRejected != 1 || m.pending.valid || m.permit() != nil {
		t.Fatal("normal ping rejection changed session")
	}
	c.advance(19 * time.Second)
	if seq, err := m.preparePing(); err != nil || seq != 0 {
		t.Fatal("rejected slot backfilled after cap cleared")
	}
}

func TestLivenessStaleReorderedWrongNonceCannotRenew(t *testing.T) {
	m, c := testLivenessModel(t, 3)
	c.advance(20 * time.Second)
	issueLivenessPing(t, m)
	old := replyLiveness(t, m)
	wrong := append([]byte(nil), old...)
	wrong[len(wrong)-1] ^= 1
	rewriteLivenessChecksums(wrong)
	if _, err := m.receive(wrong); err != nil {
		t.Fatal(err)
	}
	c.advance(5 * time.Second)
	if _, err := m.receive(old); err != nil {
		t.Fatal(err)
	}
	c.advance(15 * time.Second)
	issueLivenessPing(t, m)
	if _, err := m.receive(old); err != nil {
		t.Fatal(err)
	}
	if m.snapshot().PongValidated != 0 || m.proofSent.mono+m.budget.lease != 65*time.Second {
		t.Fatal("stale proof renewed lease")
	}
}

func TestLivenessAdmissionTokenForgeryAndWriteExpiry(t *testing.T) {
	m, c := testLivenessModel(t, 3)
	c.advance(20 * time.Second)
	seq, _ := m.preparePing()
	e, err := m.ping(seq, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	c.advance(time.Second)
	if ok, err := m.beginWrite(e); ok || err != nil || m.snapshot().OutboundExpired != 1 {
		t.Fatal("queued event sent at one-second equality")
	}
	if ok, err := m.beginWrite(e); ok || !errors.Is(err, errLivenessBudget) || m.snapshot().AdmissionBypass != 1 {
		t.Fatal("reused admission token accepted")
	}
	m, _ = testLivenessModel(t, 3)
	if ok, err := m.beginWrite(&livenessEmission{packet: make([]byte, 92)}); ok || !errors.Is(err, errLivenessBudget) {
		t.Fatal("forged intent bypassed admission")
	}
}

func TestLivenessClockFixedOriginsRollbackAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mono, utc time.Duration
		want      bool
	}{{"equal", time.Second, time.Second, true}, {"tolerance", 0, 2 * time.Second, true}, {"beyond", 0, 2*time.Second + 1, false}, {"mono backstep", -1, 0, false}, {"utc backstep", time.Second, -time.Second, true}, {"overflow", math.MaxInt64, 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := testLivenessModel(t, 3)
			c.shift(tc.mono, tc.utc)
			err := m.permit()
			if (err == nil) != tc.want {
				t.Fatalf("clock=%v", err)
			}
			if tc.name == "utc backstep" && m.snapshot().UTCRollbacks != 1 {
				t.Fatal("rollback not witnessed")
			}
		})
	}
	m, c := testLivenessModel(t, 3)
	for i := 0; i < 2; i++ {
		c.shift(0, time.Second)
		if err := m.permit(); err != nil {
			t.Fatal(err)
		}
	}
	c.shift(0, time.Second)
	if !errors.Is(m.permit(), errLivenessClock) {
		t.Fatal("short suspends reset origin")
	}
	m, c = testLivenessModel(t, 3)
	c.mu.Lock()
	c.utc = c.utc.AddDate(1000, 0, 0)
	c.mu.Unlock()
	if !errors.Is(m.permit(), errLivenessClock) {
		t.Fatal("saturating time.Sub accepted")
	}
}

func TestLivenessAbsoluteCeilingWinsAndNoSecondPending(t *testing.T) {
	m, c := testLivenessModel(t, 3)
	m.absUntil = 5 * time.Second
	c.advance(5 * time.Second)
	if !errors.Is(m.permit(), context.DeadlineExceeded) {
		t.Fatal("short absolute ceiling extended")
	}
	m, c = testLivenessModel(t, 3)
	c.advance(20 * time.Second)
	issueLivenessPing(t, m)
	if seq, err := m.preparePing(); err != nil || seq != 0 {
		t.Fatal("second pending")
	}
}

func rewriteLivenessChecksums(b []byte) {
	b[10], b[11], b[26], b[27] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	sum := livenessUDPChecksum(b)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(b[26:28], sum)
}

func TestLivenessWireNegativeMatrixAndLegacyMutualRejection(t *testing.T) {
	binding := livenessTestBinding()
	packet, err := buildLivenessPacket(oppositeLivenessBinding(binding), livenessMessage{kind: livenessPing, sequence: 1, nonce: [16]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 92 || len(packet[28:]) != 64 || livenessWireGuardSize != 128 {
		t.Fatal("wire sizes drifted")
	}
	for _, tc := range []struct {
		name      string
		edit      func([]byte) []byte
		checksums bool
	}{
		{"nonce checksum", func(b []byte) []byte { b[91] ^= 1; return b }, false},
		{"short", func(b []byte) []byte { return b[:91] }, false},
		{"long", func(b []byte) []byte { return append(b, 0) }, false},
		{"magic", func(b []byte) []byte { copy(b[28:], "WYCE"); return b }, true},
		{"version", func(b []byte) []byte { b[32] = 2; return b }, true},
		{"kind", func(b []byte) []byte { b[33] = 3; return b }, true},
		{"role", func(b []byte) []byte { b[34] = 1; return b }, true},
		{"reserved", func(b []byte) []byte { b[35] = 1; return b }, true},
		{"attempt", func(b []byte) []byte { b[36] ^= 1; return b }, true},
		{"context", func(b []byte) []byte { b[52] ^= 1; return b }, true},
		{"sequence zero", func(b []byte) []byte { clear(b[68:76]); return b }, true},
		{"fragment", func(b []byte) []byte { b[6] = 0x20; return b }, true},
		{"offset", func(b []byte) []byte { b[7] = 1; return b }, true},
		{"options", func(b []byte) []byte { b[0] = 0x46; return b }, true},
		{"source", func(b []byte) []byte { b[15] ^= 1; return b }, true},
		{"port", func(b []byte) []byte { b[23] ^= 1; return b }, true},
		{"zero udp checksum", func(b []byte) []byte { b[26], b[27] = 0, 0; return b }, false},
		{"ip checksum", func(b []byte) []byte { b[10] ^= 1; return b }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.edit(bytes.Clone(packet))
			if tc.checksums {
				rewriteLivenessChecksums(b)
			}
			if _, err := parseLivenessPacket(b, binding); !errors.Is(err, errLivenessProtocol) {
				t.Fatal("malformed authenticated control accepted")
			}
		})
	}
	old, _ := buildEchoPacket(oppositeLivenessBinding(binding), echoRequest, [8]byte{1})
	if _, err := parseLivenessPacket(old, binding); err == nil {
		t.Fatal("old packet accepted")
	}
	if _, err := parseEchoPacket(packet, binding, echoRequest, nil); err == nil {
		t.Fatal("new packet accepted by old parser")
	}
	for _, magic := range []string{"WYCR", "WYCF", "WYHB"} {
		b := bytes.Clone(packet)
		copy(b[28:], magic)
		rewriteLivenessChecksums(b)
		if _, err := parseLivenessPacket(b, binding); err == nil {
			t.Fatal("establishment frame accepted")
		}
	}
}
