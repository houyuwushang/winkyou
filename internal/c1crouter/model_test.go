//go:build fieldc1c

package c1crouter

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestUnknownObservationNeverBecomesZero(t *testing.T) {
	o := unknownObservation("initiator", "synthetic-tuple")
	if !o.Valid() {
		t.Fatal("unknown observation invalid")
	}
	b, _ := json.Marshal(o)
	if !strings.Contains(string(b), `"mapping_age_at_hit_ns":null`) {
		t.Fatal("missing sample disguised as zero")
	}
	zero := int64(0)
	o.MappingAgeAtHitNS = &zero
	if o.Valid() {
		t.Fatal("unknown-to-zero mutation escaped")
	}
}
func TestSummaryWhitelistRejectsRawDetails(t *testing.T) {
	s := Summary{Stage: "terminal", Class: "success"}
	if _, e := s.Encode(); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"192.0.2.1", "synthetic-host", "private/error"} {
		s.Class = raw
		if _, e := s.Encode(); e == nil {
			t.Fatal("raw class escaped")
		}
	}
}

type queryExit int

func (e queryExit) Error() string { return "private detail" }
func (e queryExit) ExitCode() int { return int(e) }
func TestExactQueryUnknownIsNotAbsence(t *testing.T) {
	for _, tc := range []struct {
		output string
		err    error
		want   string
	}{
		{"udp synthetic\n", nil, "present"}, {"conntrack v1: such conntrack doesn't exist", queryExit(1), "absent"},
		{"conntrack v1: such conntrack doesn't exist", queryExit(2), "unknown"}, {"", nil, "unknown"}, {"udp x\nudp y", nil, "unknown"},
		{"conntrack v1: such conntrack doesn't exist\nudp partial", queryExit(1), "unknown"},
	} {
		got, _ := classifyQuery(context.Background(), []byte(tc.output), tc.err)
		if got != tc.want {
			t.Fatal("query classification")
		}
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	got, e := classifyQuery(c, []byte("conntrack v1: such conntrack doesn't exist"), queryExit(1))
	if got != "unknown" || !errors.Is(e, context.Canceled) {
		t.Fatal("interrupted query became absence")
	}
}
func TestDatagramCodecExactAndBounded(t *testing.T) {
	s, d := netip.MustParseAddrPort("192.0.2.2:40000"), netip.MustParseAddrPort("198.51.100.1:40001")
	b, e := encodeUDP(s, d, []byte("synthetic"))
	if e != nil {
		t.Fatal(e)
	}
	v, e := parseUDP(b)
	if e != nil || v.source != s || v.target != d || string(v.payload) != "synthetic" {
		t.Fatal("round trip")
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte{}, b...), 0), {0}} {
		if _, e := parseUDP(bad); e == nil {
			t.Fatal("bad framing")
		}
	}
}
