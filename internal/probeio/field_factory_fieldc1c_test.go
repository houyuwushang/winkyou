//go:build fieldc1c

package probeio

import (
	"context"
	"net/netip"
	"testing"
	"winkyou/internal/v2/fieldc1c"
)

func TestFieldFactoryRejectsUnsealedAndRawAuthority(t *testing.T) {
	if _, err := NewFieldUDPFactory(fieldc1c.Instance{}); err == nil {
		t.Fatal("zero authorization accepted")
	}
	for _, local := range []string{"0.0.0.0:0", "0.0.0.0:9000", "192.0.2.1:0", "127.0.0.1:0"} {
		if _, err := NewUDPFactory(UDPFactoryConfig{LocalAddr: netip.MustParseAddrPort(local), AllowedTargetScope: AllowedTargetScopeFieldSingleAddress}); err == nil {
			t.Fatal("raw factory issued sealed authority")
		}
	}
	factory := &FieldUDPFactory{}
	if _, err := factory.Open(context.Background()); err == nil {
		t.Fatal("unbound factory opened")
	}
	if factory.BindAttempt(nil) == nil {
		t.Fatal("missing lease accepted")
	}
}

func TestFieldTargetPolicyMatchesExactSlotAndLocalPlan(t *testing.T) {
	observers := [4]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:3478"), netip.MustParseAddrPort("192.0.2.10:3479"), netip.MustParseAddrPort("192.0.2.11:3478"), netip.MustParseAddrPort("192.0.2.11:3479")}
	winner := netip.MustParseAddrPort("203.0.113.8:51000")
	targets := map[fieldTarget]struct{}{{3, winner}: {}}
	for slot := uint16(0); slot < 16; slot++ {
		for index, observer := range observers {
			want := slot == 0 || (slot < 8 && int(slot)%4 == index)
			if permitsFieldTarget(observers, targets, 16, false, slot, observer) != want {
				t.Fatal("observer schedule widened")
			}
		}
	}
	for _, sample := range []struct {
		slot       uint16
		target     netip.AddrPort
		plan, want bool
	}{
		{3, winner, true, true}, {3, winner, false, false}, {2, winner, true, false},
		{3, netip.MustParseAddrPort("203.0.113.9:51000"), true, false},
		{3, netip.MustParseAddrPort("203.0.113.8:51001"), true, false},
		{16, winner, true, false}, {3, netip.AddrPortFrom(winner.Addr(), 0), true, false},
	} {
		if permitsFieldTarget(observers, targets, 16, sample.plan, sample.slot, sample.target) != sample.want {
			t.Fatal("unapproved peer target accepted")
		}
	}
}
