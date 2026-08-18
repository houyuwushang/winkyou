package stunserver

import (
	"net/netip"
	"testing"
	"time"
)

func TestAdmissionControllerEnforcesGlobalRate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	controller := newAdmissionController(2, 2, 8, time.Minute, now)
	for _, address := range []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
	} {
		if got := controller.allow(address, now); got != admissionAllowed {
			t.Fatalf("initial admission for %s = %v", address, got)
		}
	}
	if got := controller.allow(netip.MustParseAddr("192.0.2.3"), now); got != admissionGlobalRate {
		t.Fatalf("third admission = %v, want global rate rejection", got)
	}
	if got := controller.allow(netip.MustParseAddr("192.0.2.3"), now.Add(500*time.Millisecond)); got != admissionAllowed {
		t.Fatalf("refilled admission = %v, want allowed", got)
	}
}

func TestAdmissionControllerSeparatesSourceBuckets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	controller := newAdmissionController(10, 1, 8, time.Minute, now)
	sourceA := netip.MustParseAddr("192.0.2.10")
	sourceB := netip.MustParseAddr("192.0.2.11")
	if got := controller.allow(sourceA, now); got != admissionAllowed {
		t.Fatalf("source A first = %v", got)
	}
	if got := controller.allow(sourceA, now); got != admissionSourceRate {
		t.Fatalf("source A second = %v, want per-source rejection", got)
	}
	if got := controller.allow(sourceB, now); got != admissionAllowed {
		t.Fatalf("source B first = %v, want independent allowance", got)
	}
}

func TestAdmissionControllerBoundsAndExpiresSourceTable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	controller := newAdmissionController(20, 10, 2, time.Minute, now)
	for _, value := range []string{"192.0.2.20", "192.0.2.21"} {
		if got := controller.allow(netip.MustParseAddr(value), now); got != admissionAllowed {
			t.Fatalf("initial source %s = %v", value, got)
		}
	}
	third := netip.MustParseAddr("192.0.2.22")
	if got := controller.allow(third, now); got != admissionSourceTableFull {
		t.Fatalf("third source = %v, want bounded-table rejection", got)
	}
	if got := controller.allow(third, now.Add(time.Minute)); got != admissionAllowed {
		t.Fatalf("third source after expiry = %v, want allowed", got)
	}
	if len(controller.sources) != 1 {
		t.Fatalf("sources after expiry = %d, want 1", len(controller.sources))
	}
}
