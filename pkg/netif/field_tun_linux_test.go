//go:build linux && fieldc1c

package netif

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
	"winkyou/internal/v2/fieldc1c"
)

func TestFieldKernelDumpCompletionIsAnExplicitSuccessWitness(t *testing.T) {
	for _, valid := range [][]byte{nil, make([]byte, 4)} {
		if fieldDumpDone(valid) != nil {
			t.Fatal("valid dump completion rejected")
		}
	}
	failure := make([]byte, 4)
	binary.NativeEndian.PutUint32(failure, ^uint32(0))
	for _, invalid := range [][]byte{{0}, failure, make([]byte, 8)} {
		if fieldDumpDone(invalid) == nil {
			t.Fatal("failed or unknown kernel dump accepted as absence")
		}
	}
}

func TestFieldInterfaceNoUnsignedAuthorityOrSetter(t *testing.T) {
	if _, err := NewFieldInterfaceAuthority(fieldc1c.Instance{}, "synthetic", 1280, netip.MustParseAddr("192.0.2.100"), netip.MustParseAddr("192.0.2.101"), nil); err == nil {
		t.Fatal("zero instance issued interface authority")
	}
	if _, err := NewFieldInterface(context.Background(), FieldInterfaceAuthority{}); err == nil {
		t.Fatal("zero authority opened interface")
	}
	if PreflightFieldInterface(FieldInterfaceAuthority{}) == nil {
		t.Fatal("zero authority reached OS preflight")
	}
	var f FieldInterface
	if f.ValidTransport() || f.SetIP(nil, nil) == nil || f.AddRoute(nil, nil) == nil || f.RemoveRoute(nil) == nil {
		t.Fatal("field object exposes arbitrary interface management")
	}
}

func TestFieldInterfaceRouteOwnershipIsFailClosed(t *testing.T) {
	local, peer := netip.MustParseAddr("192.0.2.100"), netip.MustParseAddr("192.0.2.101")
	header := "Iface\tDestination Gateway Flags RefCnt Use Metric Mask\n"
	for _, tc := range []struct {
		data     string
		conflict bool
	}{
		{header + "eth0 00000000 00000000 0001 0 0 0 00000000\n", false},
		{header + "eth0 000200C0 00000000 0001 0 0 0 00FFFFFF\n", true},
		{header + "eth0 650200C0 00000000 0001 0 0 0 FFFFFFFF\n", true},
		{header + "eth0 00000000 00000000 0001 0 0 0 malformed\n", true},
		{"", true}, {header + "truncated\n", true},
	} {
		if fieldRouteConflict([]byte(tc.data), local, peer) != tc.conflict {
			t.Fatal("route ownership assumption changed")
		}
	}
}

func TestFieldInterfaceQueueDrainNeverWaitsOnParallelReader(t *testing.T) {
	queue := make(chan []byte, 1)
	queue <- []byte("synthetic")
	finished := make(chan struct{})
	go func() { drainFieldQueue(queue); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("queue drain blocked")
	}
}
