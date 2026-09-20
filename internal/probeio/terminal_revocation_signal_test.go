package probeio

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// Hold Done open and leave the watcher unsignalled. This deterministically
// proves that operation admission observes revocation itself, not the timing
// of the asynchronous physical-close worker or final accounting release.
func TestTerminalRevocationDeniesOperationsBeforePhysicalClose(t *testing.T) {
	h := newHarness(t, normalResources())
	socket, datagram := openSocket(t, h)
	target := netip.MustParseAddrPort("127.0.0.1:40001")
	if err := socket.RegisterTarget(target); err != nil {
		t.Fatal(err)
	}
	revoked := make(chan struct{})
	h.controller.mu.Lock()
	h.controller.probeRevoked = revoked
	close(revoked)
	h.controller.mu.Unlock()
	select {
	case <-h.lease.Done():
		t.Fatal("fixture released the accounting lease")
	default:
	}
	if err := socket.SendProbe(context.Background(), target, []byte("synthetic")); !errors.Is(err, ErrLeaseClosed) {
		t.Error("revoked send reached datagram")
	}
	if err := socket.RegisterTarget(target); !errors.Is(err, ErrLeaseClosed) {
		t.Error("revoked registration accepted")
	}
	if next, err := h.controller.OpenProbeSocket(context.Background()); next != nil || !errors.Is(err, ErrLeaseClosed) {
		t.Error("revoked open reached factory")
	}
	datagram.mu.Lock()
	writes, physicallyClosed := len(datagram.writes), datagram.closed
	datagram.mu.Unlock()
	if writes != 0 || physicallyClosed || h.factory.count() != 1 {
		t.Fatal("revocation used physical close or admitted new I/O")
	}
}

func TestOrdinaryProbeRevocationRetainsOriginalDoneChannel(t *testing.T) {
	h := newHarness(t, normalResources())
	if probeRevocationForLease(h.lease) != h.lease.Done() || h.controller.probeRevoked != h.lease.Done() {
		t.Fatal("ordinary adapter revocation semantics changed")
	}
}
