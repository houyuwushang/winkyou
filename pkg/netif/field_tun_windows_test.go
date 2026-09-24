//go:build windows && fieldc1c

package netif

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/v2/fieldc1c"
)

type fieldFakeTun struct {
	done   chan struct{}
	read   chan []byte
	once   sync.Once
	writes atomic.Uint64
}

func (d *fieldFakeTun) Name() (string, error) { return fieldSyntheticBinding().name, nil }
func (d *fieldFakeTun) MTU() (int, error)     { return 1280, nil }
func (d *fieldFakeTun) BatchSize() int        { return 1 }
func (d *fieldFakeTun) LUID() uint64          { return 99 }
func (d *fieldFakeTun) Close() error          { d.once.Do(func() { close(d.done) }); return nil }
func (d *fieldFakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-d.read:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}
func (d *fieldFakeTun) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.done:
		return 0, net.ErrClosed
	default:
	}
	d.writes.Add(uint64(len(bufs)))
	return len(bufs), nil
}

type fieldFakeDriver struct {
	preflights, creates int
	device              *fieldFakeTun
}

func (d *fieldFakeDriver) preflight() error { d.preflights++; return nil }
func (d *fieldFakeDriver) create(fieldWindowsBinding) (fieldTunDevice, error) {
	d.creates++
	return d.device, nil
}
func fieldFakeFixture() (fieldWindowsPermit, *fieldFakeIP, *fieldFakeDriver) {
	permit := fieldWindowsPermit{binding: fieldSyntheticBinding(), valid: func() bool { return true }, used: new(atomic.Bool)}
	driver := &fieldFakeDriver{device: &fieldFakeTun{done: make(chan struct{}), read: make(chan []byte, 1)}}
	return permit, newFieldFakeIP(), driver
}

func TestFieldWindowsNoUnsignedAuthorityOrSetter(t *testing.T) {
	b := fieldSyntheticBinding()
	if _, err := NewFieldInterfaceAuthority(fieldc1c.Instance{}, b.name, int(b.mtu), b.local, b.peer, nil); err == nil {
		t.Fatal("zero instance issued interface authority")
	}
	if PreflightFieldInterface(FieldInterfaceAuthority{}) == nil {
		t.Fatal("zero authority reached preflight")
	}
	if _, err := NewFieldInterface(context.Background(), FieldInterfaceAuthority{}); err == nil {
		t.Fatal("zero authority created adapter")
	}
	var f FieldInterface
	if f.ValidTransport() || f.SetIP(nil, nil) == nil || f.AddRoute(nil, nil) == nil || f.RemoveRoute(nil) == nil {
		t.Fatal("arbitrary interface capability exposed")
	}
}

func TestFieldWindowsFakeAdmissionBeforeCapabilityAndSingleUse(t *testing.T) {
	for _, mode := range []string{"zero", "expired", "used", "cancelled", "nil_context"} {
		t.Run(mode, func(t *testing.T) {
			p, api, driver := fieldFakeFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "zero":
				p = fieldWindowsPermit{}
			case "expired":
				p.valid = func() bool { return false }
			case "used":
				p.used.Store(true)
			case "cancelled":
				cancel()
			case "nil_context":
				ctx = nil
			}
			if _, err := newFieldWindowsInterface(ctx, p, api, driver); err == nil {
				t.Fatal("invalid permit accepted")
			}
			if len(api.calls) != 0 || driver.preflights != 0 || driver.creates != 0 {
				t.Fatal("invalid permit reached OS capability")
			}
		})
	}
	p, api, driver := fieldFakeFixture()
	f, err := newFieldWindowsInterface(context.Background(), p, api, driver)
	if err != nil || f == nil {
		t.Fatal("fake sealed interface did not open")
	}
	defer f.Close()
	before := len(api.calls)
	if _, err := newFieldWindowsInterface(context.Background(), p, api, driver); err == nil || driver.creates != 1 || len(api.calls) != before {
		t.Fatal("single-use CAS bypassed")
	}
}

func TestFieldWindowsFakeCloseAndControlOwnership(t *testing.T) {
	p, api, driver := fieldFakeFixture()
	f, err := newFieldWindowsInterface(context.Background(), p, api, driver)
	if err != nil {
		t.Fatal("fake sealed interface did not open")
	}
	defer f.Close()
	packet := make([]byte, 76)
	packet[0] = 0x45
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], 76)
	local, peer := p.binding.local.As4(), p.binding.peer.As4()
	copy(packet[12:16], local[:])
	copy(packet[16:20], peer[:])
	binary.BigEndian.PutUint16(packet[20:22], 32112)
	binary.BigEndian.PutUint16(packet[22:24], 32112)
	if n, err := f.InjectPacket(packet); err != nil || n != 76 {
		t.Fatal("synthetic control tuple rejected")
	}
	buf := make([]byte, 1280)
	if n, err := f.Read(buf); err != nil || n != 76 {
		t.Fatal("injected control not delivered")
	}
	copy(packet[12:16], peer[:])
	copy(packet[16:20], local[:])
	if _, err := f.Write(packet); err != nil {
		t.Fatal("control echo rejected")
	}
	if n, err := f.ReceivePacket(buf); err != nil || n != 76 || driver.device.writes.Load() != 0 {
		t.Fatal("control leaked into kernel path")
	}
	packet[9] = 1
	if _, err := f.Write(packet); err != nil || driver.device.writes.Load() != 1 {
		t.Fatal("ICMP was not a separate kernel path")
	}
	started := time.Now()
	if f.Close() != nil || time.Since(started) > 2*time.Second || f.Close() != nil || f.ValidTransport() {
		t.Fatal("owned close did not drain idempotently")
	}
	if api.address != nil || api.route != nil || api.row.MTU != 1500 {
		t.Fatal("owned configuration remained after close")
	}
	for _, op := range []func([]byte) (int, error){f.Read, f.Write, f.InjectPacket, f.ReceivePacket} {
		if _, err := op(buf); err == nil {
			t.Fatal("closed handle reused")
		}
	}
	w := f.Witness()
	if !w.Closed || !w.InterfaceChecked || !w.InterfaceAbsent || !w.AddressesAbsent || !w.RoutesAbsent || w.ReaderFailedBeforeClose {
		t.Fatal("drain witness incomplete")
	}
}
