//go:build windows && fieldc1c

package netif

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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
	onPreflight         func()
	failCreate          bool
}

func (d *fieldFakeDriver) preflight() error {
	d.preflights++
	if d.onPreflight != nil {
		d.onPreflight()
	}
	return nil
}
func (d *fieldFakeDriver) create(fieldWindowsBinding) (fieldTunDevice, error) {
	d.creates++
	if d.failCreate {
		return nil, ErrFieldInterface
	}
	return d.device, nil
}

func TestFieldWindowsRevalidateAndPartialFailure(t *testing.T) {
	for _, mode := range []string{"expires_during_preflight", "cancel_during_preflight", "create_failure", "identity", "interface.set", "address.create", "route.create"} {
		t.Run(mode, func(t *testing.T) {
			p, api, driver := fieldFakeFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			valid := true
			p.valid = func() bool { return valid }
			switch mode {
			case "expires_during_preflight":
				driver.onPreflight = func() { valid = false }
			case "cancel_during_preflight":
				driver.onPreflight = cancel
			case "create_failure":
				driver.failCreate = true
			case "identity":
				api.id.guid.Data1++
			default:
				api.fail = mode
			}
			if f, err := newFieldWindowsInterface(ctx, p, api, driver); err == nil || f != nil {
				t.Fatal("fault returned a usable interface")
			}
			if strings.Contains(mode, "preflight") {
				if driver.creates != 0 || p.used.Load() {
					t.Fatal("preflight invalidation reached creation")
				}
			} else if driver.creates != 1 || !p.used.Load() {
				t.Fatal("failed creation retried or refunded authority")
			}
			if api.address != nil || api.route != nil || api.row.MTU != 1500 {
				t.Fatal("partial transaction leaked rows")
			}
			if !strings.Contains(mode, "preflight") && mode != "create_failure" {
				select {
				case <-driver.device.done:
				default:
					t.Fatal("owned device not closed on failure")
				}
			}
		})
	}
}

func TestFieldWindowsFakeConcurrentCloseUnblocksEveryQueue(t *testing.T) {
	p, api, driver := fieldFakeFixture()
	f, err := newFieldWindowsInterface(context.Background(), p, api, driver)
	if err != nil {
		t.Fatal("fake creation failed")
	}
	defer f.Close()
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(2)
		go func() { defer workers.Done(); _, _ = f.Read(make([]byte, 1280)) }()
		go func() { defer workers.Done(); _, _ = f.ReceivePacket(make([]byte, 1280)) }()
	}
	if f.Close() != nil {
		t.Fatal("concurrent drain failed")
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reader or receiver remained blocked")
	}
	if len(f.kernel) != 0 || len(f.injected) != 0 || len(f.echo) != 0 {
		t.Fatal("queue residue")
	}
}

func TestFieldWindowsUnknownResidueIsNotAbsence(t *testing.T) {
	p, api, driver := fieldFakeFixture()
	f, err := newFieldWindowsInterface(context.Background(), p, api, driver)
	if err != nil {
		t.Fatal("fake creation failed")
	}
	api.fail = "snapshot"
	if f.Close() == nil {
		t.Fatal("failed independent enumeration was called clean")
	}
	api.failed = false
	w := f.Witness()
	if !w.Closed || w.InterfaceChecked || w.InterfaceAbsent || w.AddressesAbsent || w.RoutesAbsent {
		t.Fatal("unknown fabricated a zero residue")
	}
}

func TestFieldWindowsDLLSealPureContracts(t *testing.T) {
	seen := map[string]bool{}
	for _, arch := range []string{"386", "amd64", "arm", "arm64"} {
		value := fieldDLLHash(arch)
		data, err := hex.DecodeString(value)
		if err != nil || len(data) != 32 || seen[value] {
			t.Fatal("missing or duplicate official DLL pin")
		}
		seen[value] = true
	}
	if fieldDLLHash("unknown") != "" {
		t.Fatal("unknown architecture selected a DLL")
	}
	for _, path := range []string{"wintun.dll", `\\server\share\wintun.dll`, `C:\sealed\..\wintun.dll`, `C:\sealed\wintun.dll:stream`, `C:/sealed/wintun.dll`, `C:\sealed.\wintun.dll`, `C:\sealed \wintun.dll`} {
		if fieldLocalInstallation(path) {
			t.Fatal("noncanonical installation path accepted")
		}
	}
	if !fieldLocalInstallation(`C:\sealed\wintun.dll`) {
		t.Fatal("canonical local path rejected")
	}
	// All SIDs below are well-known principals, never host/user identities.
	for _, tc := range []struct {
		name, sddl string
		leaf, want bool
	}{
		{"protected", "O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)", true, true},
		{"world_writable", "O:BAG:BAD:P(A;;FA;;;WD)", true, false},
		{"no_dacl", "O:BAG:BA", true, false},
		{"untrusted_owner", "O:BUG:BAD:P(A;;FA;;;BA)", true, false},
		{"generic_write", "O:BAG:BAD:P(A;;GW;;;BU)", true, false},
		{"delete_child", "O:BAG:BAD:P(A;;0x00000040;;;BU)", false, false},
		{"sibling_creation", "O:BAG:BAD:P(A;;0x00000004;;;BU)", false, true},
		{"leaf_creation", "O:BAG:BAD:P(A;;0x00000004;;;BU)", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal("synthetic security descriptor invalid")
			}
			if fieldInstallationACL(sd, tc.leaf) != tc.want {
				t.Fatal("installation ACL classification mismatch")
			}
		})
	}
	record := &fieldDriverLog{}
	input := bytes.Repeat([]byte("synthetic driver log\n"), 8192)
	if n, err := record.Write(input); err != nil || n != len(input) || len(record.data) != 64*1024 {
		t.Fatal("driver capture is not bounded")
	}
	if n, err := record.Write(input); err != nil || n != len(input) || len(record.data) != 64*1024 {
		t.Fatal("driver capture overflow")
	}
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
