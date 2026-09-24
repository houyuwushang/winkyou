//go:build windows && fieldc1c

package netif

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func fieldSyntheticBinding() fieldWindowsBinding {
	return fieldWindowsBinding{name: "wcf07a50348ce89", guid: windows.GUID{Data1: 0xbc505672, Data2: 0x37a8, Data3: 0xd965,
		Data4: [8]byte{0x6a, 0x5c, 0x73, 0xf9, 0xef, 0xa0, 0x02, 0x56}}, mtu: 1280,
		local: netip.MustParseAddr("192.0.2.100"), peer: netip.MustParseAddr("192.0.2.101")}
}

func TestFieldWindowsGUIDGolden(t *testing.T) {
	for _, tc := range []struct {
		text string
		guid windows.GUID
	}{
		{"bc505672-37a8-d965-6a5c-73f9efa00256", fieldSyntheticBinding().guid},
		{"653a9f1e-ed90-6e75-c74a-4d2b9780fa31", windows.GUID{Data1: 0x653a9f1e, Data2: 0xed90, Data3: 0x6e75, Data4: [8]byte{0xc7, 0x4a, 0x4d, 0x2b, 0x97, 0x80, 0xfa, 0x31}}},
	} {
		actual, err := fieldParseGUID(tc.text)
		if err != nil || actual != tc.guid || fieldGUIDString(actual) != tc.text {
			t.Fatal("canonical GUID fields or round trip mismatch")
		}
		for _, bad := range []string{"", "{" + tc.text + "}", strings.ToUpper(tc.text), tc.text + "\x00", strings.ReplaceAll(tc.text, "-", "")} {
			if _, err := fieldParseGUID(bad); err == nil {
				t.Fatal("noncanonical GUID accepted")
			}
		}
	}
}

func TestFieldWindowsConflictPreflight(t *testing.T) {
	binding := fieldSyntheticBinding()
	address := func(ip string) fieldAddressRow { return fieldAddressRow{Address: fieldIPv4(netip.MustParseAddr(ip))} }
	route := func(ip string, bits uint8) fieldRouteRow {
		return fieldRouteRow{Destination: fieldIPPrefix{Address: fieldIPv4(netip.MustParseAddr(ip)), Bits: bits}}
	}
	for _, tc := range []struct {
		name string
		snap fieldIPSnapshot
		bad  bool
	}{
		{"empty", fieldIPSnapshot{}, false},
		{"default_preserved", fieldIPSnapshot{routes: []fieldRouteRow{route("0.0.0.0", 0)}}, false},
		{"unrelated", fieldIPSnapshot{addresses: []fieldAddressRow{address("198.51.100.10")}, routes: []fieldRouteRow{route("203.0.113.0", 24)}}, false},
		{"same_name", fieldIPSnapshot{adapters: []fieldAdapterIdentity{{name: binding.name}}}, true},
		{"same_name_case", fieldIPSnapshot{adapters: []fieldAdapterIdentity{{name: strings.ToUpper(binding.name)}}}, true},
		{"same_guid", fieldIPSnapshot{adapters: []fieldAdapterIdentity{{name: "other", guid: binding.guid}}}, true},
		{"local_address", fieldIPSnapshot{addresses: []fieldAddressRow{address("192.0.2.100")}}, true},
		{"peer_address", fieldIPSnapshot{addresses: []fieldAddressRow{address("192.0.2.101")}}, true},
		{"peer_host_route", fieldIPSnapshot{routes: []fieldRouteRow{route("192.0.2.101", 32)}}, true},
		{"overlapping_route", fieldIPSnapshot{routes: []fieldRouteRow{route("192.0.2.0", 24)}}, true},
		{"unknown_family", fieldIPSnapshot{addresses: []fieldAddressRow{{}}}, true},
		{"invalid_prefix", fieldIPSnapshot{routes: []fieldRouteRow{route("192.0.2.0", 33)}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (fieldRejectConflicts(binding, tc.snap) != nil) != tc.bad {
				t.Fatal("read-only conflict classification mismatch")
			}
		})
	}
}

func TestFieldWindowsUnrelatedSnapshotComparison(t *testing.T) {
	b := fieldSyntheticBinding()
	before := fieldIPSnapshot{adapters: []fieldAdapterIdentity{{luid: 44, index: 8, name: "synthetic"}},
		addresses: []fieldAddressRow{{LUID: 44, Address: fieldIPv4(b.local), PrefixLength: 32, CreationTimestamp: 100}},
		routes:    []fieldRouteRow{{LUID: 44, Destination: fieldIPPrefix{Address: fieldIPv4(b.peer), Bits: 32}, Age: 10}}}
	after := fieldIPSnapshot{adapters: append([]fieldAdapterIdentity(nil), before.adapters...), addresses: append([]fieldAddressRow(nil), before.addresses...), routes: append([]fieldRouteRow(nil), before.routes...)}
	after.addresses[0].CreationTimestamp++
	after.routes[0].Age++
	if !fieldUnrelatedUnchanged(before, after, 99) {
		t.Fatal("OS-derived time is not configuration")
	}
	after.adapters = append(after.adapters, fieldAdapterIdentity{luid: 99})
	after.addresses = append(after.addresses, fieldAddressRow{LUID: 99})
	after.routes = append(after.routes, fieldRouteRow{LUID: 99})
	if !fieldUnrelatedUnchanged(before, after, 99) {
		t.Fatal("owned rows are not an unrelated mutation")
	}
	after.routes[0].Metric++
	if fieldUnrelatedUnchanged(before, after, 99) {
		t.Fatal("unrelated write went unnoticed")
	}
}

type fieldFakeIP struct {
	id      fieldAdapterIdentity
	row     fieldIPInterfaceRow
	address *fieldAddressRow
	route   *fieldRouteRow
	calls   []string
	fail    string
	corrupt string
	failed  bool
}

func newFieldFakeIP() *fieldFakeIP {
	b := fieldSyntheticBinding()
	return &fieldFakeIP{id: fieldAdapterIdentity{luid: 99, index: 7, guid: b.guid, name: b.name},
		row: fieldIPInterfaceRow{Family: windows.AF_INET, LUID: 99, Index: 7, MTU: 1500, Metric: 55, UseAutomaticMetric: 1}}
}
func (f *fieldFakeIP) call(name string) error {
	f.calls = append(f.calls, name)
	if name == f.fail && !f.failed {
		f.failed = true
		return errors.New("synthetic_failure")
	}
	return nil
}
func (f *fieldFakeIP) snapshot() (fieldIPSnapshot, error) {
	return fieldIPSnapshot{}, f.call("snapshot")
}
func (f *fieldFakeIP) identity(uint64) (fieldAdapterIdentity, error) {
	return f.id, f.call("identity")
}
func (f *fieldFakeIP) getInterface(uint64) (fieldIPInterfaceRow, error) {
	err := f.call("interface.get")
	return f.row, err
}
func (f *fieldFakeIP) setInterface(row fieldIPInterfaceRow) error {
	if err := f.call("interface.set"); err != nil {
		return err
	}
	f.row = row
	return nil
}
func (f *fieldFakeIP) getAddress(fieldAddressRow) (fieldAddressRow, error) {
	if err := f.call("address.get"); err != nil {
		return fieldAddressRow{}, err
	}
	if f.address == nil {
		return fieldAddressRow{}, windows.ERROR_NOT_FOUND
	}
	if f.corrupt == "address" {
		f.address.PrefixLength = 31
	}
	return *f.address, nil
}
func (f *fieldFakeIP) createAddress(row fieldAddressRow) error {
	if err := f.call("address.create"); err != nil {
		return err
	}
	if f.address != nil {
		return windows.ERROR_OBJECT_ALREADY_EXISTS
	}
	f.address = &row
	return nil
}
func (f *fieldFakeIP) deleteAddress(row fieldAddressRow) error {
	if err := f.call("address.delete"); err != nil {
		return err
	}
	if f.address == nil || *f.address != row {
		return errors.New("delete_without_comparison")
	}
	f.address = nil
	return nil
}
func (f *fieldFakeIP) getRoute(fieldRouteRow) (fieldRouteRow, error) {
	if err := f.call("route.get"); err != nil {
		return fieldRouteRow{}, err
	}
	if f.route == nil {
		return fieldRouteRow{}, windows.ERROR_NOT_FOUND
	}
	if f.corrupt == "route" {
		f.route.Metric++
	}
	return *f.route, nil
}
func (f *fieldFakeIP) createRoute(row fieldRouteRow) error {
	if err := f.call("route.create"); err != nil {
		return err
	}
	if f.route != nil {
		return windows.ERROR_OBJECT_ALREADY_EXISTS
	}
	f.route = &row
	return nil
}
func (f *fieldFakeIP) deleteRoute(row fieldRouteRow) error {
	if err := f.call("route.delete"); err != nil {
		return err
	}
	if f.route == nil || *f.route != row {
		return errors.New("delete_without_comparison")
	}
	f.route = nil
	return nil
}

func TestFieldWindowsIPTransactionReadbackAndReverseRollback(t *testing.T) {
	f := newFieldFakeIP()
	before := f.row
	txn, err := configureFieldIP(context.Background(), f, fieldSyntheticBinding(), f.id)
	if err != nil || txn == nil || f.address == nil || f.route == nil || f.row.MTU != 1280 || f.row.Metric != 55 {
		t.Fatal("single address/route/MTU transaction did not commit")
	}
	if f.address.PrefixLength != 32 || f.address.SkipAsSource != 1 || f.route.Destination.Bits != 32 || f.route.Metric != 1 {
		t.Fatal("sealed row values changed")
	}
	f.calls = nil
	if txn.rollback(context.Background()) != nil || f.address != nil || f.route != nil || f.row != before {
		t.Fatal("owned transaction did not restore only its own rows")
	}
	var writes []string
	for _, call := range f.calls {
		if strings.HasSuffix(call, ".delete") || strings.HasSuffix(call, ".set") {
			writes = append(writes, call)
		}
	}
	if !reflect.DeepEqual(writes, []string{"route.delete", "address.delete", "interface.set"}) {
		t.Fatal("rollback order changed")
	}
	f.calls = nil
	if txn.rollback(context.Background()) != nil || len(f.calls) != 0 {
		t.Fatal("rollback is not idempotent")
	}
}

func TestFieldWindowsIPTransactionEveryFailureRollsBack(t *testing.T) {
	for _, stage := range []string{"identity", "interface.get", "interface.set", "address.create", "address.get", "route.create", "route.get"} {
		t.Run(stage, func(t *testing.T) {
			f := newFieldFakeIP()
			before := f.row
			f.fail = stage
			if _, err := configureFieldIP(context.Background(), f, fieldSyntheticBinding(), f.id); err == nil || !f.failed {
				t.Fatal("configuration failure was not reached and rejected")
			}
			if f.address != nil || f.route != nil || f.row != before {
				t.Fatal("partial configuration leaked owned rows")
			}
		})
	}
}

func TestFieldWindowsIPTransactionNeverOverwritesExternalChange(t *testing.T) {
	for _, object := range []string{"identity", "interface", "address", "route"} {
		t.Run(object, func(t *testing.T) {
			f := newFieldFakeIP()
			txn, err := configureFieldIP(context.Background(), f, fieldSyntheticBinding(), f.id)
			if err != nil {
				t.Fatal("fixture transaction failed")
			}
			switch object {
			case "identity":
				f.id.guid.Data1++
			case "interface":
				f.row.Metric++
			case "address":
				f.address.PrefixLength = 31
			case "route":
				f.route.Metric++
			}
			f.calls = nil
			if txn.rollback(context.Background()) == nil {
				t.Fatal("foreign change accepted")
			}
			for _, call := range f.calls {
				if object == "identity" && (strings.HasSuffix(call, ".delete") || strings.HasSuffix(call, ".set")) ||
					object == "interface" && call == "interface.set" || call == object+".delete" {
					t.Fatal("rollback overwrote changed ownership or value")
				}
			}
		})
	}
}

func TestFieldWindowsIPTransactionRejectsReadbackAndBinding(t *testing.T) {
	for _, item := range []string{"address", "route"} {
		f := newFieldFakeIP()
		f.corrupt = item
		if _, err := configureFieldIP(context.Background(), f, fieldSyntheticBinding(), f.id); err == nil {
			t.Fatal("readback corruption accepted")
		}
	}
	for _, item := range []string{"guid", "name", "luid", "index", "context"} {
		f := newFieldFakeIP()
		id := f.id
		ctx, cancel := context.WithCancel(context.Background())
		switch item {
		case "guid":
			id.guid.Data1++
		case "name":
			id.name = "other"
		case "luid":
			id.luid = 0
		case "index":
			id.index = 0
		case "context":
			cancel()
		}
		_, err := configureFieldIP(ctx, f, fieldSyntheticBinding(), id)
		cancel()
		if err == nil {
			t.Fatal("invalid identity binding accepted")
		}
		if len(f.calls) != 0 {
			t.Fatal("invalid binding reached configuration capability")
		}
	}
}
