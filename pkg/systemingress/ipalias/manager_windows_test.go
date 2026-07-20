//go:build windows

package ipalias

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type commandCall struct {
	name string
	args []string
}

type fakeCommandRunner struct {
	calls []commandCall
	run   func(name string, args ...string) ([]byte, error)
}

func (f *fakeCommandRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, commandCall{name: name, args: append([]string(nil), args...)})
	if f.run == nil {
		return nil, nil
	}
	return f.run(name, args...)
}

type fakeAddressProbe struct {
	index       int
	loopbackErr error
	present     map[netip.Addr]bool
	checks      int
	state       func(interfaceIndex int, addr netip.Addr, check int) (aliasAddressState, error)
	check       func(interfaceIndex int, addr netip.Addr, check int) (bool, error)
}

func (f *fakeAddressProbe) LoopbackInterfaceIndex() (int, error) {
	if f.loopbackErr != nil {
		return 0, f.loopbackErr
	}
	return f.index, nil
}

func (f *fakeAddressProbe) AddressState(interfaceIndex int, addr netip.Addr) (aliasAddressState, error) {
	f.checks++
	if f.state != nil {
		return f.state(interfaceIndex, addr, f.checks)
	}
	if f.check != nil {
		present, err := f.check(interfaceIndex, addr, f.checks)
		if err != nil || !present {
			return aliasAddressState{}, err
		}
		return fakePresentAddressState(addr), nil
	}
	if !f.present[addr] {
		return aliasAddressState{}, nil
	}
	return fakePresentAddressState(addr), nil
}

func fakePresentAddressState(addr netip.Addr) aliasAddressState {
	return aliasAddressState{Present: true, PrefixLength: 128, SkipAsSource: true, RowCreationID: "fake-" + addr.String()}
}

func newFakeProbe() *fakeAddressProbe {
	return &fakeAddressProbe{index: 7, present: make(map[netip.Addr]bool)}
}

func statefulRunner(probe *fakeAddressProbe) *fakeCommandRunner {
	return &fakeCommandRunner{run: func(_ string, args ...string) ([]byte, error) {
		addr := addressFromCommand(args)
		switch commandVerb(args) {
		case "add":
			probe.present[addr] = true
		case "delete":
			delete(probe.present, addr)
		}
		return nil, nil
	}}
}

func commandVerb(args []string) string {
	if len(args) > 2 {
		return args[2]
	}
	return ""
}

func addressFromCommand(args []string) netip.Addr {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "address=") {
			continue
		}
		value := strings.TrimPrefix(arg, "address=")
		value = strings.TrimSuffix(value, "/128")
		addr, _ := netip.ParseAddr(value)
		return addr
	}
	return netip.Addr{}
}

func TestLoopbackManagerReferenceCountsAndVerifiesCommands(t *testing.T) {
	probe := newFakeProbe()
	runner := statefulRunner(probe)
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}
	addr := netip.MustParseAddr("fd7a:115c:a1e0::4")

	if err := manager.Add(addr); err != nil {
		t.Fatalf("Add(first) error = %v", err)
	}
	if err := manager.Add(addr); err != nil {
		t.Fatalf("Add(second) error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("commands after two Add calls = %d, want 1", len(runner.calls))
	}
	assertCommand(t, runner.calls[0], []string{
		"interface", "ipv6", "add", "address", "interface=7",
		"address=fd7a:115c:a1e0::4/128", "store=active", "skipassource=true",
	})
	if probe.checks != 2 {
		t.Fatalf("address probes after first creation = %d, want preflight and verification", probe.checks)
	}

	if err := manager.Remove(addr); err != nil {
		t.Fatalf("Remove(first reference) error = %v", err)
	}
	if len(runner.calls) != 1 || !probe.present[addr] {
		t.Fatalf("first Remove issued a command or removed address: calls=%d present=%v", len(runner.calls), probe.present[addr])
	}
	if err := manager.Remove(addr); err != nil {
		t.Fatalf("Remove(last reference) error = %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("commands after last Remove = %d, want 2", len(runner.calls))
	}
	assertCommand(t, runner.calls[1], []string{
		"interface", "ipv6", "delete", "address", "interface=7",
		"address=fd7a:115c:a1e0::4", "store=active",
	})
	if probe.present[addr] {
		t.Fatal("address remains after verified delete")
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("Close issued an extra command: %d", len(runner.calls))
	}
	if err := manager.Add(addr); !errors.Is(err, ErrClosed) {
		t.Fatalf("Add after Close error = %v, want ErrClosed", err)
	}
	if err := manager.Remove(addr); !errors.Is(err, ErrClosed) {
		t.Fatalf("Remove after Close error = %v, want ErrClosed", err)
	}
}

func TestLoopbackManagerAcceptsOnlyUnzonedIPv6ULA(t *testing.T) {
	probe := newFakeProbe()
	runner := &fakeCommandRunner{}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}

	invalid := []netip.Addr{
		{},
		netip.MustParseAddr("10.6.22.4"),
		netip.MustParseAddr("::ffff:10.6.22.4"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("ff02::1"),
		netip.MustParseAddr("fd00::1%7"),
	}
	for _, addr := range invalid {
		if err := manager.Add(addr); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("Add(%s) error = %v, want ErrInvalidAddress", addr, err)
		}
	}
	if len(runner.calls) != 0 || probe.checks != 0 {
		t.Fatalf("invalid addresses reached system dependencies: calls=%d probes=%d", len(runner.calls), probe.checks)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLoopbackManagerFailsClosedForExistingAddress(t *testing.T) {
	probe := newFakeProbe()
	addr := netip.MustParseAddr("fd00::99")
	probe.present[addr] = true
	runner := &fakeCommandRunner{}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}

	if err := manager.Add(addr); !errors.Is(err, ErrAddressExists) {
		t.Fatalf("Add(existing) error = %v, want ErrAddressExists", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("existing address was changed by %d command(s)", len(runner.calls))
	}
	if !probe.present[addr] {
		t.Fatal("pre-existing address was removed")
	}
}

func TestLoopbackManagerRejectsUnverifiedAdd(t *testing.T) {
	probe := newFakeProbe()
	runner := &fakeCommandRunner{}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}
	addr := netip.MustParseAddr("fd00::10")

	err = manager.Add(addr)
	if err == nil || !strings.Contains(err.Error(), "did not appear") {
		t.Fatalf("Add() error = %v, want post-command verification failure", err)
	}
	if len(runner.calls) != 1 || commandVerb(runner.calls[0].args) != "add" {
		t.Fatalf("commands = %+v, want one add", runner.calls)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unverified absent address was adopted: commands=%+v", runner.calls)
	}
}

func TestLoopbackManagerRollsBackWhenAddProbeFails(t *testing.T) {
	probe := newFakeProbe()
	probe.check = func(_ int, _ netip.Addr, check int) (bool, error) {
		switch check {
		case 1:
			return false, nil
		case 2:
			return false, errors.New("probe unavailable")
		default:
			return false, nil
		}
	}
	runner := &fakeCommandRunner{}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}

	err = manager.Add(netip.MustParseAddr("fd00::11"))
	if err == nil || !strings.Contains(err.Error(), "probe unavailable") {
		t.Fatalf("Add() error = %v, want probe failure", err)
	}
	if len(runner.calls) != 2 || commandVerb(runner.calls[0].args) != "add" || commandVerb(runner.calls[1].args) != "delete" {
		t.Fatalf("commands = %+v, want add followed by rollback delete", runner.calls)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("verified rollback left cleanup ownership: commands=%+v", runner.calls)
	}
}

func TestLoopbackManagerRetainsOwnershipUntilDeleteVerified(t *testing.T) {
	probe := newFakeProbe()
	deleteCalls := 0
	runner := &fakeCommandRunner{run: func(_ string, args ...string) ([]byte, error) {
		addr := addressFromCommand(args)
		switch commandVerb(args) {
		case "add":
			probe.present[addr] = true
		case "delete":
			deleteCalls++
			if deleteCalls == 2 {
				delete(probe.present, addr)
			}
		}
		return nil, nil
	}}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}
	addr := netip.MustParseAddr("fd00::12")

	if err := manager.Add(addr); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	err = manager.Remove(addr)
	if err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("Remove() error = %v, want delete verification failure", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close retry error = %v", err)
	}
	if deleteCalls != 2 || probe.present[addr] {
		t.Fatalf("delete retries=%d present=%v, want retained ownership and successful Close cleanup", deleteCalls, probe.present[addr])
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestLoopbackManagerCloseDeletesOnlyCreatedAddresses(t *testing.T) {
	probe := newFakeProbe()
	existing := netip.MustParseAddr("fd00::20")
	first := netip.MustParseAddr("fd00::21")
	second := netip.MustParseAddr("fd00::22")
	probe.present[existing] = true
	runner := statefulRunner(probe)
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}

	if err := manager.Add(existing); !errors.Is(err, ErrAddressExists) {
		t.Fatalf("Add(existing) error = %v, want ErrAddressExists", err)
	}
	for _, addr := range []netip.Addr{second, first, first} {
		if err := manager.Add(addr); err != nil {
			t.Fatalf("Add(%s) error = %v", addr, err)
		}
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	deleted := make([]netip.Addr, 0, 2)
	for _, call := range runner.calls {
		if commandVerb(call.args) == "delete" {
			deleted = append(deleted, addressFromCommand(call.args))
		}
	}
	if want := []netip.Addr{first, second}; !reflect.DeepEqual(deleted, want) {
		t.Fatalf("deleted addresses = %v, want %v", deleted, want)
	}
	if !probe.present[existing] {
		t.Fatal("Close removed a pre-existing address")
	}
}

func TestLoopbackManagerReportsCommandOutputAndDoesNotAdoptFailedAdd(t *testing.T) {
	probe := newFakeProbe()
	runner := &fakeCommandRunner{run: func(_ string, _ ...string) ([]byte, error) {
		return []byte("Access is denied."), errors.New("exit status 1")
	}}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}

	err = manager.Add(netip.MustParseAddr("fd00::30"))
	if err == nil || !strings.Contains(err.Error(), "Access is denied") {
		t.Fatalf("Add() error = %v, want netsh output", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("failed add was adopted: commands=%+v", runner.calls)
	}
}

func TestLoopbackManagerRollsBackFailedAddWithSideEffect(t *testing.T) {
	probe := newFakeProbe()
	runner := &fakeCommandRunner{run: func(_ string, args ...string) ([]byte, error) {
		addr := addressFromCommand(args)
		switch commandVerb(args) {
		case "add":
			probe.present[addr] = true
			return []byte("command failed after applying address"), errors.New("exit status 1")
		case "delete":
			delete(probe.present, addr)
		}
		return nil, nil
	}}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}
	addr := netip.MustParseAddr("fd00::31")

	err = manager.Add(addr)
	if err == nil || !strings.Contains(err.Error(), "command failed after applying address") {
		t.Fatalf("Add() error = %v, want original command failure", err)
	}
	if probe.present[addr] {
		t.Fatal("failed add side effect remains after rollback")
	}
	if len(runner.calls) != 2 || commandVerb(runner.calls[0].args) != "add" || commandVerb(runner.calls[1].args) != "delete" {
		t.Fatalf("commands = %+v, want add followed by delete", runner.calls)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("verified rollback retained ownership: commands=%+v", runner.calls)
	}
}

func TestLoopbackManagerRetriesCleanupAfterFailedAddProbeAndDelete(t *testing.T) {
	probe := newFakeProbe()
	probe.check = func(_ int, _ netip.Addr, check int) (bool, error) {
		switch check {
		case 1:
			return false, nil
		case 2:
			return false, errors.New("probe unavailable")
		case 3:
			return true, nil
		default:
			return false, nil
		}
	}
	deleteCalls := 0
	runner := &fakeCommandRunner{run: func(_ string, args ...string) ([]byte, error) {
		switch commandVerb(args) {
		case "add":
			return []byte("apply state unknown"), errors.New("add failed")
		case "delete":
			deleteCalls++
			if deleteCalls == 1 {
				return []byte("delete failed"), errors.New("delete failed")
			}
		}
		return nil, nil
	}}
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}

	err = manager.Add(netip.MustParseAddr("fd00::32"))
	if err == nil || !strings.Contains(err.Error(), "apply state unknown") ||
		!strings.Contains(err.Error(), "probe unavailable") || !strings.Contains(err.Error(), "delete failed") {
		t.Fatalf("Add() error = %v, want joined add, probe, and cleanup failures", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() retry error = %v", err)
	}
	if deleteCalls != 2 {
		t.Fatalf("delete calls = %d, want immediate cleanup plus Close retry", deleteCalls)
	}
}

func TestLoopbackManagerConstructorAndUnmanagedRemoveErrors(t *testing.T) {
	probe := newFakeProbe()
	probe.loopbackErr = errors.New("no loopback")
	if _, err := newLoopbackManagerWithDeps(&fakeCommandRunner{}, probe); err == nil || !strings.Contains(err.Error(), "no loopback") {
		t.Fatalf("constructor error = %v, want loopback probe failure", err)
	}

	probe = newFakeProbe()
	probe.index = 0
	if _, err := newLoopbackManagerWithDeps(&fakeCommandRunner{}, probe); err == nil || !strings.Contains(err.Error(), "invalid loopback interface index") {
		t.Fatalf("constructor index error = %v", err)
	}

	probe = newFakeProbe()
	manager, err := newLoopbackManagerWithDeps(&fakeCommandRunner{}, probe)
	if err != nil {
		t.Fatalf("newLoopbackManagerWithDeps() error = %v", err)
	}
	if err := manager.Remove(netip.MustParseAddr("fd00::40")); !errors.Is(err, ErrAddressNotManaged) {
		t.Fatalf("Remove(unmanaged) error = %v, want ErrAddressNotManaged", err)
	}
}

func assertCommand(t *testing.T, call commandCall, wantArgs []string) {
	t.Helper()
	if call.name != "netsh.exe" {
		t.Fatalf("command name = %q, want netsh.exe", call.name)
	}
	if !reflect.DeepEqual(call.args, wantArgs) {
		t.Fatalf("command args = %q, want %q", call.args, wantArgs)
	}
}
