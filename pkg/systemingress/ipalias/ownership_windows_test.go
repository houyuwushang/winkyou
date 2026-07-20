//go:build windows

package ipalias

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedLoopbackManagerRecoversHardExitAndCleansJournal(t *testing.T) {
	dir := t.TempDir()
	probe := newFakeProbe()
	runner := statefulRunner(probe)
	addr := netip.MustParseAddr("fd00::51")

	first, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-1"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Add(addr); err != nil {
		t.Fatalf("first Add() error = %v", err)
	}
	firstClaim := first.claims[addr]
	if firstClaim == nil {
		t.Fatal("first manager has no durable alias claim")
	}
	markerPath := firstClaim.markerPath
	lockPath := strings.TrimSuffix(markerPath, ".json") + ".lock"
	marker, exists, err := loadOwnershipMarker(markerPath)
	if err != nil || !exists {
		t.Fatalf("active marker = %+v exists=%v error=%v", marker, exists, err)
	}
	if marker.Phase != ownershipPhaseActive || marker.RowCreationID != fakePresentAddressState(addr).RowCreationID {
		t.Fatalf("first active marker = %+v", marker)
	}
	firstToken := marker.Token

	// Simulate operating-system cleanup after a hard process exit: Windows
	// releases the byte-range lock, while the address and marker remain.
	firstClaim.release()
	secondOptions := ownershipTestOptions(dir, "scope-a", "instance-2")
	secondOptions.PID++
	second, err := newOwnedLoopbackManagerWithDeps(secondOptions, runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	second.ownership.matches = func(pid int, startID string) (bool, error) {
		if pid != marker.PID || startID != marker.ProcessStartID {
			t.Fatalf("previous identity = %d/%q, want %d/%q", pid, startID, marker.PID, marker.ProcessStartID)
		}
		return false, nil
	}
	if err := second.Add(addr); err != nil {
		t.Fatalf("recovery Add() error = %v", err)
	}
	if len(runner.calls) != 1 || commandVerb(runner.calls[0].args) != "add" {
		t.Fatalf("recovery re-created an existing alias: calls=%+v", runner.calls)
	}
	recovered, exists, err := loadOwnershipMarker(markerPath)
	if err != nil || !exists {
		t.Fatalf("recovered marker = %+v exists=%v error=%v", recovered, exists, err)
	}
	if recovered.InstanceID != secondOptions.InstanceID || recovered.PID != secondOptions.PID ||
		recovered.Token == firstToken || recovered.Phase != ownershipPhaseActive {
		t.Fatalf("recovered marker = %+v", recovered)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("recovered Close() error = %v", err)
	}
	if probe.present[addr] {
		t.Fatal("recovered Close left alias present")
	}
	if _, exists, err := loadOwnershipMarker(markerPath); err != nil || exists {
		t.Fatalf("marker after Close exists=%v error=%v", exists, err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("stable ownership lock file was removed: %v", err)
	}
}

func TestOwnedLoopbackManagerLockExcludesSecondLiveManager(t *testing.T) {
	dir := t.TempDir()
	probe := newFakeProbe()
	runner := statefulRunner(probe)
	addr := netip.MustParseAddr("fd00::52")
	first, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-1"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Add(addr); err != nil {
		t.Fatal(err)
	}
	second, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-2"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	second.ownership.matches = func(int, string) (bool, error) {
		t.Fatal("process matcher ran while the alias lifecycle lock was held")
		return false, nil
	}
	if err := second.Add(addr); !errors.Is(err, ErrOwnershipLocked) {
		t.Fatalf("second Add() error = %v, want ErrOwnershipLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
}

func TestOwnedLoopbackManagerFailsClosedWithoutMatchingProof(t *testing.T) {
	t.Run("markerless existing address", func(t *testing.T) {
		dir := t.TempDir()
		probe := newFakeProbe()
		addr := netip.MustParseAddr("fd00::53")
		probe.present[addr] = true
		runner := &fakeCommandRunner{}
		manager, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-1"), runner, probe)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Add(addr); !errors.Is(err, ErrAddressExists) {
			t.Fatalf("Add(markerless existing) error = %v, want ErrAddressExists", err)
		}
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		markers, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil || len(markers) != 0 {
			t.Fatalf("markerless conflict created markers=%v error=%v", markers, err)
		}
		if len(runner.calls) != 0 || !probe.present[addr] {
			t.Fatalf("markerless address was changed: calls=%v present=%v", runner.calls, probe.present[addr])
		}
	})

	t.Run("different scope or configuration", func(t *testing.T) {
		dir := t.TempDir()
		probe := newFakeProbe()
		runner := statefulRunner(probe)
		addr := netip.MustParseAddr("fd00::54")
		originalOptions := ownershipTestOptions(dir, "scope-a", "instance-1")
		original, err := newOwnedLoopbackManagerWithDeps(originalOptions, runner, probe)
		if err != nil {
			t.Fatal(err)
		}
		if err := original.Add(addr); err != nil {
			t.Fatal(err)
		}
		original.claims[addr].release()

		candidates := []OwnershipOptions{
			ownershipTestOptions(dir, "scope-b", "instance-2"),
			ownershipTestOptions(dir, "scope-a", "instance-3"),
		}
		candidates[1].ConfigFingerprint = "different-config"
		for _, candidate := range candidates {
			manager, err := newOwnedLoopbackManagerWithDeps(candidate, runner, probe)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Add(addr); !errors.Is(err, ErrOwnershipConflict) {
				t.Fatalf("Add(conflicting proof) error = %v, want ErrOwnershipConflict", err)
			}
		}
		if len(runner.calls) != 1 || !probe.present[addr] {
			t.Fatalf("conflicting manager changed address: calls=%v present=%v", runner.calls, probe.present[addr])
		}

		cleanupOptions := ownershipTestOptions(dir, "scope-a", "cleanup")
		cleanup, err := newOwnedLoopbackManagerWithDeps(cleanupOptions, runner, probe)
		if err != nil {
			t.Fatal(err)
		}
		cleanup.ownership.matches = func(int, string) (bool, error) { return false, nil }
		if err := cleanup.Add(addr); err != nil {
			t.Fatal(err)
		}
		if err := cleanup.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestOwnedLoopbackManagerChecksPreviousProcessAndAddressRow(t *testing.T) {
	dir := t.TempDir()
	probe := newFakeProbe()
	runner := statefulRunner(probe)
	addr := netip.MustParseAddr("fd00::55")
	options := ownershipTestOptions(dir, "scope-a", "instance-1")
	first, err := newOwnedLoopbackManagerWithDeps(options, runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Add(addr); err != nil {
		t.Fatal(err)
	}
	first.claims[addr].release()

	live, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-live"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	live.ownership.matches = func(int, string) (bool, error) { return true, nil }
	if err := live.Add(addr); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("Add(live previous owner) error = %v, want ErrOwnershipConflict", err)
	}

	probe.state = func(_ int, candidate netip.Addr, _ int) (aliasAddressState, error) {
		state := fakePresentAddressState(candidate)
		state.PrefixLength = 64
		return state, nil
	}
	wrongShape, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-shape"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	wrongShape.ownership.matches = func(int, string) (bool, error) { return false, nil }
	if err := wrongShape.Add(addr); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("Add(wrong alias shape) error = %v, want ErrOwnershipConflict", err)
	}

	probe.state = func(_ int, candidate netip.Addr, _ int) (aliasAddressState, error) {
		state := fakePresentAddressState(candidate)
		state.RowCreationID = "replacement-row"
		return state, nil
	}
	replaced, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-replaced"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	replaced.ownership.matches = func(int, string) (bool, error) { return false, nil }
	if err := replaced.Add(addr); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("Add(replaced OS row) error = %v, want ErrOwnershipConflict", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("row conflict issued system commands: %+v", runner.calls)
	}

	probe.state = nil
	cleanup, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "cleanup"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	cleanup.ownership.matches = func(int, string) (bool, error) { return false, nil }
	if err := cleanup.Add(addr); err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedLoopbackManagerRefusesToDeleteReplacementRow(t *testing.T) {
	dir := t.TempDir()
	probe := newFakeProbe()
	runner := statefulRunner(probe)
	addr := netip.MustParseAddr("fd00::58")
	manager, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-1"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(addr); err != nil {
		t.Fatal(err)
	}
	probe.state = func(_ int, candidate netip.Addr, _ int) (aliasAddressState, error) {
		state := fakePresentAddressState(candidate)
		state.RowCreationID = "replacement-row"
		return state, nil
	}
	if err := manager.Close(); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("Close(replacement row) error = %v, want ErrOwnershipConflict", err)
	}
	if len(runner.calls) != 1 || commandVerb(runner.calls[0].args) != "add" {
		t.Fatalf("replacement row was deleted: %+v", runner.calls)
	}
	probe.state = nil
	if err := manager.Close(); err != nil {
		t.Fatalf("Close after restoring owned row error = %v", err)
	}
}

func TestOwnedLoopbackManagerRecoversIntentCrashWindow(t *testing.T) {
	dir := t.TempDir()
	probe := newFakeProbe()
	runner := statefulRunner(probe)
	addr := netip.MustParseAddr("fd00::56")
	first, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-1"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := first.ownership.acquire(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.write(ownershipPhaseIntent); err != nil {
		t.Fatal(err)
	}
	probe.present[addr] = true
	claim.release()

	second, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-2"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	second.ownership.matches = func(int, string) (bool, error) { return false, nil }
	if err := second.Add(addr); err != nil {
		t.Fatalf("recover intent Add() error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("intent recovery re-added address: %+v", runner.calls)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || commandVerb(runner.calls[0].args) != "delete" {
		t.Fatalf("intent recovery cleanup calls = %+v", runner.calls)
	}
}

func TestOwnedLoopbackManagerRetainsJournalAcrossDeleteRetry(t *testing.T) {
	dir := t.TempDir()
	probe := newFakeProbe()
	addr := netip.MustParseAddr("fd00::57")
	deleteCalls := 0
	runner := &fakeCommandRunner{run: func(_ string, args ...string) ([]byte, error) {
		switch commandVerb(args) {
		case "add":
			probe.present[addressFromCommand(args)] = true
		case "delete":
			deleteCalls++
			if deleteCalls == 2 {
				delete(probe.present, addressFromCommand(args))
			}
		}
		return nil, nil
	}}
	manager, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-1"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Add(addr); err != nil {
		t.Fatal(err)
	}
	markerPath := manager.claims[addr].markerPath
	if err := manager.Remove(addr); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("Remove() error = %v, want verification failure", err)
	}
	marker, exists, err := loadOwnershipMarker(markerPath)
	if err != nil || !exists || marker.Phase != ownershipPhaseDeleting {
		t.Fatalf("retained deleting marker = %+v exists=%v error=%v", marker, exists, err)
	}
	competitor, err := newOwnedLoopbackManagerWithDeps(ownershipTestOptions(dir, "scope-a", "instance-2"), runner, probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := competitor.Add(addr); !errors.Is(err, ErrOwnershipLocked) {
		t.Fatalf("competitor Add() error = %v, want ErrOwnershipLocked", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close retry error = %v", err)
	}
	if _, exists, err := loadOwnershipMarker(markerPath); err != nil || exists {
		t.Fatalf("marker after retry exists=%v error=%v", exists, err)
	}
}

func ownershipTestOptions(dir, scope, instance string) OwnershipOptions {
	return OwnershipOptions{
		Scope: scope, InstanceID: instance, PID: 41001,
		ProcessStartID: "start-" + instance, ConfigFingerprint: "config-v1", StoreDir: dir,
	}
}
