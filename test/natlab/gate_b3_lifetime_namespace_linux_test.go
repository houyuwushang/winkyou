//go:build linux && natlab

package natlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var gateB3UDPTimeoutKeys = [2]string{
	"net.netfilter.nf_conntrack_udp_timeout",
	"net.netfilter.nf_conntrack_udp_timeout_stream",
}

type gateB3LifetimeNamespace struct {
	name     string
	identity os.FileInfo
	original [2]int
}

// Only this constructor creates the targets. No caller-provided namespace or
// pathname can acquire timeout-setting authority. The two names and their
// namespace inodes are recorded BEFORE the first write, and never re-resolved
// as a different object. nf_conntrack_max remains the separate existing guard.
type gateB3LifetimeGuard struct {
	topology      *n2dTopology
	targets       [2]gateB3LifetimeNamespace
	control       gateB3LifetimeNamespace
	initial       os.FileInfo
	initialValues [2]int
	restored      bool
	closed        bool
	seconds       int
}

func newGateB3LifetimeTopology(t *testing.T, seconds int) *gateB3LifetimeGuard {
	t.Helper()
	if seconds != 30 && seconds != 60 {
		t.Fatal("mapping lifetime fixture is not an accepted model")
	}
	guard := &gateB3LifetimeGuard{seconds: seconds}
	var err error
	guard.initial, err = os.Stat("/proc/1/ns/net")
	self, selfErr := os.Stat("/proc/self/ns/net")
	if err != nil || selfErr != nil || !os.SameFile(guard.initial, self) {
		t.Fatal("mapping lifetime harness is not in the initial namespace")
	}
	guard.initialValues, err = readGateB3UDPTimeouts("")
	if err != nil {
		t.Fatal("mapping lifetime initial snapshot failed")
	}
	guard.control.name = fmt.Sprintf("wy3mc%08x", n2dTopologySequence.Add(1))
	if _, err := runCommand("ip", "netns", "add", guard.control.name); err != nil {
		t.Fatal("mapping lifetime control namespace creation failed")
	}
	// Register immediately; partial setup must not leak the side control.
	t.Cleanup(func() {
		if err := guard.close(); err != nil {
			t.Error("mapping lifetime restoration or namespace cleanup failed")
		}
	})
	guard.control.identity, err = os.Stat(gateB3NamespaceHandle(guard.control.name))
	if err != nil || os.SameFile(guard.control.identity, guard.initial) {
		t.Fatal("mapping lifetime control identity rejected")
	}
	guard.control.original, err = readGateB3UDPTimeouts(guard.control.name)
	if err != nil {
		t.Fatal("mapping lifetime control snapshot failed")
	}
	guard.topology = newN2DTopology(t, n2dMappingEDM, n2dMappingEDM)
	// newN2DTopology has its own fallback cleanup. Run restoration before that
	// fallback on Fatal/panic as well as on the explicit success path.
	t.Cleanup(func() {
		if err := guard.close(); err != nil {
			t.Error("mapping lifetime pre-delete restoration failed")
		}
	})
	for side, name := range []string{guard.topology.natA, guard.topology.natB} {
		target := &guard.targets[side]
		target.name = name
		target.identity, err = os.Stat(gateB3NamespaceHandle(name))
		if err != nil || os.SameFile(target.identity, guard.initial) || os.SameFile(target.identity, guard.control.identity) ||
			(side == 1 && os.SameFile(target.identity, guard.targets[0].identity)) {
			t.Fatal("mapping lifetime owned NAT identity rejected")
		}
		wantLAN, wantWAN := n2dNATALAN, n2dNATAWAN
		if side == 1 {
			wantLAN, wantWAN = n2dNATBLAN, n2dNATBWAN
		}
		if !validGateB3LifetimeTopology(name, wantLAN, wantWAN) {
			t.Fatal("mapping lifetime fixed TEST-NET topology rejected")
		}
		target.original, err = readGateB3UDPTimeouts(name)
		if err != nil {
			t.Fatal("mapping lifetime original values unavailable")
		}
	}
	// All four originals are saved before ANY timeout is changed.
	for _, target := range guard.targets {
		if err := writeGateB3UDPTimeouts(target, [2]int{seconds, seconds}); err != nil {
			t.Fatal("mapping lifetime installation/readback failed")
		}
	}
	if err := guard.checkControls(); err != nil {
		t.Fatal("mapping lifetime timeout isolation was not proved")
	}
	t.Logf("mapping lifetime installation: kernel_unreplied=%d kernel_replied=%d owned_non_init=2 initial_unchanged=true control_unchanged=true", seconds, seconds)
	return guard
}

func gateB3NamespaceHandle(name string) string { return filepath.Join("/var/run/netns", name) }

func readGateB3UDPTimeouts(namespace string) ([2]int, error) {
	var values [2]int
	for index, key := range gateB3UDPTimeoutKeys {
		var output string
		var err error
		if namespace == "" {
			output, err = runCommand("sysctl", "-n", key)
		} else {
			output, err = runNamespaced(namespace, "sysctl", nil, "-n", key)
		}
		value, parseErr := strconv.Atoi(strings.TrimSpace(output))
		if err != nil || parseErr != nil || value <= 0 {
			return values, errors.New("mapping lifetime timeout read failed")
		}
		values[index] = value
	}
	return values, nil
}

func writeGateB3UDPTimeouts(target gateB3LifetimeNamespace, values [2]int) error {
	current, err := os.Stat(gateB3NamespaceHandle(target.name))
	initial, initErr := os.Stat("/proc/1/ns/net")
	if target.name == "" || target.identity == nil || err != nil || initErr != nil ||
		!os.SameFile(current, target.identity) || os.SameFile(current, initial) {
		return errors.New("mapping lifetime write authority rejected")
	}
	for index, key := range gateB3UDPTimeoutKeys {
		if values[index] <= 0 {
			return errors.New("mapping lifetime original value rejected")
		}
		if _, err := runNamespaced(target.name, "sysctl", nil, "-qw", key+"="+strconv.Itoa(values[index])); err != nil {
			return errors.New("mapping lifetime timeout write failed")
		}
		actual, err := readGateB3UDPTimeouts(target.name)
		if err != nil || actual[index] != values[index] {
			return errors.New("mapping lifetime per-value readback failed")
		}
	}
	return nil
}

func validGateB3LifetimeTopology(namespace, wantLAN, wantWAN string) bool {
	output, err := runCommand("ip", "-j", "-n", namespace, "address", "show")
	if err != nil {
		return false
	}
	var links []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(output), &links) != nil {
		return false
	}
	var lan, wan bool
	for _, link := range links {
		for _, address := range link.Addresses {
			lan = lan || link.Name == "lan0" && address.Local == wantLAN
			wan = wan || link.Name == "wan0" && address.Local == wantWAN
		}
	}
	return lan && wan
}

func (guard *gateB3LifetimeGuard) checkControls() error {
	initial, err := readGateB3UDPTimeouts("")
	control, controlErr := readGateB3UDPTimeouts(guard.control.name)
	identity, identityErr := os.Stat(gateB3NamespaceHandle(guard.control.name))
	if err != nil || controlErr != nil || identityErr != nil || guard.control.identity == nil ||
		!os.SameFile(identity, guard.control.identity) || initial != guard.initialValues || control != guard.control.original {
		return errors.New("mapping lifetime changed a non-target namespace")
	}
	return nil
}

func (guard *gateB3LifetimeGuard) restore() error {
	if guard.restored {
		return nil
	}
	var result error
	for _, target := range guard.targets {
		if target.identity != nil && target.original[0] > 0 && target.original[1] > 0 {
			result = errors.Join(result, writeGateB3UDPTimeouts(target, target.original))
		}
	}
	if guard.control.identity != nil && guard.control.original[0] > 0 {
		result = errors.Join(result, guard.checkControls())
	}
	guard.restored = result == nil
	return result
}

func (guard *gateB3LifetimeGuard) close() error {
	if guard.closed {
		return nil
	}
	// Restore + read back while the named handles still exist. Do not claim
	// restoration if the namespace has already vanished or changed identity.
	result := guard.restore()
	if guard.topology != nil {
		result = errors.Join(result, guard.topology.cleanup(), guard.topology.assertNoLeaks())
	}
	if guard.control.name != "" {
		_, err := runCommand("ip", "netns", "delete", guard.control.name)
		result = errors.Join(result, err)
		if _, err := os.Stat(gateB3NamespaceHandle(guard.control.name)); !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, errors.New("mapping lifetime control handle remains"))
		}
	}
	for _, target := range guard.targets {
		if target.name != "" {
			if _, err := os.Stat(gateB3NamespaceHandle(target.name)); !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, errors.New("mapping lifetime owned NAT handle remains"))
			}
		}
	}
	guard.closed = true
	return result
}
