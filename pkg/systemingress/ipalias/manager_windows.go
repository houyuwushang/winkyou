//go:build windows

package ipalias

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

type commandRunner interface {
	Run(name string, args ...string) ([]byte, error)
}

type addressProbe interface {
	LoopbackInterfaceIndex() (int, error)
	AddressPresent(interfaceIndex int, addr netip.Addr) (bool, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type netAddressProbe struct{}

func (netAddressProbe) LoopbackInterfaceIndex() (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("system ingress ipalias: enumerate network interfaces: %w", err)
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })

	fallback := 0
	for _, iface := range interfaces {
		if iface.Index <= 0 || iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		if fallback == 0 {
			fallback = iface.Index
		}
		addresses, addressErr := iface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, address := range addresses {
			if parsed, ok := addrFromNetAddr(address); ok && parsed.Is6() {
				return iface.Index, nil
			}
		}
	}
	if fallback != 0 {
		return fallback, nil
	}
	return 0, fmt.Errorf("system ingress ipalias: Windows loopback interface not found")
}

func (netAddressProbe) AddressPresent(interfaceIndex int, addr netip.Addr) (bool, error) {
	iface, err := net.InterfaceByIndex(interfaceIndex)
	if err != nil {
		return false, fmt.Errorf("system ingress ipalias: find loopback interface %d: %w", interfaceIndex, err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("system ingress ipalias: list addresses on loopback interface %d: %w", interfaceIndex, err)
	}
	for _, address := range addresses {
		if parsed, ok := addrFromNetAddr(address); ok && parsed == addr {
			return true, nil
		}
	}
	return false, nil
}

func addrFromNetAddr(address net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch value := address.(type) {
	case *net.IPNet:
		ip = value.IP
	case *net.IPAddr:
		ip = value.IP
	default:
		text := address.String()
		if prefix, err := netip.ParsePrefix(text); err == nil {
			return prefix.Addr().Unmap(), true
		}
		if parsed, err := netip.ParseAddr(text); err == nil {
			return parsed.Unmap(), true
		}
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return parsed.Unmap(), true
}

type loopbackManager struct {
	mu             sync.Mutex
	runner         commandRunner
	probe          addressProbe
	interfaceIndex int
	refs           map[netip.Addr]int
	owned          map[netip.Addr]struct{}
	closing        bool
	closed         bool
}

// NewLoopbackManager creates a manager for active-store IPv6 /128 aliases on
// the Windows loopback interface.
func NewLoopbackManager() (Manager, error) {
	return newLoopbackManagerWithDeps(execCommandRunner{}, netAddressProbe{})
}

func newLoopbackManagerWithDeps(runner commandRunner, probe addressProbe) (*loopbackManager, error) {
	if runner == nil {
		return nil, fmt.Errorf("system ingress ipalias: command runner is required")
	}
	if probe == nil {
		return nil, fmt.Errorf("system ingress ipalias: address probe is required")
	}
	interfaceIndex, err := probe.LoopbackInterfaceIndex()
	if err != nil {
		return nil, err
	}
	if interfaceIndex <= 0 {
		return nil, fmt.Errorf("system ingress ipalias: invalid loopback interface index %d", interfaceIndex)
	}
	return &loopbackManager{
		runner:         runner,
		probe:          probe,
		interfaceIndex: interfaceIndex,
		refs:           make(map[netip.Addr]int),
		owned:          make(map[netip.Addr]struct{}),
	}, nil
}

func (m *loopbackManager) Add(addr netip.Addr) error {
	if err := validateULA(addr); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing {
		return ErrClosed
	}
	if refs := m.refs[addr]; refs > 0 {
		m.refs[addr] = refs + 1
		return nil
	}
	if _, cleanupPending := m.owned[addr]; cleanupPending {
		return fmt.Errorf("system ingress ipalias: cleanup is pending for %s", addr)
	}

	present, err := m.probe.AddressPresent(m.interfaceIndex, addr)
	if err != nil {
		return fmt.Errorf("system ingress ipalias: check existing address %s: %w", addr, err)
	}
	if present {
		return fmt.Errorf("%w: %s", ErrAddressExists, addr)
	}
	commandErr := m.runNetsh(
		"add address",
		"interface", "ipv6", "add", "address",
		fmt.Sprintf("interface=%d", m.interfaceIndex),
		"address="+addr.String()+"/128",
		"store=active",
		"skipassource=true",
	)
	if commandErr != nil {
		// A failed command can still have changed Windows state. Probe before
		// relinquishing responsibility, and roll the alias back if it appeared.
		present, probeErr := m.probe.AddressPresent(m.interfaceIndex, addr)
		if probeErr == nil && !present {
			return commandErr
		}
		m.owned[addr] = struct{}{}
		cleanupErr := m.removeOwnedAliasLocked(addr)
		if probeErr != nil {
			return errors.Join(commandErr, fmt.Errorf("system ingress ipalias: verify failed add address %s: %w", addr, probeErr), cleanupErr)
		}
		return errors.Join(commandErr, cleanupErr)
	}

	// netsh reported success after the preflight absence check, so retain
	// cleanup responsibility until a probe proves that no address was created.
	m.owned[addr] = struct{}{}
	present, err = m.probe.AddressPresent(m.interfaceIndex, addr)
	if err != nil {
		verifyErr := fmt.Errorf("system ingress ipalias: verify added address %s: %w", addr, err)
		cleanupErr := m.removeOwnedAliasLocked(addr)
		return errors.Join(verifyErr, cleanupErr)
	}
	if !present {
		delete(m.owned, addr)
		return fmt.Errorf("system ingress ipalias: netsh succeeded but address %s did not appear on loopback interface %d", addr, m.interfaceIndex)
	}
	m.refs[addr] = 1
	return nil
}

func (m *loopbackManager) Remove(addr netip.Addr) error {
	if err := validateULA(addr); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing {
		return ErrClosed
	}
	refs := m.refs[addr]
	if refs == 0 {
		return fmt.Errorf("%w: %s", ErrAddressNotManaged, addr)
	}
	if refs > 1 {
		m.refs[addr] = refs - 1
		return nil
	}
	if err := m.removeOwnedAliasLocked(addr); err != nil {
		return err
	}
	delete(m.refs, addr)
	return nil
}

func (m *loopbackManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closing = true

	addresses := make([]netip.Addr, 0, len(m.owned))
	for addr := range m.owned {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })

	var closeErr error
	for _, addr := range addresses {
		if err := m.removeOwnedAliasLocked(addr); err != nil {
			closeErr = errors.Join(closeErr, err)
			continue
		}
		delete(m.refs, addr)
	}
	if closeErr == nil && len(m.owned) == 0 {
		m.closed = true
	}
	return closeErr
}

func (m *loopbackManager) removeOwnedAliasLocked(addr netip.Addr) error {
	commandErr := m.runNetsh(
		"delete address",
		"interface", "ipv6", "delete", "address",
		fmt.Sprintf("interface=%d", m.interfaceIndex),
		"address="+addr.String(),
		"store=active",
	)
	present, probeErr := m.probe.AddressPresent(m.interfaceIndex, addr)
	if probeErr != nil {
		return errors.Join(commandErr, fmt.Errorf("system ingress ipalias: verify deleted address %s: %w", addr, probeErr))
	}
	if !present {
		delete(m.owned, addr)
		return nil
	}
	if commandErr != nil {
		return commandErr
	}
	return fmt.Errorf("system ingress ipalias: netsh succeeded but address %s remains on loopback interface %d", addr, m.interfaceIndex)
}

func (m *loopbackManager) runNetsh(action string, args ...string) error {
	output, err := m.runner.Run("netsh.exe", args...)
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		return fmt.Errorf("system ingress ipalias: netsh %s: %w", action, err)
	}
	return fmt.Errorf("system ingress ipalias: netsh %s: %w: %s", action, err, detail)
}
