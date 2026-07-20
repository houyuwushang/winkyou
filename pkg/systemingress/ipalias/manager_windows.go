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

	"golang.org/x/sys/windows"
)

type commandRunner interface {
	Run(name string, args ...string) ([]byte, error)
}

type addressProbe interface {
	LoopbackInterfaceIndex() (int, error)
	AddressState(interfaceIndex int, addr netip.Addr) (aliasAddressState, error)
}

type aliasAddressState struct {
	Present       bool
	PrefixLength  uint8
	SkipAsSource  bool
	RowCreationID string
}

func (s aliasAddressState) validOwnedShape() bool {
	return s.Present && s.PrefixLength == 128 && s.SkipAsSource
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

func (netAddressProbe) AddressState(interfaceIndex int, addr netip.Addr) (aliasAddressState, error) {
	if interfaceIndex <= 0 || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
		return aliasAddressState{}, fmt.Errorf("system ingress ipalias: invalid address-state lookup for interface %d address %s", interfaceIndex, addr)
	}
	row := windows.MibUnicastIpAddressRow{InterfaceIndex: uint32(interfaceIndex)}
	row.Address.Family = windows.AF_INET6
	row.Address.Addr = addr.As16()
	if err := windows.GetUnicastIpAddressEntry(&row); err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			return aliasAddressState{}, nil
		}
		return aliasAddressState{}, fmt.Errorf("system ingress ipalias: inspect address %s on interface %d: %w", addr, interfaceIndex, err)
	}
	return aliasAddressState{
		Present: true, PrefixLength: row.OnLinkPrefixLength, SkipAsSource: row.SkipAsSource != 0,
		RowCreationID: fmt.Sprintf("%08x%08x", row.CreationTimeStamp.HighDateTime, row.CreationTimeStamp.LowDateTime),
	}, nil
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
	ownership      *ownershipStore
	claims         map[netip.Addr]*aliasClaim
	closing        bool
	closed         bool
}

// NewLoopbackManager creates a manager for active-store IPv6 /128 aliases on
// the Windows loopback interface.
func NewLoopbackManager() (Manager, error) {
	return newLoopbackManagerWithDeps(execCommandRunner{}, netAddressProbe{})
}

// NewOwnedLoopbackManager creates a loopback alias manager whose ownership
// survives an ungraceful Wink process exit. Existing addresses are adopted
// only when a matching journal proves that the previous process generation
// created them and that generation is no longer alive.
func NewOwnedLoopbackManager(options OwnershipOptions) (Manager, error) {
	return newOwnedLoopbackManagerWithDeps(options, execCommandRunner{}, netAddressProbe{})
}

func newOwnedLoopbackManagerWithDeps(options OwnershipOptions, runner commandRunner, probe addressProbe) (*loopbackManager, error) {
	manager, err := newLoopbackManagerWithDeps(runner, probe)
	if err != nil {
		return nil, err
	}
	ownership, err := newOwnershipStore(options, manager.interfaceIndex)
	if err != nil {
		return nil, err
	}
	manager.ownership = ownership
	manager.claims = make(map[netip.Addr]*aliasClaim)
	return manager, nil
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
	var claim *aliasClaim
	if m.ownership != nil {
		var err error
		claim, err = m.ownership.acquire(addr.String())
		if err != nil {
			return err
		}
	}

	state, err := m.probe.AddressState(m.interfaceIndex, addr)
	if err != nil {
		claim.release()
		return fmt.Errorf("system ingress ipalias: check existing address %s: %w", addr, err)
	}
	if state.Present {
		if claim != nil && claim.recoverable {
			if err := claim.validateRecovery(state); err != nil {
				claim.release()
				return err
			}
			claim.rowCreationID = state.RowCreationID
			if err := claim.write(ownershipPhaseActive); err != nil {
				claim.release()
				return fmt.Errorf("system ingress ipalias: recover ownership of address %s: %w", addr, err)
			}
			m.owned[addr] = struct{}{}
			m.claims[addr] = claim
			m.refs[addr] = 1
			return nil
		}
		claim.release()
		return fmt.Errorf("%w: %s", ErrAddressExists, addr)
	}
	if claim != nil {
		if err := claim.write(ownershipPhaseIntent); err != nil {
			claim.release()
			return fmt.Errorf("system ingress ipalias: journal address creation %s: %w", addr, err)
		}
		m.owned[addr] = struct{}{}
		m.claims[addr] = claim
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
		state, probeErr := m.probe.AddressState(m.interfaceIndex, addr)
		if probeErr == nil && !state.Present {
			cleanupErr := m.releaseAbsentAliasLocked(addr)
			return errors.Join(commandErr, cleanupErr)
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
	state, err = m.probe.AddressState(m.interfaceIndex, addr)
	if err != nil {
		verifyErr := fmt.Errorf("system ingress ipalias: verify added address %s: %w", addr, err)
		cleanupErr := m.removeOwnedAliasLocked(addr)
		return errors.Join(verifyErr, cleanupErr)
	}
	if !state.Present {
		verifyErr := fmt.Errorf("system ingress ipalias: netsh succeeded but address %s did not appear on loopback interface %d", addr, m.interfaceIndex)
		return errors.Join(verifyErr, m.releaseAbsentAliasLocked(addr))
	}
	if !state.validOwnedShape() {
		verifyErr := fmt.Errorf(
			"system ingress ipalias: address %s appeared with prefix /%d skip-as-source=%t, want /128 and true",
			addr, state.PrefixLength, state.SkipAsSource,
		)
		return errors.Join(verifyErr, m.removeOwnedAliasLocked(addr))
	}
	if claim != nil {
		claim.rowCreationID = state.RowCreationID
		if err := claim.write(ownershipPhaseActive); err != nil {
			commitErr := fmt.Errorf("system ingress ipalias: commit ownership of address %s: %w", addr, err)
			return errors.Join(commitErr, m.removeOwnedAliasLocked(addr))
		}
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
	claim := m.claims[addr]
	if m.ownership != nil {
		if claim == nil {
			return fmt.Errorf("%w: missing ownership claim for %s", ErrOwnershipConflict, addr)
		}
		state, err := m.probe.AddressState(m.interfaceIndex, addr)
		if err != nil {
			return fmt.Errorf("system ingress ipalias: verify owned address %s before deletion: %w", addr, err)
		}
		if !state.Present {
			return m.releaseAbsentAliasLocked(addr)
		}
		if !state.validOwnedShape() {
			return fmt.Errorf(
				"%w: refusing to delete address %s with prefix /%d skip-as-source=%t",
				ErrOwnershipConflict, addr, state.PrefixLength, state.SkipAsSource,
			)
		}
		if claim.rowCreationID == "" {
			// A command may have applied the address before reporting failure,
			// while the immediate verification probe also failed. The intent
			// marker and held alias lock are the only possible proof in this
			// narrow crash/error window; bind the observed row before deleting.
			claim.rowCreationID = state.RowCreationID
		} else if claim.rowCreationID != state.RowCreationID {
			return fmt.Errorf("%w: refusing to delete replacement operating-system row for address %s", ErrOwnershipConflict, addr)
		}
		if err := claim.write(ownershipPhaseDeleting); err != nil {
			return fmt.Errorf("system ingress ipalias: journal address deletion %s: %w", addr, err)
		}
	}
	commandErr := m.runNetsh(
		"delete address",
		"interface", "ipv6", "delete", "address",
		fmt.Sprintf("interface=%d", m.interfaceIndex),
		"address="+addr.String(),
		"store=active",
	)
	state, probeErr := m.probe.AddressState(m.interfaceIndex, addr)
	if probeErr != nil {
		return errors.Join(commandErr, fmt.Errorf("system ingress ipalias: verify deleted address %s: %w", addr, probeErr))
	}
	if !state.Present {
		return m.releaseAbsentAliasLocked(addr)
	}
	if commandErr != nil {
		return commandErr
	}
	return fmt.Errorf("system ingress ipalias: netsh succeeded but address %s remains on loopback interface %d", addr, m.interfaceIndex)
}

func (m *loopbackManager) releaseAbsentAliasLocked(addr netip.Addr) error {
	claim := m.claims[addr]
	if claim != nil {
		if err := claim.removeMarker(); err != nil {
			return err
		}
		claim.release()
		delete(m.claims, addr)
	}
	delete(m.owned, addr)
	return nil
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
