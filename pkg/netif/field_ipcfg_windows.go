//go:build windows && fieldc1c

package netif

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// This private transaction receives only the new adapter's exact identity.
// No public arbitrary-address or interface-management constructor is exposed.
type fieldWindowsBinding struct {
	name        string
	guid        windows.GUID
	mtu         uint32
	local, peer netip.Addr
}

type fieldAdapterIdentity struct {
	luid  uint64
	index uint32
	guid  windows.GUID
	name  string
}

type fieldIPSnapshot struct {
	adapters  []fieldAdapterIdentity
	addresses []fieldAddressRow
	routes    []fieldRouteRow
}

type fieldIPOperations interface {
	snapshot() (fieldIPSnapshot, error)
	identity(uint64) (fieldAdapterIdentity, error)
	getInterface(uint64) (fieldIPInterfaceRow, error)
	setInterface(fieldIPInterfaceRow) error
	getAddress(fieldAddressRow) (fieldAddressRow, error)
	createAddress(fieldAddressRow) error
	deleteAddress(fieldAddressRow) error
	getRoute(fieldRouteRow) (fieldRouteRow, error)
	createRoute(fieldRouteRow) error
	deleteRoute(fieldRouteRow) error
}

type fieldIPTransaction struct {
	api      fieldIPOperations
	identity fieldAdapterIdentity
	before   fieldIPInterfaceRow
	applied  fieldIPInterfaceRow
	address  fieldAddressRow
	route    fieldRouteRow
	steps    uint8
}

func fieldParseGUID(value string) (windows.GUID, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || strings.ToLower(value) != value {
		return windows.GUID{}, ErrFieldInterface
	}
	bytes, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(bytes) != 16 {
		return windows.GUID{}, ErrFieldInterface
	}
	result := windows.GUID{Data1: binary.BigEndian.Uint32(bytes[:4]), Data2: binary.BigEndian.Uint16(bytes[4:6]), Data3: binary.BigEndian.Uint16(bytes[6:8])}
	copy(result.Data4[:], bytes[8:])
	return result, nil
}
func fieldGUIDString(value windows.GUID) string {
	var bytes [16]byte
	binary.BigEndian.PutUint32(bytes[:4], value.Data1)
	binary.BigEndian.PutUint16(bytes[4:6], value.Data2)
	binary.BigEndian.PutUint16(bytes[6:8], value.Data3)
	copy(bytes[8:], value.Data4[:])
	h := hex.EncodeToString(bytes[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func fieldIPv4(value netip.Addr) fieldSockaddr {
	if !value.Is4() {
		return fieldSockaddr{}
	}
	result := fieldSockaddr{Family: windows.AF_INET}
	address := value.As4()
	copy(result.Data[2:6], address[:])
	return result
}
func fieldAddress(value fieldSockaddr) (netip.Addr, error) {
	if value.Family != windows.AF_INET || value.Data[0] != 0 || value.Data[1] != 0 {
		return netip.Addr{}, ErrFieldInterface
	}
	return netip.AddrFrom4([4]byte(value.Data[2:6])), nil
}
func fieldRejectConflicts(binding fieldWindowsBinding, snapshot fieldIPSnapshot) error {
	if !binding.valid() {
		return ErrFieldInterface
	}
	for _, adapter := range snapshot.adapters {
		if strings.EqualFold(adapter.name, binding.name) || adapter.guid == binding.guid {
			return ErrFieldInterface
		}
	}
	for _, row := range snapshot.addresses {
		address, err := fieldAddress(row.Address)
		if err != nil || address == binding.local || address == binding.peer {
			return ErrFieldInterface
		}
	}
	for _, row := range snapshot.routes {
		address, err := fieldAddress(row.Destination.Address)
		if err != nil || row.Destination.Bits > 32 {
			return ErrFieldInterface
		}
		prefix := netip.PrefixFrom(address, int(row.Destination.Bits))
		if prefix.Masked() != prefix {
			return ErrFieldInterface
		}
		if prefix.Bits() != 0 && (prefix.Contains(binding.local) || prefix.Contains(binding.peer)) {
			return ErrFieldInterface
		}
	}
	return nil
}

func (binding fieldWindowsBinding) valid() bool {
	if len(binding.name) != 15 || !strings.HasPrefix(binding.name, "wcf") || binding.guid == (windows.GUID{}) || binding.mtu < 576 || binding.mtu > 65535 ||
		!binding.local.Is4() || !binding.peer.Is4() || !binding.local.IsGlobalUnicast() || !binding.peer.IsGlobalUnicast() || binding.local == binding.peer {
		return false
	}
	_, err := hex.DecodeString(binding.name[3:])
	return err == nil && strings.ToLower(binding.name) == binding.name
}

func configureFieldIP(ctx context.Context, api fieldIPOperations, binding fieldWindowsBinding, identity fieldAdapterIdentity) (*fieldIPTransaction, error) {
	if ctx == nil || ctx.Err() != nil || api == nil || !binding.valid() || identity.luid == 0 || identity.index == 0 || identity.name != binding.name || identity.guid != binding.guid {
		return nil, ErrFieldInterface
	}
	txn := &fieldIPTransaction{api: api, identity: identity}
	failed := func() (*fieldIPTransaction, error) {
		// Cancellation never suppresses cleanup of an earlier successful write.
		drain, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return nil, errors.Join(ErrFieldInterface, txn.rollback(drain))
	}
	actual, err := api.identity(identity.luid)
	if err != nil || actual != identity {
		return nil, ErrFieldInterface
	}
	txn.before, err = api.getInterface(identity.luid)
	if err != nil || txn.before.Family != windows.AF_INET || txn.before.LUID != identity.luid || txn.before.Index != identity.index {
		return nil, ErrFieldInterface
	}
	txn.applied = txn.before
	txn.applied.MTU = binding.mtu
	// Only this new, owned point-to-point row: DadTransmits=0 disables DAD
	// (MIB_IPINTERFACE_ROW). No background address probe or polling is added.
	// The exact previous value is compared/restored with the MTU on rollback.
	txn.applied.DadTransmits = 0
	// SetIpInterfaceEntry requires zero for IPv4 SitePrefixLength. Preserve
	// every other writable field; never initialize-and-set unrelated settings.
	txn.applied.SitePrefixLength = 0
	if ctx.Err() != nil || api.setInterface(txn.applied) != nil {
		return failed()
	}
	txn.steps |= 1
	readInterface, err := api.getInterface(identity.luid)
	if err != nil || !fieldSameInterface(readInterface, txn.applied) || !fieldIdentityMatches(api, identity) {
		return failed()
	}
	txn.address = fieldAddressRow{Address: fieldIPv4(binding.local), LUID: identity.luid, Index: identity.index,
		PrefixOrigin: 1, SuffixOrigin: 1, ValidLifetime: ^uint32(0), PreferredLifetime: ^uint32(0), PrefixLength: 32, SkipAsSource: 1, DadState: 4}
	if ctx.Err() != nil || api.createAddress(txn.address) != nil {
		return failed()
	}
	txn.steps |= 2
	readAddress, err := api.getAddress(txn.address)
	if err != nil || !fieldSameAddress(readAddress, txn.address) || !fieldIdentityMatches(api, identity) {
		return failed()
	}
	txn.route = fieldRouteRow{LUID: identity.luid, Index: identity.index, Destination: fieldIPPrefix{Address: fieldIPv4(binding.peer), Bits: 32},
		NextHop: fieldIPv4(netip.IPv4Unspecified()), ValidLifetime: ^uint32(0), PreferredLifetime: ^uint32(0), Metric: 1, Protocol: 3}
	if ctx.Err() != nil || api.createRoute(txn.route) != nil {
		return failed()
	}
	txn.steps |= 4
	readRoute, err := api.getRoute(txn.route)
	if err != nil || !fieldSameRoute(readRoute, txn.route) || !fieldIdentityMatches(api, identity) || ctx.Err() != nil {
		return failed()
	}
	return txn, nil
}

func fieldIdentityMatches(api fieldIPOperations, expected fieldAdapterIdentity) bool {
	actual, err := api.identity(expected.luid)
	return err == nil && actual == expected
}

// Compare snapshots without treating OS counters/order/route age as writes.
// Never restore a table: unrelated concurrent changes remain observable RED.
func fieldUnrelatedUnchanged(before, after fieldIPSnapshot, owned uint64) bool {
	adapters := map[fieldAdapterIdentity]int{}
	addresses := map[fieldAddressRow]int{}
	routes := map[fieldRouteRow]int{}
	for index, snapshot := range []fieldIPSnapshot{before, after} {
		sign := 1
		if index == 1 {
			sign = -1
		}
		for _, row := range snapshot.adapters {
			if row.luid != owned {
				adapters[row] += sign
			}
		}
		for _, row := range snapshot.addresses {
			if row.LUID != owned {
				row.CreationTimestamp = 0
				addresses[row] += sign
			}
		}
		for _, row := range snapshot.routes {
			if row.LUID != owned {
				row.Age = 0
				routes[row] += sign
			}
		}
	}
	for _, count := range adapters {
		if count != 0 {
			return false
		}
	}
	for _, count := range addresses {
		if count != 0 {
			return false
		}
	}
	for _, count := range routes {
		if count != 0 {
			return false
		}
	}
	return true
}

func fieldSameAddress(left, right fieldAddressRow) bool {
	// CreationTimestamp is OS-owned, not a caller-written value.
	left.CreationTimestamp, right.CreationTimestamp = 0, 0
	return left == right
}
func fieldSameRoute(left, right fieldRouteRow) bool { left.Age, right.Age = 0, 0; return left == right }
func fieldSameInterface(left, right fieldIPInterfaceRow) bool {
	// Exactly the read-only fields listed by SetIpInterfaceEntry are ignored.
	normalize := func(row fieldIPInterfaceRow) fieldIPInterfaceRow {
		row.MaxReassemblySize, row.MinRouterAdvertisementInterval, row.MaxRouterAdvertisementInterval = 0, 0, 0
		row.Connected, row.SupportsWakeUpPatterns, row.SupportsNeighborDiscovery, row.SupportsRouterDiscovery = 0, 0, 0, 0
		row.ReachableTime, row.TransmitOffload, row.ReceiveOffload = 0, 0, 0
		row.SitePrefixLength = 0
		return row
	}
	return normalize(left) == normalize(right)
}

func (transaction *fieldIPTransaction) rollback(ctx context.Context) error {
	if transaction == nil || transaction.steps == 0 {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return ErrFieldInterface
	}
	api := transaction.api
	identity, err := api.identity(transaction.identity.luid)
	if err != nil || identity != transaction.identity {
		return ErrFieldInterface
	}
	var result error
	reject := func() { result = errors.Join(result, ErrFieldInterface) }
	if transaction.steps&4 != 0 {
		row, err := api.getRoute(transaction.route)
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			transaction.steps &^= 4
		} else if err != nil || !fieldSameRoute(row, transaction.route) || ctx.Err() != nil || api.deleteRoute(row) != nil {
			reject()
		} else if _, err = api.getRoute(transaction.route); !errors.Is(err, windows.ERROR_NOT_FOUND) {
			reject()
		} else {
			transaction.steps &^= 4
		}
	}
	if transaction.steps&2 != 0 {
		row, err := api.getAddress(transaction.address)
		if errors.Is(err, windows.ERROR_NOT_FOUND) {
			transaction.steps &^= 2
		} else if err != nil || !fieldSameAddress(row, transaction.address) || ctx.Err() != nil || api.deleteAddress(row) != nil {
			reject()
		} else if _, err = api.getAddress(transaction.address); !errors.Is(err, windows.ERROR_NOT_FOUND) {
			reject()
		} else {
			transaction.steps &^= 2
		}
	}
	if transaction.steps&1 != 0 {
		row, err := api.getInterface(transaction.identity.luid)
		restore := transaction.before
		restore.SitePrefixLength = 0
		if err != nil || !fieldSameInterface(row, transaction.applied) || ctx.Err() != nil || api.setInterface(restore) != nil {
			reject()
		} else if row, err = api.getInterface(transaction.identity.luid); err != nil || !fieldSameInterface(row, restore) {
			reject()
		} else {
			transaction.steps &^= 1
		}
	}
	if ctx.Err() != nil {
		reject()
	}
	return result
}
