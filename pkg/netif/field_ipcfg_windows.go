//go:build windows && fieldc1c

package netif

import (
	"context"
	"net/netip"

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

func fieldParseGUID(value string) (windows.GUID, error) { return windows.GUID{}, ErrFieldInterface }
func fieldGUIDString(value windows.GUID) string         { return "" }
func fieldIPv4(value netip.Addr) fieldSockaddr          { return fieldSockaddr{} }
func fieldAddress(value fieldSockaddr) (netip.Addr, error) {
	return netip.Addr{}, ErrFieldInterface
}
func fieldRejectConflicts(binding fieldWindowsBinding, snapshot fieldIPSnapshot) error {
	return ErrFieldInterface
}
func configureFieldIP(ctx context.Context, api fieldIPOperations, binding fieldWindowsBinding, identity fieldAdapterIdentity) (*fieldIPTransaction, error) {
	return nil, ErrFieldInterface
}
func (transaction *fieldIPTransaction) rollback(ctx context.Context) error {
	return ErrFieldInterface
}
