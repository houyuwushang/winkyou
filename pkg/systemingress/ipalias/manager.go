// Package ipalias manages temporary IP aliases used by system-ingress
// backends.
package ipalias

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	// ErrUnsupported indicates that the current platform has no ipalias
	// implementation.
	ErrUnsupported = errors.New("system ingress ipalias: unsupported platform")
	// ErrInvalidAddress indicates that an address is not an unzoned IPv6 ULA.
	ErrInvalidAddress = errors.New("system ingress ipalias: address must be an IPv6 ULA")
	// ErrAddressExists indicates that the address existed before this manager
	// attempted to add it. Such addresses are never adopted or removed.
	ErrAddressExists = errors.New("system ingress ipalias: address already exists")
	// ErrAddressNotManaged indicates that Remove was called for an address that
	// this manager does not own.
	ErrAddressNotManaged = errors.New("system ingress ipalias: address is not managed")
	// ErrClosed indicates that the manager is closed or is completing cleanup.
	ErrClosed = errors.New("system ingress ipalias: manager is closed")
)

// Manager owns temporary /128 aliases on the Windows loopback interface.
// Repeated Add calls from the same Manager are reference counted.
type Manager interface {
	Add(netip.Addr) error
	Remove(netip.Addr) error
	Close() error
}

func validateULA(addr netip.Addr) error {
	if !addr.IsValid() || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
		return fmt.Errorf("%w: %s", ErrInvalidAddress, addr)
	}
	bytes := addr.As16()
	if bytes[0]&0xfe != 0xfc {
		return fmt.Errorf("%w: %s", ErrInvalidAddress, addr)
	}
	return nil
}
