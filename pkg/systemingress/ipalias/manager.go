// Package ipalias manages temporary IP aliases used by system-ingress
// backends.
package ipalias

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
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
	// ErrOwnershipConflict indicates that another live owner, another stable
	// owner scope, or an unverifiable ownership journal already claims the
	// address. The address is never changed when this error is returned.
	ErrOwnershipConflict = errors.New("system ingress ipalias: ownership conflict")
	// ErrOwnershipLocked indicates that another process currently holds the
	// cross-process lifecycle lock for the address.
	ErrOwnershipLocked = errors.New("system ingress ipalias: ownership locked")
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

// OwnershipOptions enables crash-safe ownership transfer for aliases created
// by the same stable Wink runtime. Scope must remain stable across process
// generations (the canonical runtime-state path plus node ID is suitable),
// while InstanceID and ProcessStartID must identify the current generation.
// ConfigFingerprint must cover the complete configured virtual-forward set.
//
// StoreDir is optional in production and primarily exists for hermetic tests.
// The default Windows store is shared across Wink processes so different state
// paths cannot race while creating the same loopback address.
type OwnershipOptions struct {
	Scope             string
	InstanceID        string
	PID               int
	ProcessStartID    string
	ConfigFingerprint string
	StoreDir          string
}

func (o OwnershipOptions) validate() error {
	if strings.TrimSpace(o.Scope) == "" {
		return fmt.Errorf("system ingress ipalias: ownership scope is required")
	}
	if strings.TrimSpace(o.InstanceID) == "" {
		return fmt.Errorf("system ingress ipalias: ownership instance id is required")
	}
	if o.PID <= 0 {
		return fmt.Errorf("system ingress ipalias: ownership pid must be positive: %d", o.PID)
	}
	if strings.TrimSpace(o.ProcessStartID) == "" {
		return fmt.Errorf("system ingress ipalias: ownership process start identity is required")
	}
	if strings.TrimSpace(o.ConfigFingerprint) == "" {
		return fmt.Errorf("system ingress ipalias: ownership config fingerprint is required")
	}
	return nil
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
