// Package netif defines the abstract NetworkInterface used by the tunnel
// and client packages. Concrete backends (TUN, userspace, proxy) will be
// added in later milestones; this file freezes the public contract.
package netif

import (
	"errors"
	"net"
)

// ErrNotImplemented is returned by stub methods that have no real
// implementation yet.
var ErrNotImplemented = errors.New("netif: not implemented")

// Config holds the parameters needed to create a NetworkInterface.
type Config struct {
	Backend string // "auto" | "tun" | "userspace" | "proxy"
	MTU     int
}

// NetworkInterface is the abstract interface for virtual network devices.
// All backends (TUN, userspace netstack, SOCKS5 proxy) must implement it.
type NetworkInterface interface {
	// Name returns the OS-visible interface name (e.g. "wink0").
	Name() string

	// Type returns the backend type as a human-readable string
	// (e.g. "tun", "userspace", "proxy").
	Type() string

	// MTU returns the Maximum Transmission Unit configured on this interface.
	MTU() int

	// Read reads one IP packet into buf and returns the number of bytes read.
	Read(buf []byte) (int, error)

	// Write writes one IP packet from buf and returns the number of bytes written.
	Write(buf []byte) (int, error)

	// Close tears down the interface and releases associated resources.
	Close() error

	// SetIP assigns an IPv4 address and subnet mask to the interface.
	SetIP(ip net.IP, mask net.IPMask) error

	// AddRoute adds a route to dst via gateway through this interface.
	AddRoute(dst *net.IPNet, gateway net.IP) error

	// RemoveRoute removes the route to dst.
	RemoveRoute(dst *net.IPNet) error
}

// New creates a NetworkInterface based on cfg.
// When cfg.Backend is "auto" or empty, the in-memory userspace backend is
// selected so callers can exercise orchestration logic without touching the
// host networking stack.
func New(cfg Config) (NetworkInterface, error) {
	if cfg.MTU <= 0 {
		cfg.MTU = 1280
	}

	backend, err := selectBackend(cfg.Backend)
	if err != nil {
		return nil, err
	}

	cfg.Backend = backend
	return newMemoryInterface(cfg), nil
}

func selectBackend(backend string) (string, error) {
	switch backend {
	case "", "auto":
		return "userspace", nil
	case "tun", "userspace", "proxy":
		return backend, nil
	default:
		return "", errors.New("netif: unknown backend: " + backend)
	}
}
