// Package netif defines the abstract NetworkInterface used by the tunnel
// and client packages.
package netif

import (
	"errors"
	"net"
	"strings"
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

// MemoryTestInterface exposes directional packet injection helpers used by
// unprivileged tests when the in-memory backend stands in for a TUN device.
type MemoryTestInterface interface {
	NetworkInterface
	InjectPacket(buf []byte) (int, error)
	ReceivePacket(buf []byte) (int, error)
}

// New creates a NetworkInterface based on cfg.
func New(cfg Config) (NetworkInterface, error) {
	if cfg.MTU <= 0 {
		cfg.MTU = 1280
	}

	return newByBackend(cfg)
}

// NewGateCMemoryInterface creates only an in-process packet queue. It never
// creates, names, configures, or routes an operating-system interface. The
// Gate C architecture gate restricts its sole production caller.
func NewGateCMemoryInterface(name string, mtu int) (MemoryTestInterface, error) {
	if !validGateCMemoryName(name) || mtu < 1280 || mtu > 9000 {
		return nil, errors.New("netif: invalid Gate C memory interface")
	}
	instance := newMemoryInterface(Config{Backend: "memory", MTU: mtu})
	instance.name = name
	return instance, nil
}

func validGateCMemoryName(name string) bool {
	if name == "" || len(name) > 32 || name != strings.TrimSpace(name) {
		return false
	}
	for index, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			index > 0 && character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_') {
			continue
		}
		return false
	}
	return true
}
