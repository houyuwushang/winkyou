//go:build !windows

package ipalias

import "fmt"

// NewLoopbackManager reports that loopback IPv6 alias management is available
// only on Windows.
func NewLoopbackManager() (Manager, error) {
	return nil, fmt.Errorf("%w: loopback IPv6 aliases require Windows", ErrUnsupported)
}

// NewOwnedLoopbackManager reports that crash-safe loopback IPv6 alias
// ownership is available only on Windows.
func NewOwnedLoopbackManager(options OwnershipOptions) (Manager, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: loopback IPv6 aliases require Windows", ErrUnsupported)
}
